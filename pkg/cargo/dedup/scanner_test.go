package dedup_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

func TestScanCompiledReleaseTarballs_FindsDuplicates(t *testing.T) {
	sharedBlob, err := dedup.MakeMinimalGzip([]byte("shared-golang-blob"))
	require.NoError(t, err)

	golangPkg := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang-abc123", Blob: sharedBlob}
	uniquePkg1 := dedup.FakePackage{Name: "nats-server", Fingerprint: "fp-nats-unique-001"}
	uniquePkg2 := dedup.FakePackage{Name: "routing-api", Fingerprint: "fp-routing-unique-002"}

	release1Bytes, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golangPkg, uniquePkg1})
	require.NoError(t, err)

	release2Bytes, err := dedup.MakeCompiledReleaseTarball("routing", "2.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golangPkg, uniquePkg2})
	require.NoError(t, err)

	dir := t.TempDir()
	path1 := filepath.Join(dir, "nats-1.0.0-ubuntu-jammy-1.1107.tgz")
	path2 := filepath.Join(dir, "routing-2.0.0-ubuntu-jammy-1.1107.tgz")
	require.NoError(t, os.WriteFile(path1, release1Bytes, 0644))
	require.NoError(t, os.WriteFile(path2, release2Bytes, 0644))

	result, err := dedup.ScanCompiledReleaseTarballs([]string{path1, path2})
	require.NoError(t, err)

	require.Len(t, result.SharedPackages, 1, "only golang-1-linux should be shared")
	shared := result.SharedPackages[0]
	assert.Equal(t, "fp-golang-abc123", shared.Fingerprint)
	assert.Equal(t, "golang-1-linux", shared.Name)
	// MakeCompiledReleaseTarball sets Version == Fingerprint; verify the field is populated.
	assert.Equal(t, "fp-golang-abc123", shared.Version)
	assert.Equal(t, int64(len(sharedBlob)), shared.BlobSize)
	assert.NotEmpty(t, shared.SourceRelease, "should record which release to extract blob from")

	assert.Contains(t, result.ReleasePackages[path1], "fp-golang-abc123")
	assert.Contains(t, result.ReleasePackages[path2], "fp-golang-abc123")
	for _, sp := range result.SharedPackages {
		assert.NotEqual(t, "fp-nats-unique-001", sp.Fingerprint)
		assert.NotEqual(t, "fp-routing-unique-002", sp.Fingerprint)
	}
}

func TestScanCompiledReleaseTarballs_NoDuplicates(t *testing.T) {
	dir := t.TempDir()
	r1, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{{Name: "nats-server", Fingerprint: "fp-nats-001"}})
	require.NoError(t, err)
	p1 := filepath.Join(dir, "nats.tgz")
	require.NoError(t, os.WriteFile(p1, r1, 0644))

	result, err := dedup.ScanCompiledReleaseTarballs([]string{p1})
	require.NoError(t, err)
	assert.Empty(t, result.SharedPackages)
}

func TestScanCompiledReleaseTarballs_SamePackageInThreeReleases(t *testing.T) {
	sharedBlob, err := dedup.MakeMinimalGzip([]byte("shared-blob-content"))
	require.NoError(t, err)
	golang := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang", Blob: sharedBlob}

	dir := t.TempDir()
	var paths []string
	for i, relName := range []string{"nats", "routing", "loggregator"} {
		b, err := dedup.MakeCompiledReleaseTarball(relName, "1.0.0", "ubuntu-jammy/1.1107",
			[]dedup.FakePackage{golang})
		require.NoError(t, err)
		p := filepath.Join(dir, relName+".tgz")
		require.NoError(t, os.WriteFile(p, b, 0644))
		paths = append(paths, p)
		_ = i
	}

	result, err := dedup.ScanCompiledReleaseTarballs(paths)
	require.NoError(t, err)
	require.Len(t, result.SharedPackages, 1)
	assert.Equal(t, "fp-golang", result.SharedPackages[0].Fingerprint)
}
