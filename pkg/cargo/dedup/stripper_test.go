package dedup_test

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pivotal-cf/kiln/pkg/cargo"
	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

func listTarEntries(t *testing.T, tgzPath string) []string {
	t.Helper()
	f, err := os.Open(tgzPath)
	require.NoError(t, err)
	defer f.Close()
	gr, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gr.Close()
	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hdr.Name)
	}
	return names
}

// --- FindJobReferencedPackages ---

func TestFindJobReferencedPackages_ReturnsRuntimePackages(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
		{Name: "nats-server", Fingerprint: "fp-nats"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("nats", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "nats.tgz")
	require.NoError(t, os.WriteFile(path, b, 0644))

	referenced, err := dedup.FindJobReferencedPackages(path)
	require.NoError(t, err)
	require.NotNil(t, referenced, "should return a non-nil map when the release has jobs")
	assert.True(t, referenced["nats-server"], "nats-server is listed in the nats job's packages")
	assert.False(t, referenced["golang-1-linux"], "golang-1-linux is not listed in any job")
}

func TestFindJobReferencedPackages_MultipleJobs_ReturnsUnion(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
		{Name: "nats-server", Fingerprint: "fp-nats"},
		{Name: "routing-api", Fingerprint: "fp-routing"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
		{Name: "router", Packages: []string{"routing-api"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("release", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "release.tgz")
	require.NoError(t, os.WriteFile(path, b, 0644))

	referenced, err := dedup.FindJobReferencedPackages(path)
	require.NoError(t, err)
	assert.True(t, referenced["nats-server"])
	assert.True(t, referenced["routing-api"])
	assert.False(t, referenced["golang-1-linux"])
}

func TestFindJobReferencedPackages_NoJobs_ReturnsNil(t *testing.T) {
	// A shared-packages release (or any release with no jobs) should return nil
	// so callers know NOT to strip it.
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
	}
	b, err := dedup.MakeCompiledReleaseTarball("shared-packages", "1.0.0", "ubuntu-jammy/1.1107", pkgs)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "shared.tgz")
	require.NoError(t, os.WriteFile(path, b, 0644))

	referenced, err := dedup.FindJobReferencedPackages(path)
	require.NoError(t, err)
	assert.Nil(t, referenced, "release with no jobs must return nil to prevent accidental stripping")
}

// --- StripCompileTimePackages ---

func TestStripCompileTimePackages_StripsUnreferencedBlob(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
		{Name: "nats-server", Fingerprint: "fp-nats"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("nats", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "nats.tgz")
	dstPath := filepath.Join(dir, "nats-stripped.tgz")
	require.NoError(t, os.WriteFile(srcPath, b, 0644))

	stripped, sha256hex, err := dedup.StripCompileTimePackages(srcPath, dstPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"golang-1-linux"}, stripped)
	assert.Len(t, sha256hex, 64, "should return hex SHA256 of output tarball")

	entries := listTarEntries(t, dstPath)
	assert.NotContains(t, entries, "./compiled_packages/golang-1-linux.tgz",
		"compile-time package blob must be removed")
	assert.Contains(t, entries, "./compiled_packages/nats-server.tgz",
		"runtime package blob must be preserved")
}

func TestStripCompileTimePackages_UpdatesReleaseMF(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
		{Name: "nats-server", Fingerprint: "fp-nats"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("nats", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "nats.tgz")
	dstPath := filepath.Join(dir, "nats-stripped.tgz")
	require.NoError(t, os.WriteFile(srcPath, b, 0644))

	_, _, err = dedup.StripCompileTimePackages(srcPath, dstPath)
	require.NoError(t, err)

	result, err := cargo.OpenBOSHReleaseTarball(dstPath)
	require.NoError(t, err)
	require.Len(t, result.Manifest.CompiledPackages, 1,
		"release.MF must only list runtime packages after stripping")
	assert.Equal(t, "nats-server", result.Manifest.CompiledPackages[0].Name)
}

func TestStripCompileTimePackages_NoJobs_NothingStripped(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
	}
	// No jobs — simulates a shared-packages release.
	b, err := dedup.MakeCompiledReleaseTarball("shared-packages", "1.0.0", "ubuntu-jammy/1.1107", pkgs)
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "shared.tgz")
	dstPath := filepath.Join(dir, "shared-stripped.tgz")
	require.NoError(t, os.WriteFile(srcPath, b, 0644))

	stripped, sha256hex, err := dedup.StripCompileTimePackages(srcPath, dstPath)
	require.NoError(t, err)
	assert.Empty(t, stripped, "releases with no jobs must not be stripped")
	assert.Empty(t, sha256hex)

	_, statErr := os.Stat(dstPath)
	assert.True(t, os.IsNotExist(statErr), "output file must not be created when nothing is stripped")
}

func TestStripCompileTimePackages_AllPackagesReferenced_NothingStripped(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "nats-server", Fingerprint: "fp-nats"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("nats", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "nats.tgz")
	dstPath := filepath.Join(dir, "nats-stripped.tgz")
	require.NoError(t, os.WriteFile(srcPath, b, 0644))

	stripped, sha256hex, err := dedup.StripCompileTimePackages(srcPath, dstPath)
	require.NoError(t, err)
	assert.Empty(t, stripped, "no packages should be stripped when all are referenced")
	assert.Empty(t, sha256hex)

	_, statErr := os.Stat(dstPath)
	assert.True(t, os.IsNotExist(statErr), "output file must not be created when nothing is stripped")
}

func TestStripCompileTimePackages_MultipleCompileTimeDeps_AllStripped(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go-linux"},
		{Name: "golang-1-darwin", Fingerprint: "fp-go-darwin"},
		{Name: "nats-server", Fingerprint: "fp-nats"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("nats", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "nats.tgz")
	dstPath := filepath.Join(dir, "nats-stripped.tgz")
	require.NoError(t, os.WriteFile(srcPath, b, 0644))

	stripped, _, err := dedup.StripCompileTimePackages(srcPath, dstPath)
	require.NoError(t, err)
	assert.Len(t, stripped, 2)
	assert.Contains(t, stripped, "golang-1-linux")
	assert.Contains(t, stripped, "golang-1-darwin")

	result, err := cargo.OpenBOSHReleaseTarball(dstPath)
	require.NoError(t, err)
	require.Len(t, result.Manifest.CompiledPackages, 1)
	assert.Equal(t, "nats-server", result.Manifest.CompiledPackages[0].Name)
}

func TestStripCompileTimePackages_PreservesNonPackageEntries(t *testing.T) {
	pkgs := []dedup.FakePackage{
		{Name: "golang-1-linux", Fingerprint: "fp-go"},
		{Name: "nats-server", Fingerprint: "fp-nats"},
	}
	jobs := []dedup.FakeJob{
		{Name: "nats", Packages: []string{"nats-server"}},
	}
	b, err := dedup.MakeCompiledReleaseTarballWithJobs("nats", "1.0.0", "ubuntu-jammy/1.1107", pkgs, jobs)
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "nats.tgz")
	dstPath := filepath.Join(dir, "nats-stripped.tgz")
	require.NoError(t, os.WriteFile(srcPath, b, 0644))

	_, _, err = dedup.StripCompileTimePackages(srcPath, dstPath)
	require.NoError(t, err)

	entries := listTarEntries(t, dstPath)
	assert.Contains(t, entries, "./release.MF", "release.MF must be preserved")
	assert.Contains(t, entries, "./jobs/nats.tgz", "job entries must be preserved")
}
