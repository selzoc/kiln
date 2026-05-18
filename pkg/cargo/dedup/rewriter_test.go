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

func TestRewriteReleaseTarball_StripsSharedBlobs(t *testing.T) {
	sharedBlob, err := dedup.MakeMinimalGzip([]byte("golang-blob"))
	require.NoError(t, err)
	golangPkg := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang", Blob: sharedBlob}
	uniquePkg := dedup.FakePackage{Name: "nats-server", Fingerprint: "fp-nats"}

	sourceBytes, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golangPkg, uniquePkg})
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "nats-full.tgz")
	dstPath := filepath.Join(dir, "nats-thin.tgz")
	require.NoError(t, os.WriteFile(srcPath, sourceBytes, 0644))

	sha256sum, err := dedup.RewriteReleaseTarball(srcPath, dstPath, map[string]bool{"fp-golang": true})
	require.NoError(t, err)
	assert.NotEmpty(t, sha256sum, "should return SHA256 of the output tarball")

	entries := listTarEntries(t, dstPath)
	assert.NotContains(t, entries, "./compiled_packages/golang-1-linux.tgz",
		"shared blob must be stripped from thin tarball")
	assert.Contains(t, entries, "./compiled_packages/nats-server.tgz",
		"unique blob must remain in thin tarball")
	assert.Contains(t, entries, "./release.MF",
		"release.MF must be preserved unchanged")

	// release.MF must still list both packages — BOSH needs the manifest intact
	thin, err := cargo.OpenBOSHReleaseTarball(dstPath)
	require.NoError(t, err)
	require.Len(t, thin.Manifest.CompiledPackages, 2, "manifest must still list all packages")
}

func TestRewriteReleaseTarball_NoSharedPackages_CopiesUnchanged(t *testing.T) {
	pkg1 := dedup.FakePackage{Name: "app-server", Fingerprint: "fp-app"}
	sourceBytes, err := dedup.MakeCompiledReleaseTarball("app", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{pkg1})
	require.NoError(t, err)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "app-full.tgz")
	dstPath := filepath.Join(dir, "app-out.tgz")
	require.NoError(t, os.WriteFile(srcPath, sourceBytes, 0644))

	_, err = dedup.RewriteReleaseTarball(srcPath, dstPath, map[string]bool{})
	require.NoError(t, err)

	entries := listTarEntries(t, dstPath)
	assert.Contains(t, entries, "./compiled_packages/app-server.tgz")
}

func TestRewriteReleaseTarball_ReturnsSHA256OfOutput(t *testing.T) {
	pkg := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-go"}
	b, err := dedup.MakeCompiledReleaseTarball("r", "1.0", "ubuntu-jammy/1.0",
		[]dedup.FakePackage{pkg})
	require.NoError(t, err)

	dir := t.TempDir()
	src := filepath.Join(dir, "r.tgz")
	dst := filepath.Join(dir, "r-thin.tgz")
	require.NoError(t, os.WriteFile(src, b, 0644))

	sha, err := dedup.RewriteReleaseTarball(src, dst, map[string]bool{"fp-go": true})
	require.NoError(t, err)

	// SHA256 must be 64 hex chars
	assert.Len(t, sha, 64)
}

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
