package dedup_test

import (
	"archive/zip"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

func makeFakeTile(t *testing.T) string {
	t.Helper()

	sharedBlob, err := dedup.MakeMinimalGzip([]byte("shared-golang-blob"))
	require.NoError(t, err)

	golang := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang-shared", Blob: sharedBlob}

	natsBytes, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golang, {Name: "nats-server", Fingerprint: "fp-nats"}})
	require.NoError(t, err)

	routingBytes, err := dedup.MakeCompiledReleaseTarball("routing", "2.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golang, {Name: "routing-api", Fingerprint: "fp-routing"}})
	require.NoError(t, err)

	metadata := map[string]any{
		"name":             "my-tile",
		"product_version":  "1.0.0",
		"metadata_version": "2.0",
		"releases": []map[string]any{
			{"name": "nats", "version": "1.0.0",
				"file": "nats-1.0.0-ubuntu-jammy-1.1107.tgz", "sha1": "orig-nats-sha"},
			{"name": "routing", "version": "2.0.0",
				"file": "routing-2.0.0-ubuntu-jammy-1.1107.tgz", "sha1": "orig-routing-sha"},
		},
	}
	metaBytes, err := yaml.Marshal(metadata)
	require.NoError(t, err)

	dir := t.TempDir()
	tilePath := filepath.Join(dir, "my-tile-1.0.0.pivotal")
	zf, err := os.Create(tilePath)
	require.NoError(t, err)
	zw := zip.NewWriter(zf)
	writeEntry := func(name string, data []byte) {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
	}
	writeEntry("metadata/metadata.yml", metaBytes)
	writeEntry("releases/nats-1.0.0-ubuntu-jammy-1.1107.tgz", natsBytes)
	writeEntry("releases/routing-2.0.0-ubuntu-jammy-1.1107.tgz", routingBytes)
	require.NoError(t, zw.Close())
	require.NoError(t, zf.Close())
	return tilePath
}

func TestDeduplicateTile(t *testing.T) {
	tilePath := makeFakeTile(t)

	var logBuf strings.Builder
	logger := log.New(&logBuf, "", 0)

	result, err := dedup.DeduplicateTile(dedup.DeduplicateInput{
		TilePath: tilePath,
		Slug:     "my-tile",
		Logger:   logger,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.PackagesDeduped)
	assert.Positive(t, result.BytesSaved, "stripping blobs from 2 releases must report positive savings")

	logOutput := logBuf.String()

	// Shared-packages table: package name/version must appear under the Created line.
	assert.Contains(t, logOutput, "golang-1-linux/fp-golang-shared",
		"shared-packages table must list package name/version")

	// Each fettled release must list the removed package names inline.
	assert.Contains(t, logOutput, "(golang-1-linux/fp-golang-shared)",
		"fettling lines must show which packages were removed")

	zr, err := zip.OpenReader(tilePath)
	require.NoError(t, err)
	defer zr.Close()

	var meta map[string]any
	var foundSharedRelease bool
	for _, f := range zr.File {
		if f.Name == "metadata/metadata.yml" {
			rc, err := f.Open()
			require.NoError(t, err)
			data, err := io.ReadAll(rc)
			rc.Close()
			require.NoError(t, err)
			require.NoError(t, yaml.Unmarshal(data, &meta))
		}
	}
	require.NotNil(t, meta, "metadata.yml must be present in output tile")

	sharedFile, ok := meta["package_deduplication_shared_release_file"].(string)
	assert.True(t, ok, "package_deduplication_shared_release_file must be set")
	assert.Contains(t, sharedFile, "shared-packages", "shared release file must mention shared-packages")

	// shared-packages tarball must be in the zip
	for _, f := range zr.File {
		if f.Name == "releases/"+sharedFile {
			foundSharedRelease = true
		}
	}
	assert.True(t, foundSharedRelease, "shared-packages tarball must exist in releases/ dir")

	// shared-packages must NOT be in the releases: list
	releases, ok := meta["releases"].([]any)
	assert.True(t, ok)
	for _, r := range releases {
		rel, ok := r.(map[string]any)
		require.True(t, ok)
		name, _ := rel["name"].(string)
		assert.NotContains(t, name, "shared-packages",
			"shared-packages must not be listed as a deployable release in metadata")
		// Rewritten releases must have sha256 and original_sha256
		assert.NotEmpty(t, rel["sha256"], "thin sha256 must be set for %s", name)
		assert.NotEmpty(t, rel["original_sha256"], "original sha256 must be set for %s", name)
	}
}

func TestDeduplicateTile_NoDuplicates_IsNoop(t *testing.T) {
	// Build a tile with no shared packages
	pkg1Bytes, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{{Name: "nats-server", Fingerprint: "fp-nats-only"}})
	require.NoError(t, err)

	metadata := map[string]any{
		"name": "solo-tile", "product_version": "1.0.0", "metadata_version": "2.0",
		"releases": []map[string]any{
			{"name": "nats", "version": "1.0.0", "file": "nats.tgz", "sha1": "sha"},
		},
	}
	metaBytes, _ := yaml.Marshal(metadata)

	dir := t.TempDir()
	tilePath := filepath.Join(dir, "solo.pivotal")
	zf, _ := os.Create(tilePath)
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("metadata/metadata.yml")
	_, _ = w.Write(metaBytes)
	w, _ = zw.Create("releases/nats.tgz")
	_, _ = w.Write(pkg1Bytes)
	zw.Close()
	zf.Close()

	origSize, _ := statSize(tilePath)
	result, err := dedup.DeduplicateTile(dedup.DeduplicateInput{
		TilePath: tilePath,
		Slug:     "solo-tile",
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.PackagesDeduped)

	// Tile must be unchanged
	newSize, _ := statSize(tilePath)
	assert.Equal(t, origSize, newSize)
}

func statSize(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
