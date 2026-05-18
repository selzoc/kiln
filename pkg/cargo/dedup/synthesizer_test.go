package dedup_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pivotal-cf/kiln/pkg/cargo"
	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

func TestCreateSharedReleaseTarball(t *testing.T) {
	sharedBlob, err := dedup.MakeMinimalGzip([]byte("golang-blob-content"))
	require.NoError(t, err)

	golangPkg := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang-abc", Blob: sharedBlob}
	sourceBytes, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golangPkg})
	require.NoError(t, err)

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "nats.tgz")
	require.NoError(t, os.WriteFile(sourcePath, sourceBytes, 0644))

	sharedPkgs := []dedup.SharedPackage{{
		Fingerprint:   "fp-golang-abc",
		Name:          "golang-1-linux",
		BlobSize:      int64(len(sharedBlob)),
		SourceRelease: sourcePath,
	}}

	input := dedup.SynthesizerInput{
		ReleaseName:     "srt-shared-packages",
		ReleaseVersion:  "10.4.0+shared",
		StemcellOS:      "ubuntu-jammy",
		StemcellVersion: "1.1107",
		Packages:        sharedPkgs,
	}

	outputPath := filepath.Join(dir, "srt-shared-packages-10.4.0+shared.tgz")
	err = dedup.CreateSharedReleaseTarball(input, outputPath)
	require.NoError(t, err)

	produced, err := cargo.OpenBOSHReleaseTarball(outputPath)
	require.NoError(t, err)

	assert.Equal(t, "srt-shared-packages", produced.Manifest.Name)
	assert.Equal(t, "10.4.0+shared", produced.Manifest.Version)
	require.Len(t, produced.Manifest.CompiledPackages, 1)
	assert.Equal(t, "golang-1-linux", produced.Manifest.CompiledPackages[0].Name)
	assert.Equal(t, "fp-golang-abc", produced.Manifest.CompiledPackages[0].Fingerprint)
	assert.Equal(t, "ubuntu-jammy/1.1107", produced.Manifest.CompiledPackages[0].Stemcell)
}

func TestCreateSharedReleaseTarball_MultiplePackages(t *testing.T) {
	dir := t.TempDir()

	blob1, err := dedup.MakeMinimalGzip([]byte("pkg1-content"))
	require.NoError(t, err)
	blob2, err := dedup.MakeMinimalGzip([]byte("pkg2-content"))
	require.NoError(t, err)

	sourceBytes, err := dedup.MakeCompiledReleaseTarball("release1", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{
			{Name: "golang-1-linux", Fingerprint: "fp-golang", Blob: blob1},
			{Name: "health-check", Fingerprint: "fp-health", Blob: blob2},
		})
	require.NoError(t, err)
	sourcePath := filepath.Join(dir, "release1.tgz")
	require.NoError(t, os.WriteFile(sourcePath, sourceBytes, 0644))

	input := dedup.SynthesizerInput{
		ReleaseName:     "my-tile-shared-packages",
		ReleaseVersion:  "1.0.0+shared",
		StemcellOS:      "ubuntu-jammy",
		StemcellVersion: "1.1107",
		Packages: []dedup.SharedPackage{
			{Fingerprint: "fp-golang", Name: "golang-1-linux", SourceRelease: sourcePath},
			{Fingerprint: "fp-health", Name: "health-check", SourceRelease: sourcePath},
		},
	}

	outputPath := filepath.Join(dir, "shared.tgz")
	require.NoError(t, dedup.CreateSharedReleaseTarball(input, outputPath))

	produced, err := cargo.OpenBOSHReleaseTarball(outputPath)
	require.NoError(t, err)
	assert.Len(t, produced.Manifest.CompiledPackages, 2)
}
