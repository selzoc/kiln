package commands_test

import (
	"archive/zip"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/internal/commands"
	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

func TestDeduplicatePackages_Execute(t *testing.T) {
	sharedBlob, err := dedup.MakeMinimalGzip([]byte("shared-golang-blob"))
	require.NoError(t, err)
	golang := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang-shared", Blob: sharedBlob}

	natsBytes, err := dedup.MakeCompiledReleaseTarball("nats", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golang, {Name: "nats-server", Fingerprint: "fp-nats"}})
	require.NoError(t, err)
	routingBytes, err := dedup.MakeCompiledReleaseTarball("routing", "2.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golang, {Name: "routing-api", Fingerprint: "fp-routing"}})
	require.NoError(t, err)

	meta := map[string]any{
		"name": "my-tile", "product_version": "1.0.0", "metadata_version": "2.0",
		"releases": []map[string]any{
			{"name": "nats", "version": "1.0.0", "file": "nats-1.0.0.tgz", "sha1": "old"},
			{"name": "routing", "version": "2.0.0", "file": "routing-2.0.0.tgz", "sha1": "old"},
		},
	}
	metaBytes, _ := yaml.Marshal(meta)

	dir := t.TempDir()
	tilePath := filepath.Join(dir, "my-tile.pivotal")
	zf, _ := os.Create(tilePath)
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("metadata/metadata.yml")
	_, _ = w.Write(metaBytes)
	w, _ = zw.Create("releases/nats-1.0.0.tgz")
	_, _ = w.Write(natsBytes)
	w, _ = zw.Create("releases/routing-2.0.0.tgz")
	_, _ = w.Write(routingBytes)
	zw.Close()
	zf.Close()

	cmd := commands.NewDeduplicatePackages(log.New(io.Discard, "", 0))
	err = cmd.Execute([]string{"--tile", tilePath})
	require.NoError(t, err)

	zr, err := zip.OpenReader(tilePath)
	require.NoError(t, err)
	defer zr.Close()

	var foundMeta map[string]any
	for _, f := range zr.File {
		if f.Name == "metadata/metadata.yml" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			yaml.Unmarshal(data, &foundMeta)
		}
	}
	require.NotNil(t, foundMeta)
	assert.NotEmpty(t, foundMeta["package_deduplication_shared_release_file"],
		"output tile must have shared release pointer in metadata")
}

func TestDeduplicatePackages_Execute_OutputPath(t *testing.T) {
	sharedBlob, err := dedup.MakeMinimalGzip([]byte("shared-blob"))
	require.NoError(t, err)
	golang := dedup.FakePackage{Name: "golang-1-linux", Fingerprint: "fp-golang", Blob: sharedBlob}

	r1, _ := dedup.MakeCompiledReleaseTarball("r1", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golang, {Name: "pkg1", Fingerprint: "fp1"}})
	r2, _ := dedup.MakeCompiledReleaseTarball("r2", "1.0.0", "ubuntu-jammy/1.1107",
		[]dedup.FakePackage{golang, {Name: "pkg2", Fingerprint: "fp2"}})

	meta := map[string]any{
		"name": "t", "product_version": "1.0", "metadata_version": "2.0",
		"releases": []map[string]any{
			{"name": "r1", "version": "1.0.0", "file": "r1.tgz", "sha1": "x"},
			{"name": "r2", "version": "1.0.0", "file": "r2.tgz", "sha1": "y"},
		},
	}
	metaBytes, _ := yaml.Marshal(meta)

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.pivotal")
	outputPath := filepath.Join(dir, "output.pivotal")

	zf, _ := os.Create(inputPath)
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("metadata/metadata.yml")
	w.Write(metaBytes)
	w, _ = zw.Create("releases/r1.tgz")
	w.Write(r1)
	w, _ = zw.Create("releases/r2.tgz")
	w.Write(r2)
	zw.Close()
	zf.Close()

	cmd := commands.NewDeduplicatePackages(log.New(io.Discard, "", 0))
	err = cmd.Execute([]string{"--tile", inputPath, "--output", outputPath})
	require.NoError(t, err)

	// Input must be unchanged
	_, err = os.Stat(inputPath)
	assert.NoError(t, err)
	// Output must exist
	_, err = os.Stat(outputPath)
	assert.NoError(t, err, "output file must be created when --output is specified")
}

func TestDeduplicatePackages_Usage(t *testing.T) {
	cmd := commands.NewDeduplicatePackages(log.New(io.Discard, "", 0))
	usage := cmd.Usage()
	assert.NotEmpty(t, usage.Description)
	assert.NotEmpty(t, usage.ShortDescription)
}
