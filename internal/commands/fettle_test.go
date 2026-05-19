package commands_test

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
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

func buildStripTestTile(t *testing.T, dir string, releases []struct {
	name    string
	version string
	pkgs    []dedup.FakePackage
	jobs    []dedup.FakeJob
}) string {
	t.Helper()

	relsMeta := make([]map[string]any, 0, len(releases))
	tileZipPath := filepath.Join(dir, "test.pivotal")
	zf, err := os.Create(tileZipPath)
	require.NoError(t, err)
	zw := zip.NewWriter(zf)

	for _, rel := range releases {
		filename := rel.name + "-" + rel.version + ".tgz"
		b, err := dedup.MakeCompiledReleaseTarballWithJobs(rel.name, rel.version, "ubuntu-jammy/1.1107", rel.pkgs, rel.jobs)
		require.NoError(t, err)
		w, err := zw.Create("releases/" + filename)
		require.NoError(t, err)
		_, err = w.Write(b)
		require.NoError(t, err)
		relsMeta = append(relsMeta, map[string]any{
			"name": rel.name, "version": rel.version, "file": filename, "sha1": "placeholder",
		})
	}

	meta := map[string]any{
		"name": "my-tile", "product_version": "1.0.0", "metadata_version": "2.0",
		"releases": relsMeta,
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	w, err := zw.Create("metadata/metadata.yml")
	require.NoError(t, err)
	_, err = w.Write(metaBytes)
	require.NoError(t, err)

	require.NoError(t, zw.Close())
	require.NoError(t, zf.Close())
	return tileZipPath
}

func tarEntriesInZip(t *testing.T, zipPath, relFilename string) []string {
	t.Helper()
	zr, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "releases/"+relFilename {
			continue
		}
		rc, err := f.Open()
		require.NoError(t, err)
		defer rc.Close()

		gr, err := gzip.NewReader(rc)
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
	t.Fatalf("release file %s not found in %s", relFilename, zipPath)
	return nil
}

func TestFettle_Execute_StripsCompileTimePackages(t *testing.T) {
	dir := t.TempDir()
	tilePath := buildStripTestTile(t, dir, []struct {
		name    string
		version string
		pkgs    []dedup.FakePackage
		jobs    []dedup.FakeJob
	}{
		{
			name:    "nats",
			version: "1.0.0",
			pkgs: []dedup.FakePackage{
				{Name: "golang-1-linux", Fingerprint: "fp-go"},
				{Name: "nats-server", Fingerprint: "fp-nats"},
			},
			jobs: []dedup.FakeJob{
				{Name: "nats", Packages: []string{"nats-server"}},
			},
		},
		{
			name:    "routing",
			version: "2.0.0",
			pkgs: []dedup.FakePackage{
				{Name: "golang-1-linux", Fingerprint: "fp-go"},
				{Name: "routing-api", Fingerprint: "fp-routing"},
			},
			jobs: []dedup.FakeJob{
				{Name: "router", Packages: []string{"routing-api"}},
			},
		},
	})

	cmd := commands.NewFettle(log.New(io.Discard, "", 0))
	require.NoError(t, cmd.Execute([]string{"--tile", tilePath}))

	natsEntries := tarEntriesInZip(t, tilePath, "nats-1.0.0.tgz")
	assert.NotContains(t, natsEntries, "./compiled_packages/golang-1-linux.tgz",
		"golang (compile-time) must be stripped from nats release")
	assert.Contains(t, natsEntries, "./compiled_packages/nats-server.tgz",
		"nats-server (runtime) must be preserved in nats release")

	routingEntries := tarEntriesInZip(t, tilePath, "routing-2.0.0.tgz")
	assert.NotContains(t, routingEntries, "./compiled_packages/golang-1-linux.tgz",
		"golang (compile-time) must be stripped from routing release")
	assert.Contains(t, routingEntries, "./compiled_packages/routing-api.tgz",
		"routing-api (runtime) must be preserved in routing release")
}

func TestFettle_Execute_NoCompileTimePackages_IsNoop(t *testing.T) {
	dir := t.TempDir()
	tilePath := buildStripTestTile(t, dir, []struct {
		name    string
		version string
		pkgs    []dedup.FakePackage
		jobs    []dedup.FakeJob
	}{
		{
			name:    "nats",
			version: "1.0.0",
			pkgs:    []dedup.FakePackage{{Name: "nats-server", Fingerprint: "fp-nats"}},
			jobs:    []dedup.FakeJob{{Name: "nats", Packages: []string{"nats-server"}}},
		},
	})

	origInfo, err := os.Stat(tilePath)
	require.NoError(t, err)

	cmd := commands.NewFettle(log.New(io.Discard, "", 0))
	require.NoError(t, cmd.Execute([]string{"--tile", tilePath}))

	newInfo, err := os.Stat(tilePath)
	require.NoError(t, err)
	assert.Equal(t, origInfo.Size(), newInfo.Size(), "tile must be unchanged when nothing to strip")
}

func TestFettle_Execute_OutputPath(t *testing.T) {
	dir := t.TempDir()
	inputPath := buildStripTestTile(t, dir, []struct {
		name    string
		version string
		pkgs    []dedup.FakePackage
		jobs    []dedup.FakeJob
	}{
		{
			name:    "nats",
			version: "1.0.0",
			pkgs: []dedup.FakePackage{
				{Name: "golang-1-linux", Fingerprint: "fp-go"},
				{Name: "nats-server", Fingerprint: "fp-nats"},
			},
			jobs: []dedup.FakeJob{{Name: "nats", Packages: []string{"nats-server"}}},
		},
	})
	outputPath := filepath.Join(dir, "output.pivotal")

	cmd := commands.NewFettle(log.New(io.Discard, "", 0))
	require.NoError(t, cmd.Execute([]string{"--tile", inputPath, "--output", outputPath}))

	_, err := os.Stat(inputPath)
	assert.NoError(t, err, "input tile must be unchanged")
	_, err = os.Stat(outputPath)
	assert.NoError(t, err, "output tile must be created")
}

func TestFettle_Usage(t *testing.T) {
	cmd := commands.NewFettle(log.New(io.Discard, "", 0))
	usage := cmd.Usage()
	assert.NotEmpty(t, usage.Description)
	assert.NotEmpty(t, usage.ShortDescription)
}
