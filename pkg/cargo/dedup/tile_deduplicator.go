package dedup

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DeduplicateInput configures DeduplicateTile.
type DeduplicateInput struct {
	TilePath   string
	OutputPath string      // if empty, overwrites TilePath in-place
	Slug       string      // tile slug used to name the shared-packages release
	Logger     *log.Logger // may be nil — defaults to discard
}

// DeduplicateResult summarises the deduplication operation.
type DeduplicateResult struct {
	PackagesDeduped int
	BytesSaved      int64
}

// Minimum metadata_version required by OpsManager to trigger reconstruction.
// Tiles below this version will be rejected by an OpsManager that understands dedup.
const dedupMetadataVersion = "2.1"

// DeduplicateTile reads the .pivotal tile at input.TilePath, deduplicates compiled
// package blobs across all releases, and writes the result to input.OutputPath
// (or overwrites TilePath if OutputPath is empty).
//
// If no duplicate packages are found the tile is left untouched and the result has
// PackagesDeduped == 0.
func DeduplicateTile(input DeduplicateInput) (DeduplicateResult, error) {
	outputPath := input.OutputPath
	if outputPath == "" {
		outputPath = input.TilePath
	}
	logger := input.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	workDir, err := os.MkdirTemp("", "kiln-dedup-*")
	if err != nil {
		return DeduplicateResult{}, err
	}
	defer os.RemoveAll(workDir)

	// 1. Extract releases and parse metadata from the tile.
	metadata, releaseFiles, err := extractTileReleases(input.TilePath, workDir)
	if err != nil {
		return DeduplicateResult{}, fmt.Errorf("extracting tile: %w", err)
	}

	// 2. Scan for duplicate fingerprints.
	scanResult, err := ScanCompiledReleaseTarballs(releaseFiles)
	if err != nil {
		return DeduplicateResult{}, fmt.Errorf("scanning releases: %w", err)
	}
	if len(scanResult.SharedPackages) == 0 {
		logger.Println("No duplicate packages found — tile is already optimal.")
		return DeduplicateResult{}, nil
	}

	// 3. Determine product version and shared-release naming.
	productVersion, _ := metadata["product_version"].(string)
	sharedReleaseName := input.Slug + "-shared-packages"
	sharedReleaseVersion := productVersion + "-shared"
	sharedReleaseFile := sharedReleaseName + "-" + sharedReleaseVersion + ".tgz"

	// 4. Extract stemcell info from the first source release.
	stemcellOS, stemcellVersion, err := stemcellFromTarball(scanResult.SharedPackages[0].SourceRelease)
	if err != nil {
		return DeduplicateResult{}, fmt.Errorf("reading stemcell info: %w", err)
	}

	// 5. Synthesize the shared-packages release.
	sharedPath := filepath.Join(workDir, sharedReleaseFile)
	synthInput := SynthesizerInput{
		ReleaseName:     sharedReleaseName,
		ReleaseVersion:  sharedReleaseVersion,
		StemcellOS:      stemcellOS,
		StemcellVersion: stemcellVersion,
		Packages:        scanResult.SharedPackages,
	}
	if err := CreateSharedReleaseTarball(synthInput, sharedPath); err != nil {
		return DeduplicateResult{}, fmt.Errorf("synthesizing shared release: %w", err)
	}
	logger.Printf("Created %s (%d shared packages)\n", sharedReleaseFile, len(scanResult.SharedPackages))

	// 6. Build the set of fingerprints to remove from individual releases.
	fingerprintsToRemove := make(map[string]bool, len(scanResult.SharedPackages))
	for _, pkg := range scanResult.SharedPackages {
		fingerprintsToRemove[pkg.Fingerprint] = true
	}

	// 7. Parse current release metadata entries.
	relMetas := extractReleaseMetas(metadata)

	// 8. Rewrite each release that contains shared packages.
	var bytesSaved int64
	for _, relPath := range releaseFiles {
		if !releaseContainsShared(scanResult.ReleasePackages[relPath], fingerprintsToRemove) {
			continue
		}

		origSHA256, err := hashFile(relPath)
		if err != nil {
			return DeduplicateResult{}, err
		}
		origSize, err := fileSize(relPath)
		if err != nil {
			return DeduplicateResult{}, err
		}

		thinPath := relPath + ".thin"
		thinSHA256, err := RewriteReleaseTarball(relPath, thinPath, fingerprintsToRemove)
		if err != nil {
			return DeduplicateResult{}, fmt.Errorf("rewriting %s: %w", filepath.Base(relPath), err)
		}
		if err := os.Rename(thinPath, relPath); err != nil {
			return DeduplicateResult{}, err
		}

		thinSize, err := fileSize(relPath)
		if err != nil {
			return DeduplicateResult{}, err
		}
		saved := origSize - thinSize
		bytesSaved += saved
		logger.Printf("Fettling %s: saved %.1f MB\n", filepath.Base(relPath), float64(saved)/1024/1024)

		// Update the metadata entry for this release.
		if rm, ok := relMetas[filepath.Base(relPath)]; ok {
			rm.sha256 = thinSHA256
			rm.originalSHA256 = origSHA256
		}
	}

	// 9. Update metadata fields.
	metadata["package_deduplication_shared_release_file"] = sharedReleaseFile
	metadata["metadata_version"] = dedupMetadataVersion
	metadata["releases"] = buildReleasesSlice(relMetas)

	// 10. Write the new .pivotal zip.
	if err := writeOutputTile(input.TilePath, outputPath, workDir, metadata); err != nil {
		return DeduplicateResult{}, fmt.Errorf("writing output tile: %w", err)
	}

	return DeduplicateResult{
		PackagesDeduped: len(scanResult.SharedPackages),
		BytesSaved:      bytesSaved,
	}, nil
}

// releaseMeta tracks per-release metadata during deduplication.
type releaseMeta struct {
	name           string
	version        string
	file           string
	sha256         string
	originalSHA256 string
	extra          map[string]any // all other metadata fields from the original entry
}

func extractReleaseMetas(metadata map[string]any) map[string]*releaseMeta {
	result := map[string]*releaseMeta{}
	releases, _ := metadata["releases"].([]any)
	for _, r := range releases {
		rel, ok := r.(map[string]any)
		if !ok {
			continue
		}
		file, _ := rel["file"].(string)
		result[file] = &releaseMeta{
			name:    stringVal(rel, "name"),
			version: stringVal(rel, "version"),
			file:    file,
			extra:   rel,
		}
	}
	return result
}

func buildReleasesSlice(metas map[string]*releaseMeta) []map[string]any {
	result := make([]map[string]any, 0, len(metas))
	for _, rm := range metas {
		entry := map[string]any{
			"name":    rm.name,
			"version": rm.version,
			"file":    rm.file,
		}
		if rm.sha256 != "" {
			entry["sha256"] = rm.sha256
			entry["original_sha256"] = rm.originalSHA256
		} else {
			for k, v := range rm.extra {
				if k != "name" && k != "version" && k != "file" {
					entry[k] = v
				}
			}
		}
		result = append(result, entry)
	}
	return result
}

func stringVal(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func releaseContainsShared(fps []string, shared map[string]bool) bool {
	for _, fp := range fps {
		if shared[fp] {
			return true
		}
	}
	return false
}

// extractTileReleases extracts all releases/*.tgz from a .pivotal zip into workDir.
// Returns the parsed metadata map and paths of extracted tarballs.
func extractTileReleases(tilePath, workDir string) (map[string]any, []string, error) {
	zr, err := zip.OpenReader(tilePath)
	if err != nil {
		return nil, nil, err
	}
	defer zr.Close()

	var metadata map[string]any
	var releasePaths []string

	for _, f := range zr.File {
		switch {
		case f.Name == "metadata/metadata.yml":
			rc, err := f.Open()
			if err != nil {
				return nil, nil, err
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, nil, err
			}
			if err := yaml.Unmarshal(data, &metadata); err != nil {
				return nil, nil, err
			}
		case strings.HasPrefix(f.Name, "releases/") && strings.HasSuffix(f.Name, ".tgz"):
			destPath := filepath.Join(workDir, filepath.Base(f.Name))
			if err := copyZipEntryToFile(f, destPath); err != nil {
				return nil, nil, err
			}
			releasePaths = append(releasePaths, destPath)
		}
	}
	return metadata, releasePaths, nil
}

func copyZipEntryToFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

// writeOutputTile assembles the final .pivotal zip from updated parts.
func writeOutputTile(origTilePath, outputPath, workDir string, metadata map[string]any) error {
	metaBytes, err := yaml.Marshal(metadata)
	if err != nil {
		return err
	}

	tmpOut, err := os.CreateTemp(filepath.Dir(outputPath), ".kiln-dedup-*.pivotal")
	if err != nil {
		return err
	}
	tmpName := tmpOut.Name()
	defer os.Remove(tmpName)

	zw := zip.NewWriter(tmpOut)

	if err := writeZipBytes(zw, "metadata/metadata.yml", metaBytes); err != nil {
		return err
	}

	// Copy non-metadata, non-release entries from the original tile.
	origZR, err := zip.OpenReader(origTilePath)
	if err != nil {
		return err
	}
	for _, f := range origZR.File {
		if f.Name == "metadata/metadata.yml" || strings.HasPrefix(f.Name, "releases/") {
			continue
		}
		if err := copyZipEntry(zw, f); err != nil {
			origZR.Close()
			return err
		}
	}
	origZR.Close()

	// Write the (rewritten) release tarballs from workDir, including the shared-packages tarball.
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tgz") {
			continue
		}
		if err := writeZipFromFile(zw, filepath.Join(workDir, e.Name()), "releases/"+e.Name()); err != nil {
			return err
		}
	}

	if err := zw.Close(); err != nil {
		return err
	}
	if err := tmpOut.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, outputPath)
}

func writeZipBytes(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func writeZipFromFile(zw *zip.Writer, srcPath, zipName string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := zw.Create(zipName)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func copyZipEntry(zw *zip.Writer, f *zip.File) error {
	w, err := zw.Create(f.Name)
	if err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(w, rc)
	return err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSize(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func stemcellFromTarball(tarballPath string) (string, string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", "", err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if filepath.Base(hdr.Name) != "release.MF" {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", "", err
		}
		var mf struct {
			CompiledPackages []struct {
				Stemcell string `yaml:"stemcell"`
			} `yaml:"compiled_packages"`
		}
		if err := yaml.Unmarshal(data, &mf); err != nil {
			return "", "", err
		}
		if len(mf.CompiledPackages) > 0 {
			os, ver, _ := strings.Cut(mf.CompiledPackages[0].Stemcell, "/")
			return os, ver, nil
		}
	}
	return "ubuntu-jammy", "0", nil
}
