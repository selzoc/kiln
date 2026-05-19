package dedup

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/pkg/cargo"
)

// releaseMeta tracks per-release metadata during tile processing.
type releaseMeta struct {
	name           string
	version        string
	file           string
	sha256         string
	originalSHA256 string
	extra          map[string]any // all other metadata fields from the original entry
}

// readManifestAndBlobSizes opens a BOSH compiled release tarball and returns the parsed
// release.MF manifest plus a map of package name → blob size in bytes.
func readManifestAndBlobSizes(tarballPath string) (cargo.BOSHReleaseManifest, map[string]int64, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return cargo.BOSHReleaseManifest{}, nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return cargo.BOSHReleaseManifest{}, nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var manifest cargo.BOSHReleaseManifest
	blobSizes := map[string]int64{}
	gotManifest := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return cargo.BOSHReleaseManifest{}, nil, err
		}
		base := filepath.Base(hdr.Name)
		dir := filepath.Base(filepath.Dir(hdr.Name))
		if base == "release.MF" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return cargo.BOSHReleaseManifest{}, nil, err
			}
			if err := yaml.Unmarshal(data, &manifest); err != nil {
				return cargo.BOSHReleaseManifest{}, nil, err
			}
			gotManifest = true
		} else if dir == "compiled_packages" && filepath.Ext(base) == ".tgz" {
			pkgName := base[:len(base)-4]
			blobSizes[pkgName] = hdr.Size
		}
	}

	if !gotManifest {
		return cargo.BOSHReleaseManifest{}, nil, fmt.Errorf("release.MF not found in %s", filepath.Base(tarballPath))
	}
	return manifest, blobSizes, nil
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

// extractReleaseMetas builds a filename → releaseMeta map from the tile's metadata releases list.
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

// buildReleasesSlice serialises releaseMeta entries back to the metadata releases slice format.
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
			if rm.originalSHA256 != "" {
				entry["original_sha256"] = rm.originalSHA256
			}
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

// writeOutputTile assembles the final .pivotal zip from updated parts in workDir.
func writeOutputTile(origTilePath, outputPath, workDir string, metadata map[string]any) error {
	metaBytes, err := yaml.Marshal(metadata)
	if err != nil {
		return err
	}

	tmpOut, err := os.CreateTemp(filepath.Dir(outputPath), ".kiln-strip-*.pivotal")
	if err != nil {
		return err
	}
	tmpName := tmpOut.Name()
	defer os.Remove(tmpName)

	zw := zip.NewWriter(tmpOut)

	if err := writeZipBytes(zw, "metadata/metadata.yml", metaBytes); err != nil {
		return err
	}

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
