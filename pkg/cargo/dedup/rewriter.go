package dedup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RewriteReleaseTarball reads the BOSH compiled release at inputPath, writes a new tarball
// to outputPath with compiled_packages/<name>.tgz entries omitted for any package whose
// fingerprint is in fingerprintsToRemove. The release.MF and all other entries are
// preserved unchanged.
//
// Returns the hex-encoded SHA256 of the output tarball.
func RewriteReleaseTarball(inputPath, outputPath string, fingerprintsToRemove map[string]bool) (string, error) {
	// First pass: build package name → fingerprint map from release.MF
	nameToFP, err := buildNameToFingerprintMap(inputPath)
	if err != nil {
		return "", fmt.Errorf("reading manifest from %s: %w", filepath.Base(inputPath), err)
	}

	in, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(out, hasher)

	gr, err := gzip.NewReader(in)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	gw := gzip.NewWriter(mw)
	tw := tar.NewWriter(gw)
	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		base := filepath.Base(hdr.Name)
		parentDir := filepath.Base(filepath.Dir(hdr.Name))
		if parentDir == "compiled_packages" && filepath.Ext(base) == ".tgz" {
			pkgName := base[:len(base)-4]
			if fp, ok := nameToFP[pkgName]; ok && fingerprintsToRemove[fp] {
				if _, err := io.Copy(io.Discard, tr); err != nil {
					return "", err
				}
				continue
			}
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		if hdr.Size > 0 {
			if _, err := io.Copy(tw, tr); err != nil {
				return "", err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// buildNameToFingerprintMap reads release.MF from a compiled release tarball and returns
// a map of package name → fingerprint.
func buildNameToFingerprintMap(tarballPath string) (map[string]string, error) {
	manifest, _, err := readManifestAndBlobSizes(tarballPath)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(manifest.CompiledPackages))
	for _, pkg := range manifest.CompiledPackages {
		m[pkg.Name] = pkg.Fingerprint
	}
	return m, nil
}
