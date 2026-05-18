package dedup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/pkg/cargo"
)

// SharedPackage is a compiled BOSH package whose identical blob appears in 2+ releases.
type SharedPackage struct {
	Fingerprint   string
	Name          string
	BlobSize      int64
	SourceRelease string // path of the first release tarball containing this package
}

// ScanResult is the output of ScanCompiledReleaseTarballs.
type ScanResult struct {
	// SharedPackages are packages (by fingerprint) present in 2+ releases.
	SharedPackages []SharedPackage
	// ReleasePackages maps release tarball path → slice of fingerprints it contains.
	ReleasePackages map[string][]string
}

// ScanCompiledReleaseTarballs reads the release.MF and compiled_packages/ entries from
// each tarball and returns the set of packages whose fingerprint appears in 2+ releases.
func ScanCompiledReleaseTarballs(tarballPaths []string) (ScanResult, error) {
	type pkgEntry struct {
		name          string
		blobSize      int64
		sourceRelease string
		count         int
	}
	seen := map[string]*pkgEntry{}
	releasePackages := map[string][]string{}

	for _, p := range tarballPaths {
		manifest, blobSizes, err := readManifestAndBlobSizes(p)
		if err != nil {
			return ScanResult{}, fmt.Errorf("reading %s: %w", filepath.Base(p), err)
		}
		var fps []string
		for _, pkg := range manifest.CompiledPackages {
			fps = append(fps, pkg.Fingerprint)
			if e, ok := seen[pkg.Fingerprint]; ok {
				e.count++
			} else {
				seen[pkg.Fingerprint] = &pkgEntry{
					name:          pkg.Name,
					blobSize:      blobSizes[pkg.Name],
					sourceRelease: p,
					count:         1,
				}
			}
		}
		releasePackages[p] = fps
	}

	var shared []SharedPackage
	for fp, e := range seen {
		if e.count >= 2 {
			shared = append(shared, SharedPackage{
				Fingerprint:   fp,
				Name:          e.name,
				BlobSize:      e.blobSize,
				SourceRelease: e.sourceRelease,
			})
		}
	}

	return ScanResult{SharedPackages: shared, ReleasePackages: releasePackages}, nil
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
