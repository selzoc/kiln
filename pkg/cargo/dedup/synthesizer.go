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

// SynthesizerInput configures CreateSharedReleaseTarball.
type SynthesizerInput struct {
	ReleaseName     string
	ReleaseVersion  string
	StemcellOS      string
	StemcellVersion string
	Packages        []SharedPackage
}

// CreateSharedReleaseTarball writes a new BOSH compiled release tarball to outputPath
// containing all packages listed in input.Packages. The blob for each package is
// extracted from its SourceRelease tarball.
func CreateSharedReleaseTarball(input SynthesizerInput, outputPath string) error {
	blobs := make(map[string][]byte, len(input.Packages))
	for _, pkg := range input.Packages {
		blob, err := extractPackageBlob(pkg.SourceRelease, pkg.Name)
		if err != nil {
			return fmt.Errorf("extracting %s from %s: %w", pkg.Name, filepath.Base(pkg.SourceRelease), err)
		}
		blobs[pkg.Fingerprint] = blob
	}

	compiledPkgs := make([]cargo.CompiledBOSHReleasePackage, 0, len(input.Packages))
	for _, pkg := range input.Packages {
		compiledPkgs = append(compiledPkgs, cargo.CompiledBOSHReleasePackage{
			Name:        pkg.Name,
			Version:     pkg.Fingerprint,
			Fingerprint: pkg.Fingerprint,
			SHA1:        fmt.Sprintf("sha256:%x", blobs[pkg.Fingerprint]),
			Stemcell:    input.StemcellOS + "/" + input.StemcellVersion,
		})
	}
	manifest := cargo.BOSHReleaseManifest{
		Name:             input.ReleaseName,
		Version:          input.ReleaseVersion,
		CompiledPackages: compiledPkgs,
	}
	mfBytes, err := yaml.Marshal(manifest)
	if err != nil {
		return err
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	gw := gzip.NewWriter(out)
	tw := tar.NewWriter(gw)

	if err := writeTarEntry(tw, "./release.MF", mfBytes); err != nil {
		return err
	}
	if err := writeTarDir(tw, "./compiled_packages/"); err != nil {
		return err
	}
	for _, pkg := range input.Packages {
		blob := blobs[pkg.Fingerprint]
		if err := writeTarEntry(tw, "./compiled_packages/"+pkg.Name+".tgz", blob); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

// extractPackageBlob opens a BOSH compiled release tarball and returns the raw bytes
// of compiled_packages/<pkgName>.tgz.
func extractPackageBlob(tarballPath, pkgName string) ([]byte, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	target := "./compiled_packages/" + pkgName + ".tgz"
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == target {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("compiled_packages/%s.tgz not found in %s", pkgName, filepath.Base(tarballPath))
}
