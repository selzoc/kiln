package dedup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/pkg/cargo"
)

// FakePackage describes one compiled package to include in a fake release tarball.
type FakePackage struct {
	Name        string
	Fingerprint string
	// Blob is the raw bytes stored in compiled_packages/<Name>.tgz.
	// If nil, a minimal gzip containing the fingerprint bytes is used.
	Blob []byte
}

// MakeCompiledReleaseTarball returns a gzip-compressed tar that mimics a valid
// BOSH compiled release tarball. stemcell should be e.g. "ubuntu-jammy/1.1107".
func MakeCompiledReleaseTarball(name, version, stemcell string, pkgs []FakePackage) ([]byte, error) {
	compiledPkgs := make([]cargo.CompiledBOSHReleasePackage, 0, len(pkgs))
	for _, p := range pkgs {
		compiledPkgs = append(compiledPkgs, cargo.CompiledBOSHReleasePackage{
			Name:        p.Name,
			Version:     p.Fingerprint,
			Fingerprint: p.Fingerprint,
			SHA1:        "sha256:" + p.Fingerprint,
			Stemcell:    stemcell,
		})
	}
	manifest := cargo.BOSHReleaseManifest{
		Name:             name,
		Version:          version,
		CompiledPackages: compiledPkgs,
	}
	mfBytes, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	gw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gw)

	if err := writeTarEntry(tw, "./release.MF", mfBytes); err != nil {
		return nil, err
	}
	if err := writeTarDir(tw, "./compiled_packages/"); err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		blob := p.Blob
		if blob == nil {
			var blobErr error
			blob, blobErr = MakeMinimalGzip([]byte(p.Fingerprint))
			if blobErr != nil {
				return nil, blobErr
			}
		}
		if err := writeTarEntry(tw, "./compiled_packages/"+p.Name+".tgz", blob); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MakeMinimalGzip returns a valid gzip-compressed byte slice containing content.
func MakeMinimalGzip(content []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	gw := gzip.NewWriter(buf)
	if _, err := io.Copy(gw, bytes.NewReader(content)); err != nil {
		return nil, err
	}
	return buf.Bytes(), gw.Close()
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0644,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeTarDir(tw *tar.Writer, name string) error {
	return tw.WriteHeader(&tar.Header{
		Name:     name,
		Typeflag: tar.TypeDir,
		Mode:     0755,
	})
}
