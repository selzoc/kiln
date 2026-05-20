// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add Signer for post-hoc Ed25519 tile signing - Cursor: Claude Sonnet 4.6
// 2026-05-20: Guard Sign against overwriting existing signatures; add SignForce and IsSigned - Cursor: Claude Sonnet 4.6

package signing

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"
)

// Signer signs .pivotal tile files with an Ed25519 private key.
type Signer struct {
	privateKey ed25519.PrivateKey
}

// NewSignerFromKey creates a Signer using an in-memory Ed25519 private key.
func NewSignerFromKey(key ed25519.PrivateKey) Signer {
	return Signer{privateKey: key}
}

// NewSignerFromFile loads an Ed25519 private key from a PEM file.
// Accepts PKCS#8 ("BEGIN PRIVATE KEY") and OpenSSH ("BEGIN OPENSSH PRIVATE KEY") formats.
func NewSignerFromFile(path string) (Signer, error) {
	key, err := loadPrivateKey(path)
	if err != nil {
		return Signer{}, fmt.Errorf("loading signing key: %w", err)
	}
	return Signer{privateKey: key}, nil
}

// ErrAlreadySigned is returned by Sign when the tile already contains a
// signature and force is false.
var ErrAlreadySigned = fmt.Errorf("tile is already signed; use --force to overwrite")

// IsSigned reports whether the tile at tilePath already contains a signature.
func IsSigned(tilePath string) (bool, error) {
	data, err := os.ReadFile(tilePath)
	if err != nil {
		return false, fmt.Errorf("reading tile: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false, fmt.Errorf("opening tile as zip: %w", err)
	}
	for _, f := range zr.File {
		if f.Name == "signature/manifest.sig" {
			return true, nil
		}
	}
	return false, nil
}

// Sign rewrites the .pivotal zip at tilePath with a fresh Ed25519 signature.
// If the tile already contains a signature and force is false, Sign returns
// ErrAlreadySigned. Pass force=true (or use the --force flag on kiln sign)
// to explicitly overwrite an existing signature.
// The file is replaced atomically via a temp-file rename.
func (s Signer) Sign(tilePath string) error {
	return s.sign(tilePath, false)
}

// SignForce is like Sign but always overwrites any existing signature.
func (s Signer) SignForce(tilePath string) error {
	return s.sign(tilePath, true)
}

func (s Signer) sign(tilePath string, force bool) error {
	data, err := os.ReadFile(tilePath)
	if err != nil {
		return fmt.Errorf("reading tile: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("opening tile as zip: %w", err)
	}

	if !force {
		for _, f := range zr.File {
			if f.Name == "signature/manifest.sig" {
				return ErrAlreadySigned
			}
		}
	}

	manifest, err := ComputeManifestFromZip(zr)
	if err != nil {
		return fmt.Errorf("computing manifest: %w", err)
	}
	manifestYAML, err := manifest.Marshal()
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}
	sig := ed25519.Sign(s.privateKey, manifestYAML)

	tmp, err := os.CreateTemp("", "kiln-sign-*.pivotal")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	writeErr := func() error {
		zw := zip.NewWriter(tmp)
		for _, f := range zr.File {
			if strings.HasPrefix(f.Name, "signature/") {
				continue
			}
			fh := f.FileHeader
			w, err := zw.CreateHeader(&fh)
			if err != nil {
				return fmt.Errorf("creating zip entry %q: %w", f.Name, err)
			}
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening zip entry %q: %w", f.Name, err)
			}
			if _, err = io.Copy(w, rc); err != nil {
				_ = rc.Close()
				return fmt.Errorf("copying zip entry %q: %w", f.Name, err)
			}
			_ = rc.Close()
		}
		if err := addBytesToZip(zw, "signature/manifest.yaml", manifestYAML); err != nil {
			return err
		}
		if err := addBytesToZip(zw, "signature/manifest.sig", sig); err != nil {
			return err
		}
		return zw.Close()
	}()

	if writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}
	return os.Rename(tmpPath, tilePath)
}

func addBytesToZip(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("creating zip entry %q: %w", name, err)
	}
	if _, err = w.Write(data); err != nil {
		return fmt.Errorf("writing zip entry %q: %w", name, err)
	}
	return nil
}
