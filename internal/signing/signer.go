// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add Signer for post-hoc Ed25519 tile signing - Cursor: Claude Sonnet 4.6

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

// NewSignerFromFile loads an Ed25519 private key from a PKCS#8 PEM file.
func NewSignerFromFile(path string) (Signer, error) {
	key, err := loadPrivateKey(path)
	if err != nil {
		return Signer{}, fmt.Errorf("loading signing key: %w", err)
	}
	return Signer{privateKey: key}, nil
}

// Sign rewrites the .pivotal zip at tilePath, replacing any pre-existing
// signature/ entries with freshly computed ones. The file is replaced atomically
// via a temp-file rename.
func (s Signer) Sign(tilePath string) error {
	data, err := os.ReadFile(tilePath)
	if err != nil {
		return fmt.Errorf("reading tile: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("opening tile as zip: %w", err)
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
			w, err := zw.CreateHeader(&f.FileHeader)
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
