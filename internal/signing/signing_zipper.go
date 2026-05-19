// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add SigningZipper for in-process tile signing during kiln bake - Cursor: Claude Sonnet 4.6

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// ZipperIface is the interface satisfied by builder.TileWriter's zipper dependency
// and by the inner zipper passed to SigningZipper.
type ZipperIface interface {
	SetWriter(w io.Writer)
	SetModified(t time.Time)
	Add(path string, file io.Reader) error
	AddWithMode(path string, file io.Reader, mode os.FileMode) error
	CreateFolder(path string) error
	Close() error
}

// SigningZipper wraps an inner ZipperIface, computing SHA-256 hashes on every
// Add/AddWithMode call and appending signature/manifest.yaml and
// signature/manifest.sig on Close.
type SigningZipper struct {
	inner    ZipperIface
	signer   Signer
	manifest map[string]string
}

// NewSigningZipper creates a SigningZipper wrapping inner.
func NewSigningZipper(inner ZipperIface, s Signer) *SigningZipper {
	return &SigningZipper{
		inner:    inner,
		signer:   s,
		manifest: make(map[string]string),
	}
}

func (sz *SigningZipper) SetWriter(w io.Writer)         { sz.inner.SetWriter(w) }
func (sz *SigningZipper) SetModified(t time.Time)        { sz.inner.SetModified(t) }
func (sz *SigningZipper) CreateFolder(path string) error { return sz.inner.CreateFolder(path) }

// Add tees the reader through a SHA-256 hasher while writing to the inner zipper.
func (sz *SigningZipper) Add(path string, file io.Reader) error {
	h := sha256.New()
	if err := sz.inner.Add(path, io.TeeReader(file, h)); err != nil {
		return err
	}
	sz.manifest[path] = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return nil
}

// AddWithMode tees the reader through a SHA-256 hasher while writing to the inner zipper.
func (sz *SigningZipper) AddWithMode(path string, file io.Reader, mode os.FileMode) error {
	h := sha256.New()
	if err := sz.inner.AddWithMode(path, io.TeeReader(file, h), mode); err != nil {
		return err
	}
	sz.manifest[path] = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return nil
}

// Close signs the accumulated manifest, appends both signature entries, then
// delegates Close to the inner zipper.
func (sz *SigningZipper) Close() error {
	m := Manifest{Version: "1", Algorithm: "sha256", Files: sz.manifest}
	manifestYAML, err := m.Marshal()
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}
	sig := ed25519.Sign(sz.signer.privateKey, manifestYAML)

	if err := sz.inner.Add("signature/manifest.yaml", bytes.NewReader(manifestYAML)); err != nil {
		return fmt.Errorf("adding manifest to zip: %w", err)
	}
	if err := sz.inner.Add("signature/manifest.sig", bytes.NewReader(sig)); err != nil {
		return fmt.Errorf("adding signature to zip: %w", err)
	}
	return sz.inner.Close()
}
