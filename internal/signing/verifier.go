// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add Verifier for Ed25519 tile signature verification with bidirectional manifest coverage - Cursor: Claude Sonnet 4.6

package signing

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Verifier verifies .pivotal tile signatures with an Ed25519 public key.
type Verifier struct {
	publicKey ed25519.PublicKey
}

// NewVerifierFromKey creates a Verifier using an in-memory Ed25519 public key.
func NewVerifierFromKey(key ed25519.PublicKey) Verifier {
	return Verifier{publicKey: key}
}

// NewVerifierFromFile loads an Ed25519 public key from a PKIX PEM file.
func NewVerifierFromFile(path string) (Verifier, error) {
	key, err := loadPublicKey(path)
	if err != nil {
		return Verifier{}, err
	}
	return Verifier{publicKey: key}, nil
}

// Verify verifies the tile at tilePath. Returns nil on success.
func (v Verifier) Verify(tilePath string) error {
	data, err := os.ReadFile(tilePath)
	if err != nil {
		return fmt.Errorf("reading tile: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("opening tile as zip: %w", err)
	}
	return v.VerifyZip(zr)
}

// VerifyZip verifies the signature and manifest coverage of an open zip.Reader.
func (v Verifier) VerifyZip(zr *zip.Reader) error {
	var manifestYAML, sigBytes []byte

	for _, f := range zr.File {
		switch f.Name {
		case "signature/manifest.yaml":
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening manifest: %w", err)
			}
			manifestYAML, err = io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				return fmt.Errorf("reading manifest: %w", err)
			}
		case "signature/manifest.sig":
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening signature: %w", err)
			}
			sigBytes, err = io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				return fmt.Errorf("reading signature: %w", err)
			}
		}
	}

	if len(manifestYAML) == 0 || len(sigBytes) == 0 {
		return fmt.Errorf("tile is unsigned: missing signature/manifest.yaml or signature/manifest.sig")
	}

	if !ed25519.Verify(v.publicKey, manifestYAML, sigBytes) {
		return fmt.Errorf("tile signature is invalid: signature does not match manifest")
	}

	return verifyManifestCoverage(zr, manifestYAML)
}

func verifyManifestCoverage(zr *zip.Reader, manifestYAML []byte) error {
	declared, err := parseManifestFiles(manifestYAML)
	if err != nil {
		return fmt.Errorf("parsing manifest: %w", err)
	}

	zipFiles := make(map[string]*zip.File)
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "signature/") && !f.FileInfo().IsDir() {
			zipFiles[f.Name] = f
		}
	}

	for name := range zipFiles {
		if _, ok := declared[name]; !ok {
			return fmt.Errorf("tile contains file not covered by signature: %q", name)
		}
	}
	for name := range declared {
		if _, ok := zipFiles[name]; !ok {
			return fmt.Errorf("tile missing file listed in manifest: %q", name)
		}
	}

	for name, expectedHash := range declared {
		rc, err := zipFiles[name].Open()
		if err != nil {
			return fmt.Errorf("opening %q for hash check: %w", name, err)
		}
		h := sha256.New()
		if _, err = io.Copy(h, rc); err != nil {
			_ = rc.Close()
			return fmt.Errorf("hashing %q: %w", name, err)
		}
		_ = rc.Close()
		actual := "sha256:" + hex.EncodeToString(h.Sum(nil))
		if actual != expectedHash {
			return fmt.Errorf("hash mismatch for %q: expected %s, got %s", name, expectedHash, actual)
		}
	}
	return nil
}

// parseManifestFiles parses the "files:" block from the YAML manifest
// produced by Manifest.Marshal. Uses a simple line parser to avoid a YAML
// library dependency in this package.
func parseManifestFiles(yamlData []byte) (map[string]string, error) {
	files := make(map[string]string)
	inFiles := false
	for _, line := range strings.Split(string(yamlData), "\n") {
		if line == "files:" {
			inFiles = true
			continue
		}
		if inFiles {
			if strings.HasPrefix(line, "  ") {
				trimmed := strings.TrimPrefix(line, "  ")
				idx := strings.Index(trimmed, ": ")
				if idx < 0 {
					continue
				}
				files[trimmed[:idx]] = trimmed[idx+2:]
			} else if line != "" {
				inFiles = false
			}
		}
	}
	return files, nil
}
