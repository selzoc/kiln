// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add tile signing Manifest type with ComputeManifestFromZip and Marshal - Cursor: Claude Sonnet 4.6

package signing

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Manifest is the hash manifest embedded in a signed tile.
// It maps each zip entry path (excluding signature/ entries) to
// its SHA-256 digest in the form "sha256:<hex>".
type Manifest struct {
	Version   string            `yaml:"version"`
	Algorithm string            `yaml:"algorithm"`
	Files     map[string]string `yaml:"files"`
}

// ComputeManifestFromZip computes a Manifest by SHA-256-hashing every zip entry
// whose name does not start with "signature/".
func ComputeManifestFromZip(zr *zip.Reader) (Manifest, error) {
	files := make(map[string]string)
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "signature/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return Manifest{}, fmt.Errorf("opening zip entry %q: %w", f.Name, err)
		}
		h := sha256.New()
		if _, err = io.Copy(h, rc); err != nil {
			_ = rc.Close()
			return Manifest{}, fmt.Errorf("hashing zip entry %q: %w", f.Name, err)
		}
		_ = rc.Close()
		files[f.Name] = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
	return Manifest{Version: "1", Algorithm: "sha256", Files: files}, nil
}

// Marshal returns the canonical, deterministic YAML bytes of the manifest.
// Keys in the files map are sorted alphabetically.
func (m Manifest) Marshal() ([]byte, error) {
	keys := make([]string, 0, len(m.Files))
	for k := range m.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("version: \"1\"\n")
	sb.WriteString("algorithm: sha256\n")
	sb.WriteString("files:\n")
	for _, k := range keys {
		sb.WriteString("  ")
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(m.Files[k])
		sb.WriteString("\n")
	}
	return []byte(sb.String()), nil
}
