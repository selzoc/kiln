package signing_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSigning(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "signing")
}

// addZipEntry writes a named entry with the given string content into zw.
func addZipEntry(zw *zip.Writer, name, content string) {
	w, err := zw.Create(name)
	Expect(err).NotTo(HaveOccurred())
	_, err = w.Write([]byte(content))
	Expect(err).NotTo(HaveOccurred())
}

// sha256Hex returns the hex-encoded SHA-256 of s, prefixed with "sha256:".
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// buildTestZip creates an in-memory zip with the provided entries (path -> content).
func buildTestZip(entries map[string]string) *bytes.Buffer {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		addZipEntry(zw, name, content)
	}
	Expect(zw.Close()).To(Succeed())
	return &buf
}

// writeTmpTile writes a .pivotal zip to a temp file and returns its path.
func writeTmpTile(entries map[string]string) string {
	f, err := os.CreateTemp("", "*.pivotal")
	Expect(err).NotTo(HaveOccurred())
	zw := zip.NewWriter(f)
	
	// Add a directory entry to ensure it is ignored by the manifest
	_, err = zw.Create("metadata/")
	Expect(err).NotTo(HaveOccurred())

	for name, content := range entries {
		addZipEntry(zw, name, content)
	}
	Expect(zw.Close()).To(Succeed())
	Expect(f.Close()).To(Succeed())
	return f.Name()
}

// assertZipHasEntry verifies a zip.Reader contains a file with the given name.
func assertZipHasEntry(zr *zip.Reader, name string) {
	GinkgoHelper()
	for _, f := range zr.File {
		if f.Name == name {
			return
		}
	}
	Fail("zip missing expected entry: " + name)
}
