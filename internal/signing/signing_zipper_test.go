package signing_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/signing"
)

// memZipper is a minimal in-memory ZipperIface implementation for testing.
type memZipper struct {
	w   *zip.Writer
	Buf *bytes.Buffer
}

func newMemZipper() *memZipper {
	buf := new(bytes.Buffer)
	return &memZipper{w: zip.NewWriter(buf), Buf: buf}
}

func (m *memZipper) SetWriter(w io.Writer)          { m.w = zip.NewWriter(w) }
func (m *memZipper) SetModified(_ time.Time)         {}
func (m *memZipper) CreateFolder(_ string) error     { return nil }
func (m *memZipper) Add(path string, file io.Reader) error {
	w, err := m.w.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, file)
	return err
}
func (m *memZipper) AddWithMode(path string, file io.Reader, _ os.FileMode) error {
	return m.Add(path, file)
}
func (m *memZipper) Close() error { return m.w.Close() }

var _ = Describe("SigningZipper", func() {
	var (
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	)

	BeforeEach(func() {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
	})

	It("appends signature entries on Close and produces a verifiable tile", func() {
		inner := newMemZipper()
		sz := signing.NewSigningZipper(inner, signing.NewSignerFromKey(priv))

		Expect(sz.Add("metadata/metadata.yml", strings.NewReader("name: test\n"))).To(Succeed())
		Expect(sz.Add("releases/r.tgz", strings.NewReader("fake-release"))).To(Succeed())
		Expect(sz.Close()).To(Succeed())

		zr, err := zip.NewReader(bytes.NewReader(inner.Buf.Bytes()), int64(inner.Buf.Len()))
		Expect(err).NotTo(HaveOccurred())

		assertZipHasEntry(zr, "signature/manifest.yaml")
		assertZipHasEntry(zr, "signature/manifest.sig")

		verifier := signing.NewVerifierFromKey(pub)
		Expect(verifier.VerifyZip(zr)).To(Succeed())
	})

	It("hashes files correctly even when AddWithMode is used", func() {
		inner := newMemZipper()
		sz := signing.NewSigningZipper(inner, signing.NewSignerFromKey(priv))

		Expect(sz.AddWithMode("embed/script.sh", strings.NewReader("#!/bin/bash\n"), 0o755)).To(Succeed())
		Expect(sz.Close()).To(Succeed())

		zr, _ := zip.NewReader(bytes.NewReader(inner.Buf.Bytes()), int64(inner.Buf.Len()))
		verifier := signing.NewVerifierFromKey(pub)
		Expect(verifier.VerifyZip(zr)).To(Succeed())
	})
})
