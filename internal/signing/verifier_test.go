package signing_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/signing"
)

var _ = Describe("Verifier", func() {
	var (
		pub      ed25519.PublicKey
		priv     ed25519.PrivateKey
		tilePath string
	)

	BeforeEach(func() {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		tilePath = writeTmpTile(map[string]string{
			"metadata/metadata.yml": "name: my-tile\n",
			"releases/r.tgz":        "fake-data",
		})

		signer := signing.NewSignerFromKey(priv)
		Expect(signer.Sign(tilePath)).To(Succeed())
	})

	AfterEach(func() {
		os.Remove(tilePath)
	})

	Describe("Verify", func() {
		It("returns nil for a validly signed tile", func() {
			verifier := signing.NewVerifierFromKey(pub)
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})

		It("returns an error when the wrong public key is used", func() {
			wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
			verifier := signing.NewVerifierFromKey(wrongPub)
			Expect(verifier.Verify(tilePath)).To(HaveOccurred())
		})

		It("returns an error when a file has been tampered with", func() {
			// Rewrite zip replacing one file's content
			data, _ := os.ReadFile(tilePath)
			zr, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))

			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, f := range zr.File {
				if f.Name == "metadata/metadata.yml" {
					addZipEntry(zw, f.Name, "name: TAMPERED\n")
				} else {
					w, _ := zw.CreateHeader(&f.FileHeader)
					rc, _ := f.Open()
					_, _ = io.Copy(w, rc)
					_ = rc.Close()
				}
			}
			Expect(zw.Close()).To(Succeed())
			Expect(os.WriteFile(tilePath, buf.Bytes(), 0o600)).To(Succeed())

			verifier := signing.NewVerifierFromKey(pub)
			Expect(verifier.Verify(tilePath)).To(HaveOccurred())
		})

		It("returns an error when an extra file is present that is not in the manifest", func() {
			// Add an extra file to the existing signed zip
			data, _ := os.ReadFile(tilePath)
			zr, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))

			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, f := range zr.File {
				w, _ := zw.CreateHeader(&f.FileHeader)
				rc, _ := f.Open()
				_, _ = io.Copy(w, rc)
				_ = rc.Close()
			}
			addZipEntry(zw, "releases/injected.tgz", "malicious")
			Expect(zw.Close()).To(Succeed())
			Expect(os.WriteFile(tilePath, buf.Bytes(), 0o600)).To(Succeed())

			verifier := signing.NewVerifierFromKey(pub)
			Expect(verifier.Verify(tilePath)).To(HaveOccurred())
		})

		It("returns an error for an unsigned tile", func() {
			unsignedTile := writeTmpTile(map[string]string{
				"metadata/metadata.yml": "name: unsigned\n",
			})
			defer os.Remove(unsignedTile)

			verifier := signing.NewVerifierFromKey(pub)
			Expect(verifier.Verify(unsignedTile)).To(HaveOccurred())
		})
	})
})
