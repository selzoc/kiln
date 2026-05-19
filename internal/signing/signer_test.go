package signing_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/signing"
)

var _ = Describe("Signer", func() {
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
			"releases/foo.tgz":      "fake-data",
		})
	})

	AfterEach(func() {
		os.Remove(tilePath)
	})

	Describe("Sign", func() {
		It("adds signature/manifest.yaml and signature/manifest.sig to the zip", func() {
			signer := signing.NewSignerFromKey(priv)
			Expect(signer.Sign(tilePath)).To(Succeed())

			data, err := os.ReadFile(tilePath)
			Expect(err).NotTo(HaveOccurred())
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			Expect(err).NotTo(HaveOccurred())

			assertZipHasEntry(zr, "signature/manifest.yaml")
			assertZipHasEntry(zr, "signature/manifest.sig")
		})

		It("produces a tile that passes Verifier.Verify", func() {
			signer := signing.NewSignerFromKey(priv)
			Expect(signer.Sign(tilePath)).To(Succeed())

			verifier := signing.NewVerifierFromKey(pub)
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})

		It("can re-sign a tile that already has signature entries", func() {
			signer := signing.NewSignerFromKey(priv)
			Expect(signer.Sign(tilePath)).To(Succeed())
			Expect(signer.Sign(tilePath)).To(Succeed()) // sign again

			data, _ := os.ReadFile(tilePath)
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			Expect(err).NotTo(HaveOccurred())

			var sigCount int
			for _, f := range zr.File {
				if f.Name == "signature/manifest.yaml" || f.Name == "signature/manifest.sig" {
					sigCount++
				}
			}
			Expect(sigCount).To(Equal(2), "should have exactly 2 signature entries, not duplicates")

			verifier := signing.NewVerifierFromKey(pub)
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})
	})
})
