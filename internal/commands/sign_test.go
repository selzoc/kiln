package commands_test

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/commands"
	"github.com/pivotal-cf/kiln/internal/signing"
)

var _ = Describe("Sign", func() {
	var (
		tmpDir         string
		privateKeyPath string
		publicKeyPath  string
		tilePath       string
		pub            ed25519.PublicKey
		priv           ed25519.PrivateKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "kiln-sign-test-*")
		Expect(err).NotTo(HaveOccurred())

		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		privateKeyPath = filepath.Join(tmpDir, "private.pem")
		publicKeyPath = filepath.Join(tmpDir, "public.pem")
		writePrivatePEM(privateKeyPath, priv)
		writePublicPEM(publicKeyPath, pub)

		tilePath = filepath.Join(tmpDir, "test.pivotal")
		writeMinimalTile(tilePath)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Describe("Execute", func() {
		It("signs the tile and produces a verifiable result", func() {
			cmd := commands.NewSign()
			Expect(cmd.Execute([]string{"--private-key-file", privateKeyPath, tilePath})).To(Succeed())

			verifier, err := signing.NewVerifierFromFile(publicKeyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})

		It("returns an error when the tile is already signed and --force is not set", func() {
			cmd := commands.NewSign()
			Expect(cmd.Execute([]string{"--private-key-file", privateKeyPath, tilePath})).To(Succeed())

			cmd2 := commands.NewSign()
			err := cmd2.Execute([]string{"--private-key-file", privateKeyPath, tilePath})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("already signed"))
		})

		It("overwrites the signature when --force is set on an already-signed tile", func() {
			cmd := commands.NewSign()
			Expect(cmd.Execute([]string{"--private-key-file", privateKeyPath, tilePath})).To(Succeed())

			cmd2 := commands.NewSign()
			Expect(cmd2.Execute([]string{"--private-key-file", privateKeyPath, "--force", tilePath})).To(Succeed())

			verifier, err := signing.NewVerifierFromFile(publicKeyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})

		It("returns an error when the private key file does not exist", func() {
			cmd := commands.NewSign()
			Expect(cmd.Execute([]string{"--private-key-file", "/no/such/key.pem", tilePath})).To(HaveOccurred())
		})

		It("returns an error when no tile path is given", func() {
			cmd := commands.NewSign()
			Expect(cmd.Execute([]string{"--private-key-file", privateKeyPath})).To(HaveOccurred())
		})
	})
})

// writePrivatePEM encodes an Ed25519 private key in PKCS#8 PEM format.
func writePrivatePEM(path string, priv ed25519.PrivateKey) {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	Expect(err).NotTo(HaveOccurred())
	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	Expect(pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: b})).To(Succeed())
	Expect(f.Close()).To(Succeed())
}

// writePublicPEM encodes an Ed25519 public key in PKIX PEM format.
func writePublicPEM(path string, pub ed25519.PublicKey) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	Expect(err).NotTo(HaveOccurred())
	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	Expect(pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: b})).To(Succeed())
	Expect(f.Close()).To(Succeed())
}

// writeMinimalTile creates a minimal .pivotal zip at path with a metadata entry.
func writeMinimalTile(path string) {
	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	zw := zip.NewWriter(f)
	w, err := zw.Create("metadata/metadata.yml")
	Expect(err).NotTo(HaveOccurred())
	_, err = w.Write([]byte("name: test-tile\n"))
	Expect(err).NotTo(HaveOccurred())
	Expect(zw.Close()).To(Succeed())
	Expect(f.Close()).To(Succeed())
}
