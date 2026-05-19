package commands_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/commands"
	"github.com/pivotal-cf/kiln/internal/signing"
)

var _ = Describe("VerifySignature", func() {
	var (
		tmpDir        string
		publicKeyPath string
		tilePath      string
		priv          ed25519.PrivateKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "kiln-verify-test-*")
		Expect(err).NotTo(HaveOccurred())

		var pub ed25519.PublicKey
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		privateKeyPath := filepath.Join(tmpDir, "private.pem")
		publicKeyPath = filepath.Join(tmpDir, "public.pem")
		writePrivatePEM(privateKeyPath, priv)
		writePublicPEM(publicKeyPath, pub)

		tilePath = filepath.Join(tmpDir, "test.pivotal")
		writeMinimalTile(tilePath)
		signer := signing.NewSignerFromKey(priv)
		Expect(signer.Sign(tilePath)).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Describe("Execute", func() {
		It("returns nil for a validly signed tile", func() {
			cmd := commands.NewVerifySignature()
			Expect(cmd.Execute([]string{"--public-key-file", publicKeyPath, tilePath})).To(Succeed())
		})

		It("returns an error for an unsigned tile", func() {
			unsignedTile := filepath.Join(tmpDir, "unsigned.pivotal")
			writeMinimalTile(unsignedTile)
			cmd := commands.NewVerifySignature()
			Expect(cmd.Execute([]string{"--public-key-file", publicKeyPath, unsignedTile})).To(HaveOccurred())
		})

		It("returns an error when the public key file does not exist", func() {
			cmd := commands.NewVerifySignature()
			Expect(cmd.Execute([]string{"--public-key-file", "/no/key.pem", tilePath})).To(HaveOccurred())
		})

		It("returns an error when no tile path is given", func() {
			cmd := commands.NewVerifySignature()
			Expect(cmd.Execute([]string{"--public-key-file", publicKeyPath})).To(HaveOccurred())
		})
	})
})
