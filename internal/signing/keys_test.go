package signing_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/ssh"

	"github.com/pivotal-cf/kiln/internal/signing"
)

var _ = Describe("loadPublicKey (via NewVerifierFromFile)", func() {
	var (
		tmpDir string
		pub    ed25519.PublicKey
		priv   ed25519.PrivateKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "kiln-pubkeys-test-*")
		Expect(err).NotTo(HaveOccurred())
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	Context("PKIX PEM format (openssl pkey -pubout)", func() {
		It("loads the key and can verify a signed tile", func() {
			pubPath := filepath.Join(tmpDir, "pub.pem")
			writePKIXPublicPEM(pubPath, pub)

			tilePath := writeTmpTile(map[string]string{"metadata/metadata.yml": "name: t\n"})
			defer os.Remove(tilePath)
			Expect(signing.NewSignerFromKey(priv).Sign(tilePath)).To(Succeed())

			verifier, err := signing.NewVerifierFromFile(pubPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})
	})

	Context("OpenSSH authorized_keys format (ssh-keygen *.pub)", func() {
		It("loads the key and can verify a signed tile", func() {
			pubPath := filepath.Join(tmpDir, "id_ed25519.pub")
			writeOpenSSHPublicKey(pubPath, pub)

			tilePath := writeTmpTile(map[string]string{"metadata/metadata.yml": "name: t\n"})
			defer os.Remove(tilePath)
			Expect(signing.NewSignerFromKey(priv).Sign(tilePath)).To(Succeed())

			verifier, err := signing.NewVerifierFromFile(pubPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifier.Verify(tilePath)).To(Succeed())
		})

		It("rejects a key from a different key pair", func() {
			wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			pubPath := filepath.Join(tmpDir, "wrong.pub")
			writeOpenSSHPublicKey(pubPath, wrongPub)

			tilePath := writeTmpTile(map[string]string{"metadata/metadata.yml": "name: t\n"})
			defer os.Remove(tilePath)
			Expect(signing.NewSignerFromKey(priv).Sign(tilePath)).To(Succeed())

			verifier, err := signing.NewVerifierFromFile(pubPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifier.Verify(tilePath)).To(HaveOccurred())
		})
	})

	Context("non-Ed25519 SSH key", func() {
		It("returns an error", func() {
			pubPath := filepath.Join(tmpDir, "rsa.pub")
			writeRSAOpenSSHPublicKey(pubPath)

			_, err := signing.NewVerifierFromFile(pubPath)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not Ed25519"))
		})
	})
})

var _ = Describe("loadPrivateKey (via NewSignerFromFile)", func() {
	var (
		tmpDir         string
		pub            ed25519.PublicKey
		priv           ed25519.PrivateKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "kiln-keys-test-*")
		Expect(err).NotTo(HaveOccurred())
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Context("PKCS#8 PEM format (openssl genpkey)", func() {
		It("loads the key and can sign a verifiable tile", func() {
			keyPath := filepath.Join(tmpDir, "priv.pem")
			writePKCS8PEM(keyPath, priv)

			signer, err := signing.NewSignerFromFile(keyPath)
			Expect(err).NotTo(HaveOccurred())

			tilePath := writeTmpTile(map[string]string{"metadata/metadata.yml": "name: t\n"})
			defer os.Remove(tilePath)
			Expect(signer.Sign(tilePath)).To(Succeed())
			Expect(signing.NewVerifierFromKey(pub).Verify(tilePath)).To(Succeed())
		})
	})

	Context("OpenSSH PEM format (ssh-keygen -t ed25519)", func() {
		It("loads the key and can sign a verifiable tile", func() {
			keyPath := filepath.Join(tmpDir, "id_ed25519")
			writeOpenSSHPEM(keyPath, priv)

			signer, err := signing.NewSignerFromFile(keyPath)
			Expect(err).NotTo(HaveOccurred())

			tilePath := writeTmpTile(map[string]string{"metadata/metadata.yml": "name: t\n"})
			defer os.Remove(tilePath)
			Expect(signer.Sign(tilePath)).To(Succeed())
			Expect(signing.NewVerifierFromKey(pub).Verify(tilePath)).To(Succeed())
		})
	})

	Context("unsupported PEM type", func() {
		It("returns a descriptive error", func() {
			keyPath := filepath.Join(tmpDir, "bad.pem")
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("bogus")})
			Expect(os.WriteFile(keyPath, pemBytes, 0o600)).To(Succeed())

			_, err := signing.NewSignerFromFile(keyPath)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported PEM block type"))
		})
	})

	Context("file does not exist", func() {
		It("returns an error", func() {
			_, err := signing.NewSignerFromFile("/no/such/key.pem")
			Expect(err).To(HaveOccurred())
		})
	})
})

// writePKCS8PEM writes an Ed25519 private key in PKCS#8 PEM format.
func writePKCS8PEM(path string, priv ed25519.PrivateKey) {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	Expect(err).NotTo(HaveOccurred())
	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	Expect(pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: b})).To(Succeed())
	Expect(f.Close()).To(Succeed())
}

// writeOpenSSHPEM writes an Ed25519 private key in OpenSSH PEM format
// (the format produced by ssh-keygen -t ed25519).
func writeOpenSSHPEM(path string, priv ed25519.PrivateKey) {
	block, err := ssh.MarshalPrivateKey(priv, "")
	Expect(err).NotTo(HaveOccurred())
	Expect(os.WriteFile(path, pem.EncodeToMemory(block), 0o600)).To(Succeed())
}

// writePKIXPublicPEM writes an Ed25519 public key in PKIX PEM format.
func writePKIXPublicPEM(path string, pub ed25519.PublicKey) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	Expect(err).NotTo(HaveOccurred())
	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	Expect(pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: b})).To(Succeed())
	Expect(f.Close()).To(Succeed())
}

// writeOpenSSHPublicKey writes an Ed25519 public key in OpenSSH authorized_keys format
// (the format produced by ssh-keygen for *.pub files).
func writeOpenSSHPublicKey(path string, pub ed25519.PublicKey) {
	sshPub, err := ssh.NewPublicKey(pub)
	Expect(err).NotTo(HaveOccurred())
	line := ssh.MarshalAuthorizedKey(sshPub)
	Expect(os.WriteFile(path, line, 0o644)).To(Succeed())
}

// writeRSAOpenSSHPublicKey writes an RSA public key in OpenSSH format (for negative tests).
func writeRSAOpenSSHPublicKey(path string) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	sshPub, err := ssh.NewPublicKey(&rsaPriv.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	line := ssh.MarshalAuthorizedKey(sshPub)
	Expect(os.WriteFile(path, line, 0o644)).To(Succeed())
}
