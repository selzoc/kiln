// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add Ed25519 PEM key loading utilities for tile signing - Cursor: Claude Sonnet 4.6
// 2026-05-19: Support OpenSSH private key format in addition to PKCS#8 - Cursor: Claude Sonnet 4.6

package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// loadPrivateKey reads an Ed25519 private key from path.
// Accepts two PEM formats:
//   - PKCS#8 ("BEGIN PRIVATE KEY")  — produced by openssl genpkey / kiln keygen
//   - OpenSSH ("BEGIN OPENSSH PRIVATE KEY") — produced by ssh-keygen -t ed25519
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 private key: %w", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
		}
		return edKey, nil

	case "OPENSSH PRIVATE KEY":
		rawKey, err := ssh.ParseRawPrivateKey(pemData)
		if err != nil {
			return nil, fmt.Errorf("parsing OpenSSH private key: %w", err)
		}
		edKey, ok := rawKey.(*ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("OpenSSH key is not Ed25519 (got %T)", rawKey)
		}
		return *edKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM block type %q (expected \"PRIVATE KEY\" or \"OPENSSH PRIVATE KEY\")", block.Type)
	}
}

// parsePrivateKeyFromPEM is like loadPrivateKey but operates on in-memory PEM bytes.
// Used by tests.
func parsePrivateKeyFromPEM(pemData []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 private key: %w", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
		}
		return edKey, nil
	case "OPENSSH PRIVATE KEY":
		rawKey, err := ssh.ParseRawPrivateKey(pemData)
		if err != nil {
			return nil, fmt.Errorf("parsing OpenSSH private key: %w", err)
		}
		edKey, ok := rawKey.(*ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("OpenSSH key is not Ed25519 (got %T)", rawKey)
		}
		return *edKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// loadPublicKey reads an Ed25519 public key from path.
// Accepts two formats:
//   - PKIX PEM ("BEGIN PUBLIC KEY")         — produced by openssl pkey -pubout
//   - OpenSSH authorized_keys format         — produced by ssh-keygen (the *.pub file)
//     e.g. "ssh-ed25519 AAAA… comment"
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return parsePublicKey(data, path)
}

func parsePublicKey(data []byte, source string) (ed25519.PublicKey, error) {
	// Try PEM first.
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing PKIX public key: %w", err)
			}
			edKey, ok := key.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
			}
			return edKey, nil
		default:
			return nil, fmt.Errorf("unsupported PEM block type %q in %q (expected \"PUBLIC KEY\")", block.Type, source)
		}
	}

	// Try OpenSSH authorized_keys format ("ssh-ed25519 AAAA… comment").
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("no PEM block found and not a valid OpenSSH public key in %q: %w", source, err)
	}
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("SSH public key does not expose a crypto.PublicKey in %q", source)
	}
	edKey, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("SSH public key is not Ed25519 in %q", source)
	}
	return edKey, nil
}
