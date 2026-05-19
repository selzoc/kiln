// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add Ed25519 PEM key loading utilities for tile signing - Cursor: Claude Sonnet 4.6

package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}
