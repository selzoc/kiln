// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add kiln verify-signature command for verifying .pivotal tile signatures - Cursor: Claude Sonnet 4.6

package commands

import (
	"fmt"
	"log"

	"github.com/pivotal-cf/jhanda"
	"github.com/pivotal-cf/kiln/internal/signing"
)

// VerifySignature implements `kiln verify-signature`.
type VerifySignature struct {
	logger  *log.Logger
	Options struct {
		PublicKeyFile string `short:"k" long:"public-key-file" required:"true" description:"path to Ed25519 public key (PKIX PEM)"`
	}
}

// NewVerifySignature creates a VerifySignature command.
func NewVerifySignature() VerifySignature {
	return VerifySignature{logger: log.Default()}
}

// Execute parses flags and verifies the tile at the given path.
func (v VerifySignature) Execute(args []string) error {
	remaining, err := jhanda.Parse(&v.Options, args)
	if err != nil {
		return fmt.Errorf("kiln verify-signature: %w", err)
	}
	if len(remaining) == 0 {
		return fmt.Errorf("kiln verify-signature: tile path is required as a positional argument")
	}
	tilePath := remaining[0]

	verifier, err := signing.NewVerifierFromFile(v.Options.PublicKeyFile)
	if err != nil {
		return fmt.Errorf("kiln verify-signature: %w", err)
	}

	if err := verifier.Verify(tilePath); err != nil {
		return fmt.Errorf("kiln verify-signature: %w", err)
	}

	v.logger.Printf("Signature valid: %s\n", tilePath)
	return nil
}

// Usage returns the command's usage descriptor.
func (v VerifySignature) Usage() jhanda.Usage {
	return jhanda.Usage{
		Description:      "Verifies the Ed25519 signature and hash manifest of a .pivotal tile",
		ShortDescription: "verify tile signature",
		Flags:            v.Options,
	}
}
