// @AI-Generated
// Modified with AI assistance
// Description:
// 2026-05-19: Add kiln sign command for signing .pivotal tiles with Ed25519 - Cursor: Claude Sonnet 4.6

package commands

import (
	"fmt"
	"log"

	"github.com/pivotal-cf/jhanda"
	"github.com/pivotal-cf/kiln/internal/signing"
)

// Sign implements `kiln sign`.
type Sign struct {
	logger  *log.Logger
	Options struct {
		PrivateKeyFile string `short:"k" long:"private-key-file" required:"true" description:"path to Ed25519 private key (PKCS#8 PEM)"`
	}
}

// NewSign creates a Sign command with the default logger.
func NewSign() Sign {
	return Sign{logger: log.Default()}
}

// Execute parses flags and signs the tile at the given path.
func (s Sign) Execute(args []string) error {
	remaining, err := jhanda.Parse(&s.Options, args)
	if err != nil {
		return fmt.Errorf("kiln sign: %w", err)
	}
	if len(remaining) == 0 {
		return fmt.Errorf("kiln sign: tile path is required as a positional argument")
	}
	tilePath := remaining[0]

	signer, err := signing.NewSignerFromFile(s.Options.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("kiln sign: %w", err)
	}

	if err := signer.Sign(tilePath); err != nil {
		return fmt.Errorf("kiln sign: %w", err)
	}

	s.logger.Printf("Signed %s\n", tilePath)
	return nil
}

// Usage returns the command's usage descriptor.
func (s Sign) Usage() jhanda.Usage {
	return jhanda.Usage{
		Description:      "Signs a .pivotal tile file with an Ed25519 private key, embedding a hash manifest and signature",
		ShortDescription: "sign a tile",
		Flags:            s.Options,
	}
}
