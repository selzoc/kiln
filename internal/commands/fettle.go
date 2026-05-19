package commands

import (
	"log"

	"github.com/pivotal-cf/jhanda"

	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

// Fettle implements `kiln fettle` — removes compile-time-only packages from
// compiled BOSH releases inside a .pivotal tile file.
type Fettle struct {
	outLogger *log.Logger
	Options   struct {
		TilePath   string `short:"t" long:"tile"   required:"true"  description:"path to the .pivotal tile file to fettle"`
		OutputPath string `short:"o" long:"output"                   description:"output path (default: overwrites input tile)"`
	}
}

// NewFettle constructs a Fettle command.
func NewFettle(outLogger *log.Logger) *Fettle {
	return &Fettle{outLogger: outLogger}
}

func (f *Fettle) Execute(args []string) error {
	if _, err := jhanda.Parse(&f.Options, args); err != nil {
		return err
	}

	result, err := dedup.StripTile(dedup.StripInput{
		TilePath:   f.Options.TilePath,
		OutputPath: f.Options.OutputPath,
		Logger:     f.outLogger,
	})
	if err != nil {
		return err
	}

	if result.PackagesStripped > 0 {
		f.outLogger.Printf("Fettled %d compile-time packages, saved %.1f MB\n",
			result.PackagesStripped, float64(result.BytesSaved)/1024/1024)
	}
	return nil
}

// Usage satisfies jhanda.Command.
func (f *Fettle) Usage() jhanda.Usage {
	return jhanda.Usage{
		Description:      "Fettles a .pivotal tile by removing compiled BOSH packages that are only needed at build time (e.g. golang toolchains). The removed packages are not installed on VMs at runtime — a fettled tile deploys identically to the original.",
		ShortDescription: "removes compile-time BOSH packages from a .pivotal tile",
		Flags:            f.Options,
	}
}
