package commands

import (
	"archive/zip"
	"fmt"
	"io"
	"log"

	"github.com/pivotal-cf/jhanda"
	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/pkg/cargo/dedup"
)

// DeduplicatePackages implements `kiln deduplicate-packages`.
type DeduplicatePackages struct {
	outLogger *log.Logger
	Options   struct {
		TilePath   string `short:"t" long:"tile"   required:"true"  description:"path to the .pivotal tile file to deduplicate"`
		OutputPath string `short:"o" long:"output"                   description:"output path (default: overwrites input tile)"`
		Slug       string `short:"s" long:"slug"                     description:"tile slug for the shared-packages release name (auto-detected from tile metadata if omitted)"`
	}
}

// NewDeduplicatePackages constructs a DeduplicatePackages command.
func NewDeduplicatePackages(outLogger *log.Logger) *DeduplicatePackages {
	return &DeduplicatePackages{outLogger: outLogger}
}

func (d *DeduplicatePackages) Execute(args []string) error {
	_, err := jhanda.Parse(&d.Options, args)
	if err != nil {
		return err
	}

	slug := d.Options.Slug
	if slug == "" {
		slug, err = tileSlugFromPivotal(d.Options.TilePath)
		if err != nil {
			return fmt.Errorf("auto-detecting tile slug (use --slug to override): %w", err)
		}
	}

	result, err := dedup.DeduplicateTile(dedup.DeduplicateInput{
		TilePath:   d.Options.TilePath,
		OutputPath: d.Options.OutputPath,
		Slug:       slug,
		Logger:     d.outLogger,
	})
	if err != nil {
		return err
	}

	if result.PackagesDeduped > 0 {
		d.outLogger.Printf("Deduplicated %d packages, saved %.1f MB\n",
			result.PackagesDeduped, float64(result.BytesSaved)/1024/1024)
	}
	return nil
}

// Usage satisfies jhanda.Command.
func (d *DeduplicatePackages) Usage() jhanda.Usage {
	return jhanda.Usage{
		Description:      "Deduplicates compiled BOSH package blobs across releases in a .pivotal tile file, producing a smaller tile that OpsManager can reconstruct on import.",
		ShortDescription: "deduplicates compiled BOSH package blobs in a .pivotal tile",
		Flags:            d.Options,
	}
}

// tileSlugFromPivotal reads the tile name from metadata/metadata.yml inside a .pivotal file.
func tileSlugFromPivotal(tilePath string) (string, error) {
	zr, err := zip.OpenReader(tilePath)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "metadata/metadata.yml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return "", err
		}
		var meta struct {
			Name string `yaml:"name"`
		}
		if err := yaml.Unmarshal(data, &meta); err != nil {
			return "", err
		}
		if meta.Name == "" {
			return "", fmt.Errorf("name field is empty in metadata/metadata.yml")
		}
		return meta.Name, nil
	}
	return "", fmt.Errorf("metadata/metadata.yml not found in %s", tilePath)
}
