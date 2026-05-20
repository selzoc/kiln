package dedup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/pivotal-cf/kiln/pkg/cargo"
)

// StripInput configures StripTile.
type StripInput struct {
	TilePath   string
	OutputPath string      // if empty, overwrites TilePath in-place
	Logger     *log.Logger // may be nil — defaults to discard
}

// StripResult summarises the strip operation.
type StripResult struct {
	PackagesStripped int
	BytesSaved       int64
}

// StripTile reads the .pivotal tile at input.TilePath, removes compiled packages from every
// release that are not referenced by any job's packages list (compile-time-only packages
// such as golang toolchains), and writes the result to input.OutputPath (or overwrites
// TilePath if OutputPath is empty).
//
// Unlike DeduplicateTile, StripTile completely removes compile-time packages and updates
// release.MF accordingly. No shared release is created and no OpsManager reconstruction
// is needed — BOSH receives clean releases containing only the packages VMs actually need.
func StripTile(input StripInput) (StripResult, error) {
	outputPath := input.OutputPath
	if outputPath == "" {
		outputPath = input.TilePath
	}
	logger := input.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	workDir, err := os.MkdirTemp("", "kiln-strip-*")
	if err != nil {
		return StripResult{}, err
	}
	defer os.RemoveAll(workDir)

	metadata, releaseFiles, err := extractTileReleases(input.TilePath, workDir)
	if err != nil {
		return StripResult{}, fmt.Errorf("extracting tile: %w", err)
	}

	relMetas := extractReleaseMetas(metadata)
	var totalBytesSaved int64
	totalStripped := 0

	for _, relPath := range releaseFiles {
		origSize, err := fileSize(relPath)
		if err != nil {
			return StripResult{}, err
		}
		origSHA256, err := hashFile(relPath)
		if err != nil {
			return StripResult{}, err
		}

		strippedPkgs, newSHA256, err := StripCompileTimePackages(relPath, relPath+".stripped")
		if err != nil {
			return StripResult{}, fmt.Errorf("stripping %s: %w", filepath.Base(relPath), err)
		}
		if len(strippedPkgs) == 0 {
			continue
		}

		if err := os.Rename(relPath+".stripped", relPath); err != nil {
			return StripResult{}, err
		}
		newSize, err := fileSize(relPath)
		if err != nil {
			return StripResult{}, err
		}
		saved := origSize - newSize
		totalBytesSaved += saved
		totalStripped += len(strippedPkgs)

		sort.Strings(strippedPkgs)
		logger.Printf("Fettled %s: saved %.1f MB\n", filepath.Base(relPath), float64(saved)/1024/1024)
		for _, name := range strippedPkgs {
			logger.Printf("  - %s\n", name)
		}

		if rm, ok := relMetas[filepath.Base(relPath)]; ok {
			rm.sha256 = newSHA256
			rm.originalSHA256 = origSHA256
		}
	}

	if totalStripped == 0 {
		logger.Println("No compile-time-only packages found — releases are already optimal.")
		return StripResult{}, nil
	}

	metadata["releases"] = buildReleasesSlice(relMetas)
	if err := writeOutputTile(input.TilePath, outputPath, workDir, metadata); err != nil {
		return StripResult{}, fmt.Errorf("writing output tile: %w", err)
	}

	return StripResult{
		PackagesStripped: totalStripped,
		BytesSaved:       totalBytesSaved,
	}, nil
}

// StripCompileTimePackages reads the BOSH compiled release at inputPath, determines which
// compiled packages are not referenced by any job's packages list (compile-time-only), and
// removes those packages from both the blob storage and release.MF. Writes result to outputPath.
//
// If the release contains no job entries (e.g. a shared-packages release), nothing is stripped
// and outputPath is not created. If no packages need stripping, outputPath is also not created.
//
// Returns the names of stripped packages and the hex-encoded SHA256 of the output tarball.
// An empty strippedNames slice means nothing was stripped and outputPath was not written.
func StripCompileTimePackages(inputPath, outputPath string) (strippedNames []string, sha256hex string, err error) {
	referenced, err := FindJobReferencedPackages(inputPath)
	if err != nil {
		return nil, "", fmt.Errorf("scanning job packages in %s: %w", filepath.Base(inputPath), err)
	}
	if referenced == nil {
		// No job entries in this release — skip stripping to avoid accidentally emptying
		// shared-packages releases or source releases that have no jobs.
		return nil, "", nil
	}

	manifest, _, err := readManifestAndBlobSizes(inputPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading manifest from %s: %w", filepath.Base(inputPath), err)
	}

	// Only compiled releases carry compiled_packages blobs that can be stripped.
	// Source releases have no compiled_packages and are safe to skip.
	if len(manifest.CompiledPackages) == 0 {
		return nil, "", nil
	}

	toStrip := map[string]bool{}
	var names []string
	for _, pkg := range manifest.CompiledPackages {
		if !referenced[pkg.Name] {
			toStrip[pkg.Name] = true
			names = append(names, pkg.Name)
		}
	}
	if len(toStrip) == 0 {
		return nil, "", nil
	}

	kept := make([]cargo.CompiledBOSHReleasePackage, 0, len(manifest.CompiledPackages)-len(toStrip))
	for _, pkg := range manifest.CompiledPackages {
		if !toStrip[pkg.Name] {
			cleanedDeps := pkg.Dependencies[:0:0]
			for _, dep := range pkg.Dependencies {
				if !toStrip[dep] {
					cleanedDeps = append(cleanedDeps, dep)
				}
			}
			pkg.Dependencies = cleanedDeps
			kept = append(kept, pkg)
		}
	}
	manifest.CompiledPackages = kept
	newManifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, "", err
	}

	sha256hex, err = rewriteWithStripping(inputPath, outputPath, toStrip, newManifestBytes)
	if err != nil {
		return nil, "", err
	}
	return names, sha256hex, nil
}

// FindJobReferencedPackages reads a BOSH compiled release tarball and returns the set of
// package names referenced by at least one job's packages list. These are the packages
// that need to be present on VMs at runtime.
//
// Returns nil (not an empty map) if no job entries are found in the tarball. Callers should
// treat nil as "this release has no jobs — don't strip" to avoid accidentally removing all
// compiled packages from shared-packages or source releases.
func FindJobReferencedPackages(tarballPath string) (map[string]bool, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	referenced := map[string]bool{}
	jobsFound := false
	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		base := filepath.Base(hdr.Name)
		dir := filepath.Base(filepath.Dir(hdr.Name))

		if dir == "jobs" && filepath.Ext(base) == ".tgz" {
			jobsFound = true
			pkgs, err := readJobPackages(tr)
			if err != nil {
				return nil, fmt.Errorf("reading job spec from %s: %w", base, err)
			}
			for _, p := range pkgs {
				referenced[p] = true
			}
			continue
		}

		if _, err := io.Copy(io.Discard, tr); err != nil {
			return nil, err
		}
	}

	if !jobsFound {
		return nil, nil
	}
	return referenced, nil
}

// readJobPackages reads a BOSH job tarball from r (positioned at a ./jobs/<name>.tgz entry
// in the outer tar reader) and returns the packages listed in its job.MF.
func readJobPackages(r io.Reader) ([]string, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) != "job.MF" {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, err
			}
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		var spec struct {
			Packages []string `yaml:"packages"`
		}
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, err
		}
		return spec.Packages, nil
	}
	return nil, nil
}

// rewriteWithStripping copies inputPath to outputPath, replacing release.MF with newManifest
// and omitting compiled_packages blobs listed in toStrip. Returns SHA256 of the output tarball.
func rewriteWithStripping(inputPath, outputPath string, toStrip map[string]bool, newManifest []byte) (string, error) {
	in, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(out, hasher)

	gr, err := gzip.NewReader(in)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	gw := gzip.NewWriter(mw)
	tw := tar.NewWriter(gw)
	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		base := filepath.Base(hdr.Name)

		if base == "release.MF" {
			newHdr := *hdr
			newHdr.Size = int64(len(newManifest))
			if err := tw.WriteHeader(&newHdr); err != nil {
				return "", err
			}
			if _, err := tw.Write(newManifest); err != nil {
				return "", err
			}
			continue
		}

		parentDir := filepath.Base(filepath.Dir(hdr.Name))
		if parentDir == "compiled_packages" && filepath.Ext(base) == ".tgz" {
			pkgName := base[:len(base)-4]
			if toStrip[pkgName] {
				if _, err := io.Copy(io.Discard, tr); err != nil {
					return "", err
				}
				continue
			}
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		if hdr.Size > 0 {
			if _, err := io.Copy(tw, tr); err != nil {
				return "", err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
