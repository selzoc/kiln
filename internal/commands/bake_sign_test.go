package commands_test

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/builder"
	"github.com/pivotal-cf/kiln/internal/commands"
	"github.com/pivotal-cf/kiln/internal/commands/fakes"
	"github.com/pivotal-cf/kiln/internal/signing"
	"github.com/pivotal-cf/kiln/pkg/cargo"
)

var _ = Describe("Bake --sign-key-file", func() {
	var (
		tmpDir         string
		privateKeyPath string
		publicKeyPath  string
		outputTilePath string
		pub            ed25519.PublicKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "bake-sign-test-*")
		Expect(err).NotTo(HaveOccurred())

		var priv ed25519.PrivateKey
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		privateKeyPath = filepath.Join(tmpDir, "priv.pem")
		publicKeyPath = filepath.Join(tmpDir, "pub.pem")
		writePrivatePEM(privateKeyPath, priv)
		writePublicPEM(publicKeyPath, pub)

		outputTilePath = filepath.Join(tmpDir, "output.pivotal")
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("signs the output tile when --sign-key-file is provided", func() {
		fakeTileWriter := &fakes.TileWriter{}
		fakeTileWriter.WriteStub = func(_ []byte, input builder.WriteInput) error {
			return writeMinimalTileToPath(input.OutputFile)
		}

		fakeInterpolator := &fakes.Interpolator{}
		fakeInterpolator.InterpolateReturns([]byte("name: bake-sign-test\n"), nil)

		fakeTemplateVars := &fakes.TemplateVariablesService{}
		fakeTemplateVars.FromPathsAndPairsReturns(map[string]any{}, nil)

		fakeMeta := &fakes.MetadataService{}
		fakeMeta.ReadReturns([]byte("name: bake-sign-test\n"), nil)

		fakeIcon := &fakes.IconService{}
		fakeIcon.EncodeReturns("", nil)

		fakeFilesystem := &fakes.FileSystem{}
		fakeVersionInfo := &fakes.FileInfo{}
		fakeVersionInfo.NameReturns("version")
		fakeVersionInfo.SizeReturns(0)
		fakeFilesystem.StatReturns(nil, nil)

		bakeCmd := commands.NewBakeWithInterfaces(
			fakeInterpolator,
			fakeTileWriter,
			log.New(GinkgoWriter, "", 0),
			log.New(GinkgoWriter, "", 0),
			fakeTemplateVars,
			&fakes.MetadataTemplatesParser{},
			&fakes.FromDirectories{},
			&fakes.StemcellService{},
			&fakes.MetadataTemplatesParser{},
			&fakes.MetadataTemplatesParser{},
			&fakes.MetadataTemplatesParser{},
			&fakes.MetadataTemplatesParser{},
			&fakes.MetadataTemplatesParser{},
			fakeIcon,
			fakeMeta,
			&fakes.Checksummer{},
			&fakes.Fetch{},
			fakeFilesystem,
			func() (string, error) { return tmpDir, nil },
			func(_, _, _ string, _ []byte) error { return nil },
		).WithKilnfileFunc(func(_ string) (cargo.Kilnfile, error) {
			return cargo.Kilnfile{}, nil
		})

		err := bakeCmd.Execute([]string{
			"--metadata", "base.yml",
			"--output-file", outputTilePath,
			"--sign-key-file", privateKeyPath,
			"--skip-fetch",
			"--stub-releases",
		})
		Expect(err).NotTo(HaveOccurred())

		verifier, err := signing.NewVerifierFromFile(publicKeyPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(verifier.Verify(outputTilePath)).To(Succeed())
	})
})

func writeMinimalTileToPath(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("metadata/metadata.yml")
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("name: bake-sign-test\n")); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Close()
}
