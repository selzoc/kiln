package signing_test

import (
	"archive/zip"
	"bytes"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/kiln/internal/signing"
)

var _ = Describe("Manifest", func() {
	Describe("ComputeManifestFromZip", func() {
		It("computes hashes for all non-signature entries", func() {
			buf := buildTestZip(map[string]string{
				"metadata/metadata.yml":  "name: my-tile\n",
				"signature/manifest.yaml": "should be excluded",
				"releases/foo-1.0.tgz":   "fake-release-data",
			})
			zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			Expect(err).NotTo(HaveOccurred())

			m, err := signing.ComputeManifestFromZip(zr)
			Expect(err).NotTo(HaveOccurred())

			Expect(m.Version).To(Equal("1"))
			Expect(m.Algorithm).To(Equal("sha256"))
			Expect(m.Files).To(HaveLen(2))
			Expect(m.Files).NotTo(HaveKey("signature/manifest.yaml"))
			Expect(m.Files["releases/foo-1.0.tgz"]).To(Equal(sha256Hex("fake-release-data")))
			Expect(m.Files["metadata/metadata.yml"]).To(Equal(sha256Hex("name: my-tile\n")))
		})
	})

	Describe("Marshal", func() {
		It("produces YAML with keys sorted alphabetically", func() {
			m := signing.Manifest{
				Version:   "1",
				Algorithm: "sha256",
				Files: map[string]string{
					"releases/z.tgz":        "sha256:zzz",
					"metadata/metadata.yml": "sha256:aaa",
				},
			}
			data, err := m.Marshal()
			Expect(err).NotTo(HaveOccurred())

			yaml := string(data)
			metaIdx := strings.Index(yaml, "metadata/metadata.yml")
			relIdx := strings.Index(yaml, "releases/z.tgz")
			Expect(metaIdx).To(BeNumerically(">", -1), "metadata key not found")
			Expect(relIdx).To(BeNumerically(">", -1), "releases key not found")
			Expect(metaIdx).To(BeNumerically("<", relIdx), "keys not sorted alphabetically")
		})

		It("includes version and algorithm headers", func() {
			m := signing.Manifest{Version: "1", Algorithm: "sha256", Files: map[string]string{}}
			data, err := m.Marshal()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(ContainSubstring("version: \"1\""))
			Expect(string(data)).To(ContainSubstring("algorithm: sha256"))
		})
	})
})
