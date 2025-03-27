package converter_test

import (
	"io"
	"strings"

	"github.com/canonical/chisel/public/manifest"
	"github.com/canonical/ssbom/internal/builder"
	"github.com/canonical/ssbom/internal/converter"
	"github.com/canonical/ssbom/internal/testutil"
	"github.com/spdx/tools-golang/spdx"
	. "gopkg.in/check.v1"
)

type ProcessTest struct {
	summary      string
	manifestData converter.ManifestData
	packageInfos []builder.PackageInfo
	pathInfos    []builder.PathInfo
	sliceInfos   []builder.SliceInfo
}

var processTests = []ProcessTest{
	{
		summary: "Converts packages",
		manifestData: converter.ManifestData{
			Packages: []manifest.Package{
				{
					Kind:    "package",
					Name:    "test",
					Version: "1.0",
					Digest:  "sha256",
					Arch:    "amd64",
				},
			},
		},
		packageInfos: []builder.PackageInfo{
			{
				Name:    "test",
				Version: "1.0",
				SHA256:  "sha256",
				Arch:    "amd64",
			},
		},
	}, {
		summary: "Converts paths",
		manifestData: converter.ManifestData{
			Paths: []manifest.Path{
				{
					Kind:        "path",
					Path:        "/test",
					Mode:        "0644",
					Slices:      []string{"test"},
					SHA256:      "sha256",
					FinalSHA256: "final_sha256",
					Size:        1024,
					Link:        "/file",
					Inode:       1,
				},
			},
		},
		pathInfos: []builder.PathInfo{
			{
				Path:        "/test",
				Mode:        "0644",
				Slices:      []string{"test"},
				SHA256:      "sha256",
				FinalSHA256: "final_sha256",
				Link:        "/file",
				Inode:       1,
			},
		},
	}, {
		summary: "Converts slices",
		manifestData: converter.ManifestData{
			Slices: []manifest.Slice{
				{
					Kind: "slice",
					Name: "test",
				},
			},
		},
		sliceInfos: []builder.SliceInfo{
			{
				Name: "test",
			},
		},
	},
}

type ConverterTest struct {
	summary      string
	jsonwall     string
	spdxDocument spdx.Document
	error        string
}

var converterTests = []ConverterTest{
	{
		summary: "Converts manifest data to SPDX document",
		jsonwall: `
			{"jsonwall":"1.0","schema":"1.0","count":3}
			{"kind":"package","name":"test","version":"1.0","sha256":"sha256","arch":"amd64"}
			{"kind":"path","path":"/test","mode":"0644","slices":["test_slice"],"sha256":"sha256","size":1024}
			{"kind":"slice","name":"test_slice"}
		`,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   builder.DocumentName,
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileNoFinalSHA256,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleSliceContainsFile,
			},
			CreationInfo: &spdx.CreationInfo{
				Creators: builder.ChiselSbomDocCreator,
			},
		},
	}, {
		summary: "Path with non-empty SHA256 and FinalSHA256 has relationship FILE_MODIFIED",
		jsonwall: `
			{"jsonwall":"1.0","schema":"1.0","count":3}
			{"kind":"package","name":"test","version":"1.0","sha256":"sha256","arch":"all"}
			{"kind":"path","path":"/test","mode":"0644","slices":["test_slice"],"sha256":"sha256","final_sha256":"final_sha256","size":1024}
			{"kind":"slice","name":"test_slice"}
		`,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   builder.DocumentName,
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackageArchAll,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Files: []*spdx.File{
				&testutil.SPDXDocSampleSingleFileModified,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleFileModifiedBySlice,
			},
			CreationInfo: &spdx.CreationInfo{
				Creators: builder.ChiselSbomDocCreator,
			},
		},
	},
}

func (s *S) TestProcessManifestData(c *C) {
	for _, test := range processTests {
		c.Logf("Running test: %s", test.summary)
		packageInfos := test.manifestData.ProcessPackages()
		c.Assert(packageInfos, DeepEquals, test.packageInfos)
		pathInfos := test.manifestData.ProcessPaths()
		c.Assert(pathInfos, DeepEquals, test.pathInfos)
		sliceInfos := test.manifestData.ProcessSlices()
		c.Assert(sliceInfos, DeepEquals, test.sliceInfos)
	}
}

func runTestConvert(c *C, tests []ConverterTest, distro string) {
	for _, test := range tests {
		if distro == "" {
			c.Logf("Running test without distro: %s", test.summary)
		} else {
			c.Logf("Running test with distro: %s: %s", distro, test.summary)
		}
		lines := strings.Split(strings.TrimSpace(test.jsonwall), "\n")
		trimmedLines := make([]string, 0, len(lines))
		for _, line := range lines {
			trimmedLines = append(trimmedLines, strings.TrimLeft(line, "\t"))
		}
		test.jsonwall = strings.Join(trimmedLines, "\n")
		var reader io.Reader = strings.NewReader(test.jsonwall)
		doc, err := converter.Convert(reader, distro)
		c.Assert(err, IsNil)
		c.Assert(doc, DeepEquals, &test.spdxDocument)
	}
}

func (s *S) TestConvert(c *C) {
	runTestConvert(c, converterTests, "")

	// Test with distro
	for i := range testutil.SPDXDocSamplePackages {
		testutil.SPDXDocSamplePackages[i].PackageExternalReferences[1].Locator += "&distro=ubuntu-24.04"
	}
	for i := range converterTests {
		converterTests[i].spdxDocument.Packages = append([]*spdx.Package{
			&testutil.SPDXDocSampleUbuntuNoble,
		}, converterTests[i].spdxDocument.Packages...)
		converterTests[i].spdxDocument.Relationships = append([]*spdx.Relationship{
			&testutil.SPDXRelSampleUbuntuNoble,
		}, converterTests[i].spdxDocument.Relationships...)
	}
	runTestConvert(c, converterTests, "24.04")
}
