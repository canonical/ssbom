package builder_test

import (
	"strings"

	"github.com/canonical/ssbom/internal/builder"
	"github.com/canonical/ssbom/internal/testutil"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	. "gopkg.in/check.v1"
)

type BuilderTest struct {
	summary      string
	packageInfos []builder.PackageInfo
	pathInfos    []builder.PathInfo
	sliceInfos   []builder.SliceInfo
	spdxDocument spdx.Document
	error        string
}

var builerTests = []BuilderTest{
	{
		summary:      "Builds package section",
		packageInfos: testutil.SampleSinglePackage,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   builder.DocumentName,
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
			},
			Relationships: []*spdx.Relationship{
				{
					RefA:         common.MakeDocElementID("", "DOCUMENT"),
					RefB:         common.MakeDocElementID("", testutil.SamplePackageID),
					Relationship: "DESCRIBES",
				},
			},
			CreationInfo: &spdx.CreationInfo{
				Creators: builder.ChiselSbomDocCreator,
			},
		},
	}, {
		summary:      "Builds slice section",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   builder.DocumentName,
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
			},
			CreationInfo: &spdx.CreationInfo{
				Creators: builder.ChiselSbomDocCreator,
			},
		},
	}, {
		summary:      "Builds file section",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathNoFinalSHA256,
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
		summary:      "Builds file section with modified file",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathModified,
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
	}, {
		summary:      "Builds doc for one slice with two files",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos: append(testutil.SampleSinglePathModified,
			builder.PathInfo{
				Path:      "/test2",
				Mode:      "0644",
				Checksums: testutil.SampleFileChecksums,
				Slices:    []string{"test_slice"},
			}),
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
				&testutil.SPDXDocSampleSingleFileModified,
				{
					FileName:           "test2",
					FileSPDXIdentifier: "File-bdbc5e82b59e2d430975cdd123931580",
					Checksums:          testutil.SampleFileChecksums,
					FileCopyrightText:  "NOASSERTION",
					FileComment:        "This file is included in the slice(s) test_slice; see Relationship information.",
				},
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				&testutil.SPDXRelSampleSingleFileModifiedBySlice,
				{
					RefA:                common.MakeDocElementID("", testutil.SampleSliceID),
					RefB:                common.MakeDocElementID("", "File-bdbc5e82b59e2d430975cdd123931580"),
					Relationship:        "CONTAINS",
					RelationshipComment: "File /test2 is included in the slice test_slice.",
				},
			},
			CreationInfo: &spdx.CreationInfo{
				Creators: builder.ChiselSbomDocCreator,
			},
		},
	}, {
		summary:      "Builds doc for two slices having a shared file",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos: append(testutil.SampleSingleSlice,
			builder.SliceInfo{
				Name: "test_slice2",
			},
		),
		pathInfos: []builder.PathInfo{
			{
				Path:      "/test",
				Mode:      "0644",
				Checksums: testutil.SampleFileChecksums,
				Slices:    []string{"test_slice", "test_slice2"},
			},
		},
		spdxDocument: spdx.Document{
			SPDXVersion:    spdx.Version,
			DataLicense:    spdx.DataLicense,
			SPDXIdentifier: spdx.ElementID("DOCUMENT"),
			DocumentName:   builder.DocumentName,
			Packages: []*spdx.Package{
				&testutil.SPDXDocSampleSinglePackage,
				&testutil.SPDXDocSampleSingleSlice,
				{
					PackageName:             "test_slice2",
					PackageSPDXIdentifier:   "Slice-14caad6701f5a02d58aaefe6ebf616f0",
					FilesAnalyzed:           true,
					PackageDownloadLocation: "NOASSERTION",
					PackageComment:          "This slice is a sub-package of the package test; see Relationship information.",
				},
			},
			Files: []*spdx.File{
				{
					FileName:           "test",
					FileSPDXIdentifier: testutil.SampleFileID,
					Checksums:          testutil.SampleFileChecksums,
					FileCopyrightText:  "NOASSERTION",
					FileComment:        "This file is included in the slice(s) test_slice, test_slice2; see Relationship information.",
				},
			},
			Relationships: []*spdx.Relationship{
				&testutil.SPDXRelSampleSingleDocDescribesPkg,
				&testutil.SPDXRelSampleSinglePkgContainsSlice,
				{
					RefA:         common.MakeDocElementID("", testutil.SamplePackageID),
					RefB:         common.MakeDocElementID("", "Slice-14caad6701f5a02d58aaefe6ebf616f0"),
					Relationship: "CONTAINS",
				},
				&testutil.SPDXRelSampleSingleSliceContainsFile,
				{
					RefA:                common.MakeDocElementID("", "Slice-14caad6701f5a02d58aaefe6ebf616f0"),
					RefB:                common.MakeDocElementID("", testutil.SampleFileID),
					Relationship:        "CONTAINS",
					RelationshipComment: "File /test is included in the slice test_slice2.",
				},
			},
			CreationInfo: &spdx.CreationInfo{
				Creators: builder.ChiselSbomDocCreator,
			},
		},
	}, {
		summary:      "Builds doc for symlink",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathLnk,
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
				&testutil.SPDXDocSampleSingleFileLnk,
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
		summary:      "Builds doc for hard link",
		packageInfos: testutil.SampleSinglePackage,
		sliceInfos:   testutil.SampleSingleSlice,
		pathInfos:    testutil.SampleSinglePathHlk,
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
				&testutil.SPDXDocSampleSingleFileHlk,
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
		summary: "Cannot build doc for mutated symlink",
		pathInfos: []builder.PathInfo{
			{
				Path:        "/test",
				Mode:        "0644",
				FinalSHA256: "final_sha256",
				Link:        "/file",
			},
		},
		error: "cannot build file section: invalid link: link /test has a final sha256",
	}, {
		summary: "Cannot build doc for mutated hard link",
		pathInfos: []builder.PathInfo{
			{
				Path:        "/test",
				Mode:        "0644",
				FinalSHA256: "final_sha256",
				Inode:       1,
			},
		},
		error: "cannot build file section: invalid link: link /test has a final sha256",
	}, {
		summary: "Cannot build doc for invalid link",
		pathInfos: []builder.PathInfo{
			{
				Path:  "/test",
				Mode:  "0644",
				Link:  "/file",
				Inode: 1,
			},
		},
		error: "cannot build file section: invalid file type: file /test simultaneously has inode 1 and link /file",
	},
}

func runTestBuilder(c *C, test []BuilderTest, distro string) {
	for _, test := range test {
		if distro == "" {
			c.Logf("Running test without distro: %s", test.summary)
		} else {
			c.Logf("Running test with distro: %s: %s", distro, test.summary)
		}
		doc, err := builder.BuildSPDXDocument("", distro, &test.sliceInfos, &test.packageInfos, &test.pathInfos)
		if test.error != "" {
			c.Assert(err, ErrorMatches, test.error)
			continue
		}
		c.Assert(err, IsNil)
		testutil.AssertDocument(c, doc, test.spdxDocument)
	}
}

func (s *S) TestBuilder(c *C) {
	runTestBuilder(c, builerTests, "")

	// Testing builder with non-empty distro
	// The package external reference is not appended with "&distro=ubuntu-24.04" because
	// the conversion from manifest to packageInfo is done in the converter
	for i := range builerTests {
		if !strings.Contains(builerTests[i].summary, "Cannot") {
			builerTests[i].spdxDocument.Packages = append([]*spdx.Package{
				&testutil.SPDXDocSampleUbuntuNoble,
			}, builerTests[i].spdxDocument.Packages...)
			builerTests[i].spdxDocument.Relationships = append([]*spdx.Relationship{
				&testutil.SPDXRelSampleUbuntuNoble,
			}, builerTests[i].spdxDocument.Relationships...)
		}
	}
	runTestBuilder(c, builerTests, "24.04")
}
