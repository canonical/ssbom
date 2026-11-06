package testutil

import (
	"strings"
	"time"

	"github.com/canonical/ssbom/internal/builder"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"gopkg.in/check.v1"
)

const (
	SamplePackageID = "Package-098f6bcd4621d373cade4e832627b4f6"
	SampleSliceID   = "Slice-350a63a76fc983a534c9098f0c34963e"
	SampleFileID    = "File-4539330648b80f94ef3bf911f6d77ac9"
	SampleUbuntuID  = "OperatingSystem-ubuntu-cd5fcfe02b1d4f040fde5ba738d7572a"
)

var (
	SampleFileChecksums = []spdx.Checksum{
		{Algorithm: spdx.SHA1, Value: "c9e870f04c9a67f50f304ab2bb80cbefa3960adb"},
		{Algorithm: spdx.SHA256, Value: "25718360e05d3c2d0963d1381e9dd4dae5fca789244ee4b9f861adcc0cc96218"},
	}
	SampleModifiedChecksums = []spdx.Checksum{
		{Algorithm: spdx.SHA1, Value: "e2fb5f2139d086ded2cb600d5a91a196e76bf020"},
		{Algorithm: spdx.SHA256, Value: "4487e24377581c1a43c957c7700c8b49920de7b8500c05590cee74996ef73f42"},
	}
	SampleSymlinkChecksums = []spdx.Checksum{
		{Algorithm: spdx.SHA1, Value: "0a63e1f569becd95cebe053cc9f7611769d58f5b"},
		{Algorithm: spdx.SHA256, Value: "e3095f60327956919d4b7e431c01378cf010359e90fe81038f28eeb600f2cecc"},
	}
)

func AssertDocument(c *check.C, got *spdx.Document, want spdx.Document) {
	c.Assert(got.CreationInfo, check.NotNil)
	created, err := time.Parse(time.RFC3339, got.CreationInfo.Created)
	c.Assert(err, check.IsNil)
	c.Assert(created.Location(), check.Equals, time.UTC)

	prefix := "https://sbom.canonical.com/spdxdocs/" + strings.ReplaceAll(want.DocumentName, " ", "-") + "-"
	suffix, found := strings.CutPrefix(got.DocumentNamespace, prefix)
	c.Assert(found, check.Equals, true)
	id, err := uuid.Parse(suffix)
	c.Assert(err, check.IsNil)
	c.Assert(id.Version(), check.Equals, uuid.Version(4))

	creationInfo := *want.CreationInfo
	creationInfo.Created = got.CreationInfo.Created
	want.CreationInfo = &creationInfo
	want.DocumentNamespace = got.DocumentNamespace
	c.Assert(got, check.DeepEquals, &want)
}

var SampleSinglePackage = []builder.PackageInfo{
	{
		Name:    "test",
		Version: "1.0",
		SHA256:  "sha256",
		Arch:    "amd64",
	},
}

var SampleSingleSlice = []builder.SliceInfo{
	{
		Name: "test_slice",
	},
}

var SampleSinglePathNoFinalSHA256 = []builder.PathInfo{
	{
		Path:      "/test",
		Mode:      "0644",
		Slices:    []string{"test_slice"},
		Checksums: SampleFileChecksums,
	},
}

var SampleSinglePathModified = []builder.PathInfo{
	{
		Path:        "/test",
		Mode:        "0644",
		Slices:      []string{"test_slice"},
		Checksums:   SampleModifiedChecksums,
		FinalSHA256: "final_sha256",
	},
}

var SampleSinglePathLnk = []builder.PathInfo{
	{
		Path:      "/test",
		Mode:      "0644",
		Slices:    []string{"test_slice"},
		Checksums: SampleSymlinkChecksums,
		Link:      "/file",
	},
}

var SampleSinglePathHlk = []builder.PathInfo{
	{
		Path:      "/test",
		Mode:      "0644",
		Slices:    []string{"test_slice"},
		Checksums: SampleFileChecksums,
		Inode:     1,
	},
}

var SPDXDocSampleSinglePackage = spdx.Package{
	PackageName:    "test",
	PackageVersion: "1.0",
	FilesAnalyzed:  false,
	PackageChecksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "sha256",
		},
	},
	PackageDownloadLocation: "NOASSERTION",
	PackageSPDXIdentifier:   SamplePackageID,
	PackageComment:          "This package includes one or more slice(s); see Relationship information.",
	PackageSupplier:         &builder.UbuntuPackageSupplier,
	PackageExternalReferences: []*spdx.PackageExternalReference{
		{
			Category: "PACKAGE_MANAGER",
			RefType:  "purl",
			Locator:  "pkg:deb/ubuntu/test@1.0?arch=amd64",
		},
	},
}

var SPDXDocSampleSinglePackageArchAll = spdx.Package{
	PackageName:    "test",
	PackageVersion: "1.0",
	FilesAnalyzed:  false,
	PackageChecksums: []spdx.Checksum{
		{
			Algorithm: spdx.SHA256,
			Value:     "sha256",
		},
	},
	PackageDownloadLocation: "NOASSERTION",
	PackageSPDXIdentifier:   SamplePackageID,
	PackageComment:          "This package includes one or more slice(s); see Relationship information.",
	PackageSupplier:         &builder.UbuntuPackageSupplier,
	PackageExternalReferences: []*spdx.PackageExternalReference{
		{
			Category: "PACKAGE_MANAGER",
			RefType:  "purl",
			Locator:  "pkg:deb/ubuntu/test@1.0?arch=all",
		},
	},
}

var SPDXDocSamplePackages = []*spdx.Package{
	&SPDXDocSampleSinglePackage,
	&SPDXDocSampleSinglePackageArchAll,
}

var SPDXDocSampleSingleSlice = spdx.Package{
	PackageName:             "test_slice",
	FilesAnalyzed:           true,
	PackageDownloadLocation: "NOASSERTION",
	PackageSPDXIdentifier:   SampleSliceID,
	PackageComment:          "This slice is a sub-package of the package test; see Relationship information.",
}

var SPDXDocSampleSingleFileNoFinalSHA256 = spdx.File{
	FileSPDXIdentifier: SampleFileID,
	FileName:           "test",
	Checksums:          SampleFileChecksums,
	FileCopyrightText:  "NOASSERTION",
	FileComment:        "This file is included in the slice(s) test_slice; see Relationship information.",
}

var SPDXDocSampleSingleFileModified = spdx.File{
	FileSPDXIdentifier: SampleFileID,
	FileName:           "test",
	Checksums:          SampleModifiedChecksums,
	FileCopyrightText:  "NOASSERTION",
	FileComment:        "This file is mutated by the slice test_slice; see Relationship information.",
}

var SPDXDocSampleSingleFileLnk = spdx.File{
	FileSPDXIdentifier: SampleFileID,
	FileName:           "test",
	Checksums:          SampleSymlinkChecksums,
	FileCopyrightText:  "NOASSERTION",
	FileComment:        "This file is a symlink to the file /file.",
}

var SPDXDocSampleSingleFileHlk = spdx.File{
	FileSPDXIdentifier: SampleFileID,
	FileName:           "test",
	Checksums:          SampleFileChecksums,
	FileCopyrightText:  "NOASSERTION",
	FileComment:        "This file is within the hard link group 1; files in the same hard link group are alias of each other.",
}

var SPDXRelSampleSingleDocDescribesPkg = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "DOCUMENT"),
	RefB:         common.MakeDocElementID("", SamplePackageID),
	Relationship: "DESCRIBES",
}

var SPDXRelSampleSinglePkgContainsSlice = spdx.Relationship{
	RefA:         common.MakeDocElementID("", SamplePackageID),
	RefB:         common.MakeDocElementID("", SampleSliceID),
	Relationship: "CONTAINS",
}

var SPDXRelSampleSingleSliceContainsFile = spdx.Relationship{
	RefA:                common.MakeDocElementID("", SampleSliceID),
	RefB:                common.MakeDocElementID("", SampleFileID),
	Relationship:        "CONTAINS",
	RelationshipComment: "File /test is included in the slice test_slice.",
}

var SPDXRelSampleSingleFileModifiedBySlice = spdx.Relationship{
	RefA:                common.MakeDocElementID("", SampleFileID),
	RefB:                common.MakeDocElementID("", SampleSliceID),
	Relationship:        "FILE_MODIFIED",
	RelationshipComment: "File /test is mutated by the slice test_slice.",
}

var SPDXDocSampleUbuntuNoble = spdx.Package{
	PackageName:             "ubuntu",
	PackageSPDXIdentifier:   SampleUbuntuID,
	PackageDownloadLocation: "NOASSERTION",
	FilesAnalyzed:           false,
	PackageComment:          "This package is the distribution of the rootfs.",
	PackageVersion:          "24.04",
	PrimaryPackagePurpose:   "OPERATING_SYSTEM",
}

var SPDXRelSampleUbuntuNoble = spdx.Relationship{
	RefA:         common.MakeDocElementID("", "DOCUMENT"),
	RefB:         common.MakeDocElementID("", SampleUbuntuID),
	Relationship: "DESCRIBES",
}
