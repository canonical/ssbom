package builder

import (
	"fmt"
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
const DocumentName = "Chiselled Ubuntu Rootfs"

type PackageInfo struct {
	Name    string
	Version string
	SHA256  string
	Arch    string
	Distro  string
}

type PathInfo struct {
	Path        string
	Mode        string
	Slices      []string
	SHA256      string
	FinalSHA256 string
	Link        string
	Inode       uint64
}

type SliceInfo struct {
	Name string
}

var ChiselSbomDocCreator = []common.Creator{
	{
		Creator:     "Chisel SBOM Exporter ()",
		CreatorType: "Tool",
	},
}

func BuildSPDXDocument(distro string, sliceInfos *[]SliceInfo, packageInfos *[]PackageInfo, pathInfos *[]PathInfo) (*spdx.Document, error) {
	doc := &spdx.Document{
		SPDXVersion:    spdx.Version,
		DataLicense:    spdx.DataLicense,
		SPDXIdentifier: spdx.ElementID("DOCUMENT"),
		DocumentName:   DocumentName,
		CreationInfo: &spdx.CreationInfo{
			Creators: ChiselSbomDocCreator,
		},
	}

	if distro != "" {
		osPackage := &spdx.Package{
			PackageName:             "ubuntu",
			PackageSPDXIdentifier:   common.ElementID(OSId(distro)),
			PackageDownloadLocation: "NOASSERTION",
			FilesAnalyzed:           false,
			PackageComment:          "This package is the distribution of the rootfs.",
			PackageVersion:          distro,
			PrimaryPackagePurpose:   "OPERATING_SYSTEM",
		}
		doc.Packages = append(doc.Packages, osPackage)
		doc.Relationships = append(doc.Relationships, &spdx.Relationship{
			RefA:         common.MakeDocElementID("", "DOCUMENT"),
			RefB:         common.MakeDocElementID("", OSId(distro)),
			Relationship: "DESCRIBES",
		})
	}

	// Add packages
	for _, p := range *packageInfos {
		pkg, rln, err := p.buildPackageSection()
		if err != nil {
			return nil, err
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, rln)
	}

	// Add slices
	for _, s := range *sliceInfos {
		pkg, rln, err := s.buildSliceSection()
		if err != nil {
			return nil, err
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, rln)
	}

	// Add paths
	for _, p := range *pathInfos {
		file, rln, err := p.buildPathSection()
		if err != nil {
			return nil, err
		}
		doc.Files = append(doc.Files, file)
		doc.Relationships = append(doc.Relationships, rln...)
	}

	return doc, nil
}

func OSId(distro string) string {
	return fmt.Sprintf("OperatingSystem-ubuntu-%s", distro)
}

func (p *PackageInfo) SPDXId() string {
	return fmt.Sprintf("Package-%s", p.Name)
}

func (s *SliceInfo) SPDXId() string {
	return fmt.Sprintf("Slice-%s", s.Name)
}

func (p *PathInfo) SPDXId() string {
	return fmt.Sprintf("File-%s", p.Path)
}

var UbuntuPackageSupplier = common.Supplier{
	SupplierType: "Person",
	Supplier:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
}

func (p *PackageInfo) CPE23Locator() string {
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", p.Name, p.Name, p.Version)
}

func (p *PackageInfo) PurlLocator() string {
	locator := fmt.Sprintf("pkg:deb/ubuntu/%s@%s?arch=%s", p.Name, p.Version, p.Arch)
	if p.Distro != "" {
		locator += fmt.Sprintf("&distro=ubuntu-%s", p.Distro)
	}
	return locator
}

func (p *PackageInfo) buildPackageSection() (*spdx.Package, *spdx.Relationship, error) {
	pkg := &spdx.Package{
		PackageName:             p.Name,
		PackageSPDXIdentifier:   common.ElementID(p.SPDXId()),
		PackageVersion:          p.Version,
		PackageChecksums:        []common.Checksum{{Algorithm: common.SHA256, Value: p.SHA256}},
		PackageDownloadLocation: "NOASSERTION",
		FilesAnalyzed:           false,
		PackageComment:          "This package includes one or more slice(s); see Relationship information.",
		PackageSupplier:         &UbuntuPackageSupplier,
		PackageExternalReferences: []*spdx.PackageExternalReference{
			{
				Category: "SECURITY",
				RefType:  "cpe23Type",
				Locator:  p.CPE23Locator(),
			},
			{
				Category: "PACKAGE_MANAGER",
				RefType:  "purl",
				Locator:  p.PurlLocator(),
			},
		},
	}

	rln := &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", p.SPDXId()),
		Relationship: "DESCRIBES",
	}

	return pkg, rln, nil
}

func (s *SliceInfo) buildSliceSection() (*spdx.Package, *spdx.Relationship, error) {
	packageName := strings.Split(s.Name, "_")[0]

	pkg := &spdx.Package{
		PackageName:             s.Name,
		PackageSPDXIdentifier:   common.ElementID(s.SPDXId()),
		PackageDownloadLocation: "NOASSERTION",
		FilesAnalyzed:           false,
		PackageComment:          fmt.Sprintf("This slice is a sub-package of the package %s; see Relationship information.", packageName),
	}

	packageInfo := PackageInfo{
		Name: packageName,
	}
	rln := &spdx.Relationship{
		RefA:         common.MakeDocElementID("", packageInfo.SPDXId()),
		RefB:         common.MakeDocElementID("", s.SPDXId()),
		Relationship: "CONTAINS",
	}

	return pkg, rln, nil
}

const (
	FileReg int = iota
	FileMod
	FileLnk
	FileHlk
)

var fileComments = map[int]string{
	FileReg: "This file is included in the slice(s) %s; see Relationship information.",
	FileMod: "This file is mutated by the slice %s; see Relationship information.",
	FileLnk: "This file is a symlink to the file %s.",
	FileHlk: "This file is within the hard link group %d; files in the same hard link group are alias of each other.",
}

func (f *PathInfo) buildPathSection() (*spdx.File, []*spdx.Relationship, error) {
	var rln []*spdx.Relationship
	sha256 := f.SHA256
	if f.FinalSHA256 != "" {
		sha256 = f.FinalSHA256
	}
	var fileType int
	file := &spdx.File{
		FileName:           f.Path,
		FileSPDXIdentifier: common.ElementID(f.SPDXId()),
		Checksums:          []common.Checksum{{Algorithm: common.SHA256, Value: sha256}},
		FileCopyrightText:  "NOASSERTION",
	}

	// Determine the file type
	// File type  |  Inode  |  Link  |  FinalSHA256  |       SHA256
	// ------------------------------------------------------------------
	// Regular    |    0    |   ""   |       ""      |       != ""
	// Modified   |    0    |   ""   |      != ""    |     (omitted)
	// Link       |    0    |  != "" |       ""      |       == ""
	// Hard link  |   != 0  |   ""   |       ""      |     (omitted)
	// ------------------------------------------------------------------
	// Note: The rest of the cases are invalid
	if f.FinalSHA256 == "" {
		if f.Inode > 0 && f.Link != "" {
			return nil, nil, fmt.Errorf("cannot build file section: invalid file type: file %s simultaneously has inode %d and link %s", f.Path, f.Inode, f.Link)
		}
		if f.Inode > 0 && f.Link == "" {
			fileType = FileHlk
		} else if f.Inode == 0 && f.Link != "" {
			fileType = FileLnk
		} else if f.Inode == 0 && f.Link == "" {
			fileType = FileReg
		}
	} else {
		if f.Inode > 0 || f.Link != "" {
			return nil, nil, fmt.Errorf("cannot build file section: invalid link: link %s has a final sha256", f.Path)
		}
		fileType = FileMod
	}

	slices := strings.Join(f.Slices, ", ")

	switch fileType {
	case FileReg:
		file.FileComment = fmt.Sprintf(fileComments[fileType], slices)
		rln = createFileAllRln(f, "CONTAINS", false)
	case FileMod:
		file.FileComment = fmt.Sprintf(fileComments[fileType], slices)
		rln = createFileAllRln(f, "FILE_MODIFIED", true)
	case FileLnk:
		file.FileComment = fmt.Sprintf(fileComments[fileType], f.Link)
		rln = createFileAllRln(f, "CONTAINS", false)
	case FileHlk:
		file.FileComment = fmt.Sprintf(fileComments[fileType], f.Inode)
		rln = createFileAllRln(f, "CONTAINS", false)
	default:
		return nil, nil, fmt.Errorf("internal error: invalid file type")
	}

	return file, rln, nil
}

var fileRlnComments = map[string]string{
	"CONTAINS":      "File %s is included in the slice %s.",
	"FILE_MODIFIED": "File %s is mutated by the slice %s.",
}

func createFileAllRln(file *PathInfo, rel string, reverseRel bool) []*spdx.Relationship {
	rln := []*spdx.Relationship{}
	for _, s := range file.Slices {
		slice := &SliceInfo{Name: s}
		refA := common.MakeDocElementID("", slice.SPDXId())
		refB := common.MakeDocElementID("", file.SPDXId())
		if reverseRel {
			refA, refB = refB, refA
		}
		rln = append(rln, &spdx.Relationship{RefA: refA,
			RefB:                refB,
			Relationship:        rel,
			RelationshipComment: fmt.Sprintf(fileRlnComments[rel], file.Path, s),
		})
	}
	return rln
}
