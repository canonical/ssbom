package converter

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/canonical/chisel/public/jsonwall"
	"github.com/canonical/chisel/public/manifest"
	"github.com/canonical/ssbom/internal/builder"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

// Convert converts a JSONWall and its root filesystem to an SPDX document.
func Convert(reader io.Reader, root fs.FS, name, distro string) (*spdx.Document, error) {
	db, err := jsonwall.ReadDB(reader)
	if err != nil {
		return nil, fmt.Errorf("cannot read manifest: %s", err)
	}

	manifestData := &ManifestData{Distro: distro}
	for _, fn := range updateFunctions {
		fn(db, manifestData)
	}

	sliceInfos := manifestData.ProcessSlices()
	packageInfos := manifestData.ProcessPackages()
	pathInfos := manifestData.ProcessPaths()
	for i := range pathInfos {
		path := &pathInfos[i]
		checksums, err := fileChecksums(root, strings.TrimPrefix(path.Path, "/"))
		if err != nil {
			return nil, fmt.Errorf("cannot checksum %s: %w", path.Path, err)
		}
		path.Checksums = checksums
	}

	doc, err := builder.BuildSPDXDocument(name, distro, &sliceInfos, &packageInfos, &pathInfos)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func fileChecksums(root fs.FS, path string) ([]common.Checksum, error) {
	info, err := fs.Lstat(root, path)
	if err != nil {
		return nil, err
	}

	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	hashes := io.MultiWriter(sha1Hash, sha256Hash)
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		// A symlink stores its target path, which may be dangling or outside the root.
		target, err := fs.ReadLink(root, path)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(hashes, target); err != nil {
			return nil, err
		}
	case info.Mode().IsRegular():
		file, err := root.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if _, err := io.Copy(hashes, file); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported file type %s", info.Mode().Type())
	}

	return []common.Checksum{
		{Algorithm: common.SHA1, Value: fmt.Sprintf("%x", sha1Hash.Sum(nil))},
		{Algorithm: common.SHA256, Value: fmt.Sprintf("%x", sha256Hash.Sum(nil))},
	}, nil
}

type ManifestData struct {
	Packages []manifest.Package
	Slices   []manifest.Slice
	Paths    []manifest.Path
	Content  []manifest.Content
	Distro   string
}

func (md *ManifestData) ProcessSlices() []builder.SliceInfo {
	var sliceInfos []builder.SliceInfo
	for _, s := range md.Slices {
		var sliceInfo builder.SliceInfo
		sliceInfo.Name = s.Name
		sliceInfos = append(sliceInfos, sliceInfo)
	}
	return sliceInfos
}

func (md *ManifestData) ProcessPackages() []builder.PackageInfo {
	var packageInfos []builder.PackageInfo
	for _, p := range md.Packages {
		var packageInfo builder.PackageInfo
		packageInfo.Name = p.Name
		packageInfo.Version = p.Version
		packageInfo.SHA256 = p.Digest
		packageInfo.Arch = p.Arch
		packageInfo.Distro = md.Distro
		packageInfos = append(packageInfos, packageInfo)
	}
	return packageInfos
}

func (md *ManifestData) ProcessPaths() []builder.PathInfo {
	var pathInfos []builder.PathInfo
	for _, p := range md.Paths {
		if strings.HasSuffix(p.Path, "/") {
			continue
		}
		var pathInfo builder.PathInfo
		pathInfo.Path = p.Path
		pathInfo.Mode = p.Mode
		pathInfo.Slices = p.Slices
		pathInfo.FinalSHA256 = p.FinalSHA256
		pathInfo.Link = p.Link
		pathInfo.Inode = p.Inode
		pathInfos = append(pathInfos, pathInfo)
	}
	return pathInfos
}

type prefixable interface {
	manifest.Path | manifest.Content | manifest.Package | manifest.Slice
}

func iteratePrefix[T prefixable](db *jsonwall.DB, prefix *T, store *[]T) error {
	iter, err := db.IteratePrefix(prefix)
	if err != nil {
		return err
	}
	for iter.Next() {
		var val T
		err := iter.Get(&val)
		if err != nil {
			return fmt.Errorf("cannot read manifest: %s", err)
		}
		*store = append(*store, val)
	}
	return nil
}

type updFnType func(db *jsonwall.DB, data *ManifestData) error

var updateFunctions = []updFnType{
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Package{Kind: "package"}, &data.Packages)
	},
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Slice{Kind: "slice"}, &data.Slices)
	},
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Path{Kind: "path"}, &data.Paths)
	},
	func(db *jsonwall.DB, data *ManifestData) error {
		return iteratePrefix(db, &manifest.Content{Kind: "content"}, &data.Content)
	},
}
