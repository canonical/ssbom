package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/canonical/ssbom/internal/converter"
	"github.com/go-ini/ini"
	"github.com/klauspost/compress/zstd"
	"github.com/spdx/tools-golang/json"
)

const manifestPath = "var/lib/chisel/manifest.wall"
const osReleasePath = "etc/os-release"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args
	if len(args) != 2 && len(args) != 3 {
		fmt.Printf("Usage: %v <path-to-chiselled-rootfs> [<spdx-file-out>]\n", args[0])
		fmt.Printf("  Build an SPDX document with the chisel jsonwall manifest\n")
		fmt.Printf("  and save it out as a json file to <spdx-file-out> if specified;\n")
		fmt.Printf("  otherwise as manifest.spdx.json in the current working directory.\n")
		return nil
	}

	// get the command-line arguments
	root := args[1]
	var outPath string
	var fileOut *os.File

	if len(args) == 3 {
		outPath = args[2]
	} else {
		if cwd, err := os.Getwd(); err != nil {
			return err
		} else {
			outPath = filepath.Join(cwd, "manifest.spdx.json")
		}
	}

	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootDir.Close()

	rootFS := rootDir.FS()
	fileReader, err := rootFS.Open(manifestPath)
	if err != nil {
		return err
	}
	defer fileReader.Close()
	zstdReader, err := zstd.NewReader(fileReader)
	if err != nil {
		return err
	}
	defer zstdReader.Close()

	osId, versionId, err := ReadOSRelease(rootFS)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Warning: OS release file not found in the chiselled rootfs.")
			fmt.Println("         The generated SBOM will be incomplete for vulnerability identification.")
		} else {
			return err
		}
	}

	doc, err := converter.Convert(zstdReader, rootFS, osId, versionId)
	if err != nil {
		return err
	}

	fileOut, err = os.Create(outPath)
	if err != nil {
		return err
	}
	defer fileOut.Close()

	json.Write(doc, fileOut, json.EscapeHTML(false))
	fmt.Printf("SPDX document created at %v\n", outPath)
	return nil
}

func ReadOSRelease(root fs.FS) (string, string, error) {
	data, err := fs.ReadFile(root, osReleasePath)
	if err != nil {
		return "", "", err
	}
	cfg, err := ini.Load(data)
	if err != nil {
		return "", "", err
	}

	versionId := cfg.Section("").Key("VERSION_ID").String()
	osId := cfg.Section("").Key("ID").String()

	return osId, versionId, nil
}
