package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"github.com/canonical/ssbom/internal/converter"
	"github.com/spdx/tools-golang/json"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args
	if len(args) != 2 && len(args) != 3 {
		fmt.Printf("Usage: %v <path-to-manifest.wall> [<spdx-file-out>]\n", args[0])
		fmt.Printf("  Build a SPDX document with the chisel jsonwall manifest;\n")
		fmt.Printf("  and save it out as a json file to <spdx-file-out> if specified;\n")
		fmt.Printf("  otherwise a manifest.spdx.json in the same directory as the manifest.wall.\n")
		return nil
	}

	// get the command-line arguments
	manifest := args[1]
	var outPath string
	var fileOut *os.File

	if len(args) == 3 {
		outPath = args[2]
	} else {
		outPath = filepath.Join(filepath.Dir(manifest), "manifest.spdx.json")
	}
	fileOut, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer fileOut.Close()

	fileReader, err := os.Open(manifest)
	if err != nil {
		return err
	}
	defer fileReader.Close()
	zstdReader, err := zstd.NewReader(fileReader)
	if err != nil {
		return err
	}
	defer zstdReader.Close()

	doc, err := converter.Convert(zstdReader)
	if err != nil {
		return err
	}

	json.Write(doc, fileOut)
	fmt.Printf("SPDX document created at %v\n", outPath)
	return nil
}
