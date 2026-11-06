package main

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestReadOSRelease(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		id      string
		version string
	}{
		{name: "complete", content: "ID=ubuntu\nVERSION_ID=\"24.04\"\n", id: "ubuntu", version: "24.04"},
		{name: "without version", content: "ID=ubuntu\n", id: "ubuntu"},
		{name: "without ID", content: "VERSION_ID=\"24.04\"\n", version: "24.04"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := fstest.MapFS{osReleasePath: {Data: []byte(test.content)}}
			id, version, err := ReadOSRelease(root)
			if err != nil {
				t.Fatal(err)
			}
			if id != test.id || version != test.version {
				t.Fatalf("got ID %q and VERSION_ID %q, want %q and %q", id, version, test.id, test.version)
			}
		})
	}

	_, _, err := ReadOSRelease(fstest.MapFS{})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing os-release: got %v, want fs.ErrNotExist", err)
	}
}
