# The Chisel SBOM Exporter

This project generates a Software Bill of Materials (SBOM) for Chisel projects.
The SBOM is generated in the SPDX format using the metadata from the Chisel 
[jsonwall](https://pkg.go.dev/github.com/canonical/chisel/public/jsonwall) manifest.

## Usage
### Build

To build the project, run the following command:
```bash
go build ./cmd/chisel-sbom
```

### Run

```
./chisel-sbom /path/to/manifest.wall [/path/to/output.spdx.json]
```

If there is no output file specified, the SBOM will be generated to a `manifest.spdx.json` file
in the same directory of the `manifest.wall` file.
