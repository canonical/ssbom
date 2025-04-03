# The Chisel SBOM Exporter

This project generates a Software Bill of Materials (SBOM) for Chisel projects.
The SBOM is generated in the SPDX format using the metadata from the Chisel 
[jsonwall](https://pkg.go.dev/github.com/canonical/chisel/public/jsonwall) manifest.

## Usage
### Build

To build the project, run the following command:

```bash
go build ./cmd/ssbom
```

### Install

Install with `go install`:

```bash
go install github.com/canonical/ssbom/cmd/ssbom@latest
```

Install with snap:
```bash
snap install ssbom --classic
```

### Run

If built with `go build`:

```bash
./ssbom <path-to-chiselled-rootfs> [<spdx-file-out>]
```

If installed with `go install` or snap:

```bash
ssbom <path-to-chiselled-rootfs> [<spdx-file-out>]
```

**NOTE:** If there is no output file specified, the SBOM will be generated to a `manifest.spdx.json` file
in the current working directory.

### Integration with trivy

This tools also provides a script to run [`trivy`](https://github.com/aquasecurity/trivy) on the generated SBOM. To use this, run the following command:

If installed with `go install`:

```bash
./scripts/ssbom-trivy <path-to-chiselled-rootfs> [<extra-trivy-args>]
```

If installed with snap:

```bash
ssbom.trivy <path-to-chiselled-rootfs> [<extra-trivy-args>]
```

### Test
```bash
go test ./...
```
