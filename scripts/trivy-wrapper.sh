#!/bin/sh

# This script uses ssbom to generate a spdx json SBOM, and runs trivy to scan
# for vulnerabilities upon this generated SBOM.

if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
    echo "Usage: $0 <path-to-chiselled-rootfs> [<extra-trivy-args>]"
    exit 1
fi

sbom_dir=$(mktemp -d)
sbom_file="$sbom_dir/spdx.json"
chiselled_rootfs=$1
shift 1

# Generate SBOM
ssbom $chiselled_rootfs $sbom_file

# Run trivy
trivy sbom $@ $sbom_file
