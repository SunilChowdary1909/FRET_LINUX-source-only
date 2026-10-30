#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/bin"
mkdir -p "$OUTPUT_DIR"
podman run --rm --network host \
    -v "$SCRIPT_DIR:/work" -w /work \
    ubuntu:24.04 \
    bash -c 'apt-get update -qq && \
             DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-aarch64-linux-gnu > /dev/null 2>&1 && \
             aarch64-linux-gnu-gcc -static -O2 -o bin/periodic_mtx_v2 periodic_mtx.c -lpthread'
ls -lh bin/periodic_mtx_v2
