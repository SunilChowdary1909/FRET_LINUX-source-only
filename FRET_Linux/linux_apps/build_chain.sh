#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Building chain_mtx..."
podman run --rm --network host \
    -v "$SCRIPT_DIR:/work" -w /work \
    ubuntu:24.04 \
    bash -c 'apt-get update -qq && \
             DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-aarch64-linux-gnu > /dev/null 2>&1 && \
             aarch64-linux-gnu-gcc -static -O2 -pthread -o bin/chain_mtx chain_mtx.c -lrt'
echo "Build complete."
