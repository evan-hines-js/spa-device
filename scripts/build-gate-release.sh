#!/usr/bin/env bash
# Build the prebuilt gate artifacts for a release (run on a Linux eBPF build host;
# see BUILD.md for the nightly + bpf-linker toolchain). The gate can't be built on
# macOS, so this host (or CI) produces what the control plane's deploy role fetches.
#
# Produces, under dist/:
#   spa-gate.o                          the XDP BPF object (CPU-arch independent)
#   spa-gated-<arch>-unknown-linux-gnu  the gate daemon binary for this host's arch
#   SHA256SUMS                          checksums of the above
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIPLE="$(uname -m)-unknown-linux-gnu"
DIST="$ROOT/dist"

echo "== build BPF object (spa-ebpf, release) =="
( cd "$ROOT/spa-ebpf" && cargo build --release )

echo "== build gate daemon (spa-gated, release, $TRIPLE) =="
( cd "$ROOT/spa-gated" && cargo build --release )

rm -rf "$DIST"
mkdir -p "$DIST"
cp "$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate" "$DIST/spa-gate.o"
cp "$ROOT/spa-gated/target/release/spa-gated" "$DIST/spa-gated-$TRIPLE"
( cd "$DIST" && sha256sum spa-gate.o "spa-gated-$TRIPLE" > SHA256SUMS )

echo "== dist =="
ls -l "$DIST"
cat "$DIST/SHA256SUMS"
