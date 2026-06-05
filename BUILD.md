# Building

## Userland crates (`spa-common`, `spa-core`, `spa-crypto`, `spa-ebpf-common`)

Build and test anywhere, including the macOS dev host:

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

(`spa-ebpf` is excluded from the workspace — see below.)

## The eBPF data plane (`spa-ebpf`) — Linux build host only

eBPF compiles and runs on Linux only. We use a remote build host; sync with
`./rsync.sh` (edit the destination at the top).

### Build-host toolchain (one-time)

```
# rustup with nightly + rust-src (for build-std=core on the BPF target)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
  --profile minimal --default-toolchain nightly
rustup component add rust-src --toolchain nightly

# bpf-linker MUST use the LLVM that ships with the Rust toolchain (it has to
# match rustc's LLVM exactly, or it can't read rustc's bitcode). Install it with
# a CLEAN env — no LLVM_SYS_*_PREFIX, no system llvm-config in PATH — so it builds
# with aya-rustc-llvm-proxy against the toolchain LLVM instead of a system one:
cargo install bpf-linker
```

### LLVM linker-script workaround

The proxy `dlopen`s `libLLVM-<major>-rust-<ver>.so` from the toolchain `lib/`, but
on current nightlies that file is a **GNU ld linker script** (`INPUT(...)`), which
`dlopen` cannot load — you'll see `unable to open LLVM shared lib ... dlopen
failed`. Symlink the name to the real shared object:

```
cd ~/.rustup/toolchains/nightly-*/lib
# adjust versions to match what's there (see: ls libLLVM*)
ln -sf libLLVM.so.22.1-rust-1.98.0-nightly libLLVM-22-rust-1.98.0-nightly.so
```

Re-apply after a toolchain update if the warning returns.

### Build

```
cd spa-ebpf && cargo build --release
# -> target/bpfel-unknown-none/release/spa-gate   (BPF ELF)
```

### Validating the object

`spa-gate` uses aya's legacy `maps` section, so **`bpftool`/libbpf reject it**
(`legacy map definitions ... not supported by libbpf v1.0+`) — that is expected,
not a fault. Validate by **loading it with aya** (the loader/daemon), never with
bpftool.

## Release artifacts

The gate can't be built on macOS, so a deploy fetches **prebuilt** artifacts
rather than building on the target. `scripts/build-gate-release.sh` (run on a
Linux build host, or in CI) produces them under `dist/`:

- `spa-gate.o` — the XDP BPF object. eBPF bytecode is **CPU-arch independent**, so
  one object serves every little-endian arch.
- `spa-gated-<arch>-unknown-linux-gnu` — the daemon binary, one per arch.
- `SHA256SUMS` — checksums.

`.github/workflows/release.yml` runs that script on a `v*` tag and uploads the
artifacts as GitHub release assets; the control plane's deploy role fetches them
from there (no target-side build).
