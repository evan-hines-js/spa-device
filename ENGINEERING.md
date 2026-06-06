# CLAUDE.md — spa-device

Single-Packet Authorization + Port Cloaking. A host-resident, line-rate gate that
makes any configured TCP/UDP service network-invisible until a client proves
authorization with one authenticated, encrypted packet. See `DESIGN.md` for the
full architecture; this file is the working contract.

## Prime directive: auditable, minimal, no bloat

This is security infrastructure for defense-grade deployments. Every line is
attack surface and every line must be readable by an auditor who is not us.

- **Least code that fully does the job.** Fewer lines, fewer branches, fewer
  dependencies. If a feature isn't in `DESIGN.md`, it doesn't get written.
- **Complexity is a defect.** Prefer a flat, obvious implementation over a clever
  or generic one. No speculative abstraction, no "might need it later," no
  config knobs nobody asked for. YAGNI is a hard rule here, not a suggestion.
- **Every dependency is a liability.** Justify each crate; prefer the std lib;
  prefer one well-audited crate over three convenient ones. The crypto comes from
  `aws-lc-rs` (FIPS) — do not add a second crypto stack.
- **Readable beats short.** Minimal does NOT mean golfed or dense. Clear names,
  early returns, small functions. An auditor should follow the packet's path
  without a debugger.
- **No dead code, no TODO stubs left in.** If it isn't implemented, it isn't
  merged. Delete commented-out code.
- When a change adds net lines or a dependency, say why in the PR/commit. Default
  answer to "should I add this?" is no.

## What it is / boundary discipline

- `spa-device` is a **standalone product**. It cloaks ports and reads authorized
  keys from a pluggable trust backend. It knows NOTHING about any consumer.
- A larger mesh ZTN VPN consumes it via the **external-authorizer trust backend**
  (`DESIGN.md` §6) — that is the only seam. **Never** import mesh/overlay code,
  Ziti SDKs, or any consumer's types into these crates. If `spa-device` grows a
  dependency on its consumer, the product is broken.
- The protected service is unmodified and unaware. The gate never parses
  application protocol (no TLS parsing, no app logic) — it only decides
  reachability.

## Stack

All-Rust, one memory-safe language across the entire untrusted-input path.

- `aya` — eBPF/XDP + TC data plane and loader (pure Rust, no C, no libbpf).
- `aws-lc-rs` — the ONLY crypto. FIPS suite default (P-256 / AES-256-GCM /
  ECDSA), Modern suite (X25519 / ChaCha20-Poly1305 / Ed25519) selectable.
- `rustls` / `reqwest` — only for the external-authorizer trust backend (mTLS to
  a system of record). Not used anywhere on the packet fast path.

## Workspace

```
spa-common/   wire format, crypto, shared types. no_std-compatible where shared with eBPF.
spa-ebpf/     aya XDP + TC programs (kernel). The data plane.
spa-device/   verification daemon + trust backends (userland, protected host).
spa-client/   knock library + CLI + sidecar (userland, client host).
```

The kernel↔userland interface is **pinned BPF maps** only. The wire format and
maps are versioned contracts — changing them is a breaking change, treat as such.

## Build reality

- **This dev host is macOS (arm64). eBPF builds and runs on Linux only.** The
  userland crates (`spa-common`, `spa-device`, `spa-client`) build and test
  natively here. `spa-ebpf` targets `bpfel-unknown-none` and is built/run on
  Linux (CI container or VM). `bpf-linker` is installed; the linux x86_64 std
  target is present.
- Do not break the macOS build of the userland crates. Gate Linux-only code
  (`aya` runtime, map I/O) behind the target so `cargo build`/`cargo test` of the
  userland crates stays green on the dev host.

## Conventions

- `cargo fmt` + `cargo clippy -- -D warnings` clean before any commit.
- Tests live with the code; the wire format and crypto get unit tests with known
  vectors. Untrusted-input parsers (packet, payload) get fuzz/round-trip tests.
- No `unwrap()`/`expect()`/`panic!` on any path that touches untrusted input or
  network data — parse defensively, return errors. Bounds-check before every
  slice into a packet.
- Constant-time compares for all secret/MAC comparisons (use the crypto crate's
  primitives, never `==`).
- Fail closed on reachability; established flows are handled per `DESIGN.md` §7.
- Commit messages and PRs state what changed and why; flag any net-new lines or
  dependencies.

## Non-goals (do not build)

- Not an identity system, not a replacement for the service's own auth — a
  reachability gate that runs in front of it.
- No second crypto library, no plugin system beyond the trust-backend trait, no
  general-purpose config framework. Match `DESIGN.md` scope exactly.
