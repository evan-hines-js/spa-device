# spa-device

**Single-Packet Authorization + port cloaking.** A host-resident, line-rate gate
that makes a TCP/UDP service *invisible* on the network until a client proves
authorization with one signed, encrypted packet.

Until a valid knock arrives, protected ports are dropped in the NIC driver
(`XDP_DROP`) — no `RST`, no banner, no response. A port scanner can't tell the
port (or the host) exists. A single authenticated UDP packet then opens it, for
that source only, for a fraction of a second; the established connection persists
via conntrack. It's the modern successor to port knocking: one packet instead of
a sequence, real authenticated encryption instead of a guessable knock, and an
in-kernel data path that holds up under load.

```
scanner ─────────────────────────► [ XDP_DROP ]            (nothing exists)
client ── signed/encrypted knock ─► [ gate verifies ] ─► port opens ─► your service's own auth ─► access
```

The gate authenticates *reachability*; the service behind it still does its own
authentication. spa-device runs *in front of* SSH, a database, an admin panel, or
an overlay-network router — never instead of their auth. Defense in depth.

Built in Rust + eBPF/XDP, FIPS-capable (`aws-lc-rs`), memory-safe on every
untrusted-input path (the one `unsafe` corner — the XDP program — is confined and
proven by the kernel verifier).

## How it works

- **Knock** — `version | suite | ephemeral_pubkey | AEAD(authorization)`. The
  client does an ephemeral ECDH to the gate's public key, derives a per-packet
  AEAD key, and encrypts an authorization signed by its identity key. Only the
  gate can decrypt it; the signature says *which* client; the payload binds the
  gate id, requested ports, a nonce, and a timestamp. The packet is opaque on the
  wire — indistinguishable from noise.
- **Gate** — an XDP program cloaks the protected ports and consults a kernel
  allow-list; a userland daemon verifies knocks and programs that allow-list. A
  fixed-window rate limit and a size pre-filter drop floods/junk *in-kernel*
  before any crypto cost.
- **Trust** — clients are authorized by their 32-byte key thumbprint
  (`SHA-256(public key)`), supplied either inline or in a **signed config
  bundle** (hot-reloaded, anti-rollback, verified against a pinned anchor).
- **Fail closed** — a base `nftables` floor keeps protected ports shut even if
  the daemon is killed and XDP detaches.

Two cipher suites, selectable per gate:

| Suite | ECDH | AEAD | Signature |
|---|---|---|---|
| `fips` | P-256 | AES-256-GCM | ECDSA P-256 |
| `modern` | X25519 | ChaCha20-Poly1305 | Ed25519 |

Both IPv4 and IPv6 are cloaked through one unified data path.

## Layout

```
spa-common        wire format (dependency-free, forbid(unsafe))
spa-core          the pure decision core — ports/adapters, no crypto, no I/O
spa-crypto        signcryption envelope + keys (aws-lc-rs)
spa-ebpf-common   POD map types shared with the kernel
spa-ebpf          the XDP data plane (Linux/BPF target)
spa-gated         the gate daemon (Linux): loader, maps, knock loop, nft, audit
spa-client        the knock client + dev keygen/enrollment/bundle tooling
```

The gate (`spa-ebpf` + `spa-gated`) is **Linux-only**. The client and the library
crates build anywhere.

## Build

Userland crates build and test on any host:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The eBPF data plane (`spa-ebpf`) and the daemon (`spa-gated`) build on a Linux
host — see **[BUILD.md](BUILD.md)** for the nightly + `bpf-linker` toolchain.

## Quick start

Generate a gate key + a client key (Modern suite by default; `fips` for FIPS):

```sh
spa-client keygen demo            # -> demo.gate.toml (gate) + demo.knock (client)
```

Write the daemon config, appending the generated gate crypto:

```sh
cat > gated.toml <<EOF
interface       = "eth0"
knock_port      = 62201
bpf_object      = "/path/to/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"
pinhole_ms      = 400
skew_seconds    = 2
protected_ports = [22]
EOF
cat demo.gate.toml >> gated.toml   # suite, gate key, and the [[client]] entry
```

Run the gate (needs root for XDP + nftables):

```sh
sudo spa-gated gated.toml
```

Port 22 is now dark. To reach it, knock first:

```sh
spa-client knock <gate-host>:62201 demo.knock && ssh user@<gate-host>
```

The daemon emits a JSON audit line per decision:

```json
{"event":"knock","ts_ms":...,"source":"...","outcome":"open","ports":[22]}
```

## Embedding the client (library)

`spa-client` is a library as well as a CLI — call it from your application to
knock before you dial, instead of shelling out:

```rust
use spa_client::Knocker;

// Provisioned out of band (enrollment/config), or loaded from a keygen file:
let knocker = Knocker::new(suite, gate_pubkey, gate_id, &client_pkcs8)?;
knocker.knock("gate.example:62201", &[22])?;   // port 22 is now reachable from us
// ...now open your connection as usual...
```

`Knocker::from_knock_file()` is a convenience for the keygen file format;
`Enroller` does the one-time-token bootstrap. The library is cross-platform (no
eBPF); only the gate is Linux-only.

## Config reference (`gated.toml`)

| Key | Meaning |
|---|---|
| `interface` | NIC to attach XDP to |
| `knock_port` | UDP port the knock arrives on |
| `bpf_object` | path to the compiled `spa-gate` BPF ELF |
| `suite` | `"fips"` or `"modern"` |
| `gate_private_hex` | the gate's 32-byte private key |
| `gate_id_hex` | 16-byte gate identity (anti-relay) |
| `protected_ports` | TCP ports to cloak |
| `pinhole_ms` / `skew_seconds` | grant window / knock timestamp tolerance |
| `nftables_floor` | install the fail-closed floor (default `true`) |
| `[[client]]` | authorized clients: `thumbprint_hex`, `public_key_hex`, `ports` |
| `[[token]]` | one-time PSK enrollment tokens: `token_id_hex`, `secret_hex`, `ports` |
| `config_anchor_hex` + `bundle_path` | use a **signed bundle** for clients/ports instead of inline |

### Signed bundles & enrollment

```sh
spa-client gen-anchor cp                       # control-plane signing key (pin cp pubkey)
spa-client sign-bundle cp.anchor.key policy.toml policy.bundle
spa-client gen-token tok                        # one-time PSK enrollment token
spa-client enroll-knock <host>:62201 demo.knock tok.enroll
```

A signed bundle carries a monotonic `generation`, the protected ports, and the
authorized clients; the daemon verifies it against the pinned anchor and
hot-reloads it (older generations are refused). A one-time token authenticates a
single PSK knock — the canonical bootstrap for an endpoint that has no registered
key yet — and is burned on use.

## Status

Implemented and tested end-to-end: cloaking (both suites, IPv4 + IPv6), conntrack
handoff, fail-closed floor, signed config bundles, in-kernel DoS hygiene,
single-use PSK enrollment, and JSON audit logging. Eight end-to-end suites under
[`scripts/`](scripts/) plus the unit tests all pass.

Not yet done (non-core): XDP fast-pathing of IPv6 *extension-header* packets
(today correctly handled by the nftables floor), graceful detach, and
key-rotation tooling.

## Docs

- **[DESIGN.md](DESIGN.md)** — architecture, wire format, crypto, config, threat
  model, fail-closed posture.
- **[BUILD.md](BUILD.md)** — the Linux/eBPF build toolchain.
- **[CLAUDE.md](CLAUDE.md)** — the engineering contract (auditable, minimal, no
  bloat).
