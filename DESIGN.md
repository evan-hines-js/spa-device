# spa-device — Single-Packet Authorization + Port Cloaking

**A host-resident, line-rate gate that makes any TCP/UDP service network-invisible
until a client proves authorization with one authenticated packet.**

- **Stack:** all-Rust — `aya` (eBPF/XDP + TC), `aws-lc-rs` (FIPS 140-3 crypto),
  `rustls`/`reqwest` (external trust sources)
- **Target:** enterprise / defense-industry deployments requiring memory-safe,
  FIPS-validated, certifiable network infrastructure

---

## 1. Problem statement

Every listening socket is a bright attack surface. The moment a service binds a
port — SSH, a database, a web admin panel, a VPN concentrator, an overlay-network
router — anyone with network reachability can scan it, fingerprint its stack,
flood it, or wait to exploit a future CVE in its pre-authentication code path.
Application-layer authentication (TLS, mTLS, passwords, zero-trust overlays) only
engages *after* the packet has already reached that vulnerable code.

**spa-device removes the reachability.** Protected ports are dropped in the NIC
driver for everyone (`XDP_DROP` — no RST, no ICMP, no banner: true silence). A
client reveals a port only by first sending a single cryptographically
authenticated packet. The protected service authenticates *connections*;
spa-device authenticates *reachability itself*, beneath it.

```
Unauthorized scanner ─► [XDP_DROP] ✗        (nothing answers — the port does not appear to exist)
Authorized client    ─► SPA packet ─► [gate opens for this source] ─► normal service handshake ─► service auth ─► access
```

This is the modern successor to port knocking: one packet instead of a sequence,
real authenticated encryption instead of a guessable knock, and an in-kernel data
path that holds up at line rate under load.

---

## 2. Core model

spa-device protects an arbitrary, configured set of **(protocol, port)** endpoints
on its host. It is a generic gate; it knows nothing about the application behind
the port. Three cooperating components:

| Component | Where | Role |
|---|---|---|
| `spa-ebpf` | router/server host, kernel | XDP cloak + TC flow-tracking data plane |
| `spa-device` | router/server host, userland | verifies SPA packets, programs the gate, sources trust |
| `spa-client` | client host, userland | builds + sends the SPA packet (library + CLI + sidecar) |

The kernel↔userland interface is a set of **pinned BPF maps**: the daemon writes
authorizations, the data plane reads them.

The service being protected is **unmodified and unaware**. spa-device is a sidecar
to *anything*: you point it at the ports you want dark.

---

## 3. Architecture

### 3.1 Data plane — `spa-ebpf`

Two attach points on the protected host's relevant interface(s):

**XDP (ingress, native/driver mode preferred, generic fallback):** for every
inbound IPv4/IPv6 packet:

1. **Packet to a protected port:**
   - belongs to an **established flow** (conntrack lookup) → `XDP_PASS`;
   - else source holds a **valid unexpired authorization** → `XDP_PASS` (this is
     what admits the connection's first `SYN`);
   - else → **`XDP_DROP`** (silent).
2. **Packet to the SPA knock port:** cheap in-kernel pre-filter (length bounds,
   per-source token-bucket rate limit) then `XDP_PASS` to the daemon. The knock
   port is the only reachable surface, so it is rate-limited in-kernel *before*
   any userland crypto runs — a flood cannot induce verification work.
3. **Everything else:** `XDP_PASS`.

**TC / conntrack (flow persistence):** the authorization pinhole is deliberately
sub-second (§5). To let *established* connections outlive it, the data path
consults kernel connection tracking (`bpf_ct_lookup`, requires `nf_conntrack`).
The pinhole admits the `SYN`; conntrack then recognizes every subsequent packet of
that flow as `ESTABLISHED` and passes it — even after the pinhole has slammed shut.
Hosts without conntrack fall back to a pinned established-4-tuple map populated by
a companion TC hook on the first observed `SYN-ACK`. **Conntrack is the supported
path; `nf_conntrack` is a documented deployment prerequisite.**

**Maps:**
- `authorizations`: `LRU_HASH`, key = source address (+ optional scope), value =
  `{ expiry_ns, allowed_ports, flags }`. LRU bounds memory under abuse.
- `protected_ports`: config of which (proto, port) tuples are cloaked.
- `static_rules`: break-glass allow/deny CIDRs (§7).
- `ratelimit`: per-source token buckets for the knock port.

### 3.2 Verification daemon — `spa-device`

Userland, on the protected host. Reads knock packets from the knock port,
verifies them (§4), and on success writes an authorization for the **post-NAT
source the host actually observed**, scoped to the requested ports, with a short
expiry. Reaps expired entries defensively. Sources and refreshes trust material
from a pluggable backend (§6). Emits structured audit telemetry over a side
channel (§9) without ever responding on the wire.

### 3.3 Client — `spa-client`

A Rust **library** with a thin **CLI** and a **sidecar** wrapper. The library is
the integration surface: any application can call `spa_client::knock(target,
services)` before it dials. The sidecar wrapper (`knock then exec <command>`)
covers everything that can't be recompiled — it sends the packet, waits for the
sub-second handoff, and `exec`s the real client. Stateless.

### 3.4 Workspace

```
spa-device/                cargo workspace
├── spa-common/   wire format, crypto, shared types (no_std-compatible where shared with eBPF)
├── spa-ebpf/     aya XDP + TC programs (kernel)
├── spa-device/   verification daemon + trust backends (userland, host)
└── spa-client/   knock library + CLI + sidecar (userland, client)
```

All-Rust end to end: one memory-safe language across the entire untrusted-input
path (raw packets and SPA payloads), no hand-written C on the exposed surface, one
supply chain to vendor and audit for accreditation.

---

## 4. Authentication & confidentiality

The SPA packet must resist **forgery**, **replay**, **relay** (a captured packet
reused against a different gate or for a different port), and **inspection** (the
packet itself must not reveal that it is an SPA knock, or to whom). spa-device
therefore *encrypts and authenticates* the knock — it is opaque on the wire.

### 4.1 Scheme (signcryption)

The gate has a long-term **identity keypair**; its public key is known to clients.
Each knock is:

1. **Ephemeral ECDH** — client generates an ephemeral key, does ECDH against the
   gate's public key, derives a per-packet symmetric key via HKDF. (Ephemeral key →
   forward secrecy; encryption to the gate's key → only the intended gate can
   decrypt, defeating relay and inspection.)
2. **AEAD encryption** of the payload with that key.
3. **Client signature** over the inner payload, carried inside the ciphertext,
   authenticating *which* client sent it.

Two interchangeable, first-class **cipher suites**, selected by policy:

| Suite | ECDH | AEAD | Signature | Use |
|---|---|---|---|---|
| **FIPS** (default) | ECDH P-256 | AES-256-GCM | ECDSA P-256 | accredited / defense |
| **Modern** | X25519 | ChaCha20-Poly1305 | Ed25519 | high-throughput, non-FIPS |

Both run entirely inside the `aws-lc-rs` validated module boundary. The suite is a
single config switch; the wire format carries a suite identifier.

### 4.2 Authorization payload (inner, encrypted)

```
version | suite | client_key_id | nonce(16) | timestamp(8) | gate_id(16) | requested_ports[] | client_signature
```

Daemon acceptance — **all** must hold:

1. Decrypts and AEAD tag verifies (constant-time).
2. `gate_id` matches *this* gate (anti-relay across gates).
3. Client signature verifies against an **authorized** public key (§6).
4. `timestamp` within a tight skew window (e.g. ±2 s; requires loose NTP).
5. `nonce` unseen within the window (replay cache, sized window × max rate).
6. Every `requested_port` is permitted for this client by policy (a valid knock
   cannot open arbitrary ports).

On success → `authorizations[observed_src] = { now + pinhole, requested_ports }`.

### 4.3 Why both PSK and PKI exist

The authenticator in step 3 is **pluggable** (§6). Public-key/PKI is the default
and the recommended posture. A symmetric pre-shared-key/HMAC mode is also
first-class for air-gapped or appliance scenarios with no key directory — same
packet structure, the signature slot carries an HMAC and the ECDH-to-gate step
uses a shared key. Operators choose per deployment; the data path is identical.

**Canonical use of PSK mode: the single-use enrollment bootstrap.** An endpoint
that has not enrolled yet holds no registered key, so it cannot make a normal
asymmetric knock — the bootstrap chicken-and-egg. The clean resolution is to
cloak the control plane's enrollment endpoint like any other port and treat the
endpoint's **one-time enrollment token as a single-use PSK**: it authenticates
exactly one knock, which opens the enrollment port long enough for the endpoint
to register its freshly generated long-term key (with proof of possession), then
the token is burned and the port re-cloaks. From then on the endpoint uses the
asymmetric mode with its own key. This keeps *even bootstrap* dark — there is no
permanently-open enrollment surface — and is driven by an `external` trust
backend (§6) that validates outstanding tokens against the control plane and
consumes them atomically on use. See `../argus/VISION.md` for the control-plane
side of this flow.

---

## 5. Authorization lifetime — the micro-pinhole

A long grant is a vulnerability. On CGNAT (cellular, corporate egress), a
multi-second pinhole for a shared public egress IP exposes the protected port to
**every other host behind that NAT** for the duration.

**The grant is sub-second** (~300–500 ms, tunable) — long enough only for the
knock to be immediately followed by the connection's `SYN`. Connection
*persistence* is decoupled from the grant: once the `SYN` is admitted, conntrack
carries the established flow indefinitely (§3.1), so the pinhole can close
immediately while the session continues. Where the kernel supports it, the grant
is additionally **scoped to the connecting 4-tuple**, so even same-NAT neighbors
cannot ride it (they cannot predict the client's ephemeral source port, and the
grant is bound to it).

Net effect: the exposure window is hundreds of milliseconds, narrowly scoped, and
established sessions are unaffected by its closing.

---

## 6. Trust sources (pluggable)

Step 3 of verification asks: *is this client's public key authorized to open these
ports on this gate?* The answer comes from a **trust backend** behind a single
trait, chosen by config. All are first-class; multiple can be layered:

- **Static keyset** — a directory or file of authorized public keys / CIDRs +
  per-key port policy. Zero external dependencies; ideal for air-gapped and small
  fleets.
- **PKI / x509** — clients present a cert chain; the gate validates against a
  configured CA and applies policy by cert attributes. Reuses existing enterprise
  PKI; no new key store.
- **External authorizer** — the daemon queries an external system of record over
  mTLS (`rustls`/`reqwest`) and caches the result, refreshing on an interval and
  on cache miss. This is the generic hook for *any* identity provider:
  - an **OpenZiti controller** edge-management API (cache the public certs of
    identities authorized to dial this host),
  - an **OIDC / SPIFFE / SPIRE** trust domain,
  - an internal directory or secrets manager.

The gate is never a participant in the external system's data plane — it only
reads authorized public-key material. No third-party SDK is required in any
component; integration is REST + PKI.

---

## 7. Configuration — dynamic, signed, transport-agnostic

Config is the gate's security policy (the authorized keys and the cloaked ports),
so it is treated as security-critical data, not a static file. Two tiers:

**Bootstrap (static, local, minimal, provisioned out-of-band).** The only thing
fixed at install:
```
gate_id            = "<16-byte gate identity>"
identity_key       = "<path to gate keypair>"      # this gate's ECDH/identity key
config_anchor      = "<pinned control-plane public key>"  # trust anchor for bundles
config_path        = "/etc/spa/bundle.spa"         # where signed bundles are read
knock_port         = 62201
```

**Dynamic (a signed bundle, hot-reloaded).** Everything else lives in a config
bundle the control plane produces:
```
generation = 42                         # monotonic; older is rejected (anti-rollback)
cipher_suite = "fips" | "modern"
pinhole_ms = 400
skew_seconds = 2

[[protected]]   proto = "tcp"; ports = [22, 8443]        # cloak any number of services
[[client]]      thumbprint = "..."; ports = [8443]       # authorized client keys + policy
[[static_rule]] action = "allow"; cidr = "10.0.0.0/24"; ports = [8443]   # break-glass
```

### Consumption is decoupled from transport

The agent consumes config through a **`ConfigSource` port** that yields a
hot-swappable snapshot. *How* the bundle arrives is a separate, pluggable adapter:

- **`FileWatch` (the minimum):** watch a local signed bundle, atomically reload on
  change. Anything may write that file — control plane, a sync sidecar, GitOps.
- **`ControlPlaneApi` (drop-in, later):** poll/stream a controller directly. Same
  port, no change to the core.

**The agent trusts the signature, not the channel.** Each bundle is signed by the
control plane; the agent verifies it against the pinned `config_anchor` before
applying. A tampered or spoofed transport cannot inject keys or open ports, so the
delivery mechanism can be fully untrusted. This is the shift-left principle (§ on
trust lifecycle) applied to config itself.

### Reload safety

- **Atomic + validated.** A bundle is fully verified (signature, then schema) and
  applied as a single atomic snapshot swap. Invalid → rejected, **last-good
  retained**, logged. Never partially applied.
- **Anti-rollback.** A bundle whose `generation` is ≤ the applied one is refused,
  so a replayed stale bundle cannot re-authorize a revoked key.
- **Fail closed on reachability.** Missing/invalid/absent config keeps ports
  **cloaked** — it never opens them. Established flows are handled separately (§5).

### Break-glass / bootstrap

Cloaking infrastructure can create dependency loops (a node that must knock to
reach the very service it needs in order to know how to knock). `static_rule`
allow-entries cover known-good management networks or peer nodes so a hard
power-cycle never bricks a cluster — the explicit, audited exception to
default-drop, with narrow CIDRs and specific ports.

### Failure posture — fail closed

The secure default is **fail closed**: any failure of the SPA layer must leave
protected ports *less* reachable, never more. There is no "fail open" mode for
access.

- **New reachability fails closed.** If the verification daemon dies, no new
  authorizations are created, the allow-list only ages out by TTL, and new
  connections to protected ports are dropped. Access control degrades to *deny*.
- **The secure default survives loss of the cloaking layer itself.** Protected
  ports carry a base `nftables`/`iptables` **default-drop** rule, independent of
  the eBPF allow-list (which only ever *adds* permits on top). If the XDP program
  is unloaded or crashes, the port stays closed — it does not revert to exposed.
- **Already-authorized established flows are preserved across a daemon restart**
  (they bypass the per-source check via conntrack). This is an *availability*
  decision, not a loosening of access control: those flows already passed both
  the gate and the service's own authentication, and the restart grants no new
  access. A strict mode can additionally reset established flows on daemon loss.

The only operator knob is how aggressively to tear down already-vetted sessions on
failure — never whether new access is granted.

---

## 8. Deployment recipes

The product is generic; these are configurations, not separate builds.

- **Harden SSH on a server.** `protected = tcp/22`, `trust = static` keyset of
  admin keys, sidecar `spa-client knock <host> ssh -- ssh user@host`. The SSH
  port vanishes from scans; only key-holders can reach it.
- **Dark database / admin panel.** Cloak the DB and admin ports; clients knock via
  the library before connecting. The service stays unmodified.
- **Dark ZTN edge (OpenZiti).** Cloak the edge router's edge-listener and
  link-listener ports. `trust = external` against the OpenZiti controller so SPA
  authorization is keyed off the same enrolled identities that already authorize
  Ziti dials — pre-authentication invisibility beneath Ziti's pre-authorization
  invisibility, with no second key system. The controller's own ctrl / management
  ports can be cloaked the same way, with `static_rule` allows for router peers to
  avoid the bootstrap loop.

---

## 9. Threat model

| Threat | Mitigation |
|---|---|
| Port scan / fingerprint | `XDP_DROP`; no RST/ICMP — port appears nonexistent |
| Volumetric DoS on protected port | Dropped in NIC driver before `sk_buff` alloc; ~0% CPU |
| DoS on the knock port | In-kernel length filter + per-source rate limit before any crypto |
| Knock forgery | AEAD + client signature over authorized key (PKI) or HMAC (PSK) |
| Knock replay | Per-packet nonce cache + tight timestamp skew window |
| Knock relay to another gate | Payload binds `gate_id`; encrypted to the gate's key |
| Knock relay to another port | Payload binds `requested_ports`; policy-checked per client |
| Packet inspection / SPA fingerprinting | Knock is AEAD-encrypted — opaque, indistinguishable from noise |
| CGNAT neighbor piggyback | Sub-second pinhole + 4-tuple-scoped grant; conntrack carries the session |
| Cluster brick / bootstrap loop | Audited `static_rule` break-glass; configurable fail-open |
| Compromised client key | Per-key revocation in the trust backend; forward secrecy from ephemeral ECDH |

## 10. Operational concerns

- **Audit without breaking darkness.** All decisions (drops, grants, rejects) are
  logged to a local side channel / SIEM export. The gate never answers on the
  wire — observability is out-of-band only.
- **Key rotation.** Gate identity and client keys rotate via the trust backend;
  ephemeral per-packet ECDH means past captures stay undecryptable across rotation.
- **High availability.** Gate identity can be shared across an HA pair so either
  node decrypts knocks; authorization maps are per-host (grants are
  source-and-flow specific and short-lived, so no cross-node map sync is needed).
- **Deployment prerequisites.** `nf_conntrack` loaded; XDP-capable NIC/driver for
  native mode (generic XDP otherwise); loose time sync (NTP) for the skew window.
- **Certification path.** Single memory-safe language, FIPS-validated crypto
  module, no C on the untrusted path, declarative auditable policy — chosen to
  ease ATO / Common Criteria evidence-gathering.
