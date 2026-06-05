# spa-device → Argus: service identity & node-agent custodian model

**Re:** `002-service-identity-and-node-agent.md`. The model is sound; the data
plane can do all of it, and the one thing it previously couldn't (PSK enrollment
knocks) is **now built**. Same invariants as `001`: the gate enforces only the
signed bundle and knows nothing but `gate_id`, `(proto, port)`, and **client**
thumbprints.

## The distinction that everything rests on

There are **two kinds of thumbprint**, and they must never be conflated:

- **Client thumbprint** — a *device/knocker's* key thumbprint. Goes in the
  bundle's `clients[]`, travels in the knock, and the **gate enforces it**.
- **Service thumbprint** — a *fronted workload's* identity. Goes in your
  `HostedEndpoint`, is how policy follows a service across gates, and the **gate
  never sees it**. It is Argus-side metadata only.

Both are `SHA-256(pubkey)` (see `003-answers.md`), but they live in different
places and only the client thumbprint reaches the data plane.

## Confirm / flag

**Q1 — Custodian (N service keypairs, port→identity by local config):** No
objection, no data-plane limit. How many identity keys the agent holds and how it
maps them to ports is entirely agent-side; the gate is oblivious. The agent ends
up custodian of 1 gate identity + N service identities — fine.

**Q2 — One combined report `(gate_id, [(proto, port, thumbprint)])`:** Endorsed.
The gate doesn't consume the report (Argus does), and the agent owns both the
ports and the identities locally, so the join is local and atomic. Splitting then
re-joining at Argus only adds a disagreement failure mode. One caveat for
fail-safe: **cloaking must not depend on a service identity existing** — allow a
reported port with no thumbprint yet (cloak it anyway), so a port is never left
bright just because its workload identity isn't enrolled.

**Q3 — Service enrollment reuses device pattern-B; token doubles as the knock
PSK:** **Confirmed and now supported.** PSK knock mode is built and tested: a
one-time token authenticates a single knock via HMAC over the same envelope,
opens the cloaked enrollment port, and is **burned on use** (a second knock with
the same token is rejected; a forged knock can't burn it). So the token-as-knock-
PSK bootstrap works at the data-plane layer today.
- Note: you also have a simpler option for *service* (vs node) enrollment — since
  the node agent is itself enrolled with an authenticated channel to Argus, it can
  enroll its services over that channel (PoP per service key) without a separate
  per-service knock. Both are fine; pick per your control-plane ergonomics.

**Q4 — Cloak vs identity (thumbprint is Argus metadata, never gate-enforced):**
**Confirmed, emphatically.** `protected[]` comes purely from reported ports (cloak
follows the host, per `001`). The gate enforces only `clients[]` (client
thumbprints) + signature/HMAC + ports. It has no field for, and never inspects, a
service thumbprint. Don't let a service thumbprint leak into `clients[]` — those
are device thumbprints.

**Q5 — Future k8s / self-attesting workloads (SPIFFE-style):** **Confirmed, no
wire change.** The gate's contracts are the bundle (`protected_ports` + client
thumbprints) and the knock format. How the agent *acquires* a service identity
(holding a key vs attesting one) never touches either — services are what's
*protected*, not what *knocks*. The report shape `(gate_id, [(proto, port,
thumbprint)])` is an Argus↔agent contract, invisible to the gate, so it can evolve
freely.

## Net

Build `Service` (keyed by `SHA-256` fingerprint, per `003`), `HostedEndpoint`
from the combined report, the bundle compiler, and the reconciler as planned. The
wire shape is confirmed; PSK enrollment is real; the gate stays a dumb
port-cloaker that never learns what a "service" is.
