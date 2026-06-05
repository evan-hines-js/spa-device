# spa-device → Argus: answers on host-reported service hosting

**Re:** `001-host-reported-service-hosting.md`. Answered from the data-plane
contract. Two invariants drive every answer below:

1. **The gate enforces only the signed bundle.** It cloaks exactly the bundle's
   `protected[]` and admits only `clients[]`, plus the base default-drop floor.
   It never cloaks or admits anything from local state. (Confirmed by what's
   built: `spa-gated` takes `protected_ports` + `clients` solely from the
   verified bundle; see `DESIGN.md` §7 and `scripts/e2e-config.sh`.)
2. **The gate has no concept of a logical service.** Its entire vocabulary is
   `(proto, port)`, its enrolled `gate_id`, and 32-byte client key thumbprints.
   "prod-ssh" is an Argus-only abstraction; never push it down to the gate.

Everything else follows from those two.

---

## Q1 — Direction of authority (BLOCKING)

**Your assumed flow is correct.** The report is *input to* the bundle; the bundle
is authoritative. Host reports what it fronts → Argus folds into `protected[]` +
computes `clients[]` → signs → gate applies and cloaks exactly that. There is **no
"host cloaks locally and is authoritative" model** — that would break invariant 1
(the gate trusts the signature, not local config) and the whole point of a signed,
anti-rollback bundle.

One honest gap to design around: **between a host first reporting a new service
and Argus issuing a bundle that covers it, that port is *not yet cloaked*** (no
bundle entry → XDP passes it → only the listener's own auth protects it). Options,
your call:
- accept the short exposure window (simplest), or
- let the agent **locally default-drop a just-reported port** as a fail-closed
  stopgap until the signed bundle arrives. This is allowed because it only makes
  the port *darker* — it never grants access (only a signed `clients[]` does). It
  does not violate invariant 1 (it's deny-only, not an access decision).

We lean toward the stopgap; it keeps "report → cloak" from having an open gap. But
access is *always* bundle-only.

## Q2 — Service identity in a report (BLOCKING)

**(b), keyed by the gate's enrolled identity:** the agent reports
`gate_id + [(proto, port), …]` — the raw ports it fronts. The host does **not**
know the admin's logical service name, and must not: that's an Argus concept, and
provisioning service names/keys to the gate (option c) leaks control-plane
modeling into a component whose job is to cloak ports.

So Argus matches a report to an admin-defined logical service by **`(proto, port)`
on that gate**, not by a name the host carries. The gate identity is the
already-existing enrollment identity (the `gate_id`); reuse it, don't invent a
per-service key.

(If you later want stronger binding than raw ports, the right move is *Argus*
attaching ports to logical services and matching reports against them — still no
service identity on the gate.)

## Q3 — Transport & auth of the report

**Agent pushes, authenticated as its enrolled gate identity (mTLS), over the
management API.** Push, not pull — the gate is cloaked (Argus can't reach into it
unsolicited), and the gate is the one that knows when its hosted set changes. The
gate already knocks the controller and holds an enrolled identity, so reuse that.

Cadence: **on-change + periodic heartbeat.** On-change keeps `protected[]` fresh;
the heartbeat re-asserts the full current set and doubles as liveness for Q4.

## Q4 — Declarative vs delta

**Declarative — full current set; Argus reconciles.** Idempotent and drift-free; a
dropped message can't corrupt state. (Same reason the bundle itself is declarative
with a generation, not a delta stream.)

**On silence: retain last-known. Your instinct is right, and fail-closed *requires*
it.** Withdrawing a hosting shrinks `protected[]`, which *uncloaks* the port — that
is fail-**open**, the one thing we never do. And it buys nothing: a silent gate
that is actually *dead* grants no access anyway (no process to verify knocks), and
a silent-but-alive gate keeps enforcing its last good bundle. So a missing report
must never trigger a bundle change. Alert/quarantine on prolonged silence
(operational), but **never auto-shrink** `protected[]`/access.

## Q5 — Discovery vs pre-declared

**Host-first discovery is safe — let it happen — but access stays admin-first.**
Recommended: a reported-but-undefined service is auto-created as "discovered,"
and Argus may immediately cloak it (`protected[]` set, **`clients[]` empty**).

This is the elegant part: discovery only ever makes things *darker*. A discovered
service is dark to everyone (empty `clients[]`) until an admin attaches a policy,
at which point `clients[]` populates and authorized devices can knock in. So:
- discovery never grants access (no policy ⇒ no `clients[]`),
- the port isn't left bright while waiting for an admin,
- a compromised host can at worst report ports and self-cloak (self-DoS), never
  pull traffic.

Don't reject reports outright (option b) — that leaves a listening port bright
until an admin notices. Cloak-on-discover, authorize-on-policy.

## Q6 — Ports: who's authoritative?

**Cloaking follows the host; access follows the admin.**
- The **host report is authoritative for the cloaked port set.** The host knows
  what is actually listening; failing to cloak a live port is a leak, while
  cloaking an extra port is harmless (dark-by-default). If admin says `22` and the
  host reports `22, 2222`, **cloak both** — do not leave 2222 bright. Letting the
  host widen its own cloak is safe (worst case: self-DoS; it already controls its
  ports).
- The **admin policy is authoritative for who may reach it** (`clients[]`), keyed
  to the logical service. Grant access only where an admin policy exists *and* the
  port was reported.

So: the admin need not enumerate ports; take the cloaked set from the report, and
take the *access* from the policy. If you keep admin ports, treat them as intent/
validation, but never let an admin port list *narrow* the cloak below what the
host reports (that would leak).

## Q7 — HA / multi-gate

**Yes — each gate reports independently, and bundles are already per-gate**
(`gate_id`-scoped; one signed bundle per gate, as built). Model `HostedService`
as **per-(gate, service)** so each fronting host reports its own ports — uniform
`service → ports` is the common case but don't *force* it; per-host port variance
falls out naturally because each gate's bundle reflects its own report.

The **access policy (`clients[]`) is per logical service** (uniform — "these
devices may reach prod-ssh"), and Argus scopes it into each fronting gate's bundle
against that gate's reported ports.

---

## Summary for the `HostedService` model

- Edge is **(gate_id, proto, ports)** — identified by gate identity + raw ports,
  never a service name on the gate.
- Report is **declarative, pushed by the gate over mTLS, on-change + heartbeat**.
- **Bundle is authoritative**; report is input. Gate cloaks/admits only the signed
  bundle (+ deny-only local floor).
- **Cloak follows the host (fail-safe/dark); access follows the admin
  (fail-closed).**
- **Silence ⇒ retain last-known.** Never auto-shrink `protected[]`.
- **Discovery cloaks (empty `clients[]`); policy authorizes.**

Nothing here requires a change to the bundle format you already integrate against
(`generation`, `protected_ports`, `clients[]`); it only tells you how to *compute*
`protected[]`/`clients[]` from reports + policies. Unblock Q1/Q2 with: report =
`(gate_id, [(proto,port)])`, bundle is authoritative.
