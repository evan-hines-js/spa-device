# Argus → spa-device: questions on host-reported service hosting

**From:** Argus (control plane). **Re:** the agent-side contract for a host
reporting which services it fronts.

## Context

Argus is the control plane. Admins define **logical services** (name, protocol,
ports) and **access policies** (which devices, by ABAC role attribute, may reach
a service) — purely in access terms, with no knowledge of gates/topology.

We are deciding how a gate↔service **hosting** edge gets established (which host
fronts which service), and we've chosen **the host self-reports it** (the
spa-device agent tells Argus what it fronts) rather than an admin/operator
declaring it. Argus then compiles each gate's signed bundle:
`protected[]` (ports the gate cloaks) + `clients[]` (policy-matched device
thumbprints, scoped to those ports).

Before we model the Argus side of this contract, we need the agent side pinned.
Q1 and Q2 are the blocking ones.

## Questions

### Q1 — Direction of authority (BLOCKING)
The signed bundle's `protected[]` already tells the gate which `(proto, ports)`
to cloak, and the gate applies the bundle. If the host *also* self-reports what
it hosts, which is authoritative?

Our assumed flow: **host reports hosted services → Argus folds them into
`protected[]` + computes `clients[]` → signs → gate applies the bundle and
cloaks exactly that.** i.e. the report is *input to* the bundle; the gate never
cloaks anything not in a signed bundle (beyond the base default-drop). Is that
right, or is there a "host cloaks locally and reports up" model where the host's
local config is authoritative and the report is just for Argus's policy view?

### Q2 — Service identity in a report (BLOCKING)
When the agent reports "I front service X," what identifier does it use?
- (a) a local config name/label the operator set on the host,
- (b) the raw `(proto, ports)` it cloaks (no name),
- (c) a service key/id provisioned to the gate at enrollment,
- (d) something else.

Concretely: does the host know the *admin's logical service name*, or only the
ports it listens on? This determines whether Argus matches reports to
admin-defined services by name, by `(proto,port)`, or by a provisioned key.

### Q3 — Transport & auth of the report
The gate is cloaked and reaches Argus by knocking the controller. Do you expect
the agent to **push** reports to Argus over the management API, authenticated as
its enrolled **gate identity** (mTLS)? Or should Argus **pull**? What cadence —
on change, periodic heartbeat, both?

### Q4 — Declarative vs delta
Does a report carry the **full current set** of hosted services (Argus
reconciles, withdrawing any no longer present), or **incremental** add/remove?
And the fail-closed question: if a gate goes silent (no report), should Argus
*withdraw* its hostings (shrinking `protected[]`/access) or *retain last-known*?
Our instinct is retain-last-known (a missing report must never silently open or
close access), but your fail-closed posture should drive this.

### Q5 — Discovery vs pre-declared
If a host reports a service Argus has no admin-defined logical service for,
should Argus (a) auto-create a "discovered" service pending an admin attaching a
policy, or (b) reject the report until an admin defines it first? (i.e. is the
intended order host-first or admin-first?)

### Q6 — Ports: who's authoritative?
Ports can come from the admin's logical service definition *and* from what the
host reports it cloaks. If they disagree (admin says `prod-ssh = 22`, host
reports it cloaks `22, 2222`), who wins? Or should the admin not specify ports
at all and we take them entirely from the host report?

### Q7 — HA / multi-gate
When several gates front the same logical service, each reports independently,
correct? Any notion of per-host port differences for the same logical service,
or is `service → ports` uniform across the hosts that front it?

## What Argus will do with the answers
Model a `HostedService` (gate↔service) populated by the report action (the
contract surface), then the bundle compiler reads it to build `protected[]` +
`clients[]`, and the reconciler reissues a gate's bundle when its hostings — or
the policies on its hosted services — change. We've **paused** building that
resource until Q1/Q2 are answered so we don't bake in the wrong identity model.
