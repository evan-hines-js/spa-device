# Argus → spa-device: service identity & the node-agent custodian model

**From:** Argus. **Re:** how a *service* gets a followable identity, given the
deployment model. Follows `001` (host-reported hosting). Mostly **confirmation** —
Argus is building against this; flag anything the data plane can't do.

## Decision

Service fingerprints are **cryptographic identity only** (a service's keypair
thumbprint, symmetric with how Devices are identified by SPA-key thumbprint).
No address/name/label fallback. This is what lets policy **follow a service
across gates** when a workload migrates.

## Deployment model we're targeting

**VMs running multiple unmodified services** (postgres, app, sshd…). One **node
agent per VM** that is BOTH:
- the **gate** (cloaks the node's ports), and
- the **identity custodian / aggregator** for the services on that node.

Unmodified services can't self-enroll, so the **agent holds a keypair per
service** it fronts (enrolled with Argus on the service's behalf via the same
pattern-B token+PoP flow used for devices), and **operator config on the node
maps `port → service identity`** (`5432 → prod-db`, `8443 → app-x`).

Because the agent owns *both* the cloaked ports and the service identities, the
**join is local** — no network-level identity inference. The agent emits **one
declarative report**:

```
report = (gate_id, [(proto, port, service_thumbprint), …])
         pushed over mTLS as the enrolled gate identity, on-change + heartbeat
```

Argus then: `HostedEndpoint(gate, service=thumbprint, proto, port)`; `protected[]`
from the node's ports; `clients[]` from each service's policies; **follow by
thumbprint** (same thumbprint reported on another gate = same service).

## Confirm / flag

1. **Custodian:** can the node agent hold N service keypairs and run pattern-B
   enrollment on each service's behalf, keyed to a `(proto, port)` by local
   operator config? Any limit / objection?
2. **One combined report** `(gate_id, [(proto, port, thumbprint)])` — OK? Or do
   you prefer two separate reports (ports-for-cloak vs identities) that Argus
   joins? We strongly prefer the single joined report since the agent owns both.
3. **Service-identity enrollment** reuses device pattern-B (one-time token, PoP,
   thumbprint recorded). The service token doubles as the knock PSK to reach the
   cloaked enrollment gate — same as device bootstrap. Any data-plane constraint?
4. **Cloak vs identity:** `protected[]` still comes purely from the reported
   ports (cloak follows host, per `001`); the thumbprint only adds *who the port
   is*, never changes *whether it's cloaked*. Confirm the thumbprint is metadata
   to Argus and never something the gate enforces on (gate still only knows
   `gate_id`, `(proto,port)`, and client thumbprints).
5. **Future k8s/self-attesting workloads:** the agent would *acquire* a
   workload's identity by attestation (SPIFFE-style) instead of *holding* a key —
   but the report stays `(gate_id, [(proto, port, thumbprint)])`. Confirm that
   evolution doesn't change the wire contract.

## What Argus is building now (against the above)
`Service` keyed by fingerprint (thumbprint); `HostedEndpoint(gate, service,
proto, port)` from the report; bundle compiler → `protected[]`/`clients[]`;
reconciler reissues affected gates. Independent of your answers to the
*mechanics* — those only affect the agent side. Reply confirms the wire shape.
