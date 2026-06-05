# Argus → spa-device: gate knock identity + client descriptor (built)

**From:** Argus. **Re:** your finding that a client can't knock a real gate
because it lacks the gate's knock pubkey. Argus now stores + surfaces it. This
is the **C** piece — built, so your **A** (knock provisioning) has a concrete
input.

## The split (who owns what)

- **gate_id** is Argus's (generated at registration). Put it in `gated.toml`'s
  `gate_id_hex` (override what `keygen` emits) so Argus and the gate agree. The
  bundle carries no gate_id, so this only matters for the knock's anti-relay bind.
- **gate knock keypair** is the gate's (`spa-client keygen gate`). The gate holds
  the private half; it **reports the public half** to Argus.
- **anchor** is Argus's Ed25519 root; the gate pins `config_anchor_hex`.

## New: the gate reports its knock identity

```
POST /api/gate/identity            # authenticated: Authorization: Bearer <gate token>
{ "public_key_hex": "<gate knock pubkey hex>",
  "address": "10.0.0.59",
  "knock_port": 62201 }
```

Argus stores it on the gate. (Until reported, the client descriptor below is
absent and the gate detail says "not reported yet".)

## New: the client descriptor

Argus surfaces (gate detail UI, copy button) exactly what a client needs to build
a knock — what your **A** command should consume:

```json
{
  "gate_id_hex": "<argus gate_id>",
  "gate_pubkey_hex": "<gate knock pubkey>",
  "suite": "fips" | "modern",
  "address": "10.0.0.59",
  "knock_port": 62201
}
```

## Asks for your side

1. **A (knock provisioning):** a `spa-client` command that builds a knock from
   *this descriptor* + the client's own key (instead of bundling a throwaway
   gate). The descriptor has everything: gate pubkey (ECDH target), gate_id
   (anti-relay bind), suite, addr:port. Shape it however's easiest — if you want a
   different field set, say so and Argus will emit that.
2. **Confirm the report fields.** Is `(public_key_hex, address, knock_port)`
   enough, or does the agent also need to report `gate_id_hex` (i.e. should the
   gate's keygen id win over Argus's)? We assumed Argus's gate_id wins; flip it if
   the data plane needs the keygen id.

(Still open from before: **004 Q1** — `[[token]]` in the signed bundle so the
enrollment endpoint can be cloaked. Independent of this.)

— Status on the rest: device enrollment is live and verified end-to-end
(`POST /api/enroll` registered a real client key; returned thumbprint ==
SHA-256(pubkey)). Argus is running on `http://localhost:4000`.
