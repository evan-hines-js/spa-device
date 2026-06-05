# Argus → spa-device: Argus now emits your bundle format (confirm)

**From:** Argus. **Re:** the signed config bundle. Not a question — a heads-up
that Argus emits exactly what `spa-gated/src/bundle.rs` + `config.rs` parse, read
straight from your code. Please confirm the few inferred points at the end.

## What Argus emits

Per gate, the **bundle file = raw Ed25519 signature (64 bytes) ‖ TOML payload**,
matching `bundle::load_verify`:

```toml
generation = <u64>            # monotonic per gate; bumped every reissue
protected_ports = [<u16>...]  # flat, sorted, unique — cloak follows the host

[[client]]
thumbprint_hex = "<64 hex>"   # SHA-256(pubkey), per 003
public_key_hex = "<hex>"      # the client's SPA public key (gate verifies knocks with it)
ports = [<u16>...]            # ports this client may open
```

- **Signature:** Ed25519 over the TOML body, verifiable with
  `verify_signature(Suite::Modern, anchor_pub, body, sig)` — so Argus's **root
  signing key (the anchor) is always Ed25519 (`:modern`)**, independent of a
  gate's knock cipher suite. `config_anchor_hex` you pin = that anchor's raw
  Ed25519 public key hex.
- **Byte-exactness:** the signed bytes are stored and served verbatim (we hit and
  fixed a trailing-whitespace-trim bug). `decode64(signature) ‖ payload` is the
  file.

## How a gate gets it

`GET /api/gate/bundle` (authenticated as the gate) returns the raw file bytes
(`application/octet-stream`, `x-bundle-generation` header). The agent writes it to
`bundle_path`. The bundle is self-authenticating, so the channel needn't be
trusted. Argus reissues automatically on any policy/hosting/device change, bumping
`generation`; your anti-rollback drops stale ones.

## Tested on our side

A round-trip test reconstructs the file and verifies it the way the gate does:
`<<sig::64, body>> = file; verify(Modern, anchor_pub, body, sig)` ✓, with the
`[[client]]` block carrying both `thumbprint_hex` and `public_key_hex`.

## Please confirm

1. **`[[token]]` for the enrollment gate.** `config.rs` parses `[[token]]`
   (`token_id_hex`, `secret_hex`, `ports`) but `bundle.rs::RawBundle` does **not**
   — tokens look local-config-only, not in the signed bundle. For the cloaked
   enrollment endpoint, do you want one-time PSK tokens **in the signed bundle**
   too (so they hot-reload + anti-rollback), or do they stay local/out-of-band? If
   in-bundle, what's `token_id` vs `secret` (we have the enrollment token + its
   SHA-256; the PSK HMAC key is the secret)?
2. **`protected_ports` is proto-agnostic** (just `u16`). Argus flattens tcp+udp to
   one port list. Confirm the gate cloaks a port regardless of L4 proto (so
   tcp/53 and udp/53 are one entry), or tell us if you need proto.
3. **Anchor = Ed25519 always.** `load_verify` hardcodes `Suite::Modern`. Confirm
   the bundle anchor is always Ed25519 even for a `fips` knock gate (we built it
   that way).
4. **TOML formatting latitude.** We emit minimal TOML (one `[[client]]` table per
   client, `ports = [..]`). `toml::from_str` is whitespace-insensitive, so the
   signature — not the formatting — is what matters. Just confirming no canonical
   form is required beyond "valid TOML that round-trips through your parser".
