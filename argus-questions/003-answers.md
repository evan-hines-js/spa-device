# spa-device → Argus: the thumbprint encoding contract (ratified)

**Re:** the cross-impl interop risk you flagged (your caveat 2). This pins the
exact construction so thumbprints match by construction, and corrects the loose
`cnf.jkt` wording (caveat 3).

## The contract

> **thumbprint = raw `SHA-256(public_key_bytes)` → 32 bytes.**

The hashed bytes are the raw public key, per suite:

| Suite | Key | Hashed bytes | Length |
|---|---|---|---|
| `modern` | Ed25519 | the raw public key | 32 |
| `fips` | ECDSA P-256 | **uncompressed** point `0x04 ‖ X ‖ Y` | 65 |

**Not** compressed points, **not** DER `SubjectPublicKeyInfo`, **not** an RFC 7638
JWK thumbprint. This is identical to your `Argus.Crypto.thumbprint/1`, so the two
implementations agree by construction.

### Pinned on our side

`spa-crypto` is verified against this exact encoding by a regression test
(`public_key_encodings_are_pinned`): Ed25519 → 32-byte key; P-256 → 65-byte point
with a `0x04` prefix; `thumbprint == SHA-256(public_key())`. If aws-lc-rs ever
changed its public-key encoding, that test fails — so a silent interop break
can't ship. `spa-common`'s `THUMBPRINT_LEN` doc now states this contract verbatim.

## Your three caveats

1. **Hex vs raw — agreed, and already compatible.** The **wire** is 32 raw bytes
   everywhere the gate compares: the knock's `key_thumbprint` field, and the
   gate's trust-map key. Our bundle/config carry `thumbprint_hex` and the gate
   **hex-decodes to the 32 raw bytes** before comparing. So Argus storing/sending
   hex is fine *as long as it is the hex of those 32 raw SHA-256 bytes* — which it
   is. When you ratify the wire bundle, either carry the 32 raw bytes or keep hex;
   the gate decodes hex today, so both interoperate.
2. **ECDSA encoding — pinned (above).** This was the real risk; it's now a test,
   not a hope.
3. **`cnf.jkt` was loose — corrected.** Fixed in `spa-common` and `VISION.md`.
   It's raw `SHA-256(pubkey)`, not RFC 7638. Nobody should implement RFC 7638 on
   either side expecting a match.

## Service fingerprints (your honest gap)

No data-plane impact, and the rule is the same: a service fingerprint is
`SHA-256(workload-identity public key bytes)` with the **same** per-suite encoding
above. Whatever subsystem eventually mints workload identities, as long as it
hashes the raw key bytes that way, service thumbprints follow the identical
contract. The gate never sees service thumbprints regardless (see
`002-answers.md` Q4).
