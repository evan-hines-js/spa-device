//! SPA signcryption envelope (aws-lc-rs adapter).
//!
//! Wire layout of a sealed knock:
//! ```text
//! version(1) | suite(1) | ephemeral_pubkey(N) | AEAD ciphertext+tag
//! ```
//! Sealing: the client signs the [`Authorization`] with its identity key, then
//! encrypts the signed plaintext to the gate via ephemeral ECDH → HKDF → AEAD.
//! Only the gate (holding the static key) can decrypt; the signature proves
//! *which* client sent it. The header is AEAD-authenticated as AAD.
//!
//! This crate provides the [`Crypto`] port (`open` + `verify`) for the gate and
//! [`ClientKey::seal`] for the client. It holds no trust/policy state. All
//! primitives come from aws-lc-rs. See `DESIGN.md` §4.

#![forbid(unsafe_code)]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::{aead, agreement, digest, hkdf, signature};

use spa_common::{Authorization, GATE_ID_LEN, NONCE_LEN, SIG_LEN, Suite, THUMBPRINT_LEN, VERSION};
use spa_core::{Crypto, OpenError, Opened};

/// AEAD nonce length (96-bit), matching aws-lc-rs.
const AEAD_NONCE_LEN: usize = 12;
const AEAD_KEY_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;
/// Domain-separation label bound into the HKDF derivation.
const HKDF_LABEL: &[u8] = b"spa-v1-envelope";

/// Errors from the client (sealing) side. The gate's `open` reports the opaque
/// [`OpenError`]; verification failures are surfaced as `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Key generation, parsing, or public-key extraction failed.
    Key,
    /// Signing failed.
    Sign,
    /// Encoding the authorization failed (see `spa_common::WireError`).
    Encode,
    /// AEAD/KDF/agreement operation failed.
    Crypto,
}

// ---- suite → algorithm selection -------------------------------------------

fn agreement_alg(suite: Suite) -> &'static agreement::Algorithm {
    match suite {
        Suite::Fips => &agreement::ECDH_P256,
        Suite::Modern => &agreement::X25519,
    }
}

fn aead_alg(suite: Suite) -> &'static aead::Algorithm {
    match suite {
        Suite::Fips => &aead::AES_256_GCM,
        Suite::Modern => &aead::CHACHA20_POLY1305,
    }
}

fn verify_alg(suite: Suite) -> &'static dyn signature::VerificationAlgorithm {
    match suite {
        Suite::Fips => &signature::ECDSA_P256_SHA256_FIXED,
        Suite::Modern => &signature::ED25519,
    }
}

/// Length of the ephemeral public key on the wire (uncompressed P-256 point, or
/// raw X25519).
fn eph_pub_len(suite: Suite) -> usize {
    match suite {
        Suite::Fips => 65,
        Suite::Modern => 32,
    }
}

// ---- shared HKDF / AEAD helpers --------------------------------------------

struct OkmLen(usize);
impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive the AEAD key and nonce from the ECDH shared secret, binding the suite
/// and the ephemeral public key into the context.
fn derive(
    suite: Suite,
    shared: &[u8],
    eph_pub: &[u8],
) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_NONCE_LEN]), ()> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(shared);
    let info: [&[u8]; 3] = [HKDF_LABEL, &[suite.to_byte()], eph_pub];
    let okm = prk
        .expand(&info, OkmLen(AEAD_KEY_LEN + AEAD_NONCE_LEN))
        .map_err(|_| ())?;
    let mut out = [0u8; AEAD_KEY_LEN + AEAD_NONCE_LEN];
    okm.fill(&mut out).map_err(|_| ())?;
    let mut key = [0u8; AEAD_KEY_LEN];
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    key.copy_from_slice(&out[..AEAD_KEY_LEN]);
    nonce.copy_from_slice(&out[AEAD_KEY_LEN..]);
    Ok((key, nonce))
}

fn aead_seal(
    suite: Suite,
    key: &[u8; AEAD_KEY_LEN],
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ()> {
    let unbound = aead::UnboundKey::new(aead_alg(suite), key).map_err(|_| ())?;
    let key = aead::LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        &mut in_out,
    )
    .map_err(|_| ())?;
    Ok(in_out)
}

fn aead_open(
    suite: Suite,
    key: &[u8; AEAD_KEY_LEN],
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let unbound = aead::UnboundKey::new(aead_alg(suite), key).map_err(|_| ())?;
    let key = aead::LessSafeKey::new(unbound);
    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| ())?;
    Ok(plaintext.to_vec())
}

/// Stateless signature check used by the gate. Constant-time inside aws-lc-rs.
pub fn verify_signature(suite: Suite, public_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    signature::UnparsedPublicKey::new(verify_alg(suite), public_key)
        .verify(message, sig)
        .is_ok()
}

// ---- gate side --------------------------------------------------------------

/// The gate's static identity key for one suite. Implements the [`Crypto`] port.
pub struct GateKeypair {
    suite: Suite,
    private: agreement::PrivateKey,
    public: Vec<u8>,
}

impl GateKeypair {
    /// Generate a fresh gate key for `suite`.
    pub fn generate(suite: Suite) -> Result<Self, CryptoError> {
        let private =
            agreement::PrivateKey::generate(agreement_alg(suite)).map_err(|_| CryptoError::Key)?;
        let public = private
            .compute_public_key()
            .map_err(|_| CryptoError::Key)?
            .as_ref()
            .to_vec();
        Ok(GateKeypair {
            suite,
            private,
            public,
        })
    }

    /// The gate's public key — distributed to clients so they can seal to it.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
}

impl Crypto for GateKeypair {
    fn open(&self, packet: &[u8]) -> Result<Opened, OpenError> {
        // header: version(1) | suite(1) | eph_pub(N)
        let version = *packet.first().ok_or(OpenError)?;
        if version != VERSION {
            return Err(OpenError);
        }
        let suite = Suite::from_byte(*packet.get(1).ok_or(OpenError)?).map_err(|_| OpenError)?;
        if suite != self.suite {
            return Err(OpenError);
        }
        let eph_end = 2 + eph_pub_len(suite);
        let eph_pub = packet.get(2..eph_end).ok_or(OpenError)?;
        let ciphertext = packet.get(eph_end..).ok_or(OpenError)?;
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(OpenError);
        }
        let header = &packet[..eph_end];

        let peer = agreement::UnparsedPublicKey::new(agreement_alg(suite), eph_pub);
        let (key, nonce) = agreement::agree(&self.private, peer, (), |secret| {
            derive(suite, secret, eph_pub)
        })
        .map_err(|_| OpenError)?;

        let plaintext = aead_open(suite, &key, nonce, header, ciphertext).map_err(|_| OpenError)?;

        let auth = Authorization::decode(&plaintext).map_err(|_| OpenError)?;
        let signing_len = plaintext.len().checked_sub(SIG_LEN).ok_or(OpenError)?;
        let signing_bytes = plaintext[..signing_len].to_vec();
        Ok(Opened {
            auth,
            signing_bytes,
        })
    }

    fn verify(&self, suite: Suite, public_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
        verify_signature(suite, public_key, message, sig)
    }
}

// ---- client side ------------------------------------------------------------

enum Signer {
    Ecdsa(signature::EcdsaKeyPair),
    Ed25519(signature::Ed25519KeyPair),
}

/// A client's identity (signing) key plus its public key and thumbprint.
pub struct ClientKey {
    suite: Suite,
    signer: Signer,
    public: Vec<u8>,
    thumbprint: [u8; THUMBPRINT_LEN],
}

impl ClientKey {
    /// Generate a fresh client identity key for `suite`.
    pub fn generate(suite: Suite) -> Result<Self, CryptoError> {
        let (signer, public) = match suite {
            Suite::Fips => {
                let kp =
                    signature::EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_FIXED_SIGNING)
                        .map_err(|_| CryptoError::Key)?;
                let pubk = kp.public_key().as_ref().to_vec();
                (Signer::Ecdsa(kp), pubk)
            }
            Suite::Modern => {
                let kp = signature::Ed25519KeyPair::generate().map_err(|_| CryptoError::Key)?;
                let pubk = kp.public_key().as_ref().to_vec();
                (Signer::Ed25519(kp), pubk)
            }
        };
        let thumbprint = thumbprint_of(&public);
        Ok(ClientKey {
            suite,
            signer,
            public,
            thumbprint,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn thumbprint(&self) -> &[u8; THUMBPRINT_LEN] {
        &self.thumbprint
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; SIG_LEN], CryptoError> {
        let sig = match &self.signer {
            Signer::Ecdsa(kp) => kp
                .sign(&SystemRandom::new(), message)
                .map_err(|_| CryptoError::Sign)?,
            Signer::Ed25519(kp) => kp.sign(message),
        };
        let bytes = sig.as_ref();
        if bytes.len() != SIG_LEN {
            return Err(CryptoError::Sign);
        }
        let mut out = [0u8; SIG_LEN];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Build, sign, and seal a knock for `gate_public`, returning the wire packet.
    pub fn seal(
        &self,
        gate_public: &[u8],
        gate_id: [u8; GATE_ID_LEN],
        ports: &[u16],
        nonce: [u8; NONCE_LEN],
        timestamp_nanos: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut auth = Authorization {
            nonce,
            timestamp_nanos,
            gate_id,
            key_thumbprint: self.thumbprint,
            ports: ports.to_vec(),
            signature: [0u8; SIG_LEN],
        };
        let signing = auth.signing_bytes().map_err(|_| CryptoError::Encode)?;
        auth.signature = self.sign(&signing)?;
        let plaintext = auth.encode().map_err(|_| CryptoError::Encode)?;

        let rng = SystemRandom::new();
        let ephemeral = agreement::EphemeralPrivateKey::generate(agreement_alg(self.suite), &rng)
            .map_err(|_| CryptoError::Crypto)?;
        let eph_pub = ephemeral
            .compute_public_key()
            .map_err(|_| CryptoError::Crypto)?
            .as_ref()
            .to_vec();

        let mut header = Vec::with_capacity(2 + eph_pub.len());
        header.push(VERSION);
        header.push(self.suite.to_byte());
        header.extend_from_slice(&eph_pub);

        let peer = agreement::UnparsedPublicKey::new(agreement_alg(self.suite), gate_public);
        let (key, aead_nonce) = agreement::agree_ephemeral(ephemeral, peer, (), |secret| {
            derive(self.suite, secret, &eph_pub)
        })
        .map_err(|_| CryptoError::Crypto)?;

        let ciphertext = aead_seal(self.suite, &key, aead_nonce, &header, &plaintext)
            .map_err(|_| CryptoError::Crypto)?;

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}

fn thumbprint_of(public_key: &[u8]) -> [u8; THUMBPRINT_LEN] {
    let d = digest::digest(&digest::SHA256, public_key);
    let mut out = [0u8; THUMBPRINT_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATE_ID: [u8; GATE_ID_LEN] = [0x42; GATE_ID_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x11; NONCE_LEN];

    fn round_trip(suite: Suite) {
        let gate = GateKeypair::generate(suite).unwrap();
        let client = ClientKey::generate(suite).unwrap();

        let packet = client
            .seal(gate.public_key(), GATE_ID, &[22, 8443], NONCE, 1_234)
            .unwrap();

        let opened = gate.open(&packet).unwrap();
        assert_eq!(opened.auth.gate_id, GATE_ID);
        assert_eq!(opened.auth.nonce, NONCE);
        assert_eq!(opened.auth.timestamp_nanos, 1_234);
        assert_eq!(opened.auth.ports, vec![22, 8443]);
        assert_eq!(&opened.auth.key_thumbprint, client.thumbprint());

        // The signature over the recovered signing region verifies under the
        // client's public key (this is what the core's verify port will do).
        assert!(gate.verify(
            suite,
            client.public_key(),
            &opened.signing_bytes,
            &opened.auth.signature
        ));
    }

    #[test]
    fn round_trip_fips() {
        round_trip(Suite::Fips);
    }

    #[test]
    fn round_trip_modern() {
        round_trip(Suite::Modern);
    }

    #[test]
    fn thumbprint_is_sha256_of_pubkey() {
        let client = ClientKey::generate(Suite::Fips).unwrap();
        assert_eq!(client.thumbprint(), &thumbprint_of(client.public_key()));
    }

    #[test]
    fn tampered_ciphertext_fails_open() {
        let gate = GateKeypair::generate(Suite::Fips).unwrap();
        let client = ClientKey::generate(Suite::Fips).unwrap();
        let mut packet = client
            .seal(gate.public_key(), GATE_ID, &[22], NONCE, 1)
            .unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        assert!(gate.open(&packet).is_err());
    }

    #[test]
    fn tampered_header_fails_open() {
        // Header is AEAD-authenticated; flipping a byte in the ephemeral key
        // breaks the tag.
        let gate = GateKeypair::generate(Suite::Fips).unwrap();
        let client = ClientKey::generate(Suite::Fips).unwrap();
        let mut packet = client
            .seal(gate.public_key(), GATE_ID, &[22], NONCE, 1)
            .unwrap();
        packet[10] ^= 0x01;
        assert!(gate.open(&packet).is_err());
    }

    #[test]
    fn wrong_gate_cannot_open() {
        let gate = GateKeypair::generate(Suite::Fips).unwrap();
        let other_gate = GateKeypair::generate(Suite::Fips).unwrap();
        let client = ClientKey::generate(Suite::Fips).unwrap();
        let packet = client
            .seal(gate.public_key(), GATE_ID, &[22], NONCE, 1)
            .unwrap();
        assert!(other_gate.open(&packet).is_err());
    }

    #[test]
    fn suite_mismatch_fails_open() {
        // A Modern-sealed packet cannot be opened by a FIPS gate.
        let fips_gate = GateKeypair::generate(Suite::Fips).unwrap();
        let modern_gate = GateKeypair::generate(Suite::Modern).unwrap();
        let client = ClientKey::generate(Suite::Modern).unwrap();
        let packet = client
            .seal(modern_gate.public_key(), GATE_ID, &[22], NONCE, 1)
            .unwrap();
        assert!(fips_gate.open(&packet).is_err());
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let gate = GateKeypair::generate(Suite::Fips).unwrap();
        let client = ClientKey::generate(Suite::Fips).unwrap();
        let impostor = ClientKey::generate(Suite::Fips).unwrap();
        let packet = client
            .seal(gate.public_key(), GATE_ID, &[22], NONCE, 1)
            .unwrap();
        let opened = gate.open(&packet).unwrap();
        assert!(!gate.verify(
            Suite::Fips,
            impostor.public_key(),
            &opened.signing_bytes,
            &opened.auth.signature
        ));
    }

    #[test]
    fn truncated_packet_fails_open() {
        let gate = GateKeypair::generate(Suite::Fips).unwrap();
        let client = ClientKey::generate(Suite::Fips).unwrap();
        let packet = client
            .seal(gate.public_key(), GATE_ID, &[22], NONCE, 1)
            .unwrap();
        for cut in 0..packet.len() {
            assert!(gate.open(&packet[..cut]).is_err(), "len {cut}");
        }
    }
}
