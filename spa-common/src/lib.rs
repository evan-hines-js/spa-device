//! SPA wire-format contract.
//!
//! This crate defines the byte layout of the authorization that travels inside
//! every SPA knock, plus bounds-checked encode/decode. It performs **no
//! crypto** — the AEAD envelope, signing, and verification live in the crates
//! that depend on this one (`spa-device`, `spa-client`) and use `aws-lc-rs`.
//! Keeping the parser dependency-free and small is deliberate: it is the most
//! security-critical untrusted-input surface in the system and must be readable
//! by an auditor in one sitting. See `DESIGN.md` §4.

#![forbid(unsafe_code)]

/// Wire-format version. Bumped on any breaking layout change.
pub const VERSION: u8 = 1;

pub const NONCE_LEN: usize = 16;
pub const GATE_ID_LEN: usize = 16;
/// Length of a key thumbprint: the **raw SHA-256 of the public-key bytes**
/// (Ed25519 = the 32-byte key; ECDSA P-256 = the 65-byte uncompressed point
/// `0x04‖X‖Y`). NOT an RFC 7638 JWK thumbprint. This exact construction is the
/// cross-implementation interop contract with the control plane.
pub const THUMBPRINT_LEN: usize = 32;
/// Raw (r‖s for ECDSA P-256, or Ed25519) signature over the signing region.
pub const SIG_LEN: usize = 64;
/// Upper bound on ports a single knock may request — caps packet size and
/// blast radius. A valid knock requests 1..=MAX_PORTS ports.
pub const MAX_PORTS: usize = 8;

/// Cipher suite selector, carried in the outer envelope so the gate knows how
/// to decrypt before decrypting. Defined here because both endpoints share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// ECDH P-256 / AES-256-GCM / ECDSA P-256. FIPS profile, the default.
    Fips,
    /// X25519 / ChaCha20-Poly1305 / Ed25519. High-throughput, non-FIPS.
    Modern,
}

impl Suite {
    pub fn to_byte(self) -> u8 {
        match self {
            Suite::Fips => 0x01,
            Suite::Modern => 0x02,
        }
    }

    pub fn from_byte(b: u8) -> Result<Suite, WireError> {
        match b {
            0x01 => Ok(Suite::Fips),
            0x02 => Ok(Suite::Modern),
            _ => Err(WireError::BadSuite(b)),
        }
    }
}

/// Errors from decoding untrusted input. No variant carries attacker-controlled
/// data beyond the offending byte, to keep error handling side-effect-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Buffer ended before a field could be read.
    TooShort,
    /// Unknown wire-format version.
    BadVersion(u8),
    /// Unknown cipher-suite byte.
    BadSuite(u8),
    /// Port count was 0 or exceeded `MAX_PORTS`.
    BadPortCount(usize),
    /// Bytes remained after a complete authorization was parsed.
    TrailingBytes,
}

/// The authorization carried inside the encrypted SPA knock.
///
/// Layout of the plaintext (before AEAD encryption):
/// ```text
/// version(1) | nonce(16) | timestamp(8, BE ns) | gate_id(16)
///   | key_thumbprint(32) | port_count(1) | ports(2*count, BE) | signature(64)
/// ```
/// The `signature` covers every preceding byte (the *signing region*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// Per-packet random nonce; gate keeps a seen-set for anti-replay.
    pub nonce: [u8; NONCE_LEN],
    /// Client clock at send time, nanoseconds since the Unix epoch. The gate
    /// rejects values outside a tight skew window.
    pub timestamp_nanos: u64,
    /// Identity of the gate this knock is for — binds the packet to one gate so
    /// a capture cannot be relayed to another (anti-relay).
    pub gate_id: [u8; GATE_ID_LEN],
    /// Thumbprint of the client's PoP key; the gate checks the signature
    /// against, and authorizes via, this key.
    pub key_thumbprint: [u8; THUMBPRINT_LEN],
    /// Ports the client is requesting be opened. 1..=MAX_PORTS.
    pub ports: Vec<u16>,
    /// Signature over the signing region (everything above).
    pub signature: [u8; SIG_LEN],
}

impl Authorization {
    /// The exact bytes a signer signs / a verifier checks: the full encoding
    /// minus the trailing signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        let n = self.ports.len();
        if n == 0 || n > MAX_PORTS {
            return Err(WireError::BadPortCount(n));
        }
        let mut out =
            Vec::with_capacity(1 + NONCE_LEN + 8 + GATE_ID_LEN + THUMBPRINT_LEN + 1 + 2 * n);
        out.push(VERSION);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.timestamp_nanos.to_be_bytes());
        out.extend_from_slice(&self.gate_id);
        out.extend_from_slice(&self.key_thumbprint);
        out.push(n as u8);
        for p in &self.ports {
            out.extend_from_slice(&p.to_be_bytes());
        }
        Ok(out)
    }

    /// Full plaintext encoding (signing region followed by the signature).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = self.signing_bytes()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Parse a decrypted plaintext into an `Authorization`, rejecting any
    /// malformed, truncated, or over-long input.
    pub fn decode(buf: &[u8]) -> Result<Authorization, WireError> {
        let mut r = Reader::new(buf);

        let version = r.u8()?;
        if version != VERSION {
            return Err(WireError::BadVersion(version));
        }
        let nonce = r.array::<NONCE_LEN>()?;
        let timestamp_nanos = r.u64()?;
        let gate_id = r.array::<GATE_ID_LEN>()?;
        let key_thumbprint = r.array::<THUMBPRINT_LEN>()?;

        let count = r.u8()? as usize;
        if count == 0 || count > MAX_PORTS {
            return Err(WireError::BadPortCount(count));
        }
        let mut ports = Vec::with_capacity(count);
        for _ in 0..count {
            ports.push(r.u16()?);
        }

        let signature = r.array::<SIG_LEN>()?;
        if r.remaining() != 0 {
            return Err(WireError::TrailingBytes);
        }

        Ok(Authorization {
            nonce,
            timestamp_nanos,
            gate_id,
            key_thumbprint,
            ports,
            signature,
        })
    }
}

/// Minimal forward-only reader. Every read is bounds-checked; there is no
/// indexing and no `unsafe`, so a short or hostile buffer can only ever produce
/// `WireError::TooShort`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::TooShort)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::TooShort)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(a))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Authorization {
        Authorization {
            nonce: [7u8; NONCE_LEN],
            timestamp_nanos: 0x0102_0304_0506_0708,
            gate_id: [9u8; GATE_ID_LEN],
            key_thumbprint: [0xAB; THUMBPRINT_LEN],
            ports: vec![22, 8443],
            signature: [0xCD; SIG_LEN],
        }
    }

    #[test]
    fn round_trip() {
        let a = sample();
        let bytes = a.encode().unwrap();
        let b = Authorization::decode(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn signing_bytes_excludes_signature() {
        let a = sample();
        let signing = a.signing_bytes().unwrap();
        let full = a.encode().unwrap();
        assert_eq!(full.len(), signing.len() + SIG_LEN);
        assert_eq!(&full[..signing.len()], signing.as_slice());
    }

    #[test]
    fn truncated_is_rejected() {
        let bytes = sample().encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(
                Authorization::decode(&bytes[..cut]).is_err(),
                "len {cut} should fail"
            );
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = sample().encode().unwrap();
        bytes.push(0);
        assert_eq!(Authorization::decode(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn bad_version_rejected() {
        let mut bytes = sample().encode().unwrap();
        bytes[0] = VERSION + 1;
        assert_eq!(
            Authorization::decode(&bytes),
            Err(WireError::BadVersion(VERSION + 1))
        );
    }

    #[test]
    fn zero_ports_rejected() {
        let mut a = sample();
        a.ports.clear();
        assert_eq!(a.encode(), Err(WireError::BadPortCount(0)));
    }

    #[test]
    fn too_many_ports_rejected() {
        let mut a = sample();
        a.ports = vec![1; MAX_PORTS + 1];
        assert_eq!(a.encode(), Err(WireError::BadPortCount(MAX_PORTS + 1)));
    }

    #[test]
    fn max_ports_ok() {
        let mut a = sample();
        a.ports = (0..MAX_PORTS as u16).collect();
        let bytes = a.encode().unwrap();
        assert_eq!(
            Authorization::decode(&bytes).unwrap().ports.len(),
            MAX_PORTS
        );
    }

    #[test]
    fn suite_round_trips() {
        for s in [Suite::Fips, Suite::Modern] {
            assert_eq!(Suite::from_byte(s.to_byte()).unwrap(), s);
        }
        assert_eq!(Suite::from_byte(0xFF), Err(WireError::BadSuite(0xFF)));
    }
}
