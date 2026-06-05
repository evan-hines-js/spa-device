//! SPA knock client library — embed this to open a cloaked port before you
//! connect.
//!
//! ```no_run
//! use spa_client::Knocker;
//! # fn run() -> Result<(), spa_client::Error> {
//! // Provisioned out of band (enrollment/config), or loaded from a keygen file:
//! let (knocker, ports) = Knocker::from_knock_file("demo.knock")?;
//! knocker.knock("gate.example:62201", &ports)?; // those ports are now reachable from us
//! // ...now connect to the service as usual...
//! # Ok(()) }
//! ```
//!
//! For production, build a [`Knocker`] with [`Knocker::new`] from material your
//! control plane provisioned (the gate's public key + id, and your client key as
//! PKCS#8). The one-time-token bootstrap is [`Enroller`].

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

pub use spa_common::Suite;
use spa_common::{GATE_ID_LEN, THUMBPRINT_LEN};
use spa_crypto::{seal_psk, ClientKey, KnockRequest};

/// Errors from building or sending a knock.
#[derive(Debug)]
pub enum Error {
    Crypto(spa_crypto::CryptoError),
    Io(std::io::Error),
    Format(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto(e) => write!(f, "crypto: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Format(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<spa_crypto::CryptoError> for Error {
    fn from(e: spa_crypto::CryptoError) -> Self {
        Error::Crypto(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Parse a cipher-suite name (`"fips"` | `"modern"`).
pub fn parse_suite(s: &str) -> Result<Suite, Error> {
    match s {
        "fips" => Ok(Suite::Fips),
        "modern" => Ok(Suite::Modern),
        other => Err(Error::Format(format!(
            "unknown suite {other:?} (use fips|modern)"
        ))),
    }
}

/// A configured client: which gate to knock, and the identity to knock with.
pub struct Knocker {
    gate_pubkey: Vec<u8>,
    gate_id: [u8; GATE_ID_LEN],
    client: ClientKey,
}

impl Knocker {
    /// Build from provisioned material: the gate's public key and 16-byte id,
    /// and your client signing key as PKCS#8 (suite must match the gate's).
    pub fn new(
        suite: Suite,
        gate_pubkey: Vec<u8>,
        gate_id: [u8; GATE_ID_LEN],
        client_pkcs8: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            gate_pubkey,
            gate_id,
            client: ClientKey::from_pkcs8(suite, client_pkcs8)?,
        })
    }

    /// Load from a `spa-client keygen`-produced `.knock` file. Returns the
    /// knocker and the ports the file requests.
    pub fn from_knock_file(path: &str) -> Result<(Self, Vec<u16>), Error> {
        let kv = read_kv(path)?;
        let knocker = Self::new(
            parse_suite(get(&kv, "suite")?)?,
            hexd(get(&kv, "gate_pubkey_hex")?)?,
            arr(get(&kv, "gate_id_hex")?)?,
            &hexd(get(&kv, "client_pkcs8_hex")?)?,
        )?;
        Ok((knocker, vec![port(&kv)?]))
    }

    /// Seal a knock requesting `ports` (with a fresh nonce + current timestamp).
    pub fn seal(&self, ports: &[u16]) -> Result<Vec<u8>, Error> {
        let req = KnockRequest {
            gate_id: self.gate_id,
            ports,
            nonce: random()?,
            timestamp_nanos: now_nanos()?,
        };
        Ok(self.client.seal(&self.gate_pubkey, &req)?)
    }

    /// Seal and send one knock to `target` (`"host:port"` or `"[v6]:port"`).
    pub fn knock(&self, target: &str, ports: &[u16]) -> Result<(), Error> {
        send_udp(&self.seal(ports)?, target)
    }
}

/// A one-time-token enrollment client: the bootstrap knock for an endpoint that
/// has no registered key yet. The token authenticates a single knock and is
/// burned by the gate on use.
pub struct Enroller {
    suite: Suite,
    gate_pubkey: Vec<u8>,
    gate_id: [u8; GATE_ID_LEN],
    token_id: [u8; THUMBPRINT_LEN],
    secret: Vec<u8>,
}

impl Enroller {
    pub fn new(
        suite: Suite,
        gate_pubkey: Vec<u8>,
        gate_id: [u8; GATE_ID_LEN],
        token_id: [u8; THUMBPRINT_LEN],
        secret: Vec<u8>,
    ) -> Self {
        Self {
            suite,
            gate_pubkey,
            gate_id,
            token_id,
            secret,
        }
    }

    /// Gate info from a `.knock` file, the one-time token from an `.enroll` file.
    pub fn from_files(knock_file: &str, enroll_file: &str) -> Result<(Self, Vec<u16>), Error> {
        let g = read_kv(knock_file)?;
        let e = read_kv(enroll_file)?;
        let enroller = Self::new(
            parse_suite(get(&g, "suite")?)?,
            hexd(get(&g, "gate_pubkey_hex")?)?,
            arr(get(&g, "gate_id_hex")?)?,
            arr(get(&e, "token_id_hex")?)?,
            hexd(get(&e, "secret_hex")?)?,
        );
        Ok((enroller, vec![port(&g)?]))
    }

    /// Seal and send one PSK enrollment knock.
    pub fn knock(&self, target: &str, ports: &[u16]) -> Result<(), Error> {
        let req = KnockRequest {
            gate_id: self.gate_id,
            ports,
            nonce: random()?,
            timestamp_nanos: now_nanos()?,
        };
        let packet = seal_psk(
            &self.gate_pubkey,
            self.suite,
            &self.secret,
            self.token_id,
            &req,
        )?;
        send_udp(&packet, target)
    }
}

// ---- helpers ----------------------------------------------------------------

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| Error::Format("rng failed".into()))?;
    Ok(b)
}

fn now_nanos() -> Result<u64, Error> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Format("system clock before epoch".into()))?
        .as_nanos() as u64)
}

fn send_udp(packet: &[u8], target: &str) -> Result<(), Error> {
    let addr = target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Format("could not resolve target".into()))?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    UdpSocket::bind(bind)?.send_to(packet, addr)?;
    Ok(())
}

fn read_kv(path: &str) -> Result<HashMap<String, String>, Error> {
    let mut kv = HashMap::new();
    for line in fs::read_to_string(path)?.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(kv)
}

fn get<'a>(kv: &'a HashMap<String, String>, k: &str) -> Result<&'a str, Error> {
    kv.get(k)
        .map(String::as_str)
        .ok_or_else(|| Error::Format(format!("missing {k}")))
}

fn port(kv: &HashMap<String, String>) -> Result<u16, Error> {
    get(kv, "port")?
        .parse()
        .map_err(|_| Error::Format("invalid port".into()))
}

fn hexd(s: &str) -> Result<Vec<u8>, Error> {
    hex::decode(s).map_err(|e| Error::Format(format!("bad hex: {e}")))
}

fn arr<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    let v = hexd(s)?;
    if v.len() != N {
        return Err(Error::Format(format!(
            "expected {N} bytes, got {}",
            v.len()
        )));
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}
