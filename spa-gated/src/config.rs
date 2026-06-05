//! Daemon bootstrap configuration (local TOML).
//!
//! The static crypto/interface bits live here. The dynamic policy (authorized
//! clients + protected ports) can either be inline here (static mode) or come
//! from a signed [`crate::bundle`] when `config_anchor_hex` + `bundle_path` are
//! set — that is the hot-reloaded, anti-rollback path of DESIGN.md §7.

use std::error::Error;
use std::fs;

use serde::Deserialize;
use spa_common::{Suite, GATE_ID_LEN, THUMBPRINT_LEN};

#[derive(Deserialize)]
struct Raw {
    interface: String,
    knock_port: u16,
    suite: String,
    gate_private_hex: String,
    gate_id_hex: String,
    bpf_object: String,
    #[serde(default = "default_pinhole")]
    pinhole_ms: u64,
    #[serde(default = "default_skew")]
    skew_seconds: u64,
    #[serde(default = "default_true")]
    nftables_floor: bool,
    // When both are set, dynamic policy comes from the signed bundle instead of
    // the inline `protected_ports` / `client` fields.
    #[serde(default)]
    config_anchor_hex: Option<String>,
    #[serde(default)]
    bundle_path: Option<String>,
    #[serde(default)]
    protected_ports: Vec<u16>,
    #[serde(default)]
    client: Vec<RawClient>,
    #[serde(default)]
    token: Vec<RawToken>,
}

#[derive(Deserialize)]
pub(crate) struct RawClient {
    pub thumbprint_hex: String,
    pub public_key_hex: String,
    pub ports: Vec<u16>,
}

#[derive(Deserialize)]
struct RawToken {
    token_id_hex: String,
    secret_hex: String,
    ports: Vec<u16>,
}

fn default_pinhole() -> u64 {
    400
}
fn default_skew() -> u64 {
    2
}
fn default_true() -> bool {
    true
}

/// An authorized client: its key thumbprint, public key, and permitted ports.
#[derive(Clone)]
pub struct ClientEntry {
    pub thumbprint: [u8; THUMBPRINT_LEN],
    pub public_key: Vec<u8>,
    pub ports: Vec<u16>,
}

/// A one-time PSK enrollment token: its id, shared secret, and permitted ports.
#[derive(Clone)]
pub struct TokenEntry {
    pub token_id: [u8; THUMBPRINT_LEN],
    pub secret: Vec<u8>,
    pub ports: Vec<u16>,
}

pub struct Config {
    pub interface: String,
    pub knock_port: u16,
    pub suite: Suite,
    pub gate_private: Vec<u8>,
    pub gate_id: [u8; GATE_ID_LEN],
    pub bpf_object: String,
    pub pinhole_ms: u64,
    pub skew_seconds: u64,
    pub nftables_floor: bool,
    /// Pinned control-plane signing public key (Ed25519) for verifying bundles.
    pub config_anchor: Option<Vec<u8>>,
    pub bundle_path: Option<String>,
    pub protected_ports: Vec<u16>,
    pub clients: Vec<ClientEntry>,
    pub tokens: Vec<TokenEntry>,
}

impl Config {
    pub fn load(path: &str) -> Result<Config, Box<dyn Error>> {
        let raw: Raw = toml::from_str(&fs::read_to_string(path)?)?;
        let suite = match raw.suite.as_str() {
            "fips" => Suite::Fips,
            "modern" => Suite::Modern,
            other => return Err(format!("unknown suite {other:?}").into()),
        };
        let config_anchor = match raw.config_anchor_hex {
            Some(h) => Some(hex::decode(&h).map_err(|e| format!("config_anchor_hex: {e}"))?),
            None => None,
        };
        Ok(Config {
            interface: raw.interface,
            knock_port: raw.knock_port,
            suite,
            gate_private: hex_len(&raw.gate_private_hex, 32, "gate_private_hex")?,
            gate_id: hex_arr::<GATE_ID_LEN>(&raw.gate_id_hex, "gate_id_hex")?,
            bpf_object: raw.bpf_object,
            pinhole_ms: raw.pinhole_ms,
            skew_seconds: raw.skew_seconds,
            nftables_floor: raw.nftables_floor,
            config_anchor,
            bundle_path: raw.bundle_path,
            protected_ports: raw.protected_ports,
            clients: parse_clients(raw.client)?,
            tokens: parse_tokens(raw.token)?,
        })
    }
}

fn parse_tokens(raw: Vec<RawToken>) -> Result<Vec<TokenEntry>, Box<dyn Error>> {
    let mut out = Vec::with_capacity(raw.len());
    for t in raw {
        out.push(TokenEntry {
            token_id: hex_arr::<THUMBPRINT_LEN>(&t.token_id_hex, "token_id_hex")?,
            secret: hex::decode(&t.secret_hex).map_err(|e| format!("secret_hex: {e}"))?,
            ports: t.ports,
        });
    }
    Ok(out)
}

pub(crate) fn parse_clients(raw: Vec<RawClient>) -> Result<Vec<ClientEntry>, Box<dyn Error>> {
    let mut out = Vec::with_capacity(raw.len());
    for c in raw {
        out.push(ClientEntry {
            thumbprint: hex_arr::<THUMBPRINT_LEN>(&c.thumbprint_hex, "thumbprint_hex")?,
            public_key: hex::decode(&c.public_key_hex)
                .map_err(|e| format!("public_key_hex: {e}"))?,
            ports: c.ports,
        });
    }
    Ok(out)
}

fn hex_len(s: &str, n: usize, what: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let b = hex::decode(s).map_err(|e| format!("{what}: {e}"))?;
    if b.len() != n {
        return Err(format!("{what}: expected {n} bytes, got {}", b.len()).into());
    }
    Ok(b)
}

fn hex_arr<const N: usize>(s: &str, what: &str) -> Result<[u8; N], Box<dyn Error>> {
    let mut a = [0u8; N];
    a.copy_from_slice(&hex_len(s, N, what)?);
    Ok(a)
}
