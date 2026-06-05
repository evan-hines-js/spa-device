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
    // Optional: a self-provisioning gate learns its gate_id from the control plane.
    #[serde(default)]
    gate_id_hex: Option<String>,
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
    // When set, the gate self-provisions: registers its own knock identity and
    // pulls its signed bundle from the control plane (no manual curl/grep).
    #[serde(default)]
    control_plane: Option<RawControlPlane>,
}

#[derive(Deserialize)]
struct RawControlPlane {
    url: String,
    gate_token: String,
    address: String,
    /// PEM CA to trust for the control-plane TLS (private PKI). Optional; system
    /// roots are used when absent.
    #[serde(default)]
    ca_cert: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RawClient {
    pub thumbprint_hex: String,
    pub public_key_hex: String,
    pub ports: Vec<u16>,
}

#[derive(Deserialize)]
pub(crate) struct RawToken {
    pub token_id_hex: String,
    pub secret_hex: String,
    pub ports: Vec<u16>,
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

/// Control-plane endpoint for gate self-provisioning. `address` is how clients
/// reach this gate (published in the descriptor); `gate_token` authenticates the
/// gate. `url` must be HTTPS; `ca_cert` pins a private CA when set.
#[derive(Clone)]
pub struct ControlPlane {
    pub url: String,
    pub gate_token: String,
    pub address: String,
    pub ca_cert: Option<String>,
}

pub struct Config {
    pub interface: String,
    pub knock_port: u16,
    pub suite: Suite,
    pub gate_private: Vec<u8>,
    /// 16-byte gate identity. `None` when self-provisioning — fetched from the
    /// control plane at registration (so it can't be hand-pinned wrong).
    pub gate_id: Option<[u8; GATE_ID_LEN]>,
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
    pub control_plane: Option<ControlPlane>,
}

impl Config {
    pub fn load(path: &str) -> Result<Config, Box<dyn Error>> {
        let text = fs::read_to_string(path).map_err(|e| format!("reading config {path}: {e}"))?;
        let raw: Raw = toml::from_str(&text).map_err(|e| format!("parsing config {path}: {e}"))?;
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
            gate_id: match raw.gate_id_hex {
                Some(h) => Some(hex_arr::<GATE_ID_LEN>(&h, "gate_id_hex")?),
                None => None,
            },
            bpf_object: raw.bpf_object,
            pinhole_ms: raw.pinhole_ms,
            skew_seconds: raw.skew_seconds,
            nftables_floor: raw.nftables_floor,
            config_anchor,
            bundle_path: raw.bundle_path,
            protected_ports: raw.protected_ports,
            clients: parse_clients(raw.client)?,
            tokens: parse_tokens(raw.token)?,
            control_plane: match raw.control_plane {
                Some(c) => Some(parse_control_plane(c)?),
                None => None,
            },
        })
    }
}

fn parse_control_plane(c: RawControlPlane) -> Result<ControlPlane, Box<dyn Error>> {
    if !c.url.starts_with("https://") {
        return Err(format!("control_plane.url must be https:// (got {:?})", c.url).into());
    }
    Ok(ControlPlane {
        url: c.url,
        gate_token: c.gate_token,
        address: c.address,
        ca_cert: c.ca_cert,
    })
}

pub(crate) fn parse_tokens(raw: Vec<RawToken>) -> Result<Vec<TokenEntry>, Box<dyn Error>> {
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
