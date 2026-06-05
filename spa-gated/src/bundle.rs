//! Signed config bundle (DESIGN.md §4, §7).
//!
//! A bundle file is `raw Ed25519 signature (64 bytes) ‖ TOML payload`. The
//! payload carries a monotonic `generation`, the protected ports, and the
//! authorized clients. The daemon verifies the signature against the pinned
//! anchor (trust the signature, not the channel) and rejects non-increasing
//! generations (anti-rollback). The control plane produces these; for dev,
//! `spa-client sign-bundle` does.

use std::error::Error;

use serde::Deserialize;
use spa_common::Suite;

use crate::config::{parse_clients, parse_tokens, ClientEntry, RawClient, RawToken, TokenEntry};

/// Raw signature length (Ed25519).
const SIG_LEN: usize = 64;

pub struct Bundle {
    pub generation: u64,
    pub protected_ports: Vec<u16>,
    pub clients: Vec<ClientEntry>,
    pub tokens: Vec<TokenEntry>,
}

#[derive(Deserialize)]
struct RawBundle {
    generation: u64,
    #[serde(default)]
    protected_ports: Vec<u16>,
    #[serde(default)]
    client: Vec<RawClient>,
    #[serde(default)]
    token: Vec<RawToken>,
}

/// Read, verify (signature against `anchor_pubkey`), and parse a bundle file.
pub fn load_verify(path: &str, anchor_pubkey: &[u8]) -> Result<Bundle, Box<dyn Error>> {
    let data = std::fs::read(path)?;
    if data.len() < SIG_LEN {
        return Err("bundle shorter than its signature".into());
    }
    let (sig, body) = data.split_at(SIG_LEN);
    if !spa_crypto::verify_signature(Suite::Modern, anchor_pubkey, body, sig) {
        return Err("bundle signature invalid".into());
    }
    let raw: RawBundle = toml::from_str(std::str::from_utf8(body)?)?;
    Ok(Bundle {
        generation: raw.generation,
        protected_ports: raw.protected_ports,
        clients: parse_clients(raw.client)?,
        tokens: parse_tokens(raw.token)?,
    })
}
