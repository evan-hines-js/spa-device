//! Control-plane client (DESIGN.md §6, §7): the gate self-provisions. It derives
//! its knock identity from its *own* keypair and registers it, then pulls its
//! signed bundle. This replaces hand-run `curl` + field-grepping — the gate is
//! the only authority on its own public key, so it can't report the wrong one.
//!
//! HTTPS only (`https_only`), off the packet fast path. TLS is rustls over the
//! shared `aws-lc-rs` provider — no second crypto stack. A private control-plane
//! CA can be pinned via `ca_cert`; the gate token is a bearer secret, so the
//! transport must be TLS.

use std::error::Error;
use std::time::Duration;

use crate::config::ControlPlane;

fn client(cp: &ControlPlane) -> Result<reqwest::blocking::Client, Box<dyn Error>> {
    let mut b = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(10));
    if let Some(ca) = &cp.ca_cert {
        let pem = std::fs::read(ca).map_err(|e| format!("control-plane ca_cert {ca}: {e}"))?;
        b = b.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
    }
    Ok(b.build()?)
}

/// Flatten an error's `source()` chain — reqwest's top-level message alone hides
/// the actual cause (connection refused, TLS, cert), which an operator needs.
fn chain(e: &dyn Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        s.push_str(&format!(": {c}"));
        src = c.source();
    }
    s
}

/// Report this gate's knock identity so the control plane can hand clients a
/// descriptor. `gate_pubkey_hex` is derived from the gate's own private key.
pub fn register_identity(
    cp: &ControlPlane,
    gate_pubkey_hex: &str,
    knock_port: u16,
) -> Result<(), Box<dyn Error>> {
    // Fixed-shape body of hex/IP/integer values — no escaping needed.
    let body = format!(
        "{{\"public_key_hex\":\"{gate_pubkey_hex}\",\"address\":\"{}\",\"knock_port\":{knock_port}}}",
        cp.address
    );
    let url = format!("{}/api/gate/identity", cp.url.trim_end_matches('/'));
    client(cp)?
        .post(url)
        .bearer_auth(&cp.gate_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("register identity: {}", chain(&e)))?;
    Ok(())
}

/// Fetch the gate's signed bundle and write it to `dest` (atomic rename). Returns
/// `true` if the bytes changed, so the caller can avoid a no-op hot-reload churn.
pub fn fetch_bundle(cp: &ControlPlane, dest: &str) -> Result<bool, Box<dyn Error>> {
    let url = format!("{}/api/gate/bundle", cp.url.trim_end_matches('/'));
    let bytes = client(cp)?
        .get(url)
        .bearer_auth(&cp.gate_token)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("fetch bundle: {}", chain(&e)))?
        .bytes()?;

    if std::fs::read(dest).ok().as_deref() == Some(bytes.as_ref()) {
        return Ok(false);
    }
    let tmp = format!("{dest}.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, dest)?;
    Ok(true)
}
