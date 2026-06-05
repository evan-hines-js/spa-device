//! The client catalog: the services this device may reach, fetched from the
//! control plane. The `GET` is authenticated by a signature from the device's
//! SPA key — the same key used at enrollment and to knock — so there is no bearer
//! secret. Each entry carries a stable `mesh_ip` and, per endpoint, the exact
//! knock descriptor + the real `address:port` to forward to. See
//! argus-questions/006.

use std::error::Error;
use std::time::Duration;

use serde::Deserialize;
use spa_client::{parse_suite, Knocker};
use spa_common::GATE_ID_LEN;
use spa_crypto::ClientKey;

#[derive(Debug, Deserialize)]
pub struct Catalog {
    pub device: Device,
    pub mesh_cidr: String,
    #[serde(default)]
    pub services: Vec<Service>,
}

#[derive(Debug, Deserialize)]
pub struct Device {
    pub name: String,
    pub thumbprint: String,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub name: String,
    pub mesh_ip: String,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Deserialize)]
pub struct Endpoint {
    pub protocol: String,
    pub port: u16,
    pub address: String,
    pub descriptor: Descriptor,
}

/// Exactly the `knock-descriptor` shape — the agent feeds this straight into the
/// knock path.
#[derive(Debug, Deserialize)]
pub struct Descriptor {
    pub gate_id_hex: String,
    pub gate_pubkey_hex: String,
    pub suite: String,
    pub address: String,
    pub knock_port: u16,
}

impl Endpoint {
    /// Build the [`Knocker`] for this endpoint's gate (from the device's PKCS#8
    /// key) plus the `host:port` knock target. The per-flow datapath calls this,
    /// then `knocker.knock(target, &[self.port])` before forwarding the flow.
    pub fn knocker(&self, client_pkcs8: &[u8]) -> Result<(Knocker, String), Box<dyn Error>> {
        let d = &self.descriptor;
        let knocker = Knocker::new(
            parse_suite(&d.suite)?,
            hex::decode(&d.gate_pubkey_hex)?,
            gate_id_arr(&d.gate_id_hex)?,
            client_pkcs8,
        )?;
        // Bracket a bare IPv6 literal so `host:port` parses.
        let target = if d.address.contains(':') {
            format!("[{}]:{}", d.address, d.knock_port)
        } else {
            format!("{}:{}", d.address, d.knock_port)
        };
        Ok((knocker, target))
    }
}

fn gate_id_arr(s: &str) -> Result<[u8; GATE_ID_LEN], Box<dyn Error>> {
    let b = hex::decode(s)?;
    if b.len() != GATE_ID_LEN {
        return Err(format!("gate_id_hex: expected {GATE_ID_LEN} bytes, got {}", b.len()).into());
    }
    let mut a = [0u8; GATE_ID_LEN];
    a.copy_from_slice(&b);
    Ok(a)
}

const PATH: &str = "/api/client/catalog";

/// The exact bytes the device signs to authenticate a catalog `GET`: method,
/// path, and timestamp, newline-joined (argus-questions/006). Pinned by a test —
/// this is a cross-impl contract with Argus.
pub fn signing_message(timestamp: u64) -> String {
    format!("GET\n{PATH}\n{timestamp}")
}

/// Fetch the catalog, authenticating with a fresh signature over
/// [`signing_message`]. `timestamp` is unix seconds (passed in for testability);
/// `ca_cert` pins a private control-plane CA.
pub fn fetch(
    argus_url: &str,
    ca_cert: Option<&str>,
    key: &ClientKey,
    timestamp: u64,
) -> Result<Catalog, Box<dyn Error>> {
    let signature = hex::encode(key.sign_detached(signing_message(timestamp).as_bytes())?);
    let thumbprint = hex::encode(key.thumbprint());

    let mut builder = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(10));
    if let Some(ca) = ca_cert {
        let pem = std::fs::read(ca).map_err(|e| format!("catalog ca_cert {ca}: {e}"))?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
    }
    let url = format!("{}{PATH}", argus_url.trim_end_matches('/'));
    let bytes = builder
        .build()?
        .get(url)
        .header("x-spa-thumbprint", thumbprint)
        .header("x-spa-timestamp", timestamp.to_string())
        .header("x-spa-signature", signature)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("fetch catalog: {}", chain(&e)))?
        .bytes()?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Flatten an error's `source()` chain — reqwest's top-level message hides the
/// real cause (connection refused, TLS, cert, 401), which an operator needs.
fn chain(e: &dyn Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        s.push_str(&format!(": {c}"));
        src = c.source();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_message_is_the_pinned_contract() {
        assert_eq!(
            signing_message(1_700_000_000),
            "GET\n/api/client/catalog\n1700000000"
        );
    }

    #[test]
    fn catalog_parses_the_spec_shape() {
        let json = r#"{
          "device":   { "name": "macos", "thumbprint": "85aa" },
          "mesh_cidr": "100.64.0.0/10",
          "services": [
            {
              "name": "demo-svc",
              "mesh_ip": "100.64.0.1",
              "endpoints": [
                { "protocol": "tcp", "port": 9999, "address": "10.0.0.59",
                  "descriptor": { "gate_id_hex": "bee2", "gate_pubkey_hex": "ab",
                    "suite": "modern", "address": "10.0.0.59", "knock_port": 62201 } }
              ]
            }
          ]
        }"#;
        let c: Catalog = serde_json::from_str(json).unwrap();
        assert_eq!(c.mesh_cidr, "100.64.0.0/10");
        assert_eq!(c.services.len(), 1);
        let s = &c.services[0];
        assert_eq!(s.name, "demo-svc");
        assert_eq!(s.mesh_ip, "100.64.0.1");
        assert_eq!(s.endpoints[0].port, 9999);
        assert_eq!(s.endpoints[0].descriptor.knock_port, 62201);
        assert_eq!(s.endpoints[0].descriptor.suite, "modern");
    }

    #[test]
    fn endpoint_builds_a_knocker_and_target() {
        let client = spa_crypto::ClientKey::generate(spa_common::Suite::Modern).unwrap();
        let pkcs8 = client.to_pkcs8().unwrap();
        let gate = spa_crypto::GateKeypair::generate(spa_common::Suite::Modern).unwrap();
        let ep = Endpoint {
            protocol: "tcp".into(),
            port: 22,
            address: "10.0.0.59".into(),
            descriptor: Descriptor {
                gate_id_hex: hex::encode([7u8; GATE_ID_LEN]),
                gate_pubkey_hex: hex::encode(gate.public_key()),
                suite: "modern".into(),
                address: "10.0.0.59".into(),
                knock_port: 62201,
            },
        };
        let (_knocker, target) = ep.knocker(&pkcs8).unwrap();
        assert_eq!(target, "10.0.0.59:62201");
    }

    #[test]
    fn services_default_to_empty_when_absent() {
        let c: Catalog = serde_json::from_str(
            r#"{ "device": { "name": "m", "thumbprint": "x" }, "mesh_cidr": "100.64.0.0/10" }"#,
        )
        .unwrap();
        assert!(c.services.is_empty());
    }
}
