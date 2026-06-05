#![forbid(unsafe_code)]
//! spa-agent — the workstation client agent. Reach mesh services by name instead
//! of hand-running `knock-descriptor`: fetch the device's signed service catalog,
//! then (TUN datapath, in progress) knock each service's gate per flow and forward
//! through the pinhole. Cross-platform userland; the counterpart to `spa-gated`.
//!
//!   spa-agent catalog <client.key> <suite> <argus-url> [ca_cert]   # list reachable services

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use spa_agent::catalog;
use spa_client::parse_suite;
use spa_crypto::ClientKey;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("catalog") => catalog_cmd(
            args.get(2)
                .ok_or("usage: catalog <client.key> <suite> <argus-url> [ca_cert]")?,
            args.get(3)
                .ok_or("usage: catalog <client.key> <suite> <argus-url> [ca_cert]")?,
            args.get(4)
                .ok_or("usage: catalog <client.key> <suite> <argus-url> [ca_cert]")?,
            args.get(5).map(String::as_str),
        ),
        _ => {
            eprintln!("usage: spa-agent catalog <client.key> <suite> <argus-url> [ca_cert]");
            Ok(())
        }
    }
}

/// List the services this device may reach (the signed catalog GET).
fn catalog_cmd(
    key_file: &str,
    suite_name: &str,
    argus_url: &str,
    ca_cert: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let suite = parse_suite(suite_name)?;
    let pkcs8 = hex::decode(std::fs::read_to_string(key_file)?.trim())
        .map_err(|e| format!("client key {key_file}: {e}"))?;
    let key = ClientKey::from_pkcs8(suite, &pkcs8)?;

    // Pin the control-plane TLS to our aws-lc-rs provider (no second crypto stack).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let cat = catalog::fetch(argus_url, ca_cert, &key, now)?;

    println!(
        "device {} ({})  mesh {}",
        cat.device.name, cat.device.thumbprint, cat.mesh_cidr
    );
    if cat.services.is_empty() {
        println!("  (no reachable services — check policy)");
    }
    for s in &cat.services {
        println!("  {}  ->  {}", s.name, s.mesh_ip);
        for e in &s.endpoints {
            println!(
                "      {}/{}  via gate {} (knock {})",
                e.protocol, e.port, e.descriptor.address, e.descriptor.knock_port
            );
        }
    }
    Ok(())
}
