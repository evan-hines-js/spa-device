//! SPA knock client + dev keygen.
//!
//!   spa-client keygen <prefix>          # write <prefix>.gate.toml + <prefix>.knock
//!   spa-client knock <addr:port> <file> # seal and send one knock
//!
//! `keygen` provisions a Modern-suite gate key + one client key and emits both
//! the daemon's crypto config and the client's knock material.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use spa_common::{Suite, GATE_ID_LEN, NONCE_LEN};
use spa_crypto::{ClientKey, GateKeypair};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(
            args.get(2).ok_or("usage: keygen <prefix> [fips|modern]")?,
            args.get(3).map(String::as_str).unwrap_or("modern"),
        ),
        Some("knock") => knock(
            args.get(2).ok_or("usage: knock <addr:port> <file>")?,
            args.get(3).ok_or("usage: knock <addr:port> <file>")?,
        ),
        Some("gen-anchor") => gen_anchor(args.get(2).ok_or("usage: gen-anchor <prefix>")?),
        Some("sign-bundle") => sign_bundle(
            args.get(2)
                .ok_or("usage: sign-bundle <anchor.key> <payload.toml> <out.bundle>")?,
            args.get(3)
                .ok_or("usage: sign-bundle <anchor.key> <payload.toml> <out.bundle>")?,
            args.get(4)
                .ok_or("usage: sign-bundle <anchor.key> <payload.toml> <out.bundle>")?,
        ),
        _ => {
            eprintln!(
                "usage: spa-client [keygen <prefix> | knock <addr:port> <file> | \
                 gen-anchor <prefix> | sign-bundle <anchor.key> <payload.toml> <out.bundle>]"
            );
            Ok(())
        }
    }
}

/// Generate a control-plane anchor keypair: writes the private key and prints
/// the public key to pin in the daemon's `config_anchor_hex`.
fn gen_anchor(prefix: &str) -> Result<(), Box<dyn Error>> {
    let anchor = ClientKey::generate(Suite::Modern)?;
    fs::write(
        format!("{prefix}.anchor.key"),
        hex::encode(anchor.to_pkcs8()?),
    )?;
    println!("anchor_pubkey_hex={}", hex::encode(anchor.public_key()));
    println!("wrote {prefix}.anchor.key");
    Ok(())
}

/// Sign a policy bundle: out = raw 64-byte signature ‖ payload bytes.
fn sign_bundle(keyfile: &str, payload: &str, out: &str) -> Result<(), Box<dyn Error>> {
    let pkcs8 = hex::decode(fs::read_to_string(keyfile)?.trim())?;
    let anchor = ClientKey::from_pkcs8(Suite::Modern, &pkcs8)?;
    let body = fs::read(payload)?;
    let mut bundle = anchor.sign_detached(&body)?;
    bundle.extend_from_slice(&body);
    fs::write(out, &bundle)?;
    println!("signed {payload} -> {out} ({} bytes)", bundle.len());
    Ok(())
}

fn random<const N: usize>() -> Result<[u8; N], Box<dyn Error>> {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| "rng failed")?;
    Ok(b)
}

fn keygen(prefix: &str, suite_name: &str) -> Result<(), Box<dyn Error>> {
    let suite = parse_suite(suite_name)?;
    let (gate, gate_raw) = GateKeypair::generate_raw(suite)?;
    let client = ClientKey::generate(suite)?;
    let pkcs8 = client.to_pkcs8()?;
    let gate_id: [u8; GATE_ID_LEN] = random()?;
    let port = 9999u16;

    fs::write(
        format!("{prefix}.gate.toml"),
        format!(
            "suite = \"{suite_name}\"\n\
             gate_private_hex = \"{}\"\n\
             gate_id_hex = \"{}\"\n\n\
             [[client]]\n\
             thumbprint_hex = \"{}\"\n\
             public_key_hex = \"{}\"\n\
             ports = [{port}]\n",
            hex::encode(gate_raw),
            hex::encode(gate_id),
            hex::encode(client.thumbprint()),
            hex::encode(client.public_key()),
        ),
    )?;

    fs::write(
        format!("{prefix}.knock"),
        format!(
            "suite={suite_name}\n\
             gate_pubkey_hex={}\n\
             gate_id_hex={}\n\
             client_pkcs8_hex={}\n\
             port={port}\n",
            hex::encode(gate.public_key()),
            hex::encode(gate_id),
            hex::encode(&pkcs8),
        ),
    )?;

    println!("wrote {prefix}.gate.toml and {prefix}.knock (suite={suite_name}, port={port})");
    Ok(())
}

fn parse_suite(s: &str) -> Result<Suite, Box<dyn Error>> {
    match s {
        "fips" => Ok(Suite::Fips),
        "modern" => Ok(Suite::Modern),
        other => Err(format!("unknown suite {other:?} (use fips|modern)").into()),
    }
}

fn knock(target: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let mut kv = HashMap::new();
    let text = fs::read_to_string(file)?;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let get = |k: &str| kv.get(k).cloned().ok_or_else(|| format!("missing {k}"));

    let gate_pubkey = hex::decode(get("gate_pubkey_hex")?)?;
    let gate_id_v = hex::decode(get("gate_id_hex")?)?;
    if gate_id_v.len() != GATE_ID_LEN {
        return Err("gate_id must be 16 bytes".into());
    }
    let mut gate_id = [0u8; GATE_ID_LEN];
    gate_id.copy_from_slice(&gate_id_v);
    let pkcs8 = hex::decode(get("client_pkcs8_hex")?)?;
    let port: u16 = get("port")?.parse()?;
    let suite = parse_suite(&get("suite")?)?;

    let client = ClientKey::from_pkcs8(suite, &pkcs8)?;
    let nonce: [u8; NONCE_LEN] = random()?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let packet = client.seal(&gate_pubkey, gate_id, &[port], nonce, ts)?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.send_to(&packet, target)?;
    println!(
        "sent {}-byte knock to {target} (requesting port {port})",
        packet.len()
    );
    Ok(())
}
