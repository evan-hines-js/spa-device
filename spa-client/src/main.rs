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
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use spa_common::{Suite, GATE_ID_LEN, NONCE_LEN, THUMBPRINT_LEN};
use spa_crypto::{seal_psk, ClientKey, GateKeypair, KnockRequest};

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
        Some("gen-token") => gen_token(args.get(2).ok_or("usage: gen-token <prefix>")?),
        Some("enroll-knock") => enroll_knock(
            args.get(2)
                .ok_or("usage: enroll-knock <addr:port> <knockfile> <enrollfile>")?,
            args.get(3)
                .ok_or("usage: enroll-knock <addr:port> <knockfile> <enrollfile>")?,
            args.get(4)
                .ok_or("usage: enroll-knock <addr:port> <knockfile> <enrollfile>")?,
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
                "usage: spa-client <command>\n  \
                 keygen <prefix> [fips|modern]\n  \
                 knock <addr:port> <file>\n  \
                 gen-token <prefix>\n  \
                 enroll-knock <addr:port> <knockfile> <enrollfile>\n  \
                 gen-anchor <prefix>\n  \
                 sign-bundle <anchor.key> <payload.toml> <out.bundle>"
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

fn read_kv(file: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut kv = HashMap::new();
    for line in fs::read_to_string(file)?.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(kv)
}

fn require<'a>(kv: &'a HashMap<String, String>, k: &str) -> Result<&'a String, Box<dyn Error>> {
    kv.get(k).ok_or_else(|| format!("missing {k}").into())
}

fn arr<const N: usize>(hexstr: &str) -> Result<[u8; N], Box<dyn Error>> {
    let v = hex::decode(hexstr)?;
    if v.len() != N {
        return Err(format!("expected {N} bytes, got {}", v.len()).into());
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}

fn now_nanos() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64)
}

/// Send one datagram, binding a socket of the target's address family (so v6
/// targets work, not just v4).
fn send_udp(packet: &[u8], target: &str) -> Result<(), Box<dyn Error>> {
    let addr = target
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve target")?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    UdpSocket::bind(bind)?.send_to(packet, addr)?;
    Ok(())
}

fn knock(target: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let kv = read_kv(file)?;
    let gate_pubkey = hex::decode(require(&kv, "gate_pubkey_hex")?)?;
    let gate_id: [u8; GATE_ID_LEN] = arr(require(&kv, "gate_id_hex")?)?;
    let pkcs8 = hex::decode(require(&kv, "client_pkcs8_hex")?)?;
    let port: u16 = require(&kv, "port")?.parse()?;
    let suite = parse_suite(require(&kv, "suite")?)?;

    let client = ClientKey::from_pkcs8(suite, &pkcs8)?;
    let nonce: [u8; NONCE_LEN] = random()?;
    let req = KnockRequest {
        gate_id,
        ports: &[port],
        nonce,
        timestamp_nanos: now_nanos()?,
    };
    let packet = client.seal(&gate_pubkey, &req)?;

    send_udp(&packet, target)?;
    println!(
        "sent {}-byte knock to {target} (requesting port {port})",
        packet.len()
    );
    Ok(())
}

/// Generate a one-time enrollment token: a `[[token]]` block for the gate config
/// plus an `.enroll` file the client uses with `enroll-knock`.
fn gen_token(prefix: &str) -> Result<(), Box<dyn Error>> {
    let token_id: [u8; THUMBPRINT_LEN] = random()?;
    let secret: [u8; 32] = random()?;
    let port = 9999u16;
    fs::write(
        format!("{prefix}.token.toml"),
        format!(
            "[[token]]\ntoken_id_hex = \"{}\"\nsecret_hex = \"{}\"\nports = [{port}]\n",
            hex::encode(token_id),
            hex::encode(secret),
        ),
    )?;
    fs::write(
        format!("{prefix}.enroll"),
        format!(
            "token_id_hex={}\nsecret_hex={}\n",
            hex::encode(token_id),
            hex::encode(secret),
        ),
    )?;
    println!("wrote {prefix}.token.toml and {prefix}.enroll (port={port})");
    Ok(())
}

/// Send a PSK enrollment knock: gate info from `knockfile`, the one-time token
/// from `enrollfile`.
fn enroll_knock(target: &str, knockfile: &str, enrollfile: &str) -> Result<(), Box<dyn Error>> {
    let g = read_kv(knockfile)?;
    let gate_pubkey = hex::decode(require(&g, "gate_pubkey_hex")?)?;
    let gate_id: [u8; GATE_ID_LEN] = arr(require(&g, "gate_id_hex")?)?;
    let suite = parse_suite(require(&g, "suite")?)?;
    let port: u16 = require(&g, "port")?.parse()?;

    let e = read_kv(enrollfile)?;
    let token_id: [u8; THUMBPRINT_LEN] = arr(require(&e, "token_id_hex")?)?;
    let secret = hex::decode(require(&e, "secret_hex")?)?;

    let nonce: [u8; NONCE_LEN] = random()?;
    let req = KnockRequest {
        gate_id,
        ports: &[port],
        nonce,
        timestamp_nanos: now_nanos()?,
    };
    let packet = seal_psk(&gate_pubkey, suite, &secret, token_id, &req)?;

    send_udp(&packet, target)?;
    println!(
        "sent {}-byte enrollment knock to {target} (requesting port {port})",
        packet.len()
    );
    Ok(())
}
