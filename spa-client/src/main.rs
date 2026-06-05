//! SPA client CLI — a thin wrapper over the `spa_client` library, plus dev
//! provisioning (keygen, tokens, bundle signing).
//!
//!   spa-client keygen <prefix> [fips|modern]    # gate + client key material
//!   spa-client gen-client <prefix> [fips|modern]      # standalone client identity
//!   spa-client knock <addr:port> <file>         # open a cloaked port
//!   spa-client knock-descriptor <descriptor.json> <client.key> <ports>
//!   spa-client gen-token <prefix>               # one-time enrollment token
//!   spa-client enroll-knock <addr:port> <knockfile> <enrollfile>
//!   spa-client gen-anchor <prefix>              # control-plane signing key
//!   spa-client sign-bundle <anchor.key> <payload.toml> <out.bundle>

use std::error::Error;
use std::fs;

use spa_client::{parse_suite, Enroller, Knocker};
use spa_common::{Suite, GATE_ID_LEN, THUMBPRINT_LEN};
use spa_crypto::{ClientKey, GateKeypair};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(
            args.get(2).ok_or("usage: keygen <prefix> [fips|modern]")?,
            args.get(3).map(String::as_str).unwrap_or("modern"),
        ),
        Some("gen-client") => gen_client(
            args.get(2)
                .ok_or("usage: gen-client <prefix> [fips|modern]")?,
            args.get(3).map(String::as_str).unwrap_or("modern"),
        ),
        Some("knock") => knock(
            args.get(2).ok_or("usage: knock <addr:port> <file>")?,
            args.get(3).ok_or("usage: knock <addr:port> <file>")?,
        ),
        Some("knock-descriptor") => knock_descriptor(
            args.get(2)
                .ok_or("usage: knock-descriptor <descriptor.json> <client.key> <ports>")?,
            args.get(3)
                .ok_or("usage: knock-descriptor <descriptor.json> <client.key> <ports>")?,
            args.get(4)
                .ok_or("usage: knock-descriptor <descriptor.json> <client.key> <ports>")?,
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
                 gen-client <prefix> [fips|modern]\n  \
                 knock <addr:port> <file>\n  \
                 knock-descriptor <descriptor.json> <client.key> <ports>\n  \
                 gen-token <prefix>\n  \
                 enroll-knock <addr:port> <knockfile> <enrollfile>\n  \
                 gen-anchor <prefix>\n  \
                 sign-bundle <anchor.key> <payload.toml> <out.bundle>"
            );
            Ok(())
        }
    }
}

fn knock(target: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let (knocker, ports) = Knocker::from_knock_file(file)?;
    knocker.knock(target, &ports)?;
    println!("sent knock to {target} (requesting ports {ports:?})");
    Ok(())
}

/// Generate a standalone client identity: the key it knocks with, decoupled from
/// any gate. Writes the PKCS#8 private key (one hex line) and prints the public
/// key to register with the control plane (e.g. `POST /api/enroll`). Pair the
/// resulting key with `knock-descriptor` to knock a real gate.
fn gen_client(prefix: &str, suite_name: &str) -> Result<(), Box<dyn Error>> {
    let suite = parse_suite(suite_name)?;
    let client = ClientKey::generate(suite)?;
    fs::write(
        format!("{prefix}.client.key"),
        hex::encode(client.to_pkcs8()?),
    )?;
    println!("suite={suite_name}");
    println!("public_key_hex={}", hex::encode(client.public_key()));
    println!("wrote {prefix}.client.key");
    Ok(())
}

/// Knock a real gate from the control plane's gate descriptor (the gate's knock
/// pubkey, gate_id, suite, address, knock_port) plus this client's `gen-client`
/// key. This is the production path — no throwaway gate, no manual target.
fn knock_descriptor(descriptor: &str, client_key: &str, ports: &str) -> Result<(), Box<dyn Error>> {
    let text = fs::read_to_string(descriptor)
        .map_err(|e| format!("reading descriptor {descriptor}: {e}"))?;
    let d: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parsing descriptor {descriptor}: {e}"))?;
    let suite = parse_suite(field(&d, "suite")?)?;
    let gate_pubkey = hex::decode(field(&d, "gate_pubkey_hex")?)?;
    let gate_id = gate_id_arr(field(&d, "gate_id_hex")?)?;
    let address = field(&d, "address")?;
    let knock_port = d
        .get("knock_port")
        .and_then(serde_json::Value::as_u64)
        .ok_or("descriptor: missing/invalid knock_port")?;
    let key_hex = fs::read_to_string(client_key)
        .map_err(|e| format!("reading client key {client_key} (from `gen-client`): {e}"))?;
    let pkcs8 = hex::decode(key_hex.trim()).map_err(|e| format!("client key {client_key}: {e}"))?;
    let ports: Vec<u16> = ports
        .split(',')
        .map(|p| p.trim().parse::<u16>())
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid ports (comma-separated u16)")?;

    let knocker = Knocker::new(suite, gate_pubkey, gate_id, &pkcs8)?;
    // Bracket a bare IPv6 literal so `host:port` parses.
    let target = if address.contains(':') {
        format!("[{address}]:{knock_port}")
    } else {
        format!("{address}:{knock_port}")
    };
    knocker.knock(&target, &ports)?;
    println!("sent knock to {target} (requesting ports {ports:?})");
    Ok(())
}

fn field<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a str, Box<dyn Error>> {
    v.get(k)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("descriptor: missing string field {k}").into())
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

fn enroll_knock(target: &str, knockfile: &str, enrollfile: &str) -> Result<(), Box<dyn Error>> {
    let (enroller, ports) = Enroller::from_files(knockfile, enrollfile)?;
    enroller.knock(target, &ports)?;
    println!("sent enrollment knock to {target} (requesting ports {ports:?})");
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
