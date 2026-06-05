#![forbid(unsafe_code)]
//! spa-agent — the workstation client agent. Reach mesh services by name instead
//! of hand-running `knock-descriptor`: fetch the device's signed service catalog,
//! create a TUN, resolve names to mesh IPs, and per flow knock the service's gate
//! and forward through the pinhole. Cross-platform userland; counterpart to
//! `spa-gated`. Needs root for `up` (TUN + hosts file).
//!
//!   spa-agent catalog <client.key> <suite> <argus-url> [ca_cert]   # list reachable services
//!   spa-agent up      <client.key> <suite> <argus-url> [ca_cert]   # bring the mesh up (root)
//!   spa-agent down                                                 # remove the resolver block

use std::collections::HashMap;
use std::error::Error;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use spa_agent::{catalog, proxy, resolver, tundev};
use spa_client::parse_suite;
use spa_crypto::ClientKey;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("catalog") => with_args(&args, catalog_cmd),
        Some("up") => with_args(&args, up_cmd),
        Some("down") => {
            resolver::clear();
            println!("removed the spa-agent resolver block");
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: spa-agent <command>\n  \
                 catalog <client.key> <suite> <argus-url> [ca_cert]\n  \
                 up <client.key> <suite> <argus-url> [ca_cert]   (root)\n  \
                 down"
            );
            Ok(())
        }
    }
}

/// A subcommand taking `<client.key> <suite> <argus-url> [ca_cert]`.
type CmdFn = fn(&str, &str, &str, Option<&str>) -> Result<(), Box<dyn Error>>;

fn with_args(args: &[String], f: CmdFn) -> Result<(), Box<dyn Error>> {
    let usage = "usage: <client.key> <suite> <argus-url> [ca_cert]";
    f(
        args.get(2).ok_or(usage)?,
        args.get(3).ok_or(usage)?,
        args.get(4).ok_or(usage)?,
        args.get(5).map(String::as_str),
    )
}

/// Load the device key: returns its PKCS#8 bytes (for knocking) and the parsed
/// [`ClientKey`] (for catalog signing).
fn load_key(key_file: &str, suite_name: &str) -> Result<(Vec<u8>, ClientKey), Box<dyn Error>> {
    let pkcs8 = hex::decode(std::fs::read_to_string(key_file)?.trim())
        .map_err(|e| format!("client key {key_file}: {e}"))?;
    let key = ClientKey::from_pkcs8(parse_suite(suite_name)?, &pkcs8)?;
    Ok((pkcs8, key))
}

fn fetch(
    key: &ClientKey,
    argus_url: &str,
    ca_cert: Option<&str>,
) -> Result<catalog::Catalog, Box<dyn Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    catalog::fetch(argus_url, ca_cert, key, now)
}

/// List the services this device may reach (the signed catalog GET).
fn catalog_cmd(
    key_file: &str,
    suite: &str,
    argus_url: &str,
    ca_cert: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let (_, key) = load_key(key_file, suite)?;
    let cat = fetch(&key, argus_url, ca_cert)?;
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

/// Bring the mesh up: TUN + resolver + per-flow knock-and-forward.
fn up_cmd(
    key_file: &str,
    suite: &str,
    argus_url: &str,
    ca_cert: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let (pkcs8, key) = load_key(key_file, suite)?;
    let cat = fetch(&key, argus_url, ca_cert)?;
    let (base, prefix) = parse_cidr(&cat.mesh_cidr)?;
    let agent_ip = top_host(base, prefix);

    let mut targets: HashMap<(Ipv4Addr, u16), proxy::Target> = HashMap::new();
    let mut names: Vec<(String, String)> = Vec::new();
    for svc in &cat.services {
        let mesh_ip: Ipv4Addr = svc
            .mesh_ip
            .parse()
            .map_err(|_| format!("bad mesh_ip {}", svc.mesh_ip))?;
        names.push((svc.name.clone(), svc.mesh_ip.clone()));
        for ep in &svc.endpoints {
            if ep.protocol != "tcp" {
                continue;
            }
            let (knocker, knock_target) = ep.knocker(&pkcs8)?;
            let backend = (ep.address.as_str(), ep.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| format!("cannot resolve backend {}:{}", ep.address, ep.port))?;
            targets.insert(
                (mesh_ip, ep.port),
                proxy::Target {
                    backend,
                    knocker,
                    knock_target,
                    knock_ports: vec![ep.port],
                },
            );
        }
    }

    resolver::apply(&names)?;
    let (device, ifname) = tundev::open(agent_ip, prefix)?;
    println!(
        "agent up: tun {ifname} ({agent_ip}/{prefix}), {} services routed on {}",
        names.len(),
        cat.mesh_cidr
    );
    for (name, ip) in &names {
        println!("  {name} -> {ip}");
    }
    proxy::run(device, agent_ip, prefix, targets)
}

/// Parse `a.b.c.d/p` into the network base and prefix.
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), Box<dyn Error>> {
    let (ip, p) = cidr
        .split_once('/')
        .ok_or_else(|| format!("bad mesh_cidr {cidr}"))?;
    Ok((
        ip.parse().map_err(|_| format!("bad mesh_cidr {cidr}"))?,
        p.parse()?,
    ))
}

/// The highest host address in the CIDR (broadcast − 1) — the TUN's own IP, kept
/// clear of the low addresses the control plane assigns to services.
fn top_host(base: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let broadcast = u32::from(base) | !mask;
    Ipv4Addr::from(broadcast.saturating_sub(1))
}
