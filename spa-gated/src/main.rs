//! The SPA gate daemon: load the XDP data plane, attach it, cloak the configured
//! ports, and verify knocks by driving the pure `spa_core::Gatekeeper`. Dynamic
//! policy (clients + ports) comes either inline from the config or from a signed,
//! hot-reloaded bundle.

mod adapters;
mod audit;
mod bundle;
mod config;
mod cp;
mod nft;

use std::collections::HashSet;
use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use aya::maps::{Array as BpfArray, HashMap as BpfHashMap, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

use spa_common::{Suite, GATE_ID_LEN};
use spa_core::{Config as GateConfig, Gatekeeper};
use spa_crypto::GateKeypair;
use spa_ebpf_common::{GateConfig as KernelConfig, Grant};

use adapters::{BpfGateWriter, MemReplay, SharedTrust, SystemClock};
use config::{ClientEntry, Config, TokenEntry};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("provision") {
        return provision(&args[2..]);
    }

    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/etc/spa/gated.toml".to_string());
    let cfg = Config::load(&path)?;

    // Bind the knock socket first: it doubles as a single-instance lock, so a
    // second spa-gated on this host fails here with a clear "port in use" instead
    // of half-starting and then dying on an opaque XDP ResourceBusy (which would
    // silently leave a config change unapplied). Dual-stack `[::]` (IPv6 +
    // IPv4-mapped); fall back to IPv4-only where IPv6 is unavailable.
    let sock = UdpSocket::bind(("::", cfg.knock_port))
        .or_else(|_| UdpSocket::bind(("0.0.0.0", cfg.knock_port)))
        .map_err(|e| {
            format!(
                "bind knock port {}: {e} — is another spa-gated already running on this host?",
                cfg.knock_port
            )
        })?;

    // Self-provision against the control plane if configured: register our own
    // knock identity (derived from our keypair, never hand-grepped — so it can't
    // be the wrong key) and pull the signed bundle. Idempotent: every start
    // re-asserts the correct identity, which self-heals a stale descriptor.
    // The bundle-signing anchor: a pinned one if configured, else the one the
    // control plane returns at registration. The control-plane channel is already
    // CA-pinned, so a fetched anchor is as trustworthy as a manual pin — and it
    // can't go stale across a control-plane re-key, which a hand-pinned one does.
    let mut anchor = cfg.config_anchor.clone();
    let mut gate_id = cfg.gate_id;
    if let Some(cp) = &cfg.control_plane {
        // Pin the control-plane TLS to our aws-lc-rs provider (no second stack).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pubkey_hex =
            hex::encode(GateKeypair::from_raw_private(cfg.suite, &cfg.gate_private)?.public_key());
        let provisioned = cp::register_identity(cp, &pubkey_hex, cfg.knock_port)?;
        audit::control_plane("registered", pubkey_hex);
        if anchor.is_none() {
            if let Some(a) = &provisioned.config_anchor {
                anchor =
                    Some(hex::decode(a).map_err(|e| format!("control-plane config_anchor: {e}"))?);
                audit::control_plane("anchor-fetched", a.clone());
            }
        }
        if gate_id.is_none() {
            if let Some(g) = &provisioned.gate_id {
                gate_id = Some(parse_gate_id(g)?);
                audit::control_plane("gate-id-fetched", g.clone());
            }
        }
        if let Some(bpath) = &cfg.bundle_path {
            cp::fetch_bundle(cp, bpath)?;
            audit::control_plane("bundle-fetched", bpath.clone());
        }
    }
    let gate_id = gate_id.ok_or("no gate_id: set gate_id_hex, or configure [control_plane]")?;

    // Dynamic policy: from a signed bundle if configured, else inline config.
    let bundle_src = match (&anchor, &cfg.bundle_path) {
        (Some(a), Some(bpath)) => Some((a.clone(), bpath.clone())),
        _ => None,
    };
    let (clients, tokens, ports, generation): (Vec<ClientEntry>, Vec<TokenEntry>, Vec<u16>, u64) =
        match &bundle_src {
            Some((anchor, bpath)) => {
                let b = bundle::load_verify(bpath, anchor)?;
                audit::bundle("loaded", Some(b.generation), None);
                (b.clients, b.tokens, b.protected_ports, b.generation)
            }
            None => (
                cfg.clients.clone(),
                cfg.tokens.clone(),
                cfg.protected_ports.clone(),
                0,
            ),
        };

    // Load + attach the XDP program.
    let object = std::fs::read(&cfg.bpf_object)
        .map_err(|e| format!("reading bpf_object {}: {e}", cfg.bpf_object))?;
    let mut ebpf = Ebpf::load(&object)?;
    {
        let prog: &mut Xdp = ebpf
            .program_mut("spa_gate")
            .ok_or("missing program spa_gate")?
            .try_into()?;
        prog.load()?;
        // Drop any leftover XDP program first so a restart isn't blocked by a
        // stale attach. Safe: the knock-port bind above is a single-instance
        // lock, so by here anything still on the NIC is genuinely orphaned.
        clear_stale_xdp(&cfg.interface);
        prog.attach(&cfg.interface, XdpFlags::SKB_MODE)
            .map_err(|e| format!("attach XDP to {}: {e}", cfg.interface))?;
    }

    // Tell the data plane the knock port so it can size-filter + rate-limit it.
    {
        let mut config: BpfArray<_, KernelConfig> =
            BpfArray::try_from(ebpf.map_mut("CONFIG").ok_or("missing map CONFIG")?)?;
        config.set(
            0,
            KernelConfig {
                knock_port: cfg.knock_port,
                _pad: [0; 6],
            },
            0,
        )?;
    }

    // Program the set of cloaked ports.
    let mut protected: BpfHashMap<MapData, u16, u8> =
        BpfHashMap::try_from(ebpf.take_map("PROTECTED").ok_or("missing map PROTECTED")?)?;
    for p in &ports {
        protected.insert(*p, 1u8, 0)?;
    }

    if cfg.nftables_floor {
        nft::install_floor(&ports)?;
        audit::floor(&ports);
    }

    // Take the allow-list map for the gate writer to own (16-byte address keys).
    let allow: BpfHashMap<_, [u8; 16], Grant> =
        BpfHashMap::try_from(ebpf.take_map("ALLOW").ok_or("missing map ALLOW")?)?;

    // Build the decision core with real adapters.
    let gate_key = GateKeypair::from_raw_private(cfg.suite, &cfg.gate_private)?;
    let trust = SharedTrust::new(cfg.suite);
    trust.set(&clients);
    trust.set_tokens(&tokens);
    let replay = MemReplay::new(Duration::from_secs(cfg.skew_seconds * 2 + 1));
    let gate_cfg = GateConfig {
        gate_id,
        skew_nanos: cfg.skew_seconds.saturating_mul(1_000_000_000),
        pinhole_nanos: cfg.pinhole_ms.saturating_mul(1_000_000),
    };
    let mut gatekeeper = Gatekeeper::new(
        gate_cfg,
        SystemClock,
        gate_key,
        trust.clone(),
        replay,
        BpfGateWriter {
            allow,
            nft_floor: cfg.nftables_floor,
        },
    );

    // Hot-reload signed bundles on a background thread.
    if let Some((anchor, bpath)) = bundle_src {
        let trust = trust.clone();
        let known = ports.iter().copied().collect::<HashSet<u16>>();
        let nft_floor = cfg.nftables_floor;
        std::thread::spawn(move || {
            watch_bundle(
                bpath, anchor, trust, protected, nft_floor, known, generation,
            )
        });
    }

    // Periodically re-pull the bundle so control-plane changes (a new enrollment,
    // a revoke) propagate with no operator action; the watcher above hot-reloads
    // whatever lands. Only re-pulls when configured to self-provision.
    if let (Some(cp), Some(bpath)) = (cfg.control_plane.clone(), cfg.bundle_path.clone()) {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(20));
            match cp::fetch_bundle(&cp, &bpath) {
                Ok(true) => audit::control_plane("bundle-fetched", bpath.clone()),
                Ok(false) => {}
                Err(e) => audit::control_plane("fetch-error", e.to_string()),
            }
        });
    }

    // Knock loop. `ebpf` is held for the process lifetime to keep the program
    // attached; `sock` was bound up front as the single-instance lock.
    let suite = match cfg.suite {
        Suite::Fips => "fips",
        Suite::Modern => "modern",
    };
    audit::startup(
        &cfg.interface,
        cfg.knock_port,
        suite,
        &ports,
        clients.len(),
        tokens.len(),
        cfg.nftables_floor,
    );

    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = sock.recv_from(&mut buf)?;
        let decision = gatekeeper.admit(&buf[..n], src.ip());
        audit::knock(src.ip(), &decision);
    }
}

/// `spa-gated provision <interface> <bpf_object> <control-plane-url> <gate-token>
/// <gate-address> [ca_cert]` — generate this gate's knock key and write a ready
/// `gated.toml`, so the key is never made + pasted by hand. `gate_id` and the
/// config anchor are deliberately omitted: a self-provisioning gate fetches both
/// from the control plane at first run, so they can't be pinned wrong or go stale.
/// Env overrides: `SPA_SUITE` (modern), `SPA_KNOCK_PORT` (62201), `SPA_GATED_TOML`
/// (gated.toml).
fn provision(args: &[String]) -> Result<(), Box<dyn Error>> {
    let usage = "usage: provision <interface> <bpf_object> <control-plane-url> <gate-token> <gate-address> [ca_cert]";
    let interface = args.first().ok_or(usage)?;
    let bpf_object = args.get(1).ok_or(usage)?;
    let url = args.get(2).ok_or(usage)?;
    let token = args.get(3).ok_or(usage)?;
    let address = args.get(4).ok_or(usage)?;
    let ca_cert = args.get(5);

    let suite_name = std::env::var("SPA_SUITE").unwrap_or_else(|_| "modern".to_string());
    let suite = match suite_name.as_str() {
        "fips" => Suite::Fips,
        "modern" => Suite::Modern,
        other => return Err(format!("unknown suite {other:?} (fips|modern)").into()),
    };
    let knock_port: u16 = std::env::var("SPA_KNOCK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(62201);
    let out = std::env::var("SPA_GATED_TOML").unwrap_or_else(|_| "gated.toml".to_string());

    let (_, gate_private) = GateKeypair::generate_raw(suite)?;
    let gate_private_hex = hex::encode(gate_private);
    let ca_line = ca_cert
        .map(|c| format!("ca_cert    = \"{c}\"\n"))
        .unwrap_or_default();

    let toml = format!(
        "interface = \"{interface}\"\n\
         knock_port = {knock_port}\n\
         bpf_object = \"{bpf_object}\"\n\
         pinhole_ms = 2000\n\
         skew_seconds = 2\n\
         bundle_path = \"/etc/spa/bundle.spa\"\n\
         suite = \"{suite_name}\"\n\
         gate_private_hex = \"{gate_private_hex}\"\n\
         \n\
         [control_plane]\n\
         url        = \"{url}\"\n\
         gate_token = \"{token}\"\n\
         address    = \"{address}\"\n\
         {ca_line}"
    );
    std::fs::write(&out, toml).map_err(|e| format!("writing {out}: {e}"))?;
    println!("wrote {out} — key generated; gate_id + anchor are fetched at first run. Run it: sudo spa-gated {out}");
    Ok(())
}

/// Decode a hex `gate_id` from the control plane into the fixed-size id.
fn parse_gate_id(hex: &str) -> Result<[u8; GATE_ID_LEN], Box<dyn Error>> {
    let bytes = hex::decode(hex).map_err(|e| format!("control-plane gate_id: {e}"))?;
    if bytes.len() != GATE_ID_LEN {
        return Err(format!(
            "control-plane gate_id: expected {GATE_ID_LEN} bytes, got {}",
            bytes.len()
        )
        .into());
    }
    let mut id = [0u8; GATE_ID_LEN];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Best-effort detach of any leftover XDP program on `iface` before we attach,
/// so a restart isn't blocked by a stale attach (`ResourceBusy`). Mirrors the
/// daemon's existing reliance on userspace `nft`; failures are ignored because a
/// clean interface is the common case.
fn clear_stale_xdp(iface: &str) {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", iface, "xdpgeneric", "off"])
        .status();
}

/// Poll the bundle file; on change, verify it, enforce anti-rollback, and
/// atomically apply the new client set and protected ports.
fn watch_bundle(
    bundle_path: String,
    anchor: Vec<u8>,
    trust: SharedTrust,
    mut protected: BpfHashMap<MapData, u16, u8>,
    nft_floor: bool,
    mut known_ports: HashSet<u16>,
    mut applied_gen: u64,
) {
    let mut last_mtime = std::fs::metadata(&bundle_path)
        .and_then(|m| m.modified())
        .ok();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let mtime = match std::fs::metadata(&bundle_path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if Some(mtime) == last_mtime {
            continue;
        }
        last_mtime = Some(mtime);

        let b = match bundle::load_verify(&bundle_path, &anchor) {
            Ok(b) => b,
            Err(e) => {
                audit::bundle("rejected", None, Some(e.to_string()));
                continue;
            }
        };
        if b.generation <= applied_gen {
            audit::bundle(
                "ignored",
                Some(b.generation),
                Some(format!("<= applied {applied_gen}")),
            );
            continue;
        }

        trust.set(&b.clients);
        trust.set_tokens(&b.tokens);
        let new_ports: HashSet<u16> = b.protected_ports.iter().copied().collect();
        for p in new_ports.difference(&known_ports) {
            let _ = protected.insert(*p, 1u8, 0);
        }
        for p in known_ports.difference(&new_ports) {
            let _ = protected.remove(p);
        }
        if nft_floor {
            let _ = nft::set_ports(&b.protected_ports);
        }
        known_ports = new_ports;
        applied_gen = b.generation;
        audit::bundle(
            "applied",
            Some(applied_gen),
            Some(format!(
                "{} clients, {} tokens, ports {:?}",
                b.clients.len(),
                b.tokens.len(),
                b.protected_ports
            )),
        );
    }
}
