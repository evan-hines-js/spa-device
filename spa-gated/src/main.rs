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

use spa_common::Suite;
use spa_core::{Config as GateConfig, Gatekeeper};
use spa_crypto::GateKeypair;
use spa_ebpf_common::{GateConfig as KernelConfig, Grant};

use adapters::{BpfGateWriter, MemReplay, SharedTrust, SystemClock};
use config::{ClientEntry, Config, TokenEntry};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
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
    if let Some(cp) = &cfg.control_plane {
        // Pin the control-plane TLS to our aws-lc-rs provider (no second stack).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pubkey_hex =
            hex::encode(GateKeypair::from_raw_private(cfg.suite, &cfg.gate_private)?.public_key());
        cp::register_identity(cp, &pubkey_hex, cfg.knock_port)?;
        audit::control_plane("registered", pubkey_hex);
        if let Some(bpath) = &cfg.bundle_path {
            cp::fetch_bundle(cp, bpath)?;
            audit::control_plane("bundle-fetched", bpath.clone());
        }
    }

    // Dynamic policy: from a signed bundle if configured, else inline config.
    let bundle_src = match (&cfg.config_anchor, &cfg.bundle_path) {
        (Some(anchor), Some(bpath)) => Some((anchor.clone(), bpath.clone())),
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
    let mut ebpf = Ebpf::load(&std::fs::read(&cfg.bpf_object)?)?;
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
        gate_id: cfg.gate_id,
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
