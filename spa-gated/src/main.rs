//! The SPA gate daemon: load the XDP data plane, attach it, cloak the configured
//! ports, and verify knocks by driving the pure `spa_core::Gatekeeper`. Dynamic
//! policy (clients + ports) comes either inline from the config or from a signed,
//! hot-reloaded bundle.

mod adapters;
mod bundle;
mod config;
mod nft;

use std::collections::HashSet;
use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use aya::maps::{Array as BpfArray, HashMap as BpfHashMap, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

use spa_core::{Config as GateConfig, Decision, Gatekeeper};
use spa_crypto::GateKeypair;
use spa_ebpf_common::{GateConfig as KernelConfig, Grant};

use adapters::{BpfGateWriter, MemReplay, SharedTrust, SystemClock};
use config::{ClientEntry, Config};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/spa/gated.toml".to_string());
    let cfg = Config::load(&path)?;

    // Dynamic policy: from a signed bundle if configured, else inline config.
    let bundle_src = match (&cfg.config_anchor, &cfg.bundle_path) {
        (Some(anchor), Some(bpath)) => Some((anchor.clone(), bpath.clone())),
        _ => None,
    };
    let (clients, ports, generation): (Vec<ClientEntry>, Vec<u16>, u64) = match &bundle_src {
        Some((anchor, bpath)) => {
            let b = bundle::load_verify(bpath, anchor)?;
            eprintln!("[spa] loaded signed bundle generation {}", b.generation);
            (b.clients, b.protected_ports, b.generation)
        }
        None => (cfg.clients.clone(), cfg.protected_ports.clone(), 0),
    };

    // Load + attach the XDP program.
    let mut ebpf = Ebpf::load(&std::fs::read(&cfg.bpf_object)?)?;
    {
        let prog: &mut Xdp = ebpf
            .program_mut("spa_gate")
            .ok_or("missing program spa_gate")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cfg.interface, XdpFlags::SKB_MODE)?;
        eprintln!("[spa] attached spa_gate to {}", cfg.interface);
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
    eprintln!("[spa] cloaking tcp ports {ports:?}");

    if cfg.nftables_floor {
        nft::install_floor(&ports)?;
        eprintln!("[spa] nftables fail-closed floor installed");
    }

    // Take the allow-list map for the gate writer to own.
    let allow: BpfHashMap<_, u32, Grant> =
        BpfHashMap::try_from(ebpf.take_map("ALLOW").ok_or("missing map ALLOW")?)?;

    // Build the decision core with real adapters.
    let gate_key = GateKeypair::from_raw_private(cfg.suite, &cfg.gate_private)?;
    let trust = SharedTrust::new(cfg.suite);
    trust.set(&clients);
    trust.set_tokens(&cfg.tokens);
    if !cfg.tokens.is_empty() {
        eprintln!(
            "[spa] loaded {} one-time enrollment token(s)",
            cfg.tokens.len()
        );
    }
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

    // Knock loop. `ebpf` is held for the process lifetime to keep the program
    // attached.
    let sock = UdpSocket::bind(("0.0.0.0", cfg.knock_port))?;
    eprintln!("[spa] listening for knocks on udp/{}", cfg.knock_port);
    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = sock.recv_from(&mut buf)?;
        match gatekeeper.admit(&buf[..n], src.ip()) {
            Decision::Opened { ports } => eprintln!("[spa] OPEN  {} -> {:?}", src.ip(), ports),
            Decision::Rejected(reason) => eprintln!("[spa] DENY  {} ({:?})", src.ip(), reason),
        }
    }
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
                eprintln!("[spa] rejected bundle: {e}");
                continue;
            }
        };
        if b.generation <= applied_gen {
            eprintln!(
                "[spa] ignored bundle generation {} (<= applied {applied_gen})",
                b.generation
            );
            continue;
        }

        trust.set(&b.clients);
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
        eprintln!(
            "[spa] applied bundle generation {applied_gen} ({} clients, ports {:?})",
            b.clients.len(),
            b.protected_ports
        );
    }
}
