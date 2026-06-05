//! The SPA gate daemon: load the XDP data plane, attach it, cloak the configured
//! ports, and verify knocks by driving the pure `spa_core::Gatekeeper`.

mod adapters;
mod config;

use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use aya::maps::HashMap as BpfHashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

use spa_core::{Config as GateConfig, Decision, Gatekeeper};
use spa_crypto::GateKeypair;
use spa_ebpf_common::Grant;

use adapters::{BpfGateWriter, ConfigTrust, MemReplay, SystemClock};
use config::Config;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/spa/gated.toml".to_string());
    let cfg = Config::load(&path)?;

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

    // Program the set of cloaked ports.
    {
        let mut protected: BpfHashMap<_, u16, u8> =
            BpfHashMap::try_from(ebpf.map_mut("PROTECTED").ok_or("missing map PROTECTED")?)?;
        for p in &cfg.protected_ports {
            protected.insert(*p, 1u8, 0)?;
        }
        eprintln!("[spa] cloaking tcp ports {:?}", cfg.protected_ports);
    }

    // Take the allow-list map for the gate writer to own.
    let allow: BpfHashMap<_, u32, Grant> =
        BpfHashMap::try_from(ebpf.take_map("ALLOW").ok_or("missing map ALLOW")?)?;

    // Build the decision core with real adapters.
    let gate_key = GateKeypair::from_raw_private(cfg.suite, &cfg.gate_private)?;
    let mut trust = ConfigTrust::new(cfg.suite);
    for c in &cfg.clients {
        trust.insert(c.thumbprint, c.public_key.clone(), c.ports.clone());
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
        trust,
        replay,
        BpfGateWriter { allow },
    );

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
