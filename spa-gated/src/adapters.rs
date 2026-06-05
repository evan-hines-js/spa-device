//! Real implementations of the `spa-core` ports, wiring the pure decision core
//! to the kernel and the system clocks.

use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aya::maps::{HashMap as BpfHashMap, MapData};
use spa_common::{Suite, NONCE_LEN, THUMBPRINT_LEN};
use spa_core::{Auth, ClientPolicy, Clock, GateWriter, ReplayGuard, TrustStore};
use spa_ebpf_common::{Grant, MAX_GRANT_PORTS};

use crate::config::{ClientEntry, TokenEntry};

/// Wall clock for the knock-timestamp skew check (unix nanoseconds).
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_nanos(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

/// In-memory replay cache: a nonce is admitted once within `window`. Entries
/// older than the window are pruned on each call, so memory is bounded by the
/// window × knock rate.
pub struct MemReplay {
    seen: StdHashMap<[u8; NONCE_LEN], Instant>,
    window: Duration,
}

impl MemReplay {
    pub fn new(window: Duration) -> Self {
        MemReplay {
            seen: StdHashMap::new(),
            window,
        }
    }
}

impl ReplayGuard for MemReplay {
    fn admit(&mut self, nonce: &[u8; NONCE_LEN]) -> bool {
        let now = Instant::now();
        self.seen
            .retain(|_, t| now.duration_since(*t) < self.window);
        if self.seen.contains_key(nonce) {
            return false;
        }
        self.seen.insert(*nonce, now);
        true
    }
}

/// Hot-swappable trust store: thumbprint → (public key, ports). Shared (cheap
/// `Clone` of an `Arc`) between the knock loop and the bundle watcher; the
/// watcher calls [`set`](Self::set) on reload while the loop keeps reading. All
/// clients share the gate's `suite`.
type Entry = (Vec<u8>, Vec<u16>); // (key material, ports)

#[derive(Clone)]
pub struct SharedTrust {
    clients: Arc<RwLock<StdHashMap<[u8; THUMBPRINT_LEN], Entry>>>,
    tokens: Arc<RwLock<StdHashMap<[u8; THUMBPRINT_LEN], Entry>>>,
    suite: Suite,
}

impl SharedTrust {
    pub fn new(suite: Suite) -> Self {
        SharedTrust {
            clients: Arc::new(RwLock::new(StdHashMap::new())),
            tokens: Arc::new(RwLock::new(StdHashMap::new())),
            suite,
        }
    }

    /// Atomically replace the entire client set (used on bundle reload).
    pub fn set(&self, clients: &[ClientEntry]) {
        let mut map = self.clients.write().expect("trust lock");
        map.clear();
        for c in clients {
            map.insert(c.thumbprint, (c.public_key.clone(), c.ports.clone()));
        }
    }

    /// Replace the one-time PSK enrollment tokens.
    pub fn set_tokens(&self, tokens: &[TokenEntry]) {
        let mut map = self.tokens.write().expect("trust lock");
        map.clear();
        for t in tokens {
            map.insert(t.token_id, (t.secret.clone(), t.ports.clone()));
        }
    }
}

impl TrustStore for SharedTrust {
    fn lookup(&self, thumbprint: &[u8; THUMBPRINT_LEN]) -> Option<ClientPolicy> {
        if let Some((pk, ports)) = self.clients.read().expect("trust lock").get(thumbprint) {
            return Some(ClientPolicy {
                public_key: pk.clone(),
                suite: self.suite,
                allowed_ports: ports.clone(),
                auth: Auth::Signature,
                single_use: false,
            });
        }
        if let Some((secret, ports)) = self.tokens.read().expect("trust lock").get(thumbprint) {
            return Some(ClientPolicy {
                public_key: secret.clone(),
                suite: self.suite,
                allowed_ports: ports.clone(),
                auth: Auth::Psk,
                single_use: true,
            });
        }
        None
    }

    fn consume(&self, thumbprint: &[u8; THUMBPRINT_LEN]) {
        self.tokens.write().expect("trust lock").remove(thumbprint);
    }
}

/// Gate writer that programs the kernel allow-list (the `ALLOW` BPF map) and,
/// when enabled, mirrors the grant into the nftables fail-closed floor.
pub struct BpfGateWriter {
    pub allow: BpfHashMap<MapData, [u8; 16], Grant>,
    pub nft_floor: bool,
}

impl GateWriter for BpfGateWriter {
    fn open(&mut self, source: IpAddr, ports: &[u16], ttl_nanos: u64) {
        let mut grant = Grant {
            expiry_ns: monotonic_now_ns().saturating_add(ttl_nanos),
            ports: [0; MAX_GRANT_PORTS],
            port_count: 0,
            _pad: [0; 7],
        };
        for (i, p) in ports.iter().take(MAX_GRANT_PORTS).enumerate() {
            grant.ports[i] = *p;
            grant.port_count += 1;
        }
        // A failed map write just means this knock doesn't open the port; the
        // client can retry. Never panic in the hot path.
        let _ = self.allow.insert(addr_key(source), grant, 0);
        if self.nft_floor {
            crate::nft::allow(source, ttl_nanos.div_ceil(1_000_000_000));
        }
    }
}

/// The 16-byte BPF allow-list key: IPv6 verbatim, IPv4 as its IPv4-mapped form
/// `::ffff:a.b.c.d` (matching how the XDP program keys both families).
fn addr_key(source: IpAddr) -> [u8; 16] {
    match source {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// CLOCK_MONOTONIC nanoseconds — the same clock the XDP program reads via
/// `bpf_ktime_get_ns`, so grant expiries compare correctly.
pub fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}
