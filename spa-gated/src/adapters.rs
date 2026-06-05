//! Real implementations of the `spa-core` ports, wiring the pure decision core
//! to the kernel and the system clocks.

use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aya::maps::{HashMap as BpfHashMap, MapData};
use spa_common::{Suite, NONCE_LEN, THUMBPRINT_LEN};
use spa_core::{ClientPolicy, Clock, GateWriter, ReplayGuard, TrustStore};
use spa_ebpf_common::{Grant, MAX_GRANT_PORTS};

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

/// Trust store backed by the daemon config: thumbprint → (public key, ports).
/// All clients share the gate's `suite`.
pub struct ConfigTrust {
    clients: StdHashMap<[u8; THUMBPRINT_LEN], (Vec<u8>, Vec<u16>)>,
    suite: Suite,
}

impl ConfigTrust {
    pub fn new(suite: Suite) -> Self {
        ConfigTrust {
            clients: StdHashMap::new(),
            suite,
        }
    }

    pub fn insert(
        &mut self,
        thumbprint: [u8; THUMBPRINT_LEN],
        public_key: Vec<u8>,
        ports: Vec<u16>,
    ) {
        self.clients.insert(thumbprint, (public_key, ports));
    }
}

impl TrustStore for ConfigTrust {
    fn lookup(&self, thumbprint: &[u8; THUMBPRINT_LEN]) -> Option<ClientPolicy> {
        self.clients
            .get(thumbprint)
            .map(|(pk, ports)| ClientPolicy {
                public_key: pk.clone(),
                suite: self.suite,
                allowed_ports: ports.clone(),
            })
    }
}

/// Gate writer that programs the kernel allow-list (the `ALLOW` BPF map).
pub struct BpfGateWriter {
    pub allow: BpfHashMap<MapData, u32, Grant>,
}

impl GateWriter for BpfGateWriter {
    fn open(&mut self, source: IpAddr, ports: &[u16], ttl_nanos: u64) {
        // The XDP key is the IPv4 source as it sits in the packet, read as a
        // native u32 — match that exactly. IPv6 is not yet cloaked.
        let key = match source {
            IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
            IpAddr::V6(_) => return,
        };
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
        let _ = self.allow.insert(key, grant, 0);
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
