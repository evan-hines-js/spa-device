//! POD types shared verbatim between the XDP program (kernel) and the userland
//! loader. `repr(C)`, fixed-size, no semantically-meaningful padding — both
//! sides must agree on the exact byte layout of every BPF map value. The `user`
//! feature adds `aya::Pod` impls used only by the loader. See `DESIGN.md` §3.

#![no_std]
// `deny` (not `forbid`) so the `user` feature can locally allow the `unsafe impl
// aya::Pod` below; the rest of the crate stays unsafe-free.
#![deny(unsafe_code)]

/// Maximum ports a single grant may cover. Matches `spa_common::MAX_PORTS`.
pub const MAX_GRANT_PORTS: usize = 8;

/// An entry in the allow-list map: a source is permitted to reach `ports` until
/// `expiry_ns`. Keyed in the map by source address.
///
/// `expiry_ns` is **`CLOCK_MONOTONIC` nanoseconds** (the clock the XDP program
/// reads via `bpf_ktime_get_ns`), NOT wall-clock — the daemon converts when it
/// writes the grant. The knock's wall-clock freshness check is separate and
/// happens in userland.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Grant {
    /// Monotonic-clock nanoseconds after which the grant is dead. The data path
    /// passes while `bpf_ktime_get_ns() < expiry_ns`.
    pub expiry_ns: u64,
    /// Granted destination ports (host byte order). Only the first
    /// `port_count` entries are valid.
    pub ports: [u16; MAX_GRANT_PORTS],
    /// Number of valid entries in `ports` (0..=MAX_GRANT_PORTS).
    pub port_count: u8,
    /// Explicit padding to a clean 8-byte size; keeps the layout deterministic.
    pub _pad: [u8; 7],
}

impl Grant {
    /// True if `port` is one of the granted ports. Bounded loop (verifier-safe).
    pub fn allows_port(&self, port: u16) -> bool {
        let n = if (self.port_count as usize) > MAX_GRANT_PORTS {
            MAX_GRANT_PORTS
        } else {
            self.port_count as usize
        };
        let mut i = 0;
        while i < n {
            if self.ports[i] == port {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// Singleton config the loader pushes to the data path (one-element array map).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GateConfig {
    /// UDP port the SPA knock arrives on (host byte order). Packets to this port
    /// are passed up to the daemon for verification.
    pub knock_port: u16,
    pub _pad: [u8; 6],
}

#[cfg(feature = "user")]
mod user {
    // SAFETY: both types are `repr(C)`, `Copy`, and every bit pattern is a valid
    // value (all fields are integers / integer arrays, padding is explicit), so
    // they satisfy `aya::Pod`'s contract.
    #[allow(unsafe_code)]
    unsafe impl aya::Pod for super::Grant {}
    #[allow(unsafe_code)]
    unsafe impl aya::Pod for super::GateConfig {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(ports: &[u16]) -> Grant {
        let mut g = Grant {
            expiry_ns: 0,
            ports: [0; MAX_GRANT_PORTS],
            port_count: ports.len() as u8,
            _pad: [0; 7],
        };
        g.ports[..ports.len()].copy_from_slice(ports);
        g
    }

    #[test]
    fn allows_listed_ports_only() {
        let g = grant(&[22, 8443]);
        assert!(g.allows_port(22));
        assert!(g.allows_port(8443));
        assert!(!g.allows_port(80));
    }

    #[test]
    fn empty_grant_allows_nothing() {
        assert!(!grant(&[]).allows_port(22));
    }

    #[test]
    fn count_is_clamped_to_capacity() {
        // A corrupt port_count larger than the array must not read out of bounds
        // (the loop is clamped to the array capacity).
        let mut g = grant(&[22]);
        g.port_count = 255;
        assert!(g.allows_port(22));
        assert!(!g.allows_port(80));
    }

    #[test]
    fn layout_is_stable() {
        assert_eq!(core::mem::size_of::<Grant>(), 32);
        assert_eq!(core::mem::align_of::<Grant>(), 8);
        assert_eq!(core::mem::size_of::<GateConfig>(), 8);
    }
}
