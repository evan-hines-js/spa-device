//! SPA port-cloaking XDP data plane.
//!
//! TCP to a **protected** port:
//!   * tracked, non-idle flow → `PASS` (conntrack handoff past the pinhole);
//!   * pure `SYN` from a source holding a live grant → track + `PASS`;
//!   * else → `DROP` (silent cloak; stray ACKs included, so no RST leak).
//! UDP to the **knock** port (the one reachable surface): a cheap in-kernel
//! size pre-filter and per-source rate limit drop malformed / flooding knocks
//! before they reach the daemon's crypto path; survivors `PASS` up.
//! Everything else `PASS`es.
//!
//! Parsing is dependency-free and every read is bounds-checked. See `DESIGN.md`
//! §3, §5.

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap, LruHashMap};
use aya_ebpf::programs::XdpContext;
use spa_ebpf_common::{GateConfig, Grant};

/// Allow-list: source IPv4 (`src_addr`, host-native `u32`) → grant.
#[map]
static ALLOW: HashMap<u32, Grant> = HashMap::with_max_entries(1024, 0);

/// Set of cloaked TCP ports (host byte order). Presence means "protected".
#[map]
static PROTECTED: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

/// Tracked flows: inbound 4-tuple → last-seen monotonic ns (LRU-bounded).
#[map]
static ESTABLISHED: LruHashMap<FlowKey, u64> = LruHashMap::with_max_entries(65536, 0);

/// Singleton gate config (the knock port), set by the daemon at startup.
#[map]
static CONFIG: Array<GateConfig> = Array::with_max_entries(1, 0);

/// Per-source knock rate state (LRU-bounded), for the fixed-window limiter.
#[map]
static RATE: LruHashMap<u32, RateState> = LruHashMap::with_max_entries(65536, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RateState {
    window_ns: u64,
    count: u32,
    _pad: u32,
}

// --- offsets (IPv4). Hand-rolled to stay dependency-free. ---
const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFF: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_IHL_OFF: usize = 0;
const IP_PROTO_OFF: usize = 9;
const IP_SRC_OFF: usize = 12;
const IP_DST_OFF: usize = 16;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const TCP_SPORT_OFF: usize = 0;
const TCP_DPORT_OFF: usize = 2;
const TCP_FLAGS_OFF: usize = 13;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;
const UDP_HDR_LEN: usize = 8;
const UDP_DPORT_OFF: usize = 2;
/// A tracked flow idle this long is treated as gone (re-knock required).
const FLOW_IDLE_NS: u64 = 120_000_000_000; // 2 minutes
/// Valid knock payload size window (covers both suites with margin); anything
/// outside is dropped before touching userland crypto.
const KNOCK_MIN: usize = 180;
const KNOCK_MAX: usize = 260;
/// Per-source knock budget per `RATE_WINDOW_NS`.
const RATE_LIMIT: u32 = 10;
const RATE_WINDOW_NS: u64 = 1_000_000_000; // 1 second

#[xdp]
pub fn spa_gate(ctx: XdpContext) -> u32 {
    match try_gate(&ctx) {
        Ok(action) => action,
        Err(()) => XDP_PASS,
    }
}

fn try_gate(ctx: &XdpContext) -> Result<u32, ()> {
    if u16::from_be(load::<u16>(ctx, ETH_TYPE_OFF)?) != ETHERTYPE_IPV4 {
        return Ok(XDP_PASS);
    }
    let ip_off = ETH_HDR_LEN;
    let ihl = ((load::<u8>(ctx, ip_off + IP_IHL_OFF)? & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Ok(XDP_PASS); // malformed IPv4 header
    }
    let l4 = ip_off + ihl;
    match load::<u8>(ctx, ip_off + IP_PROTO_OFF)? {
        IPPROTO_TCP => tcp_gate(ctx, ip_off, l4),
        IPPROTO_UDP => udp_gate(ctx, ip_off, l4),
        _ => Ok(XDP_PASS),
    }
}

fn tcp_gate(ctx: &XdpContext, ip_off: usize, l4: usize) -> Result<u32, ()> {
    let dport = u16::from_be(load::<u16>(ctx, l4 + TCP_DPORT_OFF)?);
    if !is_protected(dport) {
        return Ok(XDP_PASS);
    }
    let flow = FlowKey {
        saddr: load::<u32>(ctx, ip_off + IP_SRC_OFF)?,
        daddr: load::<u32>(ctx, ip_off + IP_DST_OFF)?,
        sport: u16::from_be(load::<u16>(ctx, l4 + TCP_SPORT_OFF)?),
        dport,
    };
    let flags = load::<u8>(ctx, l4 + TCP_FLAGS_OFF)?;
    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(&last) = unsafe { ESTABLISHED.get(&flow) } {
        if now.wrapping_sub(last) < FLOW_IDLE_NS {
            if flags & (TCP_FIN | TCP_RST) != 0 {
                let _ = ESTABLISHED.remove(&flow);
            } else {
                let _ = ESTABLISHED.insert(&flow, &now, 0);
            }
            return Ok(XDP_PASS);
        }
        let _ = ESTABLISHED.remove(&flow);
    }

    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && source_allowed(flow.saddr, dport, now) {
        let _ = ESTABLISHED.insert(&flow, &now, 0);
        return Ok(XDP_PASS);
    }

    Ok(XDP_DROP)
}

fn udp_gate(ctx: &XdpContext, ip_off: usize, l4: usize) -> Result<u32, ()> {
    let dport = u16::from_be(load::<u16>(ctx, l4 + UDP_DPORT_OFF)?);
    let knock_port = match CONFIG.get(0) {
        Some(cfg) => cfg.knock_port,
        None => return Ok(XDP_PASS), // not configured yet
    };
    if dport != knock_port {
        return Ok(XDP_PASS); // not the knock port; not our concern
    }

    // Read the source first: its bounds check must precede the size pre-filter,
    // or the optimizer elides it (the verifier can't carry the pre-filter's range
    // proof across the variable-length IP header).
    let saddr = load::<u32>(ctx, ip_off + IP_SRC_OFF)?;

    // Cheap size pre-filter: drop anything that cannot be a valid knock, before
    // any per-packet crypto cost in userland.
    let base = ctx.data() + l4 + UDP_HDR_LEN;
    let end = ctx.data_end();
    if base + KNOCK_MIN > end || base + KNOCK_MAX < end {
        return Ok(XDP_DROP);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    if rate_ok(saddr, now) {
        Ok(XDP_PASS)
    } else {
        Ok(XDP_DROP)
    }
}

/// Per-source fixed-window limiter: at most `RATE_LIMIT` knocks per window.
fn rate_ok(saddr: u32, now: u64) -> bool {
    let next = match unsafe { RATE.get(&saddr) } {
        Some(&s) if now.wrapping_sub(s.window_ns) < RATE_WINDOW_NS => {
            if s.count >= RATE_LIMIT {
                return false;
            }
            RateState {
                window_ns: s.window_ns,
                count: s.count + 1,
                _pad: 0,
            }
        }
        _ => RateState {
            window_ns: now,
            count: 1,
            _pad: 0,
        },
    };
    let _ = RATE.insert(&saddr, &next, 0);
    true
}

/// Bounds-checked read of a `Copy` value at `offset` from the packet start.
#[inline(always)]
fn load<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    // SAFETY: bounds checked above; packet bytes may be unaligned.
    Ok(unsafe { core::ptr::read_unaligned((start + offset) as *const T) })
}

fn is_protected(dport: u16) -> bool {
    unsafe { PROTECTED.get(&dport) }.is_some()
}

fn source_allowed(src: u32, dport: u16, now: u64) -> bool {
    match unsafe { ALLOW.get(&src) } {
        Some(grant) => now < grant.expiry_ns && grant.allows_port(dport),
        None => false,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
