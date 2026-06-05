//! SPA port-cloaking XDP data plane (IPv4 + IPv6).
//!
//! TCP to a **protected** port:
//!   * tracked, non-idle flow → `PASS` (conntrack handoff past the pinhole);
//!   * pure `SYN` from a source holding a live grant → track + `PASS`;
//!   * else → `DROP` (silent cloak; stray ACKs included, so no RST leak).
//! UDP to the **knock** port: in-kernel size pre-filter + per-source rate limit
//! before the daemon's crypto path. Everything else `PASS`es.
//!
//! Addresses are unified to 16 bytes: IPv6 verbatim, IPv4 as its IPv4-mapped form
//! (`::ffff:a.b.c.d`), so one set of maps and one decision path serve both. IPv6
//! packets carrying extension headers (no direct L4) fall through to `PASS` and
//! are backstopped by the nftables floor. Parsing is dependency-free and every
//! read is bounds-checked. See `DESIGN.md` §3, §5.

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap, LruHashMap};
use aya_ebpf::programs::XdpContext;
use spa_ebpf_common::{GateConfig, Grant};

/// 16-byte address key (IPv6, or IPv4-mapped IPv4).
type Addr = [u8; 16];

/// Allow-list: source address → grant.
#[map]
static ALLOW: HashMap<Addr, Grant> = HashMap::with_max_entries(1024, 0);

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
static RATE: LruHashMap<Addr, RateState> = LruHashMap::with_max_entries(65536, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    saddr: Addr,
    daddr: Addr,
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

/// Parsed L3/L4 locator: addresses (16-byte), L4 protocol, and the L4 offset.
struct Packet {
    saddr: Addr,
    daddr: Addr,
    proto: u8,
    l4_off: usize,
}

// --- offsets. Hand-rolled to stay dependency-free. ---
const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFF: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const IP_IHL_OFF: usize = 0;
const IP_PROTO_OFF: usize = 9;
const IP_SRC_OFF: usize = 12;
const IP_DST_OFF: usize = 16;
const IP6_HDR_LEN: usize = 40;
const IP6_NEXTHDR_OFF: usize = 6;
const IP6_SRC_OFF: usize = 8;
const IP6_DST_OFF: usize = 24;
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
/// Valid knock payload size window (covers both suites with margin).
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
    let pkt = match parse(ctx)? {
        Some(p) => p,
        None => return Ok(XDP_PASS),
    };
    match pkt.proto {
        IPPROTO_TCP => tcp_gate(ctx, &pkt),
        IPPROTO_UDP => udp_gate(ctx, &pkt),
        _ => Ok(XDP_PASS),
    }
}

/// Parse to L4 for IPv4 and IPv6 (direct L4 only). `None` = not our concern
/// (non-IP, malformed, or IPv6 with extension headers).
fn parse(ctx: &XdpContext) -> Result<Option<Packet>, ()> {
    let ip_off = ETH_HDR_LEN;
    match u16::from_be(load::<u16>(ctx, ETH_TYPE_OFF)?) {
        ETHERTYPE_IPV4 => {
            let ihl = ((load::<u8>(ctx, ip_off + IP_IHL_OFF)? & 0x0f) as usize) * 4;
            if ihl < 20 {
                return Ok(None);
            }
            Ok(Some(Packet {
                saddr: mapped_v4(load::<[u8; 4]>(ctx, ip_off + IP_SRC_OFF)?),
                daddr: mapped_v4(load::<[u8; 4]>(ctx, ip_off + IP_DST_OFF)?),
                proto: load::<u8>(ctx, ip_off + IP_PROTO_OFF)?,
                l4_off: ip_off + ihl,
            }))
        }
        ETHERTYPE_IPV6 => {
            let proto = load::<u8>(ctx, ip_off + IP6_NEXTHDR_OFF)?;
            if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
                return Ok(None); // extension headers → let the nft floor handle it
            }
            Ok(Some(Packet {
                saddr: load::<Addr>(ctx, ip_off + IP6_SRC_OFF)?,
                daddr: load::<Addr>(ctx, ip_off + IP6_DST_OFF)?,
                proto,
                l4_off: ip_off + IP6_HDR_LEN,
            }))
        }
        _ => Ok(None),
    }
}

fn tcp_gate(ctx: &XdpContext, pkt: &Packet) -> Result<u32, ()> {
    let dport = u16::from_be(load::<u16>(ctx, pkt.l4_off + TCP_DPORT_OFF)?);
    if !is_protected(dport) {
        return Ok(XDP_PASS);
    }
    let flow = FlowKey {
        saddr: pkt.saddr,
        daddr: pkt.daddr,
        sport: u16::from_be(load::<u16>(ctx, pkt.l4_off + TCP_SPORT_OFF)?),
        dport,
    };
    let flags = load::<u8>(ctx, pkt.l4_off + TCP_FLAGS_OFF)?;
    let now = now_ns();

    // SAFETY: aya map `get` is unsafe because it hands back a pointer into map
    // memory; the map is static and outlives the program, and we only copy the
    // returned value out. The verifier proves the access.
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

    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && source_allowed(&pkt.saddr, dport, now) {
        let _ = ESTABLISHED.insert(&flow, &now, 0);
        return Ok(XDP_PASS);
    }

    Ok(XDP_DROP)
}

fn udp_gate(ctx: &XdpContext, pkt: &Packet) -> Result<u32, ()> {
    let dport = u16::from_be(load::<u16>(ctx, pkt.l4_off + UDP_DPORT_OFF)?);
    let knock_port = match CONFIG.get(0) {
        Some(cfg) => cfg.knock_port,
        None => return Ok(XDP_PASS),
    };
    if dport != knock_port {
        return Ok(XDP_PASS);
    }

    // Size pre-filter (cheap, before any userland crypto).
    let base = ctx.data() + pkt.l4_off + UDP_HDR_LEN;
    let end = ctx.data_end();
    if base + KNOCK_MIN > end || base + KNOCK_MAX < end {
        return Ok(XDP_DROP);
    }

    let now = now_ns();
    if rate_ok(&pkt.saddr, now) {
        Ok(XDP_PASS)
    } else {
        Ok(XDP_DROP)
    }
}

/// Per-source fixed-window limiter: at most `RATE_LIMIT` knocks per window.
fn rate_ok(saddr: &Addr, now: u64) -> bool {
    // SAFETY: map `get` returns a pointer into static map memory; we copy the
    // value out. Verifier-checked.
    let next = match unsafe { RATE.get(saddr) } {
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
    let _ = RATE.insert(saddr, &next, 0);
    true
}

/// IPv4 octets → IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
fn mapped_v4(o: [u8; 4]) -> Addr {
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12] = o[0];
    a[13] = o[1];
    a[14] = o[2];
    a[15] = o[3];
    a
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

fn source_allowed(src: &Addr, dport: u16, now: u64) -> bool {
    // SAFETY: map `get` returns a pointer into static map memory; we only read
    // the grant. Verifier-checked.
    match unsafe { ALLOW.get(src) } {
        Some(grant) => now < grant.expiry_ns && grant.allows_port(dport),
        None => false,
    }
}

/// Monotonic nanoseconds (the clock the daemon's grants are expressed in).
fn now_ns() -> u64 {
    // SAFETY: `bpf_ktime_get_ns` takes no arguments and is always valid to call.
    unsafe { bpf_ktime_get_ns() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
