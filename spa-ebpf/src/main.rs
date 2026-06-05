//! SPA port-cloaking XDP data plane.
//!
//! For every inbound IPv4/TCP packet to a **protected** port:
//!   * if it belongs to a tracked, non-idle flow → `PASS` (the conntrack handoff
//!     that lets an established connection outlive the micro-pinhole);
//!   * else if it is a pure `SYN` from a source holding a live grant → start
//!     tracking the flow and `PASS`;
//!   * else → `DROP` (silent cloak — including stray ACKs, so no RST leaks).
//! All other traffic `PASS`es (the knock is UDP, handled by the daemon's socket).
//!
//! Parsing is dependency-free and every read is bounds-checked, so a short or
//! malformed packet can only fall through to `PASS`, never read out of bounds.
//! See `DESIGN.md` §3, §5.

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{HashMap, LruHashMap};
use aya_ebpf::programs::XdpContext;
use spa_ebpf_common::Grant;

/// Allow-list: source IPv4 (the packet's `src_addr`, host-native `u32`) → grant.
#[map]
static ALLOW: HashMap<u32, Grant> = HashMap::with_max_entries(1024, 0);

/// Set of cloaked TCP ports (host byte order). Presence means "protected".
#[map]
static PROTECTED: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

/// Tracked flows: inbound 4-tuple → last-seen monotonic ns. LRU-bounded; an
/// admitted connection is tracked here so its packets pass after the grant
/// expires, until it is idle past `FLOW_IDLE_NS` or torn down (FIN/RST).
#[map]
static ESTABLISHED: LruHashMap<FlowKey, u64> = LruHashMap::with_max_entries(65536, 0);

/// Inbound TCP 4-tuple. `repr(C)` so the byte layout is a stable map key.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

// --- L2/L3/L4 offsets (IPv4). Hand-rolled to stay dependency-free. ---
const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFF: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_IHL_OFF: usize = 0; // low nibble of byte 0, ×4 = header length
const IP_PROTO_OFF: usize = 9;
const IP_SRC_OFF: usize = 12;
const IP_DST_OFF: usize = 16;
const IPPROTO_TCP: u8 = 6;
const TCP_SPORT_OFF: usize = 0;
const TCP_DPORT_OFF: usize = 2;
const TCP_FLAGS_OFF: usize = 13;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;
/// A tracked flow idle this long is treated as gone (re-knock required).
const FLOW_IDLE_NS: u64 = 120_000_000_000; // 2 minutes

#[xdp]
pub fn spa_gate(ctx: XdpContext) -> u32 {
    match try_gate(&ctx) {
        Ok(action) => action,
        // Any parse miss falls through to the stack; the base default-drop
        // firewall rule (DESIGN.md §7) backs the cloak regardless.
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
    if load::<u8>(ctx, ip_off + IP_PROTO_OFF)? != IPPROTO_TCP {
        return Ok(XDP_PASS);
    }

    let l4 = ip_off + ihl;
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

    // Established flow → pass (outlives the micro-pinhole).
    if let Some(&last) = unsafe { ESTABLISHED.get(&flow) } {
        if now.wrapping_sub(last) < FLOW_IDLE_NS {
            if flags & (TCP_FIN | TCP_RST) != 0 {
                let _ = ESTABLISHED.remove(&flow);
            } else {
                let _ = ESTABLISHED.insert(&flow, &now, 0);
            }
            return Ok(XDP_PASS);
        }
        let _ = ESTABLISHED.remove(&flow); // idle too long
    }

    // New connection: only a pure SYN from a currently-authorized source may
    // open one. Track it so the rest of the flow passes.
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && source_allowed(flow.saddr, dport, now) {
        let _ = ESTABLISHED.insert(&flow, &now, 0);
        return Ok(XDP_PASS);
    }

    Ok(XDP_DROP) // cloaked: silent discard, no RST
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
    // Unreachable: the program is panic-free, so this is dead-code-eliminated
    // before the verifier sees it.
    loop {}
}
