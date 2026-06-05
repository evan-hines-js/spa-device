//! SPA port-cloaking XDP data plane.
//!
//! For every inbound packet:
//!   * TCP to a **protected** port → `PASS` only if the source holds a live
//!     grant covering that port, else `DROP` (silent cloak);
//!   * everything else → `PASS` (the knock arrives as UDP and is handled by the
//!     userland daemon's socket; only listening TCP ports are cloaked).
//!
//! Parsing is dependency-free; every read is bounds-checked against the packet
//! tail, so a short or malformed packet can only ever fall through to `PASS` —
//! never an out-of-bounds read. The grant/expiry logic lives in the tested
//! `spa-ebpf-common`. See `DESIGN.md` §3.

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use spa_ebpf_common::Grant;

/// Allow-list: source IPv4 (the packet's `src_addr`, host-native `u32`) → grant.
#[map]
static ALLOW: HashMap<u32, Grant> = HashMap::with_max_entries(1024, 0);

/// Set of cloaked TCP ports (host byte order). Presence means "protected".
#[map]
static PROTECTED: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

// --- L2/L3/L4 offsets (IPv4). Hand-rolled to stay dependency-free. ---
const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFF: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_IHL_OFF: usize = 0; // low nibble of byte 0, ×4 = header length
const IP_PROTO_OFF: usize = 9;
const IP_SRC_OFF: usize = 12;
const IPPROTO_TCP: u8 = 6;
const L4_DPORT_OFF: usize = 2; // dest port at offset 2 in the TCP header

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

    let dport = u16::from_be(load::<u16>(ctx, ip_off + ihl + L4_DPORT_OFF)?);
    if !is_protected(dport) {
        return Ok(XDP_PASS);
    }

    let src = load::<u32>(ctx, ip_off + IP_SRC_OFF)?; // map key, as-on-wire
    Ok(if source_allowed(src, dport) {
        XDP_PASS
    } else {
        XDP_DROP // cloaked: silent discard, no RST
    })
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

fn source_allowed(src: u32, dport: u16) -> bool {
    match unsafe { ALLOW.get(&src) } {
        Some(grant) => {
            let now = unsafe { bpf_ktime_get_ns() };
            now < grant.expiry_ns && grant.allows_port(dport)
        }
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
