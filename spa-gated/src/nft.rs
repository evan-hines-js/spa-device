//! Fail-closed nftables floor (DESIGN.md §7).
//!
//! XDP is the fast path, but if the daemon is `kill -9`'d the XDP program
//! detaches and the port would be exposed. This installs a base netfilter floor
//! that drops the protected ports unless the source is in the `allow4` set (which
//! the gate writer mirrors the grants into, with a timeout) or the flow is
//! already established. The floor outlives the daemon, and its set entries expire
//! on their own, so a crashed daemon fails *closed*.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Install (idempotently) the base floor for the given protected ports. The
/// `inet` table covers both IPv4 and IPv6.
pub fn install_floor(protected: &[u16]) -> std::io::Result<()> {
    let mut script = String::from(
        "add table inet spa\n\
         flush table inet spa\n\
         table inet spa {\n\
         \x20 set allow4 { type ipv4_addr; flags timeout; }\n\
         \x20 set allow6 { type ipv6_addr; flags timeout; }\n\
         \x20 set ports { type inet_service; }\n\
         \x20 chain input {\n\
         \x20   type filter hook input priority filter; policy accept;\n\
         \x20   iif \"lo\" accept\n\
         \x20   ct state established,related accept\n\
         \x20   tcp dport @ports ip saddr @allow4 accept\n\
         \x20   tcp dport @ports ip6 saddr @allow6 accept\n\
         \x20   tcp dport @ports drop\n\
         \x20 }\n\
         }\n",
    );
    for p in protected {
        script.push_str(&format!("add element inet spa ports {{ {p} }}\n"));
    }
    run_stdin(&script)
}

/// Mirror a grant: permit `source` to the protected ports for `timeout_secs`
/// (rounded up to nftables' 1s granularity). Best-effort; the BPF allow-list is
/// the authoritative fast path while the daemon lives.
pub fn allow(source: IpAddr, timeout_secs: u64) {
    let secs = timeout_secs.max(1);
    let (set, addr) = match normalize(source) {
        IpAddr::V4(v4) => ("allow4", v4.to_string()),
        IpAddr::V6(v6) => ("allow6", v6.to_string()),
    };
    let _ = Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            "spa",
            set,
            &format!("{{ {addr} timeout {secs}s }}"),
        ])
        .status();
}

/// An IPv4-mapped IPv6 source (seen on a dual-stack socket) is really IPv4, so it
/// belongs in `allow4` to match the `ip saddr` rule on real v4 packets.
fn normalize(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Replace the protected-ports set (used on bundle reload).
pub fn set_ports(protected: &[u16]) -> std::io::Result<()> {
    let mut script = String::from("flush set inet spa ports\n");
    for p in protected {
        script.push_str(&format!("add element inet spa ports {{ {p} }}\n"));
    }
    run_stdin(&script)
}

fn run_stdin(script: &str) -> std::io::Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("nft -f failed"))
    }
}
