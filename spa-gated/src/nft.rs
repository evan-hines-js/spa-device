//! Fail-closed nftables floor (DESIGN.md §7).
//!
//! XDP is the fast path, but if the daemon is `kill -9`'d the XDP program
//! detaches and the port would be exposed. This installs a base netfilter floor
//! that drops the protected ports unless the source is in the `allow4` set (which
//! the gate writer mirrors the grants into, with a timeout) or the flow is
//! already established. The floor outlives the daemon, and its set entries expire
//! on their own, so a crashed daemon fails *closed*.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

/// Install (idempotently) the base floor for the given protected ports.
pub fn install_floor(protected: &[u16]) -> std::io::Result<()> {
    let mut script = String::from(
        "add table inet spa\n\
         flush table inet spa\n\
         table inet spa {\n\
         \x20 set allow4 { type ipv4_addr; flags timeout; }\n\
         \x20 set ports { type inet_service; }\n\
         \x20 chain input {\n\
         \x20   type filter hook input priority filter; policy accept;\n\
         \x20   ct state established,related accept\n\
         \x20   tcp dport @ports ip saddr @allow4 accept\n\
         \x20   tcp dport @ports drop\n\
         \x20 }\n\
         }\n",
    );
    for p in protected {
        script.push_str(&format!("add element inet spa ports {{ {p} }}\n"));
    }
    run_stdin(&script)
}

/// Mirror a grant: permit `ip` to the protected ports for `timeout_secs`
/// (rounded up to nftables' 1s granularity). Best-effort; the BPF allow-list is
/// the authoritative fast path while the daemon lives.
pub fn allow(ip: Ipv4Addr, timeout_secs: u64) {
    let secs = timeout_secs.max(1);
    let _ = Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            "spa",
            "allow4",
            &format!("{{ {ip} timeout {secs}s }}"),
        ])
        .status();
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
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "nft -f failed",
        ))
    }
}
