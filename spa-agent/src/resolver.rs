//! Name resolution for mesh services. v1 writes a managed block into the system
//! hosts file (`name -> mesh_ip`), so `ssh demo-svc` resolves to the service's
//! stable mesh IP and routes into the TUN. The block is delimited by markers and
//! fully rewritten each refresh; everything outside it is left untouched. (An
//! embedded DNS responder is a later enhancement.)

use std::error::Error;
use std::fs;

const HOSTS: &str = "/etc/hosts";
const BEGIN: &str = "# >>> spa-agent (managed) >>>";
const END: &str = "# <<< spa-agent (managed) <<<";

/// Rewrite `existing` hosts-file text so its spa-agent block reflects `entries`
/// (`(name, mesh_ip)`). Pure (no I/O) so it is unit-tested; idempotent — repeated
/// applies converge, and empty `entries` removes the block.
fn render(existing: &str, entries: &[(String, String)]) -> String {
    // Drop any prior managed block, keeping the rest verbatim.
    let mut kept = String::new();
    let mut in_block = false;
    for line in existing.lines() {
        if line.trim() == BEGIN {
            in_block = true;
            continue;
        }
        if line.trim() == END {
            in_block = false;
            continue;
        }
        if !in_block {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    let mut out = kept.trim_end().to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    if !entries.is_empty() {
        out.push_str(BEGIN);
        out.push('\n');
        for (name, ip) in entries {
            out.push_str(&format!("{ip}\t{name}\n"));
        }
        out.push_str(END);
        out.push('\n');
    }
    out
}

/// Write the managed block for `entries` into the hosts file (needs root).
pub fn apply(entries: &[(String, String)]) -> Result<(), Box<dyn Error>> {
    let existing = fs::read_to_string(HOSTS).unwrap_or_default();
    fs::write(HOSTS, render(&existing, entries))
        .map_err(|e| format!("writing {HOSTS} (need root?): {e}").into())
}

/// Remove the managed block (best-effort cleanup on shutdown).
pub fn clear() {
    if let Ok(existing) = fs::read_to_string(HOSTS) {
        let _ = fs::write(HOSTS, render(&existing, &[]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, String)> {
        vec![
            ("demo-svc".into(), "100.64.0.1".into()),
            ("db-svc".into(), "100.64.0.2".into()),
        ]
    }

    #[test]
    fn adds_block_preserving_existing() {
        let out = render("127.0.0.1 localhost\n", &entries());
        assert!(out.starts_with("127.0.0.1 localhost\n"));
        assert!(out.contains("100.64.0.1\tdemo-svc"));
        assert!(out.contains("100.64.0.2\tdb-svc"));
        assert!(out.contains(BEGIN) && out.contains(END));
    }

    #[test]
    fn reapply_is_idempotent() {
        let once = render("127.0.0.1 localhost\n", &entries());
        let twice = render(&once, &entries());
        assert_eq!(once, twice);
    }

    #[test]
    fn empty_entries_removes_block_and_keeps_rest() {
        let with = render("127.0.0.1 localhost\n", &entries());
        let without = render(&with, &[]);
        assert_eq!(without, "127.0.0.1 localhost\n");
        assert!(!without.contains(BEGIN));
    }
}
