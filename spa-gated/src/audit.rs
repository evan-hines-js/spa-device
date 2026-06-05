//! Structured audit log: one JSON object per line on stdout. This is the
//! out-of-band observability channel — the gate never answers on the wire, so
//! every decision (grant, deny, drop) and policy change is recorded here for a
//! SIEM/journald to collect. See `DESIGN.md` §10.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use spa_core::Decision;

fn ts_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event<'a> {
    Startup {
        ts_ms: u128,
        interface: &'a str,
        knock_port: u16,
        suite: &'a str,
        protected: &'a [u16],
        clients: usize,
        tokens: usize,
        nft_floor: bool,
    },
    Floor {
        ts_ms: u128,
        protected: &'a [u16],
    },
    Knock {
        ts_ms: u128,
        source: String,
        outcome: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        ports: Option<&'a [u16]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Bundle {
        ts_ms: u128,
        action: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        generation: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

fn emit(event: &Event) {
    if let Ok(line) = serde_json::to_string(event) {
        println!("{line}");
    }
}

pub fn startup(
    interface: &str,
    knock_port: u16,
    suite: &str,
    protected: &[u16],
    clients: usize,
    tokens: usize,
    nft_floor: bool,
) {
    emit(&Event::Startup {
        ts_ms: ts_ms(),
        interface,
        knock_port,
        suite,
        protected,
        clients,
        tokens,
        nft_floor,
    });
}

pub fn floor(protected: &[u16]) {
    emit(&Event::Floor {
        ts_ms: ts_ms(),
        protected,
    });
}

/// The audit-critical event: every knock decision.
pub fn knock(source: IpAddr, decision: &Decision) {
    let event = match decision {
        Decision::Opened { ports } => Event::Knock {
            ts_ms: ts_ms(),
            source: source.to_string(),
            outcome: "open",
            ports: Some(ports.as_slice()),
            reason: None,
        },
        Decision::Rejected(reason) => Event::Knock {
            ts_ms: ts_ms(),
            source: source.to_string(),
            outcome: "deny",
            ports: None,
            reason: Some(format!("{reason:?}")),
        },
    };
    emit(&event);
}

pub fn bundle(action: &str, generation: Option<u64>, detail: Option<String>) {
    emit(&Event::Bundle {
        ts_ms: ts_ms(),
        action,
        generation,
        detail,
    });
}
