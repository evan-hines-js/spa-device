#![forbid(unsafe_code)]
//! spa-agent library: the workstation client agent's building blocks — the signed
//! service [`catalog`], the [`resolver`] (name → mesh IP), the [`tundev`] TUN
//! device, and the [`proxy`] datapath (per-flow knock-then-forward). The
//! `spa-agent` binary is a thin CLI over these.

pub mod catalog;
pub mod proxy;
pub mod resolver;
pub mod tundev;
