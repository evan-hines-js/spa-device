#![forbid(unsafe_code)]
//! spa-agent library: the workstation client agent's building blocks — the signed
//! service [`catalog`] and (soon) the TUN knock-and-forward datapath. The
//! `spa-agent` binary is a thin CLI over this.

pub mod catalog;
