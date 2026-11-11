//! Sentra: AI-assisted security research and remediation platform.
//!
//! This crate serves as the primary façade and unified entry point for the Sentra
//! security platform, re-exporting the complete deterministic core analysis engine
//! from [`sentra_core`] alongside CLI execution interfaces from [`sentra_cli`].
//!
//! # Scope (see `docs/LIMITATIONS.md`)
//! - **Safe Rust Invariant:** `#![forbid(unsafe_code)]` unconditionally enforced.
//! - **SAST:** Heuristic line-based rules and intra-procedural lexical taint tracking for
//!   CWE-89, CWE-78, CWE-95 and CWE-22; no syntax tree is built.
//! - **Dependency Audit:** Lockfile parsers for 12 ecosystems, matched against a small
//!   bundled advisory sample, not a synchronized OSV or RustSec feed.
//! - **Three-Tier Verification:** Verification bundles (baseline fails, target passes, no
//!   regressions) are modelled; no isolated runner executes them yet.
//! - **Model Context Protocol (MCP):** Local stdio JSON-RPC 2.0 server whose tools write no
//!   workspace files. With `--database`, the session-status tool opens the SQLite store, which
//!   may update its `-wal` and `-shm` files (see `docs/LIMITATIONS.md` §5).

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub use sentra_core::*;

/// Terminal adapter and CLI commands execution interface.
pub mod cli {
    pub use sentra_cli::*;
}
