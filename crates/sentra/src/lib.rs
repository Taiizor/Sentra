//! Sentra: Autonomous Security Research & Independently Verified Remediation Platform.
//!
//! This crate serves as the primary façade and unified entry point for the Sentra
//! security platform, re-exporting the complete deterministic core analysis engine
//! from [`sentra_core`] alongside CLI execution interfaces from [`sentra_cli`].
//!
//! # Architectural Invariants
//! - **Safe Rust Invariant:** `#![forbid(unsafe_code)]` unconditionally enforced.
//! - **Pure AST & Taint Tracking:** Interprocedural lexical dataflow analysis for CWE-89, CWE-78, CWE-95, CWE-22.
//! - **12-Ecosystem Advisory Auditor:** Pinned OSV and RustSec vulnerability auditing across lockfiles.
//! - **Three-Tier Verification:** Patch validation with 0 regressions in isolated cleanrooms.
//! - **Model Context Protocol (MCP):** Native stdio JSON-RPC 2.0 transport server for AI coding assistants.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub use sentra_core::*;

/// Terminal adapter and CLI commands execution interface.
pub mod cli {
    pub use sentra_cli::*;
}
