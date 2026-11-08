//! RustSec advisory auditing and dependency vulnerability analysis (Requirement F-07).
//!
//! Provides pure-Rust `Cargo.lock` parsing, semantic version constraint evaluation,
//! and pinned advisory matching with explicit reachability classification (`Reachability::PresentOnly`).

pub mod cargo_lock;
pub mod database;
pub mod error;
pub mod semver;

pub use cargo_lock::{PackageRecord, parse_cargo_lock};
pub use database::{Advisory, AdvisoryAuditResult, AdvisoryDatabase, AdvisoryMatch};
pub use error::{AdvisoryError, AdvisoryErrorKind};
pub use semver::{Comparator, Op, SemverVersion, VersionReq};
