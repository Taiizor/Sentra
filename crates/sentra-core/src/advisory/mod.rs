//! Multi-ecosystem advisory auditing and dependency vulnerability analysis (Requirement F-07).
//!
//! Provides pure-Rust lockfile parsing across:
//! - Rust: `Cargo.lock`
//! - npm & Node.js: `package-lock.json`
//! - Yarn: `yarn.lock`
//! - pnpm: `pnpm-lock.yaml`
//! - Bun: `bun.lock`
//! - Deno: `deno.lock`
//!
//! Evaluates semantic version constraints and pinned advisory matching with explicit
//! reachability classification (`Reachability::PresentOnly`).

pub mod bun_lock;
pub mod cargo_lock;
pub mod database;
pub mod deno_lock;
pub mod error;
pub mod multi_lock;
pub mod package_lock;
pub mod pnpm_lock;
pub mod semver;
pub mod yarn_lock;

pub use bun_lock::parse_bun_lock;
pub use cargo_lock::{PackageRecord, parse_cargo_lock};
pub use database::{Advisory, AdvisoryAuditResult, AdvisoryDatabase, AdvisoryMatch};
pub use deno_lock::parse_deno_lock;
pub use error::{AdvisoryError, AdvisoryErrorKind};
pub use multi_lock::{
    LockfileKind, discover_workspace_lockfiles, parse_lockfile_content, split_package_specifier,
};
pub use package_lock::parse_package_lock;
pub use pnpm_lock::parse_pnpm_lock;
pub use semver::{Comparator, Op, SemverVersion, VersionReq};
pub use yarn_lock::parse_yarn_lock;
