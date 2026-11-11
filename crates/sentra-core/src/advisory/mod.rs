//! Multi-ecosystem advisory auditing and dependency vulnerability analysis (Requirement F-07).
//!
//! Provides pure-Rust lockfile parsing across:
//! - Rust: `Cargo.lock`
//! - npm & Node.js: `package-lock.json`
//! - Yarn: `yarn.lock`
//! - pnpm: `pnpm-lock.yaml`
//! - Bun: `bun.lock`
//! - Deno: `deno.lock`
//! - Python: `requirements.txt`, `poetry.lock`, `Pipfile.lock`
//! - Go: `go.sum`
//! - PHP: `composer.lock`
//! - .NET: `packages.lock.json`
//! - Ruby: `Gemfile.lock`
//!
//! Evaluates semantic version constraints and pinned advisory matching with explicit
//! reachability classification (`Reachability::PresentOnly`).

pub mod bun_lock;
pub mod cargo_lock;
pub mod composer_lock;
pub mod database;
pub mod deno_lock;
pub mod error;
pub mod gemfile_lock;
pub mod go_lock;
pub mod inventory;
pub mod multi_lock;
pub mod nuget_lock;
pub mod osv;
pub mod package_lock;
pub mod pnpm_lock;
pub mod python_lock;
pub mod semver;
pub mod yarn_lock;

pub use bun_lock::parse_bun_lock;
pub use cargo_lock::{PackageRecord, parse_cargo_lock};
pub use composer_lock::parse_composer_lock;
pub use database::{
    Advisory, AdvisoryAuditResult, AdvisoryDatabase, AdvisoryMatch,
    PINNED_ADVISORY_SET_CURATED_AT_MILLIS,
};
pub use deno_lock::parse_deno_lock;
pub use error::{AdvisoryError, AdvisoryErrorKind};
pub use gemfile_lock::parse_gemfile_lock;
pub use go_lock::parse_go_sum;
pub use inventory::{
    DEFAULT_INVENTORY_MAX_DEPTH, InventoryLimits, InventoryLockfile, InventoryPackage,
    MAX_INVENTORY_DEPTH, SKIPPED_DIRECTORY_NAMES, WorkspaceInventory, collect_lockfile_inventory,
};
pub use multi_lock::{
    LockfileKind, discover_workspace_lockfiles, parse_lockfile_content, split_package_specifier,
};
pub use nuget_lock::parse_nuget_lock;
pub use osv::{
    OsvAffected, OsvDirectoryIngest, OsvPackage, OsvRange, OsvRecord, OsvSeverity,
    ingest_osv_directory, ingest_osv_directory_report, parse_osv_payload,
};
pub use package_lock::parse_package_lock;
pub use pnpm_lock::parse_pnpm_lock;
pub use python_lock::{parse_pipfile_lock, parse_poetry_lock, parse_requirements_txt};
pub use semver::{Comparator, Op, SemverVersion, VersionReq};
pub use yarn_lock::parse_yarn_lock;
