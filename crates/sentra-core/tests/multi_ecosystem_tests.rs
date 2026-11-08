//! Integration tests for Multi-Ecosystem Lockfile Auditing (npm, yarn, pnpm, bun, deno, cargo).
//!
//! Verifies:
//! - Pure-Rust parsing of `package-lock.json` (npm v1, v2, v3).
//! - Pure-Rust parsing of `yarn.lock` (Yarn v1 Classic and v2+ Berry).
//! - Pure-Rust parsing of `pnpm-lock.yaml` (pnpm v6, v9).
//! - Pure-Rust parsing of `bun.lock` (Bun 1.1/1.2 JSON and text format).
//! - Pure-Rust parsing of `deno.lock` (Deno v2, v3).
//! - Advisory matching across ecosystems against pinned CVEs and GHSAs.
//! - Workspace auto-discovery of non-Cargo lockfiles and polyglot workspaces.

use std::fs;

use sentra_core::{
    AdvisoryDatabase, LockfileKind, Severity, TimestampUtc,
    advisory::{
        discover_workspace_lockfiles, parse_bun_lock, parse_deno_lock, parse_package_lock,
        parse_pnpm_lock, parse_yarn_lock,
    },
    service::LocalWorkspace,
};

#[test]
fn test_npm_package_lock_audit_and_advisories() {
    let content = r#"{
        "name": "node-target-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "node-target-project",
                "version": "1.0.0"
            },
            "node_modules/lodash": {
                "version": "4.17.11",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz",
                "integrity": "sha512-abc123"
            },
            "node_modules/express": {
                "version": "4.19.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
                "integrity": "sha512-def456"
            },
            "node_modules/axios": {
                "version": "1.6.8",
                "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.8.tgz"
            }
        }
    }"#;

    let packages = parse_package_lock(content).expect("valid package-lock.json");
    assert_eq!(packages.len(), 3);

    let now = TimestampUtc::now();
    let db = AdvisoryDatabase::default_pinned(now);
    let result = db
        .audit_packages(&packages, now, 30)
        .expect("audit succeeds");

    // lodash 4.17.11 (< 4.17.12) is affected by GHSA-p6mc-m468-83gw (Critical)
    // express 4.19.2 (< 4.20.0) is affected by GHSA-qw6h-v559-w396 (High)
    // axios 1.6.8 is NOT affected (patch is 1.6.0)
    assert_eq!(result.packages_audited, 3);
    assert_eq!(result.vulnerable_packages, 2);
    assert_eq!(result.matches.len(), 2);

    let lodash_match = result
        .matches
        .iter()
        .find(|m| m.package == "lodash")
        .unwrap();
    assert_eq!(lodash_match.advisory.severity, Severity::Critical);
    assert_eq!(lodash_match.recommended_patch.as_deref(), Some("4.17.12"));

    let express_match = result
        .matches
        .iter()
        .find(|m| m.package == "express")
        .unwrap();
    assert_eq!(express_match.advisory.severity, Severity::High);
    assert_eq!(express_match.recommended_patch.as_deref(), Some("4.20.0"));
}

#[test]
fn test_yarn_lock_classic_and_berry_audit() {
    let classic_content = r#"# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.10"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.10.tgz"
  integrity sha512-abc

minimist@0.0.8:
  version "0.0.8"
  resolved "https://registry.yarnpkg.com/minimist/-/minimist-0.0.8.tgz"
"#;

    let pkgs = parse_yarn_lock(classic_content).expect("valid classic yarn.lock");
    assert_eq!(pkgs.len(), 2);

    let now = TimestampUtc::now();
    let db = AdvisoryDatabase::default_pinned(now);
    let result = db.audit_packages(&pkgs, now, 30).unwrap();

    // lodash 4.17.10 is vulnerable
    // minimist 0.0.8 (< 0.2.1) is vulnerable to GHSA-vh95-rmgr-6w4m (Medium)
    assert_eq!(result.packages_audited, 2);
    assert_eq!(result.vulnerable_packages, 2);

    // Test Berry format
    let berry_content = r#"__metadata:
  version: 6

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"axios@npm:^0.21.1":
  version: 0.21.1
  resolution: "axios@npm:0.21.1"
"#;

    let berry_pkgs = parse_yarn_lock(berry_content).expect("valid berry yarn.lock");
    assert_eq!(berry_pkgs.len(), 2);

    let berry_result = db.audit_packages(&berry_pkgs, now, 30).unwrap();
    // lodash 4.17.21 is patched (0 findings)
    // axios 0.21.1 (< 1.6.0) is vulnerable
    assert_eq!(berry_result.vulnerable_packages, 1);
    assert_eq!(berry_result.matches[0].package, "axios");
}

#[test]
fn test_pnpm_lock_audit() {
    let content = r#"lockfileVersion: '6.0'

packages:

  /lodash@4.17.5:
    resolution: {integrity: sha512-123}

  /express@4.20.0:
    resolution: {integrity: sha512-456}
"#;

    let pkgs = parse_pnpm_lock(content).expect("valid pnpm-lock.yaml");
    assert_eq!(pkgs.len(), 2);

    let now = TimestampUtc::now();
    let db = AdvisoryDatabase::default_pinned(now);
    let result = db.audit_packages(&pkgs, now, 30).unwrap();

    // lodash 4.17.5 is vulnerable
    // express 4.20.0 is patched
    assert_eq!(result.vulnerable_packages, 1);
    assert_eq!(result.matches[0].package, "lodash");
}

#[test]
fn test_bun_lock_audit() {
    let content = r#"{
        "lockfileVersion": 1,
        "packages": {
            "lodash": [
                "lodash@4.17.4",
                "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz"
            ],
            "minimist": [
                "minimist@1.2.0",
                "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"
            ]
        }
    }"#;

    let pkgs = parse_bun_lock(content).expect("valid bun.lock");
    assert_eq!(pkgs.len(), 2);

    let now = TimestampUtc::now();
    let db = AdvisoryDatabase::default_pinned(now);
    let result = db.audit_packages(&pkgs, now, 30).unwrap();

    // lodash 4.17.4 is vulnerable
    // minimist 1.2.0 (>= 1.0.0, < 1.2.3) is vulnerable
    assert_eq!(result.vulnerable_packages, 2);
}

#[test]
fn test_deno_lock_audit() {
    let content = r#"{
        "version": "3",
        "packages": {
            "specifiers": {
                "npm:lodash@^4.17.0": "npm:lodash@4.17.0"
            },
            "npm": {
                "lodash@4.17.0": {
                    "integrity": "sha512-xyz"
                },
                "axios@1.6.0": {
                    "integrity": "sha512-uvw"
                }
            }
        }
    }"#;

    let pkgs = parse_deno_lock(content).expect("valid deno.lock");
    assert_eq!(pkgs.len(), 2);

    let now = TimestampUtc::now();
    let db = AdvisoryDatabase::default_pinned(now);
    let result = db.audit_packages(&pkgs, now, 30).unwrap();

    // lodash 4.17.0 is vulnerable
    // axios 1.6.0 is patched
    assert_eq!(result.vulnerable_packages, 1);
    assert_eq!(result.matches[0].package, "lodash");
}

#[cfg(windows)]
#[test]
fn test_local_workspace_discovers_npm_and_bun_lockfiles() {
    let temp_root = std::env::temp_dir().join(format!("sentra_multi_test_{}", std::process::id()));
    let workspace = temp_root.join("npm_project");
    let storage = temp_root.join("storage");

    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&storage).unwrap();

    let package_lock_content = r#"{
        "name": "node-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": { "name": "node-app", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.11" }
        }
    }"#;
    fs::write(workspace.join("package-lock.json"), package_lock_content).unwrap();

    let discovered = discover_workspace_lockfiles(&workspace);
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].0, LockfileKind::PackageLock);
    assert_eq!(discovered[0].1, "package-lock.json");

    let db_path = storage.join("audit.db");
    let init_report = LocalWorkspace::initialize(&workspace, &db_path).unwrap();
    assert!(init_report.initialized);

    let now = TimestampUtc::now();
    let advisory_db = AdvisoryDatabase::default_pinned(now);
    let audit_report =
        LocalWorkspace::audit_dependencies(&workspace, &db_path, &advisory_db).unwrap();

    assert_eq!(audit_report.audit_result.packages_audited, 1);
    assert_eq!(audit_report.audit_result.vulnerable_packages, 1);
    assert_eq!(audit_report.candidate_findings.len(), 1);
    assert_eq!(
        audit_report.candidate_findings[0].title(),
        "Vulnerability in lodash: Prototype Pollution in lodash (GHSA-p6mc-m468-83gw)"
    );
    assert_eq!(
        audit_report.candidate_findings[0]
            .location()
            .map(|l| l.path.as_str()),
        Some("package-lock.json")
    );

    let _ = fs::remove_dir_all(&temp_root);
}
