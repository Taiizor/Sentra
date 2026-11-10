use std::{fs, path::PathBuf};

use sentra_core::{
    AdvisoryDatabase, Confidence, Finding, FindingId, FindingSource, Reachability,
    SARIF_SCHEMA_V2_1_0, SARIF_VERSION_2_1_0, SarifLevel, SarifLog, SessionId, Severity,
    TargetLocation, TaskId, TimestampUtc,
    export::{
        generate_sarif_json, generate_sarif_report, severity_to_sarif_level,
        severity_to_security_score,
    },
    service::LocalWorkspace,
};

fn sample_finding(advisory_id: &str, severity: Severity) -> Finding {
    Finding::new_candidate(
        FindingId::new(),
        SessionId::new(),
        TaskId::new(),
        format!("Vulnerability in crate for {advisory_id}"),
        "Detailed vulnerability explanation and impact.",
        severity,
        Confidence::Confirmed,
        Reachability::PresentOnly,
        FindingSource::CargoLockAdvisory {
            advisory_id: advisory_id.to_string(),
            package: "smallvec".to_string(),
            version: "0.6.13".to_string(),
        },
        Some(TargetLocation {
            path: "Cargo.lock".to_string(),
            start_line: Some(10),
            end_line: Some(15),
        }),
        None,
        TimestampUtc::now(),
    )
}

#[test]
fn test_sarif_empty_findings() {
    let log = generate_sarif_report(&[], "0.1.0");
    assert_eq!(log.schema, SARIF_SCHEMA_V2_1_0);
    assert_eq!(log.version, SARIF_VERSION_2_1_0);
    assert_eq!(log.runs.len(), 1);

    let run = &log.runs[0];
    assert_eq!(run.tool.driver.name, "Sentra");
    assert_eq!(run.tool.driver.version, "0.1.0");
    assert!(run.tool.driver.rules.is_empty());
    assert!(run.results.is_empty());

    let json = generate_sarif_json(&[], "0.1.0").unwrap();
    assert!(json.contains("\"version\": \"2.1.0\""));
    assert!(json.contains("\"name\": \"Sentra\""));
}

#[test]
fn test_sarif_severity_mappings() {
    assert_eq!(
        severity_to_sarif_level(Severity::Critical),
        SarifLevel::Error
    );
    assert_eq!(severity_to_sarif_level(Severity::High), SarifLevel::Error);
    assert_eq!(
        severity_to_sarif_level(Severity::Medium),
        SarifLevel::Warning
    );
    assert_eq!(severity_to_sarif_level(Severity::Low), SarifLevel::Note);
    assert_eq!(
        severity_to_sarif_level(Severity::Informational),
        SarifLevel::Note
    );

    assert_eq!(severity_to_security_score(Severity::Critical), "9.0");
    assert_eq!(severity_to_security_score(Severity::High), "7.5");
    assert_eq!(severity_to_security_score(Severity::Medium), "5.0");
    assert_eq!(severity_to_security_score(Severity::Low), "2.0");
    assert_eq!(severity_to_security_score(Severity::Informational), "0.0");
}

#[test]
fn test_sarif_dependency_findings_structure() {
    let finding1 = sample_finding("RUSTSEC-2021-0145", Severity::High);
    let finding2 = sample_finding("RUSTSEC-2021-0145", Severity::High); // Duplicate advisory
    let finding3 = sample_finding("RUSTSEC-2020-0001", Severity::Critical);

    let log = generate_sarif_report(&[finding1, finding2, finding3], "0.1.0");
    let run = &log.runs[0];

    // 3 results, but only 2 unique rules
    assert_eq!(run.results.len(), 3);
    assert_eq!(run.tool.driver.rules.len(), 2);

    let rule_rustsec = run
        .tool
        .driver
        .rules
        .iter()
        .find(|r| r.id == "RUSTSEC-2021-0145")
        .unwrap();
    assert_eq!(rule_rustsec.name, "DependencyVulnerability");
    assert_eq!(
        rule_rustsec.help_uri.as_deref(),
        Some("https://rustsec.org/advisories/RUSTSEC-2021-0145.html")
    );
    assert_eq!(
        rule_rustsec.properties.get("security-severity").unwrap(),
        "7.5"
    );

    let rule_crit = run
        .tool
        .driver
        .rules
        .iter()
        .find(|r| r.id == "RUSTSEC-2020-0001")
        .unwrap();
    assert_eq!(rule_crit.default_configuration.level, SarifLevel::Error);
    assert_eq!(
        rule_crit.properties.get("security-severity").unwrap(),
        "9.0"
    );

    // Verify result properties
    let result = &run.results[0];
    assert_eq!(result.rule_id, "RUSTSEC-2021-0145");
    assert_eq!(result.level, SarifLevel::Error);
    assert_eq!(
        result.properties.get("reachability").unwrap(),
        "PRESENT_ONLY"
    );
    assert_eq!(result.properties.get("status").unwrap(), "CANDIDATE");

    // Location verification
    let loc = &result.locations[0].physical_location;
    assert_eq!(loc.artifact_location.uri, "Cargo.lock");
    assert_eq!(loc.region.unwrap().start_line, Some(10));
    assert_eq!(loc.region.unwrap().end_line, Some(15));
}

#[test]
fn test_sarif_static_and_dynamic_provenance() {
    let static_f = Finding::new_candidate(
        FindingId::new(),
        SessionId::new(),
        TaskId::new(),
        "Hardcoded credentials detected",
        "Found plaintext token in source",
        Severity::Critical,
        Confidence::High,
        Reachability::DemonstratedRuntime,
        FindingSource::StaticAnalysis {
            engine: "Semgrep".to_string(),
            rule_id: "rules.security.hardcoded-token".to_string(),
        },
        Some(TargetLocation {
            path: "src/auth/token.rs".to_string(),
            start_line: Some(42),
            end_line: Some(42),
        }),
        None,
        TimestampUtc::now(),
    );

    let dynamic_f = Finding::new_candidate(
        FindingId::new(),
        SessionId::new(),
        TaskId::new(),
        "Heap buffer overflow in parser",
        "AddressSanitizer caught SIGSEGV",
        Severity::High,
        Confidence::High,
        Reachability::DemonstratedRuntime,
        FindingSource::DynamicAnalysis {
            agent_role: "Fuzzer".to_string(),
            oracle_id: "cwe-120-asan".to_string(),
        },
        Some(TargetLocation {
            path: "src/parser.c".to_string(),
            start_line: Some(108),
            end_line: Some(120),
        }),
        None,
        TimestampUtc::now(),
    );

    let json = generate_sarif_json(&[static_f, dynamic_f], "0.1.0").unwrap();
    let parsed: SarifLog = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.runs[0].results.len(), 2);
    assert_eq!(parsed.runs[0].tool.driver.rules.len(), 2);

    let r1 = &parsed.runs[0].results[0];
    assert_eq!(r1.rule_id, "rules.security.hardcoded-token");
    assert_eq!(
        r1.locations[0].physical_location.artifact_location.uri,
        "src/auth/token.rs"
    );

    let r2 = &parsed.runs[0].results[1];
    assert_eq!(r2.rule_id, "Fuzzer-cwe-120-asan");
    assert_eq!(
        r2.locations[0].physical_location.artifact_location.uri,
        "src/parser.c"
    );
}

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    db: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let unique = format!("sentra_sarif_test_{}", SessionId::new());
        let root = temp.join(unique);
        let workspace = root.join("workspace");
        let storage = root.join("storage");
        let db = storage.join("local.db");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&storage).unwrap();
        Self {
            root,
            workspace,
            db,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = fs::canonicalize(&self.root).unwrap();
        assert!(path.starts_with(&temp) && path != temp);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
#[cfg_attr(
    not(windows),
    ignore = "Workspace filesystem operations require Windows"
)]
fn test_local_workspace_export_audit_sarif_e2e() {
    let f = Fixture::new();
    // Initialize workspace
    let init_rep = LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    assert!(init_rep.initialized);

    // Create Cargo.lock with vulnerable atty 0.2.11
    let vulnerable_lock = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "atty"
version = "0.2.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "52524bb7379625ca310543f1e8f48446b1f997ca92021c152ab74507ddfc4043"
"#;
    fs::write(f.workspace.join("Cargo.lock"), vulnerable_lock).unwrap();

    let clock = TimestampUtc::now();
    let advisory_db = AdvisoryDatabase::new(AdvisoryDatabase::pinned_advisories(), clock);

    // Export to SARIF
    let sarif_json = LocalWorkspace::export_audit_sarif(&f.workspace, &f.db, &advisory_db).unwrap();
    let parsed: SarifLog = serde_json::from_str(&sarif_json).unwrap();

    assert_eq!(parsed.schema, SARIF_SCHEMA_V2_1_0);
    assert_eq!(parsed.runs.len(), 1);
    let run = &parsed.runs[0];
    assert_eq!(run.results.len(), 1);
    assert_eq!(run.results[0].rule_id, "RUSTSEC-2021-0145");
    assert_eq!(run.results[0].level, SarifLevel::Warning);
    assert_eq!(
        run.results[0].locations[0]
            .physical_location
            .artifact_location
            .uri,
        "Cargo.lock"
    );
}
