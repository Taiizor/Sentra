//! Integration tests for In-Engine Pure-Rust Taint Analysis & Data-Flow Tracking (REQ-F05, REQ-F07).

#![forbid(unsafe_code)]

use sentra_core::{
    FindingSource, Reachability, SastScanner, SessionId, Severity, TaskId, TimestampUtc,
};

#[test]
fn test_end_to_end_multi_variable_sql_injection() {
    let code = r#"
        let user_input = req.body.search_term;
        let intermediate = user_input.trim();
        let query = format!("SELECT * FROM products WHERE description LIKE '%{}%'", intermediate);
        db.execute(&query);
    "#;

    let scanner = SastScanner::new();
    let matches = scanner.scan_content("src/db/search.rs", code);

    let taint_match = matches
        .iter()
        .find(|m| m.rule.id == "SENTRA-TAINT-001")
        .expect("must detect SENTRA-TAINT-001");

    assert_eq!(taint_match.rule.severity, Severity::Critical);
    assert_eq!(taint_match.rule.cwe_id, "CWE-89");
    assert!(taint_match.rationale.contains("`🔴 SOURCE`"));
    assert!(taint_match.rationale.contains("user_input"));
    assert!(taint_match.rationale.contains("`🟡 PROPAGATE`"));
    assert!(taint_match.rationale.contains("intermediate"));
    assert!(taint_match.rationale.contains("query"));
    assert!(taint_match.rationale.contains("`💥 SINK`"));

    // Verify candidate finding reachability classification
    let report = sentra_core::SastReport {
        files_scanned: 1,
        directories_scanned: 0,
        matches,
    };
    let findings =
        report.to_candidate_findings(SessionId::new(), TaskId::new(), TimestampUtc::now());

    let f = findings
        .iter()
        .find(|f| f.title().contains("SENTRA-TAINT-001"))
        .expect("finding must exist");

    assert_eq!(f.reachability(), Reachability::ReachableCallPath);
    assert_eq!(f.severity(), Severity::Critical);
    assert_eq!(
        f.source(),
        &FindingSource::StaticAnalysis {
            engine: "sentra-sast".to_string(),
            rule_id: "SENTRA-TAINT-001".to_string(),
        }
    );
}

#[test]
fn test_sanitizer_validation_blocks_sql_injection() {
    let code = r#"
        let raw_id = req.query.id;
        let safe_num = parseInt(raw_id);
        let query = format!("SELECT * FROM users WHERE id = {}", safe_num);
        db.execute(&query);
    "#;

    let scanner = SastScanner::new();
    let matches = scanner.scan_content("src/users.js", code);

    let taint_match = matches.iter().find(|m| m.rule.id == "SENTRA-TAINT-001");
    assert!(
        taint_match.is_none(),
        "Sanitized variable via parseInt must NOT trigger SENTRA-TAINT-001"
    );
}

#[test]
fn test_static_format_without_untrusted_input_blocks_sql_injection() {
    let code = r#"
        let table_name = "audit_log";
        let query = format!("SELECT * FROM {}", table_name);
        db.query(&query);
    "#;

    let scanner = SastScanner::new();
    let matches = scanner.scan_content("src/audit.rs", code);

    let taint_match = matches.iter().find(|m| m.rule.id == "SENTRA-TAINT-001");
    assert!(
        taint_match.is_none(),
        "Static constant formatting must NOT trigger SENTRA-TAINT-001 (False Positive Suppressed!)"
    );
}

#[test]
fn test_command_injection_via_cli_argument() {
    let code = r#"
        let host = process.argv[2];
        let command = "traceroute " + host;
        child_process.exec(command);
    "#;

    let scanner = SastScanner::new();
    let matches = scanner.scan_content("src/network.js", code);

    let taint_match = matches
        .iter()
        .find(|m| m.rule.id == "SENTRA-TAINT-002")
        .expect("must detect SENTRA-TAINT-002");

    assert_eq!(taint_match.rule.severity, Severity::Critical);
    assert_eq!(taint_match.rule.cwe_id, "CWE-78");
    assert!(taint_match.rationale.contains("`🔴 SOURCE`"));
    assert!(taint_match.rationale.contains("host"));
    assert!(taint_match.rationale.contains("`💥 SINK`"));
    assert!(taint_match.rationale.contains("child_process.exec"));
}

#[test]
fn test_path_traversal_via_route_parameter() {
    let code = r#"
        const userPath = req.params.filepath;
        const target = "/assets/docs/" + userPath;
        fs.readFile(target);
    "#;

    let scanner = SastScanner::new();
    let matches = scanner.scan_content("src/download.ts", code);

    let taint_match = matches
        .iter()
        .find(|m| m.rule.id == "SENTRA-TAINT-004")
        .expect("must detect SENTRA-TAINT-004");

    assert_eq!(taint_match.rule.severity, Severity::High);
    assert_eq!(taint_match.rule.cwe_id, "CWE-22");
    assert!(taint_match.rationale.contains("`🔴 SOURCE`"));
    assert!(taint_match.rationale.contains("userPath"));
    assert!(taint_match.rationale.contains("`💥 SINK`"));
}

#[test]
fn test_eval_injection_via_untrusted_payload() {
    let code = r#"
        const rawFormula = req.body.formula;
        const script = "evalMath(" + rawFormula + ")";
        eval(script);
    "#;

    let scanner = SastScanner::new();
    let matches = scanner.scan_content("src/calc.js", code);

    let taint_match = matches
        .iter()
        .find(|m| m.rule.id == "SENTRA-TAINT-003")
        .expect("must detect SENTRA-TAINT-003");

    assert_eq!(taint_match.rule.severity, Severity::Critical);
    assert_eq!(taint_match.rule.cwe_id, "CWE-95");
    assert!(taint_match.rationale.contains("`🔴 SOURCE`"));
    assert!(taint_match.rationale.contains("rawFormula"));
    assert!(taint_match.rationale.contains("`💥 SINK`"));
}
