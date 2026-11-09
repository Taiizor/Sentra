//! Integration tests for pure-Rust SAST & Secret Scanner engine (REQ-F05, REQ-F07).

use sentra_core::{
    FindingSource, SastScanner, Severity,
    export::generate_sarif_report,
    sast::{RuleCategory, find_rule_by_id},
};

#[test]
fn test_builtin_rules_integrity() {
    let rules = sentra_core::sast::BUILTIN_RULES;
    assert!(rules.len() >= 10);

    for rule in rules {
        assert!(rule.id.starts_with("SENTRA-"));
        assert!(!rule.name.is_empty());
        assert!(rule.cwe_id.starts_with("CWE-"));
        assert!(!rule.description.is_empty());
        assert!(!rule.recommendation.is_empty());
    }

    assert!(find_rule_by_id("SENTRA-SEC-001").is_some());
    assert!(find_rule_by_id("SENTRA-SAST-001").is_some());
    assert!(find_rule_by_id("NONEXISTENT").is_none());
}

#[test]
fn test_detect_aws_access_key() {
    let scanner = SastScanner::new();
    let content = r#"
        // Configuration
        const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
        const SAFE_STRING = "AKIA_SHORT";
    "#;

    let matches = scanner.scan_content("config/aws.js", content);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.id, "SENTRA-SEC-001");
    assert_eq!(matches[0].rule.category, RuleCategory::Secret);
    assert_eq!(matches[0].rule.severity, Severity::Critical);
    assert_eq!(matches[0].line_number, 3);
    assert!(matches[0].snippet.contains("AKIA"));
    assert!(matches[0].snippet.contains("[REDACTED]"));
}

#[test]
fn test_detect_github_tokens() {
    let scanner = SastScanner::new();
    let content = r#"
        let token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
        let pat = "github_pat_11AAAAAAA0123456789_abcdefghijklmnopqrstuvwxyz";
    "#;

    let matches = scanner.scan_content("auth/github.ts", content);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].rule.id, "SENTRA-SEC-002");
    assert_eq!(matches[1].rule.id, "SENTRA-SEC-002");
    assert!(matches[0].snippet.contains("ghp_"));
    assert!(matches[1].snippet.contains("github_pat_"));
}

#[test]
fn test_detect_private_keys() {
    let scanner = SastScanner::new();
    let content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+example...
-----END RSA PRIVATE KEY-----
    "#;

    let matches = scanner.scan_content("certs/server.pem", content);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.id, "SENTRA-SEC-003");
    assert_eq!(matches[0].line_number, 2);
}

#[test]
fn test_detect_slack_and_generic_secrets() {
    let scanner = SastScanner::new();
    let content = r#"
        const SLACK_BOT = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";
        const api_key = "sk_live_99887766554433221100";
        const safe_dummy = "YOUR_API_KEY_HERE";
        const env_var = process.env.API_KEY;
    "#;

    let matches = scanner.scan_content("src/services.js", content);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].rule.id, "SENTRA-SEC-004");
    assert_eq!(matches[1].rule.id, "SENTRA-SEC-005");
}

#[test]
fn test_detect_sql_injection() {
    let scanner = SastScanner::new();
    let rust_code = r#"
        fn query_user(id: &str) {
            let sql = format!("SELECT * FROM users WHERE id = '{}'", id);
            db.execute(&sql);
        }
    "#;

    let js_code = r#"
        async function getUser(id) {
            const query = `SELECT id, name FROM users WHERE id = ${id}`;
            return db.query(query);
        }
    "#;

    let rust_matches = scanner.scan_content("src/db.rs", rust_code);
    assert_eq!(rust_matches.len(), 1);
    assert_eq!(rust_matches[0].rule.id, "SENTRA-SAST-001");
    assert_eq!(rust_matches[0].line_number, 3);

    let js_matches = scanner.scan_content("src/db.js", js_code);
    assert_eq!(js_matches.len(), 1);
    assert_eq!(js_matches[0].rule.id, "SENTRA-SAST-001");
    assert_eq!(js_matches[0].line_number, 3);
}

#[test]
fn test_detect_command_injection_and_eval() {
    let scanner = SastScanner::new();
    let content = r#"
        function runTask(userInput) {
            const cmd = "cat " + userInput;
            exec(cmd, cb);
            eval("calculate(" + userInput + ")");
        }
    "#;

    let matches = scanner.scan_content("src/executor.js", content);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].rule.id, "SENTRA-SAST-002");
    assert_eq!(matches[1].rule.id, "SENTRA-SAST-003");
}

#[test]
fn test_rust_naked_unsafe_detection_and_safety_exemption() {
    let scanner = SastScanner::new();
    let bad_rust = r#"
        fn deref_ptr(ptr: *const u8) -> u8 {
            unsafe { *ptr }
        }
    "#;

    let good_rust = r#"
        fn deref_ptr(ptr: *const u8) -> u8 {
            // SAFETY: Caller guarantees pointer is non-null and points to valid u8 memory.
            unsafe { *ptr }
        }
    "#;

    let bad_matches = scanner.scan_content("src/bad.rs", bad_rust);
    assert_eq!(bad_matches.len(), 1);
    assert_eq!(bad_matches[0].rule.id, "SENTRA-SAST-004");

    let good_matches = scanner.scan_content("src/good.rs", good_rust);
    assert_eq!(good_matches.len(), 0);
}

#[test]
fn test_path_traversal_detection() {
    let scanner = SastScanner::new();
    let content = r#"
        app.get('/download', (req, res) => {
            const file = path.join(__dirname, req.query.filename);
            res.sendFile(file);
        });
    "#;

    let matches = scanner.scan_content("src/routes.js", content);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.id, "SENTRA-SAST-005");
}

#[test]
fn test_sast_findings_sarif_export() {
    let scanner = SastScanner::new();
    let content = r#"
        const API_SECRET = "sk_live_abcdef1234567890xyz";
        const q = format!("SELECT * FROM items WHERE name = '{}'", input);
    "#;

    let matches = scanner.scan_content("src/app.rs", content);
    assert_eq!(matches.len(), 2);

    let report = sentra_core::sast::SastReport {
        files_scanned: 1,
        directories_scanned: 1,
        matches,
    };

    let session_id = sentra_core::SessionId::new();
    let task_id = sentra_core::TaskId::new();
    let now = sentra_core::TimestampUtc::now();
    let findings = report.to_candidate_findings(session_id, task_id, now);

    assert_eq!(findings.len(), 2);
    assert!(matches!(
        findings[0].source(),
        FindingSource::StaticAnalysis { engine, .. } if engine == "sentra-sast"
    ));

    let sarif = generate_sarif_report(&findings, "0.1.0");
    assert_eq!(sarif.runs.len(), 1);
    assert_eq!(sarif.runs[0].results.len(), 2);
    assert_eq!(sarif.runs[0].tool.driver.name, "Sentra");

    // Check location
    let res = &sarif.runs[0].results[0];
    assert!(!res.locations.is_empty());
    assert_eq!(
        res.locations[0].physical_location.artifact_location.uri,
        "src/app.rs"
    );
}
