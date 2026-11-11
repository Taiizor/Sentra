//! CodeQL SARIF normalisation for `sentra codeql analyze|import` (ADR-0011).

use std::path::PathBuf;

use sentra_core::plugin::{
    CODEQL_SARIF_MAX_BYTES, CodeQlLanguageStatus, CodeQlSarifError, CodeQlSarifOptions,
    CodeQlSeverity, MAX_SARIF_RUNS, UNKNOWN_LANGUAGE, codeql_result_fingerprint,
    fallback_fingerprint, import_codeql_sarif, normalize_codeql_sarif,
};
use serde_json::{Value, json};

fn options(max_results: usize) -> CodeQlSarifOptions {
    CodeQlSarifOptions {
        max_results,
        default_language: None,
    }
}

fn result(rule: &str, uri: &str, line: u32, extra: Value) -> Value {
    let mut value = json!({
        "ruleId": rule,
        "message": { "text": format!("{rule} at {uri}:{line}") },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": uri, "uriBaseId": "%SRCROOT%" },
            "region": { "startLine": line }
        }}]
    });
    if let (Some(target), Some(source)) = (value.as_object_mut(), extra.as_object()) {
        for (k, v) in source {
            target.insert(k.clone(), v.clone());
        }
    }
    value
}

fn rule(id: &str, properties: Value) -> Value {
    json!({ "id": id, "name": id, "shortDescription": { "text": format!("Short {id}") }, "properties": properties })
}

/// One CodeQL run with rules in a query-pack extension (as CodeQL writes them).
fn sarif(rules: Vec<Value>, results: Vec<Value>) -> Vec<u8> {
    json!({
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": { "name": "CodeQL", "semanticVersion": "2.27.4", "rules": [] },
                "extensions": [{ "name": "codeql/javascript-queries", "rules": rules }]
            },
            "results": results
        }]
    })
    .to_string()
    .into_bytes()
}

#[test]
fn security_severity_thresholds_and_fallbacks() {
    let rules = vec![
        rule("js/critical", json!({ "security-severity": "9.0" })),
        rule("js/high", json!({ "security-severity": "7.0" })),
        rule("js/medium", json!({ "security-severity": "6.9" })),
        rule("js/low", json!({ "security-severity": "0.1" })),
        rule("js/none", json!({ "security-severity": "0.0" })),
        rule("js/numeric", json!({ "security-severity": 9.8 })),
        rule(
            "js/bogus",
            json!({ "security-severity": "11", "problem.severity": "warning" }),
        ),
        rule("js/error", json!({ "problem.severity": "error" })),
        rule("js/warning", json!({ "problem.severity": "warning" })),
        rule("js/rec", json!({ "problem.severity": "recommendation" })),
        rule("js/level-note", json!({})),
        rule("js/no-level", json!({})),
    ];
    let mut results: Vec<Value> = rules
        .iter()
        .map(|r| result(r["id"].as_str().unwrap(), "src/a.js", 1, json!({})))
        .collect();
    results[10]["level"] = json!("note");
    let summary = normalize_codeql_sarif(&sarif(rules, results), &options(100)).unwrap();
    let severity = |id: &str| {
        summary
            .findings
            .iter()
            .find(|f| f.rule_id == id)
            .unwrap()
            .severity
    };
    assert_eq!(severity("js/critical"), CodeQlSeverity::Critical);
    assert_eq!(severity("js/high"), CodeQlSeverity::High);
    assert_eq!(severity("js/medium"), CodeQlSeverity::Medium);
    assert_eq!(severity("js/low"), CodeQlSeverity::Low);
    assert_eq!(severity("js/none"), CodeQlSeverity::Info);
    assert_eq!(severity("js/numeric"), CodeQlSeverity::Critical);
    // A score outside 0..=10 is ignored; problem.severity decides.
    assert_eq!(severity("js/bogus"), CodeQlSeverity::Low);
    assert_eq!(severity("js/error"), CodeQlSeverity::Medium);
    assert_eq!(severity("js/warning"), CodeQlSeverity::Low);
    assert_eq!(severity("js/rec"), CodeQlSeverity::Info);
    assert_eq!(severity("js/level-note"), CodeQlSeverity::Info);
    assert_eq!(severity("js/no-level"), CodeQlSeverity::Low);
    let bogus = summary
        .findings
        .iter()
        .find(|f| f.rule_id == "js/bogus")
        .unwrap();
    assert_eq!(bogus.security_severity, None);
    assert_eq!(bogus.problem_severity.as_deref(), Some("warning"));
}

#[test]
fn metadata_cwe_fingerprints_and_language() {
    let rules = vec![rule(
        "js/xss",
        json!({
            "name": "Client-side cross-site scripting",
            "precision": "high",
            "problem.severity": "error",
            "security-severity": "7.8",
            "tags": ["security", "external/cwe/cwe-079", "external/cwe/cwe-116"]
        }),
    )];
    let with_hash = result(
        "js/xss",
        "web/app.js",
        12,
        json!({ "partialFingerprints": { "primaryLocationLineHash": "7f9e2c:1" } }),
    );
    let without_hash = result("js/xss", "web/other.js", 4, json!({}));
    let summary =
        normalize_codeql_sarif(&sarif(rules, vec![with_hash, without_hash]), &options(10)).unwrap();
    assert_eq!(summary.findings.len(), 2);
    let first = &summary.findings[0];
    assert_eq!(
        first.rule_name.as_deref(),
        Some("Client-side cross-site scripting")
    );
    assert_eq!(first.cwe, ["CWE-79", "CWE-116"]);
    assert_eq!(first.tags.len(), 3);
    assert_eq!(first.precision.as_deref(), Some("high"));
    assert_eq!(first.fingerprint, "7f9e2c:1");
    assert_eq!(first.language.as_deref(), Some("javascript"));
    assert_eq!((first.start_line, first.end_line), (12, 12));
    let second = &summary.findings[1];
    assert_eq!(
        second.fingerprint,
        fallback_fingerprint("js/xss", "web/other.js", 4, &second.message)
    );
    assert_eq!(second.fingerprint.len(), 64);
    let tool = summary.source_tool.as_ref().unwrap();
    assert_eq!(
        (tool.name.as_str(), tool.version.as_deref()),
        ("CodeQL", Some("2.27.4"))
    );
}

#[test]
fn driver_rules_by_index_and_missing_regions() {
    let doc = json!({
        "runs": [{
            "tool": { "driver": { "name": "CodeQL", "version": "2.20.0", "rules": [
                { "id": "py/a", "properties": { "security-severity": "5.0" } },
                { "id": "py/b", "helpUri": "https://codeql.github.com/b", "properties": { "security-severity": "9.1" } }
            ]}},
            "results": [
                { "ruleIndex": 1, "ruleId": "py/b", "message": { "text": "m" },
                  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "x.py" } } }] },
                { "message": { "text": "no rule id or location" } }
            ]
        }]
    });
    let summary = normalize_codeql_sarif(doc.to_string().as_bytes(), &options(10)).unwrap();
    assert_eq!(summary.results_total, 2);
    assert_eq!(summary.results_without_location, 1);
    let finding = &summary.findings[0];
    assert_eq!(finding.severity, CodeQlSeverity::Critical);
    assert_eq!(
        finding.help_uri.as_deref(),
        Some("https://codeql.github.com/b")
    );
    assert_eq!((finding.start_line, finding.end_line), (1, 1));
    assert_eq!(finding.language.as_deref(), Some("python"));
    assert_eq!(
        summary.source_tool.unwrap().version.as_deref(),
        Some("2.20.0")
    );
}

#[test]
fn paths_outside_the_workspace_are_dropped_and_counted() {
    let rules = vec![rule("js/r", json!({}))];
    let results = vec![
        result("js/r", "src/ok.js", 1, json!({})),
        result("js/r", "../escape.js", 1, json!({})),
        result("js/r", "src/../../escape.js", 1, json!({})),
        result("js/r", "/etc/passwd", 1, json!({})),
        result("js/r", "file:///C:/Users/op/secret.js", 1, json!({})),
        result("js/r", "C:\\Users\\op\\secret.js", 1, json!({})),
        result("js/r", "%2e%2e/escape.js", 1, json!({})),
        result("js/r", "src/sub/../fine.js", 1, json!({})),
    ];
    let summary = normalize_codeql_sarif(&sarif(rules, results), &options(10)).unwrap();
    assert_eq!(summary.results_total, 8);
    assert_eq!(summary.results_outside_workspace, 6);
    let paths: Vec<&str> = summary.findings.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["src/ok.js", "src/fine.js"]);
    assert!(
        summary
            .warnings
            .iter()
            .any(|w| w.contains("6 result(s) dropped"))
    );
}

#[test]
fn findings_are_truncated_at_max_results() {
    let rules = vec![rule("js/r", json!({}))];
    let results = (1..=5)
        .map(|line| result("js/r", "a.js", line, json!({})))
        .collect();
    let summary = normalize_codeql_sarif(&sarif(rules, results), &options(2)).unwrap();
    assert_eq!(summary.findings.len(), 2);
    assert_eq!(summary.results_total, 5);
    assert!(summary.truncated);
}

#[test]
fn non_codeql_empty_and_malformed_documents_are_rejected() {
    let semgrep =
        json!({ "runs": [{ "tool": { "driver": { "name": "Semgrep OSS" } }, "results": [] }] });
    let err = normalize_codeql_sarif(semgrep.to_string().as_bytes(), &options(10)).unwrap_err();
    assert_eq!(err.code(), "sarif_not_codeql");
    assert!(err.to_string().contains("Semgrep OSS"));

    let mixed = json!({ "runs": [
        { "tool": { "driver": { "name": "CodeQL" } }, "results": [] },
        { "tool": { "driver": { "name": "ESLint" } }, "results": [] }
    ]});
    assert_eq!(
        normalize_codeql_sarif(mixed.to_string().as_bytes(), &options(10))
            .unwrap_err()
            .code(),
        "sarif_not_codeql"
    );
    let nameless = json!({ "runs": [{ "tool": { "driver": {} }, "results": [] }] });
    assert_eq!(
        normalize_codeql_sarif(nameless.to_string().as_bytes(), &options(10))
            .unwrap_err()
            .code(),
        "sarif_not_codeql"
    );
    let empty = json!({ "runs": [] });
    assert_eq!(
        normalize_codeql_sarif(empty.to_string().as_bytes(), &options(10))
            .unwrap_err()
            .code(),
        "sarif_not_codeql"
    );
    for malformed in [&b"{ not json"[..], b"[]", b"{\"version\":\"2.1.0\"}", b""] {
        let err = normalize_codeql_sarif(malformed, &options(10)).unwrap_err();
        assert!(matches!(err, CodeQlSarifError::Invalid(_)), "{err:?}");
        assert_eq!(err.code(), "sarif_invalid");
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "sentra-codeql-sarif-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn import_reports_languages_and_rejects_oversized_files() {
    let dir = TempDir::new("import");
    let workspace = dir.0.join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let file = dir.0.join("results.sarif");
    let rules = vec![rule("js/r", json!({ "security-severity": "4.5" }))];
    let results = vec![
        result("js/r", "a.js", 1, json!({})),
        result("js/r", "b.js", 2, json!({})),
    ];
    std::fs::write(&file, sarif(rules, results)).unwrap();
    let report = import_codeql_sarif(&file, &workspace, 100).unwrap();
    assert_eq!(report.command, "codeql import");
    assert_eq!(report.codeql_version, None);
    assert_eq!(report.suite, None);
    assert!(!report.target_code_executed);
    assert!(!report.pack_download_allowed);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.languages.len(), 1);
    assert_eq!(report.languages[0].language, "javascript");
    assert_eq!(report.languages[0].status, CodeQlLanguageStatus::Analyzed);
    assert_eq!(report.languages[0].results, 2);
    assert_eq!(report.languages[0].duration_ms, None);
    let json = serde_json::to_value(&report).unwrap();
    for key in [
        "schema_version",
        "command",
        "workspace",
        "codeql_version",
        "suite",
        "pack_download_allowed",
        "target_code_executed",
        "languages",
        "findings",
        "results_total",
        "results_outside_workspace",
        "truncated",
        "warnings",
        "source_tool",
    ] {
        assert!(json.get(key).is_some(), "{key} missing");
    }
    assert_eq!(json["findings"][0]["severity"], "medium");

    let big = dir.0.join("big.sarif");
    let handle = std::fs::File::create(&big).unwrap();
    handle.set_len(CODEQL_SARIF_MAX_BYTES + 1).unwrap();
    drop(handle);
    let err = import_codeql_sarif(&big, &workspace, 100).unwrap_err();
    assert_eq!(err.code(), "sarif_too_large");

    let err = import_codeql_sarif(&dir.0.join("missing.sarif"), &workspace, 100).unwrap_err();
    assert_eq!(err.code(), "io_error");
}

#[test]
fn results_of_one_rule_on_one_line_keep_distinct_fingerprints() {
    let rules = vec![rule("js/reflected-xss", json!({}))];
    let at = |column: u32, extra: Value| {
        let mut value = result("js/reflected-xss", "app.js", 10, extra);
        value["locations"][0]["physicalLocation"]["region"]["startColumn"] = json!(column);
        value["message"]["text"] = json!(format!("sink at column {column}"));
        value
    };
    // CodeQL writes both partial fingerprints; the line hash alone is shared.
    let with_column_fingerprints = vec![
        at(
            5,
            json!({ "partialFingerprints": { "primaryLocationLineHash": "aaaa:1", "primaryLocationStartColumnFingerprint": "4" } }),
        ),
        at(
            25,
            json!({ "partialFingerprints": { "primaryLocationLineHash": "aaaa:1", "primaryLocationStartColumnFingerprint": "24" } }),
        ),
    ];
    let summary = normalize_codeql_sarif(
        &sarif(rules.clone(), with_column_fingerprints),
        &options(10),
    )
    .unwrap();
    let fingerprints: Vec<&str> = summary
        .findings
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    assert_eq!(fingerprints, ["aaaa:1|4", "aaaa:1|24"]);

    // Without the column fingerprint, the start column keeps them apart.
    let line_hash_only = vec![
        at(
            5,
            json!({ "partialFingerprints": { "primaryLocationLineHash": "aaaa:1" } }),
        ),
        at(
            25,
            json!({ "partialFingerprints": { "primaryLocationLineHash": "aaaa:1" } }),
        ),
    ];
    let summary = normalize_codeql_sarif(&sarif(rules, line_hash_only), &options(10)).unwrap();
    let fingerprints: Vec<&str> = summary
        .findings
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    assert_eq!(fingerprints, ["aaaa:1|c5", "aaaa:1|c25"]);
    assert_eq!(
        codeql_result_fingerprint(Some("h:1"), None, None, || unreachable!()),
        "h:1"
    );
    assert_eq!(
        codeql_result_fingerprint(None, Some("4"), Some(5), || "fallback".to_string()),
        "fallback"
    );
}

#[test]
fn rules_that_ran_are_reported_per_language_even_without_results() {
    let rules = vec![
        rule("js/xss", json!({})),
        rule("js/sql-injection", json!({})),
    ];
    let summary = normalize_codeql_sarif(&sarif(rules.clone(), Vec::new()), &options(10)).unwrap();
    assert!(summary.findings.is_empty());
    let javascript: Vec<&str> = summary.rule_ids["javascript"]
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(javascript, ["js/sql-injection", "js/xss"]);

    // An import of a SARIF whose results are all gone still covers its language.
    let dir = TempDir::new("zero-results");
    let workspace = dir.0.join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let file = dir.0.join("fixed.sarif");
    std::fs::write(&file, sarif(rules, Vec::new())).unwrap();
    let report = import_codeql_sarif(&file, &workspace, 100).unwrap();
    assert_eq!(report.languages.len(), 1);
    let language = &report.languages[0];
    assert_eq!(language.language, "javascript");
    assert_eq!(language.status, CodeQlLanguageStatus::Analyzed);
    assert_eq!(language.results, 0);
    assert_eq!(language.rules, ["js/sql-injection", "js/xss"]);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["languages"][0]["rules"],
        json!(["js/sql-injection", "js/xss"])
    );

    // A rule without a language hint and without a default lands in UNKNOWN_LANGUAGE.
    let custom = json!({ "runs": [{
        "tool": { "driver": { "name": "CodeQL", "rules": [{ "id": "custom/check" }] } },
        "results": []
    }]});
    let summary = normalize_codeql_sarif(custom.to_string().as_bytes(), &options(10)).unwrap();
    assert!(summary.rule_ids[UNKNOWN_LANGUAGE].contains("custom/check"));
}

#[test]
fn huge_documents_are_streamed_and_only_kept_results_are_retained() {
    // Regression: the whole document used to be read into typed vectors, so a few MB of
    // empty results cost hundreds of MB. One million empty results and three real ones:
    // every result is counted, and only `max_results` findings are kept.
    let mut text = String::from(r#"{"runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":["#);
    for i in 0..1_000_000 {
        text.push_str(if i == 0 { "{}" } else { ",{}" });
    }
    for line in 1..=3 {
        text.push_str(&format!(
            r#",{{"ruleId":"js/x","locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"a.js"}},"region":{{"startLine":{line}}}}}}}]}}"#
        ));
    }
    text.push_str("]}]}");
    let started = std::time::Instant::now();
    let summary = normalize_codeql_sarif(text.as_bytes(), &options(2)).unwrap();
    assert_eq!(summary.results_total, 1_000_003);
    assert_eq!(summary.results_without_location, 1_000_000);
    assert_eq!(summary.findings.len(), 2);
    assert!(summary.truncated);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "took {:?}",
        started.elapsed()
    );

    // Locations beyond the first, oversized rule lists and properties of unexpected types
    // neither fail the document nor are kept.
    let many_rules: Vec<Value> = (0..4_100)
        .map(|i| json!({ "id": format!("js/r{i}") }))
        .collect();
    let doc = json!({ "runs": [{
        "tool": {
            "driver": { "name": "CodeQL" },
            "extensions": [{ "name": "codeql/javascript-queries", "rules": many_rules }]
        },
        "results": [{
            "ruleId": "js/r1",
            "rule": { "id": "js/r1", "index": -1 },
            "properties": { "security-severity": { "not": "a number" } },
            "partialFingerprints": { "primaryLocationLineHash": 7 },
            "locations": [
                { "physicalLocation": { "artifactLocation": { "uri": "first.js" }, "region": { "startLine": 2 } } },
                { "physicalLocation": { "artifactLocation": { "uri": "second.js" } } }
            ]
        }]
    }]});
    let summary = normalize_codeql_sarif(doc.to_string().as_bytes(), &options(10)).unwrap();
    assert_eq!(summary.findings.len(), 1);
    assert_eq!(summary.findings[0].path, "first.js");
    assert_eq!(summary.findings[0].security_severity, None);
    assert_eq!(summary.rule_ids["javascript"].len(), 4_000);
    assert!(
        summary
            .warnings
            .iter()
            .any(|w| w.contains("4000 rules per tool component")),
        "{:?}",
        summary.warnings
    );

    // Runs beyond the cap are skipped and the findings are marked truncated.
    let run = r#"{"tool":{"driver":{"name":"CodeQL"}},"results":[]}"#;
    let runs = vec![run; MAX_SARIF_RUNS + 2].join(",");
    let summary =
        normalize_codeql_sarif(format!(r#"{{"runs":[{runs}]}}"#).as_bytes(), &options(10)).unwrap();
    assert!(summary.truncated);
    assert!(
        summary
            .warnings
            .iter()
            .any(|w| w.contains("2 later run(s) were skipped")),
        "{:?}",
        summary.warnings
    );
}

#[test]
fn rule_property_types_are_read_leniently() {
    let rules = vec![rule(
        "js/odd",
        json!({
            "name": 42,
            "precision": ["high"],
            "problem.severity": "warning",
            "security-severity": "7.5",
            "tags": ["security", 7, null, { "x": 1 }, ["nested"], "external/cwe/cwe-022"]
        }),
    )];
    let summary = normalize_codeql_sarif(
        &sarif(rules, vec![result("js/odd", "a.js", 1, json!({}))]),
        &options(10),
    )
    .unwrap();
    let finding = &summary.findings[0];
    assert_eq!(finding.rule_name.as_deref(), Some("Short js/odd"));
    assert_eq!(finding.precision, None);
    assert_eq!(finding.security_severity, Some(7.5));
    assert_eq!(finding.tags, ["security", "external/cwe/cwe-022"]);
    assert_eq!(finding.cwe, ["CWE-22"]);
}
