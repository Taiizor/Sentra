//! Pure-Rust Intra-procedural Taint & Data-Flow Tracking Engine (REQ-F05, REQ-F07).
//!
//! Provides deterministic semantic flow analysis tracking data from untrusted sources
//! through variable assignments, string concatenations, and sanitizers to sensitive execution sinks.
//!
//! Complies with `#![forbid(unsafe_code)]` with zero runtime dependencies and zero ReDoS risk.

use std::collections::HashMap;

use crate::{
    domain::finding::Severity,
    sast::taint::model::{
        TaintFlowStep, TaintSinkKind, TaintSourceKind, TaintStepRole, TaintVulnerability,
    },
};

/// Tracked state of a variable within a lexical scope.
#[derive(Clone, Debug)]
struct TrackedVariable {
    name: String,
    is_tainted: bool,
    is_sanitized: bool,
    history: Vec<TaintFlowStep>,
}

/// Known source definition patterns.
struct SourcePattern {
    token: &'static str,
    #[allow(dead_code)]
    kind: TaintSourceKind,
    description: &'static str,
}

static KNOWN_SOURCES: &[SourcePattern] = &[
    SourcePattern {
        token: "req.body",
        kind: TaintSourceKind::HttpParameter,
        description: "HTTP request body property",
    },
    SourcePattern {
        token: "req.query",
        kind: TaintSourceKind::HttpParameter,
        description: "HTTP query string parameter",
    },
    SourcePattern {
        token: "req.params",
        kind: TaintSourceKind::HttpParameter,
        description: "HTTP route path parameter",
    },
    SourcePattern {
        token: "req.headers",
        kind: TaintSourceKind::HttpParameter,
        description: "HTTP request header value",
    },
    SourcePattern {
        token: "request.args",
        kind: TaintSourceKind::HttpParameter,
        description: "Flask/Python HTTP query argument",
    },
    SourcePattern {
        token: "request.form",
        kind: TaintSourceKind::HttpParameter,
        description: "Flask/Python form submission input",
    },
    SourcePattern {
        token: "request.get_json",
        kind: TaintSourceKind::HttpParameter,
        description: "Flask/Python JSON request payload",
    },
    SourcePattern {
        token: "request.json",
        kind: TaintSourceKind::HttpParameter,
        description: "HTTP JSON payload",
    },
    SourcePattern {
        token: "r.url.query()",
        kind: TaintSourceKind::HttpParameter,
        description: "Go HTTP URL query value",
    },
    SourcePattern {
        token: "r.formvalue(",
        kind: TaintSourceKind::HttpParameter,
        description: "Go HTTP form value",
    },
    SourcePattern {
        token: "sys.argv",
        kind: TaintSourceKind::EnvironmentOrCli,
        description: "CLI argument vector",
    },
    SourcePattern {
        token: "process.argv",
        kind: TaintSourceKind::EnvironmentOrCli,
        description: "Node.js/Bun CLI arguments",
    },
    SourcePattern {
        token: "env::args",
        kind: TaintSourceKind::EnvironmentOrCli,
        description: "Rust CLI argument iterator",
    },
    SourcePattern {
        token: "os.environ",
        kind: TaintSourceKind::EnvironmentOrCli,
        description: "Environment variable map",
    },
];

/// Known sanitizer definition patterns.
struct SanitizerPattern {
    token: &'static str,
    description: &'static str,
}

static KNOWN_SANITIZERS: &[SanitizerPattern] = &[
    SanitizerPattern {
        token: "parseint(",
        description: "Integer parsing cast",
    },
    SanitizerPattern {
        token: "parsefloat(",
        description: "Float parsing cast",
    },
    SanitizerPattern {
        token: "int(",
        description: "Python integer typecast",
    },
    SanitizerPattern {
        token: "float(",
        description: "Python float typecast",
    },
    SanitizerPattern {
        token: ".parse::<",
        description: "Rust strongly-typed parse",
    },
    SanitizerPattern {
        token: "to_digit(",
        description: "Rust numeric radix validation",
    },
    SanitizerPattern {
        token: "uuid::parse(",
        description: "UUID schema validation",
    },
    SanitizerPattern {
        token: "escape_string(",
        description: "Database string escaping",
    },
    SanitizerPattern {
        token: "encodeuricomponent(",
        description: "URI component encoding",
    },
    SanitizerPattern {
        token: "validator.is",
        description: "Strict input schema validator",
    },
    SanitizerPattern {
        token: "sanitize(",
        description: "Explicit sanitizer function",
    },
    SanitizerPattern {
        token: "html.escape(",
        description: "HTML entity encoder",
    },
    SanitizerPattern {
        token: "path.basename(",
        description: "Filesystem basename traversal sanitizer",
    },
    SanitizerPattern {
        token: "filepath.base(",
        description: "Go filepath basename traversal sanitizer",
    },
];

/// Known sink definition patterns.
struct SinkPattern {
    token: &'static str,
    kind: TaintSinkKind,
    rule_id: &'static str,
    rule_name: &'static str,
    cwe_id: &'static str,
    severity: Severity,
}

static KNOWN_SINKS: &[SinkPattern] = &[
    SinkPattern {
        token: "db.query(",
        kind: TaintSinkKind::SqlQuery,
        rule_id: "SENTRA-TAINT-001",
        rule_name: "SqlInjectionViaTaintFlow",
        cwe_id: "CWE-89",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "db.execute(",
        kind: TaintSinkKind::SqlQuery,
        rule_id: "SENTRA-TAINT-001",
        rule_name: "SqlInjectionViaTaintFlow",
        cwe_id: "CWE-89",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "cursor.execute(",
        kind: TaintSinkKind::SqlQuery,
        rule_id: "SENTRA-TAINT-001",
        rule_name: "SqlInjectionViaTaintFlow",
        cwe_id: "CWE-89",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "pool.query(",
        kind: TaintSinkKind::SqlQuery,
        rule_id: "SENTRA-TAINT-001",
        rule_name: "SqlInjectionViaTaintFlow",
        cwe_id: "CWE-89",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "sqlx::query(",
        kind: TaintSinkKind::SqlQuery,
        rule_id: "SENTRA-TAINT-001",
        rule_name: "SqlInjectionViaTaintFlow",
        cwe_id: "CWE-89",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "child_process.exec(",
        kind: TaintSinkKind::ShellCommand,
        rule_id: "SENTRA-TAINT-002",
        rule_name: "CommandInjectionViaTaintFlow",
        cwe_id: "CWE-78",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "execsync(",
        kind: TaintSinkKind::ShellCommand,
        rule_id: "SENTRA-TAINT-002",
        rule_name: "CommandInjectionViaTaintFlow",
        cwe_id: "CWE-78",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "os.system(",
        kind: TaintSinkKind::ShellCommand,
        rule_id: "SENTRA-TAINT-002",
        rule_name: "CommandInjectionViaTaintFlow",
        cwe_id: "CWE-78",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "subprocess.popen(",
        kind: TaintSinkKind::ShellCommand,
        rule_id: "SENTRA-TAINT-002",
        rule_name: "CommandInjectionViaTaintFlow",
        cwe_id: "CWE-78",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "eval(",
        kind: TaintSinkKind::DynamicCode,
        rule_id: "SENTRA-TAINT-003",
        rule_name: "DynamicCodeEvalViaTaintFlow",
        cwe_id: "CWE-95",
        severity: Severity::Critical,
    },
    SinkPattern {
        token: "fs.readfilesync(",
        kind: TaintSinkKind::FilePath,
        rule_id: "SENTRA-TAINT-004",
        rule_name: "PathTraversalViaTaintFlow",
        cwe_id: "CWE-22",
        severity: Severity::High,
    },
    SinkPattern {
        token: "fs.readfile(",
        kind: TaintSinkKind::FilePath,
        rule_id: "SENTRA-TAINT-004",
        rule_name: "PathTraversalViaTaintFlow",
        cwe_id: "CWE-22",
        severity: Severity::High,
    },
    SinkPattern {
        token: "file::open(",
        kind: TaintSinkKind::FilePath,
        rule_id: "SENTRA-TAINT-004",
        rule_name: "PathTraversalViaTaintFlow",
        cwe_id: "CWE-22",
        severity: Severity::High,
    },
];

/// In-Engine Pure-Rust Taint Analysis Engine.
#[derive(Clone, Debug, Default)]
pub struct TaintAnalysisEngine;

impl TaintAnalysisEngine {
    /// Creates a new taint analysis engine instance.
    pub fn new() -> Self {
        Self
    }

    /// Analyzes the source content of a file and returns verified taint vulnerabilities with end-to-end traces.
    pub fn analyze_source(&self, file_path: &str, content: &str) -> Vec<TaintVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut scope: HashMap<String, TrackedVariable> = HashMap::new();

        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Skip pure comment lines
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
                continue;
            }

            // 1. Variable Assignment / Declaration Parsing
            if let Some((var_name, expr)) = parse_assignment(trimmed) {
                let lower_expr = expr.to_ascii_lowercase();

                // Check A: Does expression directly ingest an untrusted Source?
                if let Some(src) = KNOWN_SOURCES.iter().find(|s| lower_expr.contains(s.token)) {
                    let mut var_state = TrackedVariable {
                        name: var_name.clone(),
                        is_tainted: true,
                        is_sanitized: false,
                        history: vec![TaintFlowStep {
                            step_index: 1,
                            role: TaintStepRole::Source,
                            line_number: line_num,
                            variable_name: var_name.clone(),
                            expression: expr.to_string(),
                            description: format!("Source entry: {}", src.description),
                        }],
                    };

                    // Check if the source itself is immediately sanitized on the same line
                    if let Some(san) = KNOWN_SANITIZERS
                        .iter()
                        .find(|s| lower_expr.contains(s.token))
                    {
                        var_state.is_tainted = false;
                        var_state.is_sanitized = true;
                        let step_idx = var_state.history.len() + 1;
                        var_state.history.push(TaintFlowStep {
                            step_index: step_idx,
                            role: TaintStepRole::Sanitizer,
                            line_number: line_num,
                            variable_name: var_name.clone(),
                            expression: expr.to_string(),
                            description: format!("Sanitized inline via {}", san.description),
                        });
                    }

                    scope.insert(var_name, var_state);
                    continue;
                }

                // Check B: Does expression propagate from an existing variable in scope?
                // Look for any tainted variable referenced in expr
                let mut found_tainted: Option<TrackedVariable> = None;
                for (prev_name, prev_var) in &scope {
                    if is_identifier_in_expression(prev_name, expr)
                        && prev_var.is_tainted
                        && !prev_var.is_sanitized
                    {
                        found_tainted = Some(prev_var.clone());
                        break;
                    }
                }

                if let Some(tainted_parent) = found_tainted {
                    // Check if expr applies a sanitizer to the tainted variable
                    let is_sanitized_here = KNOWN_SANITIZERS
                        .iter()
                        .any(|s| lower_expr.contains(s.token));

                    let mut new_history = tainted_parent.history.clone();
                    let next_step = new_history.len() + 1;

                    if is_sanitized_here {
                        new_history.push(TaintFlowStep {
                            step_index: next_step,
                            role: TaintStepRole::Sanitizer,
                            line_number: line_num,
                            variable_name: var_name.clone(),
                            expression: expr.to_string(),
                            description: "Neutralized via recognized sanitizer guard".to_string(),
                        });
                        scope.insert(
                            var_name.clone(),
                            TrackedVariable {
                                name: var_name,
                                is_tainted: false,
                                is_sanitized: true,
                                history: new_history,
                            },
                        );
                    } else {
                        new_history.push(TaintFlowStep {
                            step_index: next_step,
                            role: TaintStepRole::Propagation,
                            line_number: line_num,
                            variable_name: var_name.clone(),
                            expression: expr.to_string(),
                            description: format!(
                                "Taint propagated from `{}` into `{}`",
                                tainted_parent.name, var_name
                            ),
                        });
                        scope.insert(
                            var_name.clone(),
                            TrackedVariable {
                                name: var_name,
                                is_tainted: true,
                                is_sanitized: false,
                                history: new_history,
                            },
                        );
                    }
                    continue;
                }
            }

            // 2. Sensitive Sink Invocation Parsing
            let lower_line = trimmed.to_ascii_lowercase();
            for sink in KNOWN_SINKS {
                if lower_line.contains(sink.token) {
                    // Extract the arguments inside the sink call
                    if let Some(arg_str) = extract_call_arguments(trimmed, sink.token) {
                        // Check if any argument is an unsanitized tainted variable
                        for (var_name, var_state) in &scope {
                            if var_state.is_tainted
                                && !var_state.is_sanitized
                                && is_identifier_in_expression(var_name, arg_str)
                            {
                                // Taint confirmed! Construct end-to-end vulnerability
                                let mut flow_steps = var_state.history.clone();
                                let sink_step_idx = flow_steps.len() + 1;
                                flow_steps.push(TaintFlowStep {
                                    step_index: sink_step_idx,
                                    role: TaintStepRole::Sink,
                                    line_number: line_num,
                                    variable_name: var_name.clone(),
                                    expression: trimmed.to_string(),
                                    description: format!(
                                        "Tainted value reached sensitive execution sink `{}`",
                                        sink.token
                                    ),
                                });

                                vulnerabilities.push(TaintVulnerability {
                                    rule_id: sink.rule_id,
                                    rule_name: sink.rule_name,
                                    cwe_id: sink.cwe_id,
                                    sink_kind: sink.kind,
                                    severity: sink.severity,
                                    file_path: file_path.to_string(),
                                    sink_line: line_num,
                                    sink_expression: trimmed.to_string(),
                                    flow_steps,
                                });
                            }
                        }
                    }
                }
            }
        }

        vulnerabilities
    }
}

/// Parses variable assignments in JS/TS, Python, and Rust.
/// Returns (variable_name, expression) if matched.
fn parse_assignment(line: &str) -> Option<(String, &str)> {
    // 1. Strip keywords: `let mut `, `let `, `const `, `var `
    let s = line.trim();
    let rest = if let Some(stripped) = s.strip_prefix("let mut ") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("let ") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("const ") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("var ") {
        stripped
    } else {
        s
    };

    // Find `=` that is not `==` or `===` or `!=` or `<=` or `>=`
    let bytes = rest.as_bytes();
    let len = bytes.len();

    for i in 0..len {
        if bytes[i] == b'=' {
            // Check preceding character
            if i > 0
                && (bytes[i - 1] == b'='
                    || bytes[i - 1] == b'!'
                    || bytes[i - 1] == b'<'
                    || bytes[i - 1] == b'>')
            {
                continue;
            }
            // Check succeeding character
            if i + 1 < len && (bytes[i + 1] == b'=' || bytes[i + 1] == b'>') {
                continue;
            }

            let lhs = rest[..i].trim();
            let rhs = rest[i + 1..].trim().trim_end_matches(';');

            // Extract pure identifier from LHS (handles type annotations e.g. `query: string`)
            let ident = if let Some(colon_pos) = lhs.find(':') {
                lhs[..colon_pos].trim()
            } else {
                lhs
            };

            if is_valid_ident(ident) && !rhs.is_empty() {
                return Some((ident.to_string(), rhs));
            }
        }
    }

    None
}

/// Checks if string is a valid identifier (alphanumeric + underscore).
fn is_valid_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Checks if an identifier appears as a discrete whole word in an expression.
fn is_identifier_in_expression(ident: &str, expr: &str) -> bool {
    if ident.is_empty() || expr.is_empty() {
        return false;
    }

    let mut start = 0;
    while let Some(pos) = expr[start..].find(ident) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + ident.len();

        let prev_ok = if abs_pos == 0 {
            true
        } else {
            let prev_char = expr[..abs_pos].chars().last().unwrap();
            !prev_char.is_alphanumeric() && prev_char != '_'
        };

        let next_ok = if end_pos == expr.len() {
            true
        } else {
            let next_char = expr[end_pos..].chars().next().unwrap();
            !next_char.is_alphanumeric() && next_char != '_'
        };

        if prev_ok && next_ok {
            return true;
        }

        start = abs_pos + 1;
    }

    false
}

/// Extracts arguments inside a call pattern e.g. `db.query(args)` -> `args`.
fn extract_call_arguments<'a>(line: &'a str, pattern_with_paren: &str) -> Option<&'a str> {
    let lower_line = line.to_ascii_lowercase();
    let lower_pattern = pattern_with_paren.to_ascii_lowercase();

    if let Some(pos) = lower_line.find(&lower_pattern) {
        let arg_start = pos + pattern_with_paren.len();
        if arg_start <= line.len() {
            // Find closing paren or end of line
            let rem = &line[arg_start..];
            if let Some(end) = rem.rfind(')') {
                return Some(&rem[..end]);
            } else {
                return Some(rem);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_sql_injection_detected() {
        let code = r#"
            const username = req.body.username;
            const query = `SELECT * FROM users WHERE name = '${username}'`;
            db.query(query);
        "#;

        let engine = TaintAnalysisEngine::new();
        let vulns = engine.analyze_source("src/api.ts", code);

        assert_eq!(vulns.len(), 1);
        let v = &vulns[0];
        assert_eq!(v.rule_id, "SENTRA-TAINT-001");
        assert_eq!(v.sink_kind, TaintSinkKind::SqlQuery);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.flow_steps.len(), 3);

        assert_eq!(v.flow_steps[0].role, TaintStepRole::Source);
        assert_eq!(v.flow_steps[0].variable_name, "username");
        assert_eq!(v.flow_steps[1].role, TaintStepRole::Propagation);
        assert_eq!(v.flow_steps[1].variable_name, "query");
        assert_eq!(v.flow_steps[2].role, TaintStepRole::Sink);
    }

    #[test]
    fn test_taint_sanitizer_suppresses_vulnerability() {
        let code = r#"
            const id_str = req.query.id;
            const safe_id = parseInt(id_str);
            const query = `SELECT * FROM users WHERE id = ${safe_id}`;
            db.query(query);
        "#;

        let engine = TaintAnalysisEngine::new();
        let vulns = engine.analyze_source("src/safe.ts", code);

        // Should be 0 because parseInt sanitized safe_id!
        assert_eq!(vulns.len(), 0);
    }

    #[test]
    fn test_taint_static_query_suppresses_false_positive() {
        let code = r#"
            const status = "active";
            const query = `SELECT * FROM users WHERE status = '${status}'`;
            db.query(query);
        "#;

        let engine = TaintAnalysisEngine::new();
        let vulns = engine.analyze_source("src/static.ts", code);

        // Should be 0 because neither status nor query comes from untrusted source!
        assert_eq!(vulns.len(), 0);
    }

    #[test]
    fn test_taint_command_injection_detected() {
        let code = r#"
            let target = req.query.host;
            let cmd = format!("ping -c 1 {}", target);
            child_process.exec(cmd);
        "#;

        let engine = TaintAnalysisEngine::new();
        let vulns = engine.analyze_source("src/ping.rs", code);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].rule_id, "SENTRA-TAINT-002");
        assert_eq!(vulns[0].sink_kind, TaintSinkKind::ShellCommand);
    }

    #[test]
    fn test_taint_path_traversal_detected() {
        let code = r#"
            const filename = req.params.file;
            const fullPath = "/data/" + filename;
            fs.readFileSync(fullPath);
        "#;

        let engine = TaintAnalysisEngine::new();
        let vulns = engine.analyze_source("src/read.js", code);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].rule_id, "SENTRA-TAINT-004");
        assert_eq!(vulns[0].sink_kind, TaintSinkKind::FilePath);
    }
}
