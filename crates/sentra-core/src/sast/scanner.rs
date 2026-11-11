//! Pure-Rust, zero-dependency SAST and Secret Scanner Engine (REQ-F05, REQ-F07, EXTENSIONS.md).
//!
//! Provides deterministic, ReDoS-proof, sub-millisecond static code analysis
//! for secrets, API tokens, and critical code antipatterns without external process dependencies.

use std::{collections::HashSet, fs, path::Path};

use crate::{
    domain::{
        finding::{Confidence, Finding, FindingSource, Reachability, TargetLocation},
        id::{FindingId, SessionId, TaskId},
        time::TimestampUtc,
    },
    sast::rule::{SastRule, find_rule_by_id},
};

/// Maximum file size scanned by the engine (2 MB) to prevent denial of service.
pub const MAX_SCANNABLE_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Lowercase identifier fragments that name an AWS secret access key (SENTRA-SEC-006).
const AWS_SECRET_KEY_HINTS: &[&str] = &[
    "secret_access_key",
    "secretaccesskey",
    "secret-access-key",
    "aws_secret",
    "awssecret",
    "aws-secret",
];

/// Length of an AWS secret access key value.
const AWS_SECRET_KEY_LEN: usize = 40;

/// Keywords whose line is checked for a long quoted literal (SENTRA-SEC-005).
const GENERIC_SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api_secret",
    "secret_key",
    "secret",
    "client_secret",
    "access_token",
    "auth_token",
    "secret_token",
    "password",
];

/// Minimum length of the quoted literal on a generic secret keyword line (SENTRA-SEC-005).
const MIN_GENERIC_SECRET_LITERAL_LEN: usize = 16;

/// Lowercase identifier endings that name a password value (SENTRA-SEC-005).
const PASSWORD_IDENTIFIER_SUFFIXES: &[&str] = &["password", "passwd", "passphrase"];

/// Minimum length of a literal assigned to a password identifier (SENTRA-SEC-005).
const MIN_PASSWORD_LITERAL_LEN: usize = 6;

/// A single matched SAST or secret signal before finding admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SastMatch {
    /// Rule that triggered.
    pub rule: SastRule,
    /// Canonical workspace-relative path.
    pub file_path: String,
    /// Line number (1-based).
    pub line_number: u32,
    /// Redacted or sanitized code snippet.
    pub snippet: String,
    /// Context explanation.
    pub rationale: String,
}

/// Consolidated report returned by the SAST scanning engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SastReport {
    /// Total number of source files scanned.
    pub files_scanned: usize,
    /// Total number of directories traversed.
    pub directories_scanned: usize,
    /// Matched signals.
    pub matches: Vec<SastMatch>,
}

impl SastReport {
    /// Converts matched SAST findings into authoritative candidate `Finding` records.
    pub fn to_candidate_findings(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        now: TimestampUtc,
    ) -> Vec<Finding> {
        self.matches
            .iter()
            .map(|m| {
                let id = FindingId::new();
                let title = format!("{}: {} in {}", m.rule.id, m.rule.name, m.file_path);
                let mut description = format!(
                    "Static check '{}' ({}) triggered at {}:{}.\n\nCWE: {}\nDescription: {}\nRecommendation: {}\n\nSnippet:\n    {}",
                    m.rule.name,
                    m.rule.id,
                    m.file_path,
                    m.line_number,
                    m.rule.cwe_id,
                    m.rule.description,
                    m.rule.recommendation,
                    m.snippet
                );

                if !m.rationale.is_empty() {
                    description.push_str(&format!("\n\n{}", m.rationale));
                }

                let reachability = if m.rule.id.starts_with("SENTRA-TAINT-") {
                    Reachability::ReachableCallPath
                } else {
                    Reachability::SyntacticallyReferenced
                };

                Finding::new_candidate(
                    id,
                    session_id,
                    task_id,
                    title,
                    description,
                    m.rule.severity,
                    Confidence::High,
                    reachability,
                    FindingSource::StaticAnalysis {
                        engine: "sentra-sast".to_string(),
                        rule_id: m.rule.id.to_string(),
                    },
                    Some(TargetLocation {
                        path: m.file_path.clone(),
                        start_line: Some(m.line_number),
                        end_line: Some(m.line_number),
                    }),
                    None,
                    now,
                )
            })
            .collect()
    }
}

/// Pure-Rust source code and secret scanner.
pub struct SastScanner {
    ignored_dir_names: HashSet<&'static str>,
    ignored_file_extensions: HashSet<&'static str>,
}

impl Default for SastScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SastScanner {
    /// Creates a new scanner with default security exclusions.
    pub fn new() -> Self {
        let mut ignored_dir_names = HashSet::new();
        ignored_dir_names.insert(".git");
        ignored_dir_names.insert("node_modules");
        ignored_dir_names.insert("target");
        ignored_dir_names.insert("dist");
        ignored_dir_names.insert("build");
        ignored_dir_names.insert(".cargo");
        ignored_dir_names.insert(".svn");
        ignored_dir_names.insert(".hg");
        ignored_dir_names.insert("vendor");
        ignored_dir_names.insert(".next");

        let mut ignored_file_extensions = HashSet::new();
        ignored_file_extensions.insert("png");
        ignored_file_extensions.insert("jpg");
        ignored_file_extensions.insert("jpeg");
        ignored_file_extensions.insert("gif");
        ignored_file_extensions.insert("ico");
        ignored_file_extensions.insert("svg");
        ignored_file_extensions.insert("woff");
        ignored_file_extensions.insert("woff2");
        ignored_file_extensions.insert("ttf");
        ignored_file_extensions.insert("eot");
        ignored_file_extensions.insert("exe");
        ignored_file_extensions.insert("dll");
        ignored_file_extensions.insert("so");
        ignored_file_extensions.insert("dylib");
        ignored_file_extensions.insert("wasm");
        ignored_file_extensions.insert("tar");
        ignored_file_extensions.insert("gz");
        ignored_file_extensions.insert("zip");
        ignored_file_extensions.insert("pdf");
        ignored_file_extensions.insert("bin");
        ignored_file_extensions.insert("lock"); // lockfiles handled by advisory engine

        Self {
            ignored_dir_names,
            ignored_file_extensions,
        }
    }

    /// Recursively scans a workspace directory and returns detected signals.
    pub fn scan_workspace(&self, root_dir: &Path) -> std::io::Result<SastReport> {
        let mut files_scanned = 0;
        let mut directories_scanned = 0;
        let mut matches = Vec::new();

        self.traverse_and_scan(
            root_dir,
            root_dir,
            &mut files_scanned,
            &mut directories_scanned,
            &mut matches,
        )?;

        Ok(SastReport {
            files_scanned,
            directories_scanned,
            matches,
        })
    }

    /// Scans a single source file content directly.
    pub fn scan_content(&self, rel_path: &str, content: &str) -> Vec<SastMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_num = (idx as u32) + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            let matches_before_secrets = matches.len();

            // 1. AWS Access Key Check (SENTRA-SEC-001)
            if let Some(m) = self.check_aws_key(rel_path, line_num, line) {
                matches.push(m);
            }

            // 1b. AWS Secret Access Key Check (SENTRA-SEC-006)
            if let Some(m) = self.check_aws_secret_key(rel_path, line_num, line) {
                matches.push(m);
            }

            // 2. GitHub Token Check (SENTRA-SEC-002)
            if let Some(m) = self.check_github_token(rel_path, line_num, line) {
                matches.push(m);
            }

            // 3. Private Key Block Check (SENTRA-SEC-003)
            if let Some(m) = self.check_private_key(rel_path, line_num, line) {
                matches.push(m);
            }

            // 4. Slack Token Check (SENTRA-SEC-004)
            if let Some(m) = self.check_slack_token(rel_path, line_num, line) {
                matches.push(m);
            }

            // 5. Generic Hardcoded Secret (SENTRA-SEC-005), only when no specific secret
            // rule already reported this line, so one secret yields one finding.
            if matches.len() == matches_before_secrets
                && let Some(m) = self.check_generic_secret(rel_path, line_num, line)
            {
                matches.push(m);
            }

            // 6. SQL Injection Antipattern (SENTRA-SAST-001)
            if let Some(m) = self.check_sql_injection(rel_path, line_num, line) {
                matches.push(m);
            }

            // 7. Command Injection Antipattern (SENTRA-SAST-002)
            if let Some(m) = self.check_command_injection(rel_path, line_num, line) {
                matches.push(m);
            }

            // 8. Dangerous Dynamic Code Evaluation (SENTRA-SAST-003)
            if let Some(m) = self.check_dangerous_eval(rel_path, line_num, line) {
                matches.push(m);
            }

            // 9. Naked Rust Unsafe Block (SENTRA-SAST-004)
            if rel_path.ends_with(".rs")
                && let Some(m) = self.check_naked_unsafe(rel_path, line_num, idx, &lines)
            {
                matches.push(m);
            }

            // 10. Path Traversal Antipattern (SENTRA-SAST-005)
            if let Some(m) = self.check_path_traversal(rel_path, line_num, line) {
                matches.push(m);
            }

            // 11. CI/CD Workflow Security (SENTRA-CICD-001 to 004)
            if rel_path.contains(".github/workflows")
                || rel_path.ends_with(".yml")
                || rel_path.ends_with(".yaml")
            {
                matches.extend(self.check_cicd_workflow(rel_path, line_num, line));
            }

            // 12. Authentication and Cryptography Hygiene (SENTRA-AUTH-001 to 003)
            matches.extend(self.check_auth_and_crypto(rel_path, line_num, line));

            // 13. AI Agent & Skill Safety (SENTRA-SKILL-001 to 002)
            matches.extend(self.check_agent_skill_security(rel_path, line_num, line));

            // 14. Go Security & Path Traversal (SENTRA-GO-001 to 004)
            if rel_path.ends_with(".go") {
                matches.extend(self.check_go_security(rel_path, line_num, line));
            }

            // 15. Django Security Misconfigurations (SENTRA-DJANGO-001 to 005)
            if rel_path.ends_with(".py")
                || rel_path.ends_with(".html")
                || rel_path.ends_with(".jinja")
                || rel_path.ends_with(".jinja2")
            {
                matches.extend(self.check_django_security(rel_path, line_num, line));
            }

            // 16. Laravel Misconfigurations (SENTRA-LARAVEL-001 to 002)
            if rel_path.ends_with(".php")
                || rel_path.ends_with(".env")
                || rel_path.ends_with(".env.example")
            {
                matches.extend(self.check_laravel_security(rel_path, line_num, line));
            }

            // 17. Spring Boot Misconfigurations (SENTRA-SPRING-001 to 002)
            if rel_path.ends_with(".java")
                || rel_path.ends_with(".properties")
                || rel_path.ends_with(".yml")
            {
                matches.extend(self.check_spring_security(rel_path, line_num, line));
            }

            // 18. Firebase Rules Permissive Access (SENTRA-FIREBASE-001)
            if (rel_path.ends_with(".rules")
                || rel_path.contains("firestore")
                || rel_path.contains("firebase"))
                && let Some(m) = self.check_firebase_rules(rel_path, line_num, line)
            {
                matches.push(m);
            }

            // 19. Solidity Smart Contract Flaws (SENTRA-SOLIDITY-001 to 002)
            if rel_path.ends_with(".sol") {
                matches.extend(self.check_solidity_security(rel_path, line_num, line));
            }

            // 20. Cloud Metadata SSRF Target (SENTRA-CLOUD-001)
            if let Some(m) = self.check_cloud_metadata_ssrf(rel_path, line_num, line) {
                matches.push(m);
            }

            // 21. API Security & Mass Assignment (SENTRA-API-001 to 002)
            if rel_path.ends_with(".js")
                || rel_path.ends_with(".ts")
                || rel_path.ends_with(".py")
                || rel_path.ends_with(".go")
            {
                matches.extend(self.check_api_security(rel_path, line_num, line));
            }

            // 22. Insecure Download Pipe to Shell (SENTRA-SUPPLY-001)
            if let Some(m) = self.check_supply_chain_security(rel_path, line_num, line) {
                matches.push(m);
            }
        }

        // 11. In-Engine Pure-Rust Semantic Taint Tracking
        let taint_engine = crate::sast::taint::TaintAnalysisEngine::new();
        let taint_vulns = taint_engine.analyze_source(rel_path, content);
        for tv in taint_vulns {
            if let Some(rule) = find_rule_by_id(tv.rule_id) {
                let rationale = tv.to_markdown_trace();
                matches.push(SastMatch {
                    rule: rule.clone(),
                    file_path: rel_path.to_string(),
                    line_number: tv.sink_line as u32,
                    snippet: tv.sink_expression,
                    rationale,
                });
            }
        }

        matches
    }

    fn traverse_and_scan(
        &self,
        current_dir: &Path,
        root_dir: &Path,
        files_count: &mut usize,
        dirs_count: &mut usize,
        matches: &mut Vec<SastMatch>,
    ) -> std::io::Result<()> {
        *dirs_count += 1;
        let entries = match fs::read_dir(current_dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };

            let path = entry.path();
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_type.is_dir() {
                if self.ignored_dir_names.contains(file_name_str.as_ref()) {
                    continue;
                }
                self.traverse_and_scan(&path, root_dir, files_count, dirs_count, matches)?;
            } else if file_type.is_file() {
                if let Some(ext) = path.extension()
                    && self
                        .ignored_file_extensions
                        .contains(ext.to_string_lossy().as_ref())
                {
                    continue;
                }

                // Check file size limit
                if let Ok(metadata) = entry.metadata()
                    && metadata.len() > MAX_SCANNABLE_FILE_BYTES
                {
                    continue;
                }

                // Exclude rule definitions or tests in Sentra core from false-positive self-matching
                let rel_path_str = path
                    .strip_prefix(root_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");

                if rel_path_str.ends_with(".lock")
                    || rel_path_str.ends_with(".png")
                    || rel_path_str.ends_with(".ico")
                {
                    continue;
                }

                // Fast binary detection (first 1024 bytes)
                if let Ok(bytes) = fs::read(&path) {
                    let probe_len = bytes.len().min(1024);
                    if bytes[..probe_len].contains(&0) {
                        continue;
                    }

                    if let Ok(content) = std::str::from_utf8(&bytes) {
                        *files_count += 1;
                        let file_matches = self.scan_content(&rel_path_str, content);
                        matches.extend(file_matches);
                    }
                }
            }
        }

        Ok(())
    }

    // --- High Precision Matchers ---

    fn check_aws_key(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let bytes = line.as_bytes();
        let target = b"AKIA";

        for i in 0..bytes.len() {
            if i + 20 <= bytes.len() && &bytes[i..i + 4] == target {
                // Ensure word boundary before
                if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
                    continue;
                }

                // Ensure 16 characters following are uppercase alphanumerics
                let suffix = &bytes[i + 4..i + 20];
                let is_aws_key = suffix
                    .iter()
                    .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit());

                if is_aws_key {
                    // Ensure word boundary after
                    if i + 20 < bytes.len()
                        && (bytes[i + 20].is_ascii_alphanumeric() || bytes[i + 20] == b'_')
                    {
                        continue;
                    }

                    let rule = find_rule_by_id("SENTRA-SEC-001")?.clone();
                    let redacted = format!(
                        "AKIA{}...[REDACTED]",
                        std::str::from_utf8(&suffix[..2]).unwrap_or("**")
                    );
                    return Some(SastMatch {
                        rule,
                        file_path: path.to_string(),
                        line_number: line_num,
                        snippet: redacted,
                        rationale: "Matched AWS Access Key format (AKIA...)".to_string(),
                    });
                }
            }
        }
        None
    }

    /// Flags a 40-character AWS secret access key value that follows an identifier naming
    /// one (`aws_secret_access_key`, `secretAccessKey`, `AWS_SECRET`). Like SENTRA-SEC-001,
    /// documentation sample values are reported too: the scanner cannot tell them apart from
    /// live keys, and the finding is what lets consumers redact the line.
    fn check_aws_secret_key(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let lower = line.to_ascii_lowercase();
        let hint_pos = AWS_SECRET_KEY_HINTS
            .iter()
            .filter_map(|hint| lower.find(hint))
            .min()?;
        let bytes = line.as_bytes();
        let is_key_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'/' || b == b'+';

        let mut i = hint_pos;
        while i < bytes.len() {
            if !is_key_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_key_byte(bytes[i]) {
                i += 1;
            }
            let token = &bytes[start..i];
            // Base64 padding right after the run marks a longer encoded blob, not a key.
            let padded = bytes.get(i) == Some(&b'=');
            if token.len() == AWS_SECRET_KEY_LEN && !padded && is_mixed_key_material(token) {
                let rule = find_rule_by_id("SENTRA-SEC-006")?.clone();
                let prefix = std::str::from_utf8(&token[..4]).unwrap_or("****");
                return Some(SastMatch {
                    rule,
                    file_path: path.to_string(),
                    line_number: line_num,
                    snippet: format!("{prefix}...[REDACTED]"),
                    rationale:
                        "Matched a 40-character AWS secret access key value next to an AWS secret key identifier"
                            .to_string(),
                });
            }
        }
        None
    }

    fn check_github_token(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
        for prefix in &prefixes {
            if let Some(pos) = line.find(prefix) {
                let rest = &line[pos + 4..];
                let token_chars = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .count();
                if token_chars >= 30 {
                    let rule = find_rule_by_id("SENTRA-SEC-002")?.clone();
                    return Some(SastMatch {
                        rule,
                        file_path: path.to_string(),
                        line_number: line_num,
                        snippet: format!("{prefix}****************[REDACTED]"),
                        rationale: format!("Matched GitHub personal access token ({prefix}...)"),
                    });
                }
            }
        }

        if let Some(pos) = line.find("github_pat_") {
            let rest = &line[pos + 11..];
            let token_chars = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .count();
            if token_chars >= 20 {
                let rule = find_rule_by_id("SENTRA-SEC-002")?.clone();
                return Some(SastMatch {
                    rule,
                    file_path: path.to_string(),
                    line_number: line_num,
                    snippet: "github_pat_****************[REDACTED]".to_string(),
                    rationale: "Matched GitHub fine-grained PAT (github_pat_...)".to_string(),
                });
            }
        }

        None
    }

    fn check_private_key(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        if line.contains("-----BEGIN ")
            && (line.contains("PRIVATE KEY-----")
                || line.contains("RSA PRIVATE KEY-----")
                || line.contains("OPENSSH PRIVATE KEY-----")
                || line.contains("EC PRIVATE KEY-----")
                || line.contains("PGP PRIVATE KEY BLOCK-----"))
        {
            let rule = find_rule_by_id("SENTRA-SEC-003")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: "-----BEGIN [REDACTED PRIVATE KEY]-----".to_string(),
                rationale: "Found plaintext cryptographic private key header".to_string(),
            });
        }
        None
    }

    fn check_slack_token(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let prefixes = ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"];
        for prefix in &prefixes {
            if let Some(pos) = line.find(prefix) {
                let rest = &line[pos + 5..];
                let token_chars = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .count();
                if token_chars >= 20 {
                    let rule = find_rule_by_id("SENTRA-SEC-004")?.clone();
                    return Some(SastMatch {
                        rule,
                        file_path: path.to_string(),
                        line_number: line_num,
                        snippet: format!("{prefix}****************[REDACTED]"),
                        rationale: format!("Matched Slack API token prefix ({prefix})"),
                    });
                }
            }
        }
        None
    }

    fn check_generic_secret(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        // Must have an assignment operator: '=' or ':'
        let has_assign = line.contains('=') || line.contains(':');
        if !has_assign {
            return None;
        }

        let lower = line.to_ascii_lowercase();
        if is_placeholder_or_reference_line(&lower) {
            return None;
        }

        // 1. Long quoted literal on a line that mentions a secret keyword.
        if GENERIC_SECRET_KEYWORDS.iter().any(|k| lower.contains(k))
            && let Some(literal) = first_quoted_literal(line)
            && literal.len() >= MIN_GENERIC_SECRET_LITERAL_LEN
            && !literal.contains(' ')
            && literal.chars().any(|c| c.is_ascii_alphanumeric())
        {
            let rule = find_rule_by_id("SENTRA-SEC-005")?.clone();
            let prefix: String = literal.chars().take(3).collect();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: format!("{prefix}[REDACTED_SECRET]"),
                rationale: "Detected hardcoded literal secret assignment".to_string(),
            });
        }

        // 2. Shorter literal assigned directly to a password identifier. Passwords are often
        // well below the generic length threshold (`password = "hunter2"`).
        if assigned_password_literal(path, line, &lower).is_some() {
            let rule = find_rule_by_id("SENTRA-SEC-005")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: "[REDACTED_SECRET]".to_string(),
                rationale: "Detected hardcoded password literal assigned to a password identifier"
                    .to_string(),
            });
        }

        None
    }

    fn check_sql_injection(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let upper = line.to_ascii_uppercase();
        let has_sql_keyword = upper.contains("SELECT ")
            || upper.contains("INSERT INTO ")
            || upper.contains("UPDATE ")
            || upper.contains("DELETE FROM ");

        if !has_sql_keyword {
            return None;
        }

        // Check for dynamic string interpolation / formatting
        let has_dynamic_format = (line.contains("format!(") && line.contains("{}"))
            || (line.contains("${") && line.contains('`')) // JS template literal
            || (line.contains(" + ") && (line.contains('"') || line.contains('\''))) // String concatenation
            || (line.contains("f\"") && line.contains('{')) // Python f-string
            || (line.contains("f'") && line.contains('{'))
            || (line.contains("%s") && line.contains('%'));

        if has_dynamic_format {
            let rule = find_rule_by_id("SENTRA-SAST-001")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                rationale: "SQL query constructed via dynamic string interpolation / concatenation"
                    .to_string(),
            });
        }

        None
    }

    fn check_command_injection(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let is_rust_shell = line.contains("Command::new(\"sh\")")
            || line.contains("Command::new(\"bash\")")
            || line.contains("Command::new(\"cmd\")");

        let is_js_shell = (line.contains("exec(") || line.contains("execSync("))
            && (line.contains("${")
                || line.contains(" + ")
                || (!line.contains("exec(\"") && !line.contains("exec('")));

        let is_py_shell = line.contains("os.system(")
            || (line.contains("subprocess.Popen(") && line.contains("shell=True"))
            || (line.contains("subprocess.run(") && line.contains("shell=True"));

        if is_rust_shell || is_js_shell || is_py_shell {
            let rule = find_rule_by_id("SENTRA-SAST-002")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                rationale:
                    "Shell command execution using dynamic arguments without argv separation"
                        .to_string(),
            });
        }

        None
    }

    fn check_dangerous_eval(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let trimmed = line.trim();

        // JS eval(...) or new Function(...)
        let is_eval = trimmed.starts_with("eval(")
            || trimmed.contains(" eval(")
            || trimmed.contains("=eval(")
            || trimmed.contains("(eval(");

        let is_new_func = line.contains("new Function(") || line.contains("Function(");

        if is_eval || is_new_func {
            // Avoid false positive on simple comment or safe identifier
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with('#') {
                return None;
            }

            let rule = find_rule_by_id("SENTRA-SAST-003")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Dynamic code execution via eval() or new Function()".to_string(),
            });
        }

        None
    }

    fn check_naked_unsafe(
        &self,
        path: &str,
        line_num: u32,
        line_idx: usize,
        all_lines: &[&str],
    ) -> Option<SastMatch> {
        let line = all_lines[line_idx].trim();

        // Check for unsafe block or unsafe fn
        let is_unsafe_block = line.starts_with("unsafe {")
            || line.starts_with("unsafe fn ")
            || line.contains(" unsafe {");

        if !is_unsafe_block {
            return None;
        }

        // Look back up to 3 non-empty lines for `// SAFETY:` rationale
        let mut lookback_has_safety = false;
        let mut checked = 0;
        let mut current_idx = line_idx;

        while current_idx > 0 && checked < 4 {
            current_idx -= 1;
            let prev_line = all_lines[current_idx].trim();
            if prev_line.is_empty() {
                continue;
            }
            checked += 1;
            let upper = prev_line.to_ascii_uppercase();
            if upper.contains("// SAFETY:") || upper.contains("//SAFETY:") {
                lookback_has_safety = true;
                break;
            }
        }

        // Also check if same line has inline safety comment
        if line.to_ascii_uppercase().contains("// SAFETY:") {
            lookback_has_safety = true;
        }

        if !lookback_has_safety {
            let rule = find_rule_by_id("SENTRA-SAST-004")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: line.to_string(),
                rationale: "Rust unsafe block lacking mandatory '// SAFETY:' documentation comment"
                    .to_string(),
            });
        }

        None
    }

    fn check_path_traversal(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let has_path_op = line.contains("path.join(")
            || line.contains("Path::new(")
            || line.contains("fs.readFile(")
            || line.contains("fs.readFileSync(")
            || line.contains("fs.createReadStream(");

        let has_unvalidated_input = line.contains("req.params")
            || line.contains("req.query")
            || line.contains("req.body")
            || line.contains("params.")
            || line.contains("user_input");

        if has_path_op && has_unvalidated_input {
            let rule = find_rule_by_id("SENTRA-SAST-005")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                rationale:
                    "Unsanitized user request input passed directly into filesystem path operation"
                        .to_string(),
            });
        }

        None
    }

    fn check_cicd_workflow(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. pull_request_target trigger (SENTRA-CICD-001)
        if trimmed.starts_with("pull_request_target:")
            || trimmed == "pull_request_target"
            || trimmed.contains(" pull_request_target:")
        {
            let rule = find_rule_by_id("SENTRA-CICD-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Workflow triggers on pull_request_target with privileged access to secrets and write tokens"
                        .to_string(),
            });
        }

        // 2. Script template injection in ${{ ... }} (SENTRA-CICD-002)
        let is_untrusted_event_expr = line.contains("${{ github.event.")
            || line.contains("${{github.event.")
            || line.contains("${{ github.head_ref")
            || line.contains("${{github.head_ref");
        if is_untrusted_event_expr
            && (line.contains("run:")
                || trimmed.starts_with("- run:")
                || trimmed.starts_with("run:")
                || line.contains("echo ")
                || line.contains("bash ")
                || line.contains("sh "))
        {
            let rule = find_rule_by_id("SENTRA-CICD-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Untrusted GitHub context expression interpolated directly into shell execution"
                        .to_string(),
            });
        }

        // 3. permissions: write-all (SENTRA-CICD-003)
        if trimmed.contains("permissions: write-all")
            || trimmed.contains("permissions: 'write-all'")
            || trimmed.contains("permissions: \"write-all\"")
        {
            let rule = find_rule_by_id("SENTRA-CICD-003").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Workflow grants write-all permissions to GITHUB_TOKEN, violating principle of least privilege"
                        .to_string(),
            });
        }

        // 4. Environment file injection (SENTRA-CICD-004)
        if (line.contains(">> $GITHUB_ENV")
            || line.contains(">> \"$GITHUB_ENV\"")
            || line.contains(">> $GITHUB_OUTPUT")
            || line.contains(">> \"$GITHUB_OUTPUT\""))
            && line.contains("${{")
        {
            let rule = find_rule_by_id("SENTRA-CICD-004").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Untrusted expression appended directly to GITHUB_ENV or GITHUB_OUTPUT without delimiter isolation"
                        .to_string(),
            });
        }

        // 5. Unpinned Action using mutable branch (SENTRA-CICD-005)
        if (trimmed.starts_with("uses:") || trimmed.starts_with("- uses:"))
            && !trimmed.contains("./")
            && (trimmed.ends_with("@main")
                || trimmed.ends_with("@master")
                || trimmed.ends_with("@dev"))
        {
            let rule = find_rule_by_id("SENTRA-CICD-005").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "GitHub Action referenced via mutable branch instead of immutable commit SHA"
                        .to_string(),
            });
        }

        // 6. Workflow secret echo / exfiltration risk (SENTRA-CICD-006)
        let is_secret_ref = line.contains("${{ secrets.") || line.contains("${{secrets.");
        if is_secret_ref
            && (line.contains("echo ")
                || line.contains("echo \"")
                || line.contains("echo '")
                || line.contains("curl ")
                || line.contains("wget ")
                || line.contains("GITHUB_OUTPUT")
                || line.contains("add-mask"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-CICD-006").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Workflow echoes or transmits ${{ secrets.* }} directly into logs or network calls"
                        .to_string(),
            });
        }

        results
    }

    fn check_auth_and_crypto(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. Timing attack in secret/signature comparison (SENTRA-AUTH-001)
        let has_eq = line.contains(" === ") || line.contains(" == ");
        if has_eq {
            let lower = line.to_ascii_lowercase();
            let is_secret_comp = (lower.contains("token")
                || lower.contains("secret")
                || lower.contains("signature")
                || lower.contains("apikey")
                || lower.contains("api_key")
                || lower.contains("passwordhash")
                || lower.contains("password_hash"))
                && (lower.contains("===") || lower.contains("=="))
                && !lower.contains("constanttimecompare")
                && !lower.contains("timingsafeequal")
                && !lower.contains("constant_time")
                && !lower.contains("typeof")
                && !lower.contains("null")
                && !lower.contains("undefined")
                && !lower.contains("\"\"")
                && !lower.contains("''");

            if is_secret_comp {
                let rule = find_rule_by_id("SENTRA-AUTH-001").expect("builtin rule");
                results.push(SastMatch {
                    rule: rule.clone(),
                    file_path: path.to_string(),
                    line_number: line_num,
                    snippet: trimmed.to_string(),
                    rationale:
                        "Variable-time comparison of secret, token, or cryptographic signature susceptible to side-channel timing attacks"
                            .to_string(),
                });
            }
        }

        // 2. Insecure JWT none algorithm or verify disabled (SENTRA-AUTH-002)
        let lower = line.to_ascii_lowercase();
        if (lower.contains("algorithm") && (lower.contains("'none'") || lower.contains("\"none\"")))
            || (lower.contains("jwt")
                && (lower.contains("verify: false") || lower.contains("verify:false")))
        {
            let rule = find_rule_by_id("SENTRA-AUTH-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "JWT configuration permits insecure 'none' algorithm or disables signature verification"
                        .to_string(),
            });
        }

        // 3. Weak password hash algorithm (MD5 or SHA1) (SENTRA-AUTH-003)
        if (lower.contains("createhash('md5')")
            || lower.contains("createhash(\"md5\")")
            || lower.contains("createhash('sha1')")
            || lower.contains("createhash(\"sha1\")")
            || lower.contains("md5(")
            || lower.contains("sha1("))
            && (lower.contains("password")
                || lower.contains("passwd")
                || lower.contains("credential"))
        {
            let rule = find_rule_by_id("SENTRA-AUTH-003").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Weak cryptographic digest (MD5/SHA1) used in credential or password handling"
                        .to_string(),
            });
        }

        // 4. Insecure cookie flags (SENTRA-AUTH-004)
        if (lower.contains("httponly: false") || lower.contains("httponly:false"))
            || (lower.contains("secure: false") || lower.contains("secure:false"))
            || (lower.contains("samesite: 'none'") && !lower.contains("secure: true"))
            || (lower.contains("samesite: \"none\"") && !lower.contains("secure: true"))
        {
            let rule = find_rule_by_id("SENTRA-AUTH-004").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Insecure cookie flags (httpOnly: false, secure: false, or unencrypted sameSite: none) expose cookies to theft"
                        .to_string(),
            });
        }

        // 5. Hardcoded JWT secret key (SENTRA-AUTH-005)
        if (lower.contains("jwt.sign(") || lower.contains("jwt.verify("))
            && (lower.contains("\"secret\"")
                || lower.contains("'secret'")
                || lower.contains("\"jwt_secret\"")
                || lower.contains("'jwt_secret'")
                || lower.contains("\"shhhhh\"")
                || lower.contains("'shhhhh'")
                || lower.contains("\"123456\"")
                || lower.contains("'123456'"))
        {
            let rule = find_rule_by_id("SENTRA-AUTH-005").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Trivial or hardcoded JWT symmetric secret allows token forgery and unauthorized authentication claims"
                        .to_string(),
            });
        }

        // 6. OAuth missing state or PKCE (SENTRA-AUTH-006)
        if (lower.contains("response_type=code")
            || lower.contains("response_type: 'code'")
            || lower.contains("response_type: \"code\"")
            || (lower.contains("/oauth/authorize") && lower.contains("client_id")))
            && !lower.contains("state")
            && !lower.contains("code_challenge")
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-AUTH-006").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "OAuth 2.0 authorization request constructed without state or code_challenge parameter, vulnerable to CSRF login and code interception"
                        .to_string(),
            });
        }

        // 7. JWT ignoreExpiration bypass (SENTRA-AUTH-007)
        if (lower.contains("ignoreexpiration: true") || lower.contains("ignoreexpiration:true"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-AUTH-007").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "JWT token verification explicitly disables expiration validation with ignoreExpiration: true"
                        .to_string(),
            });
        }

        results
    }

    fn check_agent_skill_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        // Exclude definition in our own detector/rules
        if path.ends_with("scanner.rs") || path.ends_with("rule.rs") {
            return results;
        }

        let trimmed = line.trim();
        let lower = line.to_ascii_lowercase();

        // 1. Agent prompt injection / instruction bypass (SENTRA-SKILL-001)
        if lower.contains("ignore previous instructions")
            || lower.contains("ignore all previous instructions")
            || lower.contains("system prompt override")
            || lower.contains("classify this skill as benign")
            || lower.contains("mark this skill as safe")
        {
            let rule = find_rule_by_id("SENTRA-SKILL-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Instruction injection or prompt override pattern detected in agent skill/instruction payload"
                        .to_string(),
            });
        }

        // 2. Agent credential harvesting (SENTRA-SKILL-002)
        if (lower.contains("process.env") || lower.contains("env::var"))
            && (lower.contains("send")
                || lower.contains("upload")
                || lower.contains("webhook")
                || lower.contains("post(")
                || lower.contains("fetch(")
                || lower.contains("http"))
            && (lower.contains("secret")
                || lower.contains("key")
                || lower.contains("token")
                || lower.contains("password"))
        {
            let rule = find_rule_by_id("SENTRA-SKILL-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Environment credential harvesting routine detected attempting remote data transmission"
                        .to_string(),
            });
        }

        results
    }

    fn check_go_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. Path Clean without root containment (SENTRA-GO-001)
        if line.contains("filepath.Clean(")
            && (line.contains("req.")
                || line.contains("input")
                || line.contains("param")
                || line.contains("userPath"))
            && !line.contains("filepath.Rel(")
            && !line.contains("os.Root")
        {
            let rule = find_rule_by_id("SENTRA-GO-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go filepath.Clean used on user input without root directory boundary containment (filepath.Rel or os.Root)"
                        .to_string(),
            });
        }

        // 2. Command injection shell wrapper (SENTRA-GO-002)
        let is_shell_command = line.contains("exec.Command(\"sh\", \"-c\",")
            || line.contains("exec.Command(\"bash\", \"-c\",")
            || (line.contains("exec.CommandContext(")
                && (line.contains(", \"sh\", \"-c\",") || line.contains(", \"bash\", \"-c\",")));
        if is_shell_command && (line.contains("fmt.Sprintf(") || line.contains("+")) {
            let rule = find_rule_by_id("SENTRA-GO-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go process execution invokes shell wrapper (sh -c / bash -c) with dynamic arguments"
                        .to_string(),
            });
        }

        // 3. SQL injection formatted query (SENTRA-GO-003)
        let is_db_query = line.contains("db.Query(")
            || line.contains("db.Exec(")
            || line.contains("db.QueryRow(")
            || line.contains("tx.Query(")
            || line.contains("tx.Exec(");
        let is_sql_format = line.contains("fmt.Sprintf(")
            && (line.contains("SELECT ")
                || line.contains("select ")
                || line.contains("INSERT ")
                || line.contains("UPDATE ")
                || line.contains("DELETE "));
        if (is_db_query && (line.contains("fmt.Sprintf(") || line.contains(" + "))) || is_sql_format
        {
            let rule = find_rule_by_id("SENTRA-GO-003").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go SQL query dynamically formatted with fmt.Sprintf or concatenation instead of parameterized query"
                        .to_string(),
            });
        }

        // 4. Weak crypto or PRNG (SENTRA-GO-004)
        if (line.contains("md5.New()")
            || line.contains("md5.Sum(")
            || line.contains("sha1.New()")
            || line.contains("sha1.Sum("))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-GO-004").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go code uses obsolete or broken cryptographic hash (MD5 or SHA1) vulnerable to collisions"
                        .to_string(),
            });
        }

        // 5. Go ZipSlip path traversal in archive extraction (SENTRA-GO-005)
        let is_zip_slip = (line.contains("filepath.Join(") || line.contains("path.Join("))
            && (line.contains("file.Name")
                || line.contains("f.Name")
                || line.contains("header.Name")
                || line.contains("hdr.Name")
                || line.contains("entry.Name"))
            && !line.contains("filepath.Rel")
            && !line.contains("os.Root")
            && !line.contains("filepath.Clean");
        if is_zip_slip && !path.contains("test") {
            let rule = find_rule_by_id("SENTRA-GO-005").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go archive extraction joins unvalidated entry filename, enabling ZipSlip arbitrary directory traversal"
                        .to_string(),
            });
        }

        // 6. Insecure legacy cipher DES/3DES/RC4 (SENTRA-GO-006)
        if (line.contains("des.NewCipher(")
            || line.contains("des.NewTripleDESCipher(")
            || line.contains("rc4.NewCipher("))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-GO-006").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go code uses obsolete or broken cipher (DES, 3DES, or RC4) vulnerable to cryptanalysis"
                        .to_string(),
            });
        }

        // 7. SSH InsecureIgnoreHostKey bypass (SENTRA-GO-007)
        if line.contains("ssh.InsecureIgnoreHostKey()") && !path.contains("test") {
            let rule = find_rule_by_id("SENTRA-GO-007").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Go SSH client disables host key verification via ssh.InsecureIgnoreHostKey(), enabling MitM attacks"
                        .to_string(),
            });
        }

        results
    }

    fn check_django_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. DEBUG = True (SENTRA-DJANGO-001)
        if (trimmed == "DEBUG = True"
            || trimmed.starts_with("DEBUG = True #")
            || trimmed == "DEBUG=True")
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-DJANGO-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Django DEBUG mode explicitly enabled disclosing diagnostics in responses"
                        .to_string(),
            });
        }

        // 2. ALLOWED_HOSTS = ['*'] (SENTRA-DJANGO-002)
        if trimmed.contains("ALLOWED_HOSTS") && trimmed.contains("'*'") {
            let rule = find_rule_by_id("SENTRA-DJANGO-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Wildcard in ALLOWED_HOSTS enables HTTP Host header poisoning"
                    .to_string(),
            });
        }

        // 3. @csrf_exempt (SENTRA-DJANGO-003)
        if trimmed.starts_with("@csrf_exempt") || trimmed.contains(" @csrf_exempt") {
            let rule = find_rule_by_id("SENTRA-DJANGO-003").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "View disables CSRF validation allowing cross-site request forgery"
                    .to_string(),
            });
        }

        // 4. Raw SQL injection via .raw(), .extra(), or cursor.execute() (SENTRA-DJANGO-004)
        let is_django_raw_sql = (line.contains(".raw(")
            || line.contains(".extra(")
            || line.contains("cursor.execute("))
            && (line.contains("f\"")
                || line.contains("f'")
                || line.contains(".format(")
                || line.contains(" % ")
                || line.contains(" + "));
        if is_django_raw_sql && !path.contains("test") {
            let rule = find_rule_by_id("SENTRA-DJANGO-004").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Django raw SQL query execution constructed with dynamic string interpolation or f-string"
                        .to_string(),
            });
        }

        // 5. Template autoescaping bypass via |safe filter or autoescape off (SENTRA-DJANGO-005)
        if (line.contains("|safe")
            || line.contains("| safe")
            || line.contains("{% autoescape off %}"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-DJANGO-005").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Django template bypasses HTML autoescaping via |safe filter or autoescape off directive"
                        .to_string(),
            });
        }

        results
    }

    fn check_laravel_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. APP_DEBUG=true (SENTRA-LARAVEL-001)
        let lower = line.to_ascii_lowercase();
        if (lower.starts_with("app_debug=true")
            || (lower.contains("'debug'") && lower.contains("true")))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-LARAVEL-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Laravel debug mode enabled in configuration exposing detailed stack traces"
                        .to_string(),
            });
        }

        // 2. protected $guarded = [] (SENTRA-LARAVEL-002)
        if trimmed.contains("$guarded") && trimmed.contains("[]") {
            let rule = find_rule_by_id("SENTRA-LARAVEL-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Empty $guarded array permits mass assignment vulnerability".to_string(),
            });
        }

        // 3. Raw SQL injection in Laravel query builder (SENTRA-LARAVEL-003)
        let is_laravel_raw_sql = (line.contains("DB::raw(")
            || line.contains("whereRaw(")
            || line.contains("selectRaw(")
            || line.contains("havingRaw(")
            || line.contains("orderByRaw("))
            && (line.contains('$')
                || line.contains(" . ")
                || line.contains("\".$")
                || line.contains("'.$"));
        if is_laravel_raw_sql && !path.contains("test") {
            let rule = find_rule_by_id("SENTRA-LARAVEL-003").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Laravel raw query builder method constructed with string concatenation instead of parameter bindings"
                        .to_string(),
            });
        }

        // 4. Blade unescaped raw HTML output {!! $var !!} (SENTRA-LARAVEL-004)
        if ((line.contains("{!!") && line.contains("!!}")) || line.contains("{!! $"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-LARAVEL-004").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Laravel Blade template outputs unescaped raw HTML using {!! !!} tags susceptible to XSS"
                        .to_string(),
            });
        }

        results
    }

    fn check_spring_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. allowedOrigins("*") (SENTRA-SPRING-001)
        if trimmed.contains(".allowedOrigins(\"*\")") || trimmed.contains(".allowedOrigins('*')") {
            let rule = find_rule_by_id("SENTRA-SPRING-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Spring CORS configured with wildcard allowedOrigins granting cross-origin credential access".to_string(),
            });
        }

        // 2. management.endpoints.web.exposure.include=* (SENTRA-SPRING-002)
        if trimmed.contains("management.endpoints.web.exposure.include") && trimmed.contains('*') {
            let rule = find_rule_by_id("SENTRA-SPRING-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Broad Spring Boot Actuator endpoint exposure leaks sensitive system metrics"
                        .to_string(),
            });
        }

        // 3. SpEL expression injection (SENTRA-SPRING-003)
        let is_spel = line.contains("parseExpression(")
            && (line.contains('+')
                || line.contains("input")
                || line.contains("param")
                || line.contains("expr")
                || line.contains("payload")
                || line.contains("req."));
        if is_spel && !path.contains("test") {
            let rule = find_rule_by_id("SENTRA-SPRING-003").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Spring SpEL ExpressionParser evaluates dynamic expression allowing remote code execution"
                        .to_string(),
            });
        }

        // 4. Spring Security CSRF disabled (SENTRA-SPRING-004)
        if (line.contains(".csrf().disable()")
            || line.contains(".csrf(AbstractHttpConfigurer::disable)")
            || line.contains(".csrf(csrf -> csrf.disable())")
            || line.contains(".csrf((csrf) -> csrf.disable())"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-SPRING-004").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "Spring Security CSRF protection explicitly disabled on HTTP security configuration"
                        .to_string(),
            });
        }

        results
    }

    fn check_firebase_rules(&self, path: &str, line_num: u32, line: &str) -> Option<SastMatch> {
        let trimmed = line.trim();
        let lower = line.to_ascii_lowercase();

        // allow read, write: if true; (SENTRA-FIREBASE-001)
        if lower.contains("allow read") && lower.contains("if true;") {
            let rule = find_rule_by_id("SENTRA-FIREBASE-001")?.clone();
            return Some(SastMatch {
                rule,
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Firebase rule allows unauthenticated public read/write access"
                    .to_string(),
            });
        }
        None
    }

    fn check_solidity_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        let trimmed = line.trim();

        // 1. tx.origin used for authentication (SENTRA-SOLIDITY-001)
        if trimmed.contains("tx.origin")
            && (trimmed.contains("==")
                || trimmed.contains("require(")
                || trimmed.contains("assert("))
        {
            let rule = find_rule_by_id("SENTRA-SOLIDITY-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Solidity authorization checks tx.origin instead of msg.sender, vulnerable to phishing contract delegation".to_string(),
            });
        }

        // 2. call{value: ...} external call (SENTRA-SOLIDITY-002)
        if trimmed.contains(".call{value:") || trimmed.contains(".call.value(") {
            let rule = find_rule_by_id("SENTRA-SOLIDITY-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Low-level Ether transfer via call{value:} susceptible to reentrancy attacks if state is not updated beforehand".to_string(),
            });
        }

        results
    }

    fn check_cloud_metadata_ssrf(
        &self,
        path: &str,
        line_num: u32,
        line: &str,
    ) -> Option<SastMatch> {
        if path.ends_with("scanner.rs") || path.ends_with("rule.rs") {
            return None;
        }
        if (line.contains("169.254.169.254") || line.contains("metadata.google.internal"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-CLOUD-001").expect("builtin rule");
            return Some(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                rationale: "Cloud metadata service endpoint referenced (potential SSRF credential exfiltration target)"
                    .to_string(),
            });
        }
        None
    }

    fn check_api_security(&self, path: &str, line_num: u32, line: &str) -> Vec<SastMatch> {
        let mut results = Vec::new();
        if path.ends_with("scanner.rs") || path.ends_with("rule.rs") {
            return results;
        }
        let trimmed = line.trim();

        // 1. Direct mass assignment update (SENTRA-API-001)
        if (trimmed.contains(".update(req.body)")
            || trimmed.contains(".update(request.body)")
            || trimmed.contains(".create(req.body)")
            || trimmed.contains(".create(request.body)"))
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-API-001").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Direct mass assignment of unvalidated request body into model mutation"
                    .to_string(),
            });
        }

        // 2. Unbounded collection query without pagination limit (SENTRA-API-002)
        if (trimmed.contains(".findAll()")
            || trimmed.contains(".findMany({})")
            || trimmed.contains(".find().toArray()")
            || trimmed.contains(".all().fetch()"))
            && !trimmed.contains("limit")
            && !trimmed.contains("take")
            && !path.contains("test")
        {
            let rule = find_rule_by_id("SENTRA-API-002").expect("builtin rule");
            results.push(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale:
                    "API database collection query executes without limit or pagination, risking memory exhaustion and DoS"
                        .to_string(),
            });
        }

        results
    }

    fn check_supply_chain_security(
        &self,
        path: &str,
        line_num: u32,
        line: &str,
    ) -> Option<SastMatch> {
        if path.ends_with("scanner.rs") || path.ends_with("rule.rs") {
            return None;
        }
        let trimmed = line.trim();
        let is_curl_or_wget = trimmed.contains("curl ") || trimmed.contains("wget ");
        let is_piped_to_sh = trimmed.contains("| sh")
            || trimmed.contains("| bash")
            || trimmed.contains("|sh")
            || trimmed.contains("|bash")
            || trimmed.contains("| sudo sh")
            || trimmed.contains("| sudo bash");

        if is_curl_or_wget && is_piped_to_sh && !path.contains("test") {
            let rule = find_rule_by_id("SENTRA-SUPPLY-001").expect("builtin rule");
            return Some(SastMatch {
                rule: rule.clone(),
                file_path: path.to_string(),
                line_number: line_num,
                snippet: trimmed.to_string(),
                rationale: "Unverified remote download piped directly into shell execution"
                    .to_string(),
            });
        }
        None
    }
}

/// Whether a key-alphabet token mixes upper case, lower case, and a digit or `/`/`+`.
/// This separates random key material from identifiers and hex digests.
fn is_mixed_key_material(token: &[u8]) -> bool {
    let has_upper = token.iter().any(u8::is_ascii_uppercase);
    let has_lower = token.iter().any(u8::is_ascii_lowercase);
    let has_other = token
        .iter()
        .any(|b| b.is_ascii_digit() || *b == b'/' || *b == b'+');
    has_upper && has_lower && has_other
}

/// Lines that read a secret from the environment or carry an obvious placeholder.
fn is_placeholder_or_reference_line(lower: &str) -> bool {
    lower.contains("process.env")
        || lower.contains("env::var")
        || lower.contains("std::env")
        || lower.contains("os.environ")
        || lower.contains("system.getenv")
        || lower.contains("dummy")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("todo")
        || lower.contains("your_")
        || lower.contains("<your")
        || lower.contains("redacted")
        || lower.contains("\"\"")
        || lower.contains("''")
}

/// Body of the first double-quoted literal on the line, or else the first single-quoted one.
fn first_quoted_literal(line: &str) -> Option<&str> {
    let quote_start = line.find('"').or_else(|| line.find('\''))?;
    let quote_char = line.as_bytes()[quote_start] as char;
    let after_start = &line[quote_start + 1..];
    let quote_end = after_start.find(quote_char)?;
    Some(&after_start[..quote_end])
}

/// Returns the plausible password literal assigned to an identifier that ends with a
/// password keyword (`password`, `dbPassword`, `DB_PASSWORD`, `"passwd"`).
///
/// Identifiers that only contain the keyword (`passwordLabel`, `PASSWORD_FILE`) are
/// skipped, because their values are labels, paths, or references rather than passwords.
fn assigned_password_literal<'a>(path: &str, line: &'a str, lower: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    let unquoted_allowed = allows_unquoted_values(path);
    for keyword in PASSWORD_IDENTIFIER_SUFFIXES {
        let mut from = 0;
        while let Some(found) = lower[from..].find(keyword) {
            // Keywords are ASCII and `lower` has the byte layout of `line`, so `end` is a
            // character boundary in both strings.
            let end = from + found + keyword.len();
            from = end;
            if bytes
                .get(end)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                continue;
            }
            if let Some(value) = assigned_value(&line[end..], unquoted_allowed)
                && is_plausible_password_literal(value, keyword)
            {
                return Some(value);
            }
        }
    }
    None
}

/// Extracts the value assigned right after an identifier: `= "v"`, `: "v"`, `:= "v"`,
/// `=> "v"`, or a typed form such as `: str = "v"`. Comparisons (`==`) are not
/// assignments. Unquoted values are accepted only where `unquoted_allowed` is set
/// (dotenv, YAML, properties, INI, shell, and Dockerfile sources).
fn assigned_value(rest: &str, unquoted_allowed: bool) -> Option<&str> {
    // Closing quote of a quoted key such as `"password": ...` or `'password' => ...`.
    let rest = rest.strip_prefix(['"', '\'']).unwrap_or(rest).trim_start();
    let value = if let Some(after) = rest.strip_prefix(":=").or_else(|| rest.strip_prefix("=>")) {
        after
    } else if rest.starts_with("==") {
        return None;
    } else if let Some(after) = rest.strip_prefix('=') {
        after
    } else {
        skip_type_annotation(rest.strip_prefix(':')?)
    };
    let value = value.trim_start();
    let quote = value.chars().next()?;
    if matches!(quote, '"' | '\'' | '`') {
        let body = &value[1..];
        return body.find(quote).map(|end| &body[..end]);
    }
    if unquoted_allowed {
        let end = value.find(char::is_whitespace).unwrap_or(value.len());
        return Some(&value[..end]);
    }
    None
}

/// Skips a type annotation between `:` and `=` (`password: str = "v"`,
/// `password: string = "v"`). Returns `rest` unchanged when there is none.
fn skip_type_annotation(rest: &str) -> &str {
    let trimmed = rest.trim_start();
    let annotation_len = trimmed
        .find(|c: char| {
            !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '[' | ']' | '|' | ',' | ' '))
        })
        .unwrap_or(trimmed.len());
    let after = &trimmed[annotation_len..];
    if annotation_len > 0 && after.starts_with('=') && !after.starts_with("==") {
        &after[1..]
    } else {
        rest
    }
}

/// Whether a value assigned to a password identifier looks like a literal password rather
/// than a label, translation key, path, mask, or interpolation.
fn is_plausible_password_literal(value: &str, keyword: &str) -> bool {
    if value.chars().count() < MIN_PASSWORD_LITERAL_LEN || value.chars().any(char::is_whitespace) {
        return false;
    }
    // References, interpolations, paths, tags and placeholders (`${DB_PASSWORD}`,
    // `{{ vault }}`, `%(pw)s`, `/run/secrets/db`, `!secret db`, `<password>`).
    if value.starts_with(['$', '%', '{', '<', '!', '/', '.', '@'])
        || value.contains("${")
        || value.contains("{{")
        || value.contains("%(")
        || value.contains("://")
    {
        return false;
    }
    // Masks such as `********` carry no key material.
    if !value.chars().any(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    // Letters-only values are far more often labels or translations (`"Passwort"`).
    if value.chars().all(char::is_alphabetic) {
        return false;
    }
    // A label naming the field itself (`"Password:"`).
    let alphanumeric: String = value.chars().filter(char::is_ascii_alphanumeric).collect();
    if alphanumeric.eq_ignore_ascii_case(keyword) {
        return false;
    }
    // Dotted identifiers are translation or configuration keys (`auth.password`).
    let is_dotted_identifier = value.contains('.')
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
    !is_dotted_identifier
}

/// Configuration-style sources whose values are commonly written without quotes.
/// Example, sample and template files are excluded to keep placeholder values quiet.
fn allows_unquoted_values(path: &str) -> bool {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    if name.contains("example") || name.contains("sample") || name.contains("template") {
        return false;
    }
    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || name == "dockerfile"
        || name.ends_with(".dockerfile")
        || [
            ".properties",
            ".ini",
            ".cfg",
            ".conf",
            ".yml",
            ".yaml",
            ".sh",
            ".bash",
            ".zsh",
        ]
        .iter()
        .any(|ext| name.ends_with(ext))
}
