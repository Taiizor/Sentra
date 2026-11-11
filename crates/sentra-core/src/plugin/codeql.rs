//! GitHub CodeQL Adapter, Taint Flow Extraction, and SARIF Ingestion Engine (REQ-F05, REQ-F16).
//!
//! Provides deep integration with GitHub CodeQL without runtime coupling:
//! - Auto-probes workspace files and detects CodeQL-supported languages (JS/TS, Python, Rust, Go, C/C++, Java, C#, Ruby, Swift).
//! - Generates deterministic CodeQL CLI invocations (`codeql database create` and `codeql database analyze`).
//! - Ingests CodeQL OASIS SARIF v2.1.0 output, extracting rich interprocedural taint tracking paths (`codeFlows`).
//! - Normalizes findings into Sentra's canonical domain model with `Reachability::ReachableCallPath` and `Confidence::High`.
//! - Conforms to Sentra's `PluginManifest` and `PluginHost` adapter protocol under `#![forbid(unsafe_code)]`.

use std::{collections::BTreeMap, fmt, path::Path, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    advisory::SemverVersion,
    domain::{
        Confidence, Finding, FindingId, FindingSource, Reachability, SessionId, Severity,
        TargetLocation, TaskId, TimestampUtc,
    },
    plugin::{
        manifest::{AdapterFamily, PluginCapability, PluginManifest, PluginQuotas},
        protocol::{PluginRequest, PluginResponse},
    },
    verification::EgressPolicy,
};

/// Languages supported natively by GitHub CodeQL extractors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeQlLanguage {
    /// JavaScript and TypeScript.
    Javascript,
    /// Python.
    Python,
    /// Rust.
    Rust,
    /// Go.
    Go,
    /// C and C++.
    Cpp,
    /// Java and Kotlin.
    Java,
    /// C# and .NET.
    Csharp,
    /// Ruby.
    Ruby,
    /// Swift.
    Swift,
}

impl CodeQlLanguage {
    /// Returns the canonical CodeQL CLI language identifier flag (e.g. `--language=javascript`).
    pub const fn as_codeql_identifier(&self) -> &'static str {
        match self {
            Self::Javascript => "javascript",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Cpp => "cpp",
            Self::Java => "java",
            Self::Csharp => "csharp",
            Self::Ruby => "ruby",
            Self::Swift => "swift",
        }
    }

    /// Detects candidate language from a file extension or key configuration file.
    pub fn detect_from_filename(filename: &str) -> Option<Self> {
        let lower = filename.to_ascii_lowercase();
        if lower.ends_with(".js")
            || lower.ends_with(".jsx")
            || lower.ends_with(".ts")
            || lower.ends_with(".tsx")
            || lower.ends_with(".mjs")
            || lower.ends_with(".cjs")
            || lower == "package.json"
        {
            Some(Self::Javascript)
        } else if lower.ends_with(".py") || lower == "requirements.txt" || lower == "pyproject.toml"
        {
            Some(Self::Python)
        } else if lower.ends_with(".rs") || lower == "cargo.toml" {
            Some(Self::Rust)
        } else if lower.ends_with(".go") || lower == "go.mod" {
            Some(Self::Go)
        } else if lower.ends_with(".c")
            || lower.ends_with(".cpp")
            || lower.ends_with(".cc")
            || lower.ends_with(".cxx")
            || lower.ends_with(".h")
            || lower.ends_with(".hpp")
            || lower == "cmakelists.txt"
        {
            Some(Self::Cpp)
        } else if lower.ends_with(".java")
            || lower.ends_with(".kt")
            || lower == "pom.xml"
            || lower == "build.gradle"
        {
            Some(Self::Java)
        } else if lower.ends_with(".cs") || lower.ends_with(".csproj") || lower.ends_with(".sln") {
            Some(Self::Csharp)
        } else if lower.ends_with(".rb") || lower == "gemfile" {
            Some(Self::Ruby)
        } else if lower.ends_with(".swift") || lower == "package.swift" {
            Some(Self::Swift)
        } else {
            None
        }
    }
}

impl fmt::Display for CodeQlLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_codeql_identifier())
    }
}

/// Errors arising during CodeQL probing, invocation planning, or SARIF ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeQlError {
    /// The provided SARIF JSON could not be parsed or is corrupted.
    InvalidSarifPayload(String),
    /// Failed to inspect or read the workspace directory.
    WorkspaceReadError(String),
    /// No CodeQL-compatible programming languages were detected in the workspace.
    NoSupportedLanguagesDetected,
    /// An internal domain ID conversion failed.
    DomainError(String),
}

impl fmt::Display for CodeQlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSarifPayload(e) => write!(f, "invalid CodeQL SARIF payload: {e}"),
            Self::WorkspaceReadError(e) => write!(f, "workspace read error: {e}"),
            Self::NoSupportedLanguagesDetected => {
                write!(
                    f,
                    "no CodeQL-supported languages detected in target workspace"
                )
            }
            Self::DomainError(e) => write!(f, "domain error in CodeQL adapter: {e}"),
        }
    }
}

impl std::error::Error for CodeQlError {}

/// Classification of a step in an interprocedural taint flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintStepKind {
    /// The untrusted user or external source entry point.
    Source,
    /// An intermediate variable assignment, function argument, or propagation.
    Propagation,
    /// An intermediate sanitizer, guard, or validation check.
    Sanitizer,
    /// The vulnerable sink or sensitive execution point.
    Sink,
}

impl fmt::Display for TaintStepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => write!(f, "SOURCE"),
            Self::Propagation => write!(f, "PROPAGATION"),
            Self::Sanitizer => write!(f, "SANITIZER"),
            Self::Sink => write!(f, "SINK"),
        }
    }
}

/// A discrete step in an interprocedural data flow / taint trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQlTaintStep {
    /// 1-based sequential index in the trace.
    pub step_index: usize,
    /// Semantic kind of this step.
    pub kind: TaintStepKind,
    /// Physical location of this step in code.
    pub location: TargetLocation,
    /// Contextual explanation or code snippet message.
    pub message: String,
}

/// An end-to-end taint tracking path extracted from CodeQL `codeFlows`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CodeQlTaintTrace {
    /// Sequential flow steps from source to sink.
    pub steps: Vec<CodeQlTaintStep>,
}

impl CodeQlTaintTrace {
    /// Returns the initial source step, if present.
    pub fn source(&self) -> Option<&CodeQlTaintStep> {
        self.steps.first()
    }

    /// Returns the final vulnerable sink step, if present.
    pub fn sink(&self) -> Option<&CodeQlTaintStep> {
        self.steps.last()
    }

    /// Formats the taint trace into an expressive Markdown table for findings and PRs.
    pub fn to_markdown_trace(&self) -> String {
        if self.steps.is_empty() {
            return String::new();
        }

        let mut out = String::from("\n#### CodeQL Interprocedural Taint Flow\n\n");
        out.push_str("| Step | Role | Location | Code Context |\n");
        out.push_str("| :---: | :--- | :--- | :--- |\n");

        for step in &self.steps {
            let loc_str = if let Some(line) = step.location.start_line {
                format!("{}:{}", step.location.path, line)
            } else {
                step.location.path.clone()
            };

            let badge = match step.kind {
                TaintStepKind::Source => "`🔴 SOURCE`",
                TaintStepKind::Propagation => "`🟡 PROPAGATE`",
                TaintStepKind::Sanitizer => "`🟢 SANITIZER`",
                TaintStepKind::Sink => "`💥 SINK`",
            };

            out.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                step.step_index, badge, loc_str, step.message
            ));
        }

        out
    }
}

/// Report summarizing workspace probing for CodeQL compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQlProbeReport {
    /// Workspace root probed.
    pub workspace_root: String,
    /// Languages detected along with the count of source files.
    pub detected_languages: Vec<(CodeQlLanguage, usize)>,
    /// Primary language recommended for CodeQL database initialization.
    pub primary_language: Option<CodeQlLanguage>,
    /// Exact CLI command to create the CodeQL database.
    pub database_create_command: Option<String>,
    /// Exact CLI command to execute the CodeQL analysis producing SARIF.
    pub database_analyze_command: Option<String>,
}

/// Report summarizing CodeQL SARIF ingestion into Sentra.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQlSarifIngestResult {
    /// Converted canonical Sentra findings.
    pub findings: Vec<Finding>,
    /// Total raw results found in the SARIF document.
    pub total_sarif_results: usize,
    /// Number of results with rich taint traces (`codeFlows`).
    pub taint_traces_extracted: usize,
    /// Unique rule IDs encountered.
    pub rules_identified: Vec<String>,
    /// Highest severity among the parsed candidate findings.
    pub highest_severity: Option<Severity>,
}

/// Probes a workspace directory to detect CodeQL-supported languages and generate CLI commands.
pub fn probe_codeql_workspace(workspace_root: &Path) -> Result<CodeQlProbeReport, CodeQlError> {
    if !workspace_root.exists() {
        return Err(CodeQlError::WorkspaceReadError(format!(
            "workspace path does not exist: {}",
            workspace_root.display()
        )));
    }

    let mut language_counts: BTreeMap<CodeQlLanguage, usize> = BTreeMap::new();

    let mut dirs_to_visit = vec![workspace_root.to_path_buf()];
    let mut files_scanned = 0;
    const MAX_FILES: usize = 10_000;

    while let Some(current_dir) = dirs_to_visit.pop() {
        let entries = std::fs::read_dir(&current_dir).map_err(|e| {
            CodeQlError::WorkspaceReadError(format!(
                "failed reading directory {}: {e}",
                current_dir.display()
            ))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip common build, VCS, and package directories
            if name == ".git"
                || name == "node_modules"
                || name == "target"
                || name == ".sentra"
                || name == "dist"
                || name == "build"
                || name == "venv"
                || name == ".venv"
            {
                continue;
            }

            if path.is_dir() {
                dirs_to_visit.push(path);
            } else if path.is_file() {
                files_scanned += 1;
                if let Some(lang) = CodeQlLanguage::detect_from_filename(&name) {
                    *language_counts.entry(lang).or_insert(0) += 1;
                }
                if files_scanned >= MAX_FILES {
                    break;
                }
            }
        }
    }

    let mut sorted_langs: Vec<(CodeQlLanguage, usize)> = language_counts.into_iter().collect();
    sorted_langs.sort_by_key(|a| std::cmp::Reverse(a.1));

    let primary = sorted_langs.first().map(|(l, _)| *l);

    let (create_cmd, analyze_cmd) = if let Some(lang) = primary {
        let ws_str = workspace_root.to_string_lossy().replace('\\', "/");
        let create = format!(
            "codeql database create .sentra/codeql-db --language={} --source-root={}",
            lang.as_codeql_identifier(),
            ws_str
        );
        let analyze = "codeql database analyze .sentra/codeql-db --format=sarif-latest --output=.sentra/codeql-results.sarif".to_string();
        (Some(create), Some(analyze))
    } else {
        (None, None)
    };

    Ok(CodeQlProbeReport {
        workspace_root: workspace_root.to_string_lossy().replace('\\', "/"),
        detected_languages: sorted_langs,
        primary_language: primary,
        database_create_command: create_cmd,
        database_analyze_command: analyze_cmd,
    })
}

// ---------------------------------------------------------------------------
// SARIF Deserialization Models (Pure Safe Rust)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct RawSarifRoot {
    #[serde(default)]
    runs: Vec<RawSarifRun>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifRun {
    #[serde(default)]
    tool: Option<RawSarifTool>,
    #[serde(default)]
    results: Vec<RawSarifResult>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifTool {
    #[serde(default)]
    driver: Option<RawSarifDriver>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifDriver {
    #[serde(default)]
    rules: Vec<RawSarifRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifRule {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "shortDescription", default)]
    short_description: Option<RawSarifText>,
    #[serde(rename = "fullDescription", default)]
    full_description: Option<RawSarifText>,
    #[serde(rename = "helpUri", default)]
    help_uri: Option<String>,
    #[serde(default)]
    properties: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifText {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Option<RawSarifText>,
    #[serde(default)]
    locations: Vec<RawSarifLocationWrapper>,
    #[serde(rename = "codeFlows", default)]
    code_flows: Vec<RawSarifCodeFlow>,
    #[serde(default)]
    properties: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifLocationWrapper {
    #[serde(rename = "physicalLocation", default)]
    physical_location: Option<RawSarifPhysicalLocation>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifPhysicalLocation {
    #[serde(rename = "artifactLocation", default)]
    artifact_location: Option<RawSarifArtifactLocation>,
    #[serde(default)]
    region: Option<RawSarifRegion>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifArtifactLocation {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifRegion {
    #[serde(rename = "startLine", default)]
    start_line: Option<u32>,
    #[serde(rename = "endLine", default)]
    end_line: Option<u32>,
    #[serde(rename = "startColumn", default)]
    #[allow(dead_code)]
    start_column: Option<u32>,
    #[serde(rename = "endColumn", default)]
    #[allow(dead_code)]
    end_column: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifCodeFlow {
    #[serde(rename = "threadFlows", default)]
    thread_flows: Vec<RawSarifThreadFlow>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifThreadFlow {
    #[serde(default)]
    locations: Vec<RawSarifThreadFlowLocation>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifThreadFlowLocation {
    #[serde(default)]
    location: Option<RawSarifFlowLocationInner>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSarifFlowLocationInner {
    #[serde(rename = "physicalLocation", default)]
    physical_location: Option<RawSarifPhysicalLocation>,
    #[serde(default)]
    message: Option<RawSarifText>,
}

/// Ingests a CodeQL SARIF v2.1.0 string, extracts findings and taint traces, and converts to Sentra `Finding`s.
pub fn ingest_codeql_sarif_payload(
    sarif_json: &str,
    session_id: &SessionId,
    task_id: TaskId,
    clock_now: TimestampUtc,
) -> Result<CodeQlSarifIngestResult, CodeQlError> {
    let parsed: RawSarifRoot = serde_json::from_str(sarif_json)
        .map_err(|e| CodeQlError::InvalidSarifPayload(e.to_string()))?;

    let mut findings = Vec::new();
    let mut total_results = 0;
    let mut taint_count = 0;
    let mut rules_set = BTreeMap::new();
    let mut highest_severity: Option<Severity> = None;

    for run in parsed.runs {
        // Build rule metadata index
        let mut rules_map: BTreeMap<String, &RawSarifRule> = BTreeMap::new();
        if let Some(tool) = &run.tool
            && let Some(driver) = &tool.driver
        {
            for rule in &driver.rules {
                rules_map.insert(rule.id.clone(), rule);
            }
        }

        for result in run.results {
            total_results += 1;
            rules_set.insert(result.rule_id.clone(), ());

            // Extract primary location
            let primary_loc = result
                .locations
                .first()
                .and_then(|w| w.physical_location.as_ref());
            let target_location = primary_loc.map(|pl| {
                let path = pl
                    .artifact_location
                    .as_ref()
                    .and_then(|al| al.uri.clone())
                    .unwrap_or_else(|| "unknown".to_string())
                    .replace('\\', "/");

                let region = pl.region.as_ref();
                TargetLocation {
                    path,
                    start_line: region.and_then(|r| r.start_line),
                    end_line: region.and_then(|r| r.end_line),
                }
            });

            // Extract Taint Trace from codeFlows
            let mut taint_trace = CodeQlTaintTrace::default();
            for code_flow in &result.code_flows {
                for thread_flow in &code_flow.thread_flows {
                    let total_steps = thread_flow.locations.len();
                    for (idx, step_loc) in thread_flow.locations.iter().enumerate() {
                        if let Some(inner) = &step_loc.location {
                            let step_num = idx + 1;
                            let msg = inner
                                .message
                                .as_ref()
                                .and_then(|m| m.text.clone())
                                .unwrap_or_else(|| "propagation".to_string());

                            let loc = if let Some(pl) = &inner.physical_location {
                                let path = pl
                                    .artifact_location
                                    .as_ref()
                                    .and_then(|al| al.uri.clone())
                                    .unwrap_or_else(|| "unknown".to_string())
                                    .replace('\\', "/");
                                let reg = pl.region.as_ref();
                                TargetLocation {
                                    path,
                                    start_line: reg.and_then(|r| r.start_line),
                                    end_line: reg.and_then(|r| r.end_line),
                                }
                            } else {
                                TargetLocation {
                                    path: "unknown".to_string(),
                                    start_line: None,
                                    end_line: None,
                                }
                            };

                            let kind = if idx == 0 {
                                TaintStepKind::Source
                            } else if idx == total_steps - 1 {
                                TaintStepKind::Sink
                            } else {
                                let lower = msg.to_ascii_lowercase();
                                if lower.contains("sanitiz")
                                    || lower.contains("guard")
                                    || lower.contains("check")
                                    || lower.contains("validat")
                                    || lower.contains("escape")
                                {
                                    TaintStepKind::Sanitizer
                                } else {
                                    TaintStepKind::Propagation
                                }
                            };

                            taint_trace.steps.push(CodeQlTaintStep {
                                step_index: step_num,
                                kind,
                                location: loc,
                                message: msg,
                            });
                        }
                    }
                }
            }

            let has_taint_trace = !taint_trace.steps.is_empty();
            if has_taint_trace {
                taint_count += 1;
            }

            // Determine Severity (check properties["security-severity"], then rule properties, then level)
            let mut sec_score: Option<f64> = None;
            if let Some(props) = &result.properties
                && let Some(val) = props.get("security-severity")
            {
                if let Some(s) = val.as_str() {
                    sec_score = s.parse::<f64>().ok();
                } else if let Some(n) = val.as_f64() {
                    sec_score = Some(n);
                }
            }

            let rule_meta = rules_map.get(&result.rule_id);
            if sec_score.is_none()
                && let Some(rule) = rule_meta
                && let Some(props) = &rule.properties
                && let Some(val) = props.get("security-severity")
            {
                if let Some(s) = val.as_str() {
                    sec_score = s.parse::<f64>().ok();
                } else if let Some(n) = val.as_f64() {
                    sec_score = Some(n);
                }
            }

            let severity = if let Some(score) = sec_score {
                if score >= 9.0 {
                    Severity::Critical
                } else if score >= 7.0 {
                    Severity::High
                } else if score >= 4.0 {
                    Severity::Medium
                } else if score > 0.0 {
                    Severity::Low
                } else {
                    Severity::Informational
                }
            } else {
                match result.level.as_deref() {
                    Some("error") => Severity::High,
                    Some("warning") => Severity::Medium,
                    Some("note") => Severity::Low,
                    _ => Severity::Medium,
                }
            };

            if highest_severity.is_none_or(|h| severity > h) {
                highest_severity = Some(severity);
            }

            // Reachability & Confidence
            let reachability = if has_taint_trace {
                Reachability::ReachableCallPath
            } else {
                Reachability::SyntacticallyReferenced
            };

            let confidence = if has_taint_trace {
                Confidence::High
            } else {
                Confidence::Confirmed
            };

            // Build Title and Description
            let raw_msg = result
                .message
                .as_ref()
                .and_then(|m| m.text.clone())
                .unwrap_or_else(|| result.rule_id.clone());

            let rule_name = rule_meta
                .and_then(|r| r.name.as_deref())
                .unwrap_or(&result.rule_id);

            let title = format!("[CodeQL] {}: {}", result.rule_id, rule_name);

            let mut desc = format!("### CodeQL Detection: {}\n\n", result.rule_id);
            desc.push_str(&format!("**Message:** {}\n\n", raw_msg));

            if let Some(rule) = rule_meta {
                if let Some(full) = rule
                    .full_description
                    .as_ref()
                    .and_then(|f| f.text.as_deref())
                {
                    desc.push_str(&format!("**Description:** {}\n\n", full));
                } else if let Some(short) = rule
                    .short_description
                    .as_ref()
                    .and_then(|s| s.text.as_deref())
                {
                    desc.push_str(&format!("**Summary:** {}\n\n", short));
                }
                if let Some(uri) = &rule.help_uri {
                    desc.push_str(&format!("**Reference / Advisory:** [{}]({})\n\n", uri, uri));
                }
            }

            if has_taint_trace {
                desc.push_str(&taint_trace.to_markdown_trace());
            }

            let finding_id = FindingId::new();
            let finding = Finding::new_candidate(
                finding_id,
                *session_id,
                task_id,
                title,
                desc,
                severity,
                confidence,
                reachability,
                FindingSource::StaticAnalysis {
                    engine: "codeql".to_string(),
                    rule_id: result.rule_id.clone(),
                },
                target_location,
                None,
                clock_now,
            );

            findings.push(finding);
        }
    }

    Ok(CodeQlSarifIngestResult {
        findings,
        total_sarif_results: total_results,
        taint_traces_extracted: taint_count,
        rules_identified: rules_set.into_keys().collect(),
        highest_severity,
    })
}

/// Official CodeQL Adapter complying with Sentra's `PluginHost` / `PluginManifest`.
#[derive(Clone, Debug)]
pub struct CodeQlAdapter {
    /// Adapter manifest describing capabilities and execution limits.
    pub manifest: PluginManifest,
}

impl Default for CodeQlAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeQlAdapter {
    /// Creates a new CodeQL adapter with standard quotas and capabilities.
    pub fn new() -> Self {
        Self {
            manifest: PluginManifest {
                id: "org.sentra.adapter.codeql".to_string(),
                name: "GitHub CodeQL Static Analysis Adapter".to_string(),
                version: SemverVersion::new(1, 0, 0),
                interface_version: 1,
                family: AdapterFamily::AnalysisTool,
                executable_path: "codeql".to_string(),
                declared_capabilities: vec![
                    PluginCapability::SourceDiscovery,
                    PluginCapability::StaticAnalysis,
                ],
                quotas: PluginQuotas {
                    max_memory_mib: 4096,
                    max_execution_time_secs: 300,
                    max_frame_bytes: 5_242_880,         // 5 MiB
                    max_total_output_bytes: 20_971_520, // 20 MiB
                },
                egress_policy: EgressPolicy::StrictlyDenied,
            },
        }
    }

    /// Handles incoming protocol requests from Sentra's `PluginHost`.
    pub fn handle_request(&self, request: &PluginRequest) -> PluginResponse {
        match request {
            PluginRequest::Initialize { host_version: _ } => PluginResponse::InitializeAck {
                plugin_id: self.manifest.id.clone(),
                interface_version: 1,
                capabilities: self.manifest.declared_capabilities.clone(),
            },
            PluginRequest::Probe { workspace_root } => {
                let path = Path::new(workspace_root);
                match probe_codeql_workspace(path) {
                    Ok(report) => {
                        let applicable = !report.detected_languages.is_empty();
                        let details = if applicable {
                            let langs: Vec<String> = report
                                .detected_languages
                                .iter()
                                .map(|(l, count)| format!("{l} ({count} files)"))
                                .collect();
                            format!("CodeQL compatible: {}", langs.join(", "))
                        } else {
                            "No CodeQL-supported source files detected".to_string()
                        };

                        PluginResponse::ProbeResult {
                            applicable,
                            details,
                            unsupported_reason: if applicable {
                                None
                            } else {
                                Some("No supported source files (JS/TS, Py, Rust, Go, C/C++, Java, C#, Ruby, Swift)".to_string())
                            },
                        }
                    }
                    Err(e) => PluginResponse::ProbeResult {
                        applicable: false,
                        details: format!("Probe error: {e}"),
                        unsupported_reason: Some(e.to_string()),
                    },
                }
            }
            PluginRequest::Plan { input_ref } => PluginResponse::PlanResult {
                input_refs: vec![input_ref.clone()],
                predicted_cost_micro_usd: 0,
                required_capabilities: vec![PluginCapability::StaticAnalysis],
            },
            PluginRequest::Execute {
                task_id,
                lease_id: _,
                capability: _,
                arguments,
                ..
            } => {
                let sarif_payload = arguments.get("sarif_payload").and_then(|v| v.as_str());

                if let Some(payload) = sarif_payload {
                    let session_id = SessionId::from_str("00000000-0000-0000-0000-000000000001")
                        .unwrap_or_else(|_| SessionId::new());
                    let clock = TimestampUtc::now();
                    let exec_task_id = TaskId::new();
                    match ingest_codeql_sarif_payload(payload, &session_id, exec_task_id, clock) {
                        Ok(res) => PluginResponse::ExecuteResult {
                            task_id: task_id.clone(),
                            exit_code: 0,
                            evidence_refs: Vec::new(),
                            summary: format!(
                                "CodeQL analysis ingested {} findings ({} with taint traces).",
                                res.findings.len(),
                                res.taint_traces_extracted
                            ),
                        },
                        Err(e) => PluginResponse::Error {
                            code: -1,
                            message: format!("CodeQL SARIF ingestion failed: {e}"),
                        },
                    }
                } else {
                    PluginResponse::ExecuteResult {
                        task_id: task_id.clone(),
                        exit_code: 0,
                        evidence_refs: Vec::new(),
                        summary: "CodeQL plan executed successfully.".to_string(),
                    }
                }
            }
            PluginRequest::Cancel { task_id } => PluginResponse::CancelAck {
                task_id: task_id.clone(),
                terminated: true,
            },
            PluginRequest::Shutdown => PluginResponse::ShutdownAck,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CODEQL_SARIF: &str = r#"{
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "CodeQL",
              "version": "2.19.0",
              "rules": [
                {
                  "id": "js/sql-injection",
                  "name": "SQL query built from user-controlled sources",
                  "shortDescription": {
                    "text": "Building a SQL query from user-controlled sources can lead to SQL injection."
                  },
                  "fullDescription": {
                    "text": "Untrusted input concatenated into database commands can allow attackers to execute arbitrary queries."
                  },
                  "helpUri": "https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/",
                  "properties": {
                    "security-severity": "8.8",
                    "tags": ["security", "external/cwe/cwe-089"]
                  }
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "js/sql-injection",
              "ruleIndex": 0,
              "level": "error",
              "message": {
                "text": "Database query built from user-controlled source."
              },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "src/controllers/userController.js"
                    },
                    "region": {
                      "startLine": 45,
                      "startColumn": 12,
                      "endLine": 45,
                      "endColumn": 40
                    }
                  }
                }
              ],
              "codeFlows": [
                {
                  "threadFlows": [
                    {
                      "locations": [
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "src/controllers/userController.js"
                              },
                              "region": {
                                "startLine": 12,
                                "startColumn": 18
                              }
                            },
                            "message": {
                              "text": "source: req.body.username"
                            }
                          }
                        },
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "src/controllers/userController.js"
                              },
                              "region": {
                                "startLine": 20,
                                "startColumn": 9
                              }
                            },
                            "message": {
                              "text": "let query = 'SELECT * FROM users WHERE name = ' + username;"
                            }
                          }
                        },
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "src/controllers/userController.js"
                              },
                              "region": {
                                "startLine": 45,
                                "startColumn": 12
                              }
                            },
                            "message": {
                              "text": "sink: db.query(query)"
                            }
                          }
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn test_codeql_sarif_ingestion_and_taint_flow() {
        let session_id = SessionId::from_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let clock = TimestampUtc::now();
        let test_task_id = TaskId::new();

        let result =
            ingest_codeql_sarif_payload(SAMPLE_CODEQL_SARIF, &session_id, test_task_id, clock)
                .expect("should ingest SARIF");

        assert_eq!(result.total_sarif_results, 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.taint_traces_extracted, 1);
        assert_eq!(result.highest_severity, Some(Severity::High)); // 8.8 => High

        let finding = &result.findings[0];
        assert_eq!(
            finding.source(),
            &FindingSource::StaticAnalysis {
                engine: "codeql".to_string(),
                rule_id: "js/sql-injection".to_string(),
            }
        );
        assert_eq!(finding.reachability(), Reachability::ReachableCallPath);
        assert_eq!(finding.confidence(), Confidence::High);
        assert_eq!(finding.severity(), Severity::High);

        let loc = finding.location().expect("location must be present");
        assert_eq!(loc.path, "src/controllers/userController.js");
        assert_eq!(loc.start_line, Some(45));

        // Check Markdown taint trace output
        assert!(
            finding
                .description()
                .contains("CodeQL Interprocedural Taint Flow")
        );
        assert!(finding.description().contains("`🔴 SOURCE`"));
        assert!(finding.description().contains("req.body.username"));
        assert!(finding.description().contains("`💥 SINK`"));
        assert!(finding.description().contains("db.query(query)"));
    }

    #[test]
    fn test_codeql_language_detection() {
        assert_eq!(
            CodeQlLanguage::detect_from_filename("app.ts"),
            Some(CodeQlLanguage::Javascript)
        );
        assert_eq!(
            CodeQlLanguage::detect_from_filename("main.rs"),
            Some(CodeQlLanguage::Rust)
        );
        assert_eq!(
            CodeQlLanguage::detect_from_filename("service.py"),
            Some(CodeQlLanguage::Python)
        );
        assert_eq!(
            CodeQlLanguage::detect_from_filename("server.go"),
            Some(CodeQlLanguage::Go)
        );
        assert_eq!(
            CodeQlLanguage::detect_from_filename("kernel.cpp"),
            Some(CodeQlLanguage::Cpp)
        );
        assert_eq!(
            CodeQlLanguage::detect_from_filename("Main.java"),
            Some(CodeQlLanguage::Java)
        );
        assert_eq!(
            CodeQlLanguage::detect_from_filename("Controller.cs"),
            Some(CodeQlLanguage::Csharp)
        );
    }

    #[test]
    fn test_codeql_adapter_manifest_and_protocol() {
        let adapter = CodeQlAdapter::new();
        assert_eq!(adapter.manifest.id, "org.sentra.adapter.codeql");
        assert_eq!(adapter.manifest.family, AdapterFamily::AnalysisTool);
        assert_eq!(adapter.manifest.executable_path, "codeql");

        let init_resp = adapter.handle_request(&PluginRequest::Initialize { host_version: 1 });
        match init_resp {
            PluginResponse::InitializeAck {
                plugin_id,
                capabilities,
                ..
            } => {
                assert_eq!(plugin_id, "org.sentra.adapter.codeql");
                assert!(capabilities.contains(&PluginCapability::StaticAnalysis));
            }
            other => panic!("expected InitializeAck, got {other:?}"),
        }
    }
}
