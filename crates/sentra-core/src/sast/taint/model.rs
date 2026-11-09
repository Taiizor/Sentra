//! Data models for intra-procedural taint analysis and data-flow tracking (REQ-F05, REQ-F07).

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::domain::finding::Severity;

/// Classification of external/untrusted data sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintSourceKind {
    /// HTTP request body, query parameters, path variables, or headers.
    HttpParameter,
    /// Command line arguments (`sys.argv`, `process.argv`, `env::args`) or environment variables.
    EnvironmentOrCli,
    /// Unvalidated filesystem reads or stream data.
    FileOrStream,
    /// Untrusted deserialization payloads (JSON, YAML, pickle).
    Deserialization,
}

impl fmt::Display for TaintSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpParameter => write!(f, "HTTP_PARAMETER"),
            Self::EnvironmentOrCli => write!(f, "ENV_OR_CLI"),
            Self::FileOrStream => write!(f, "FILE_OR_STREAM"),
            Self::Deserialization => write!(f, "DESERIALIZATION"),
        }
    }
}

/// Sensitive execution points (sinks) where unvalidated tainted data triggers vulnerabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintSinkKind {
    /// Database query execution (`db.query`, `execute`, `sqlx::query`).
    SqlQuery,
    /// Operating system shell or process execution (`exec`, `system`, `Command::new`).
    ShellCommand,
    /// Dynamic code evaluation (`eval`, `Function`).
    DynamicCode,
    /// Filesystem access path (`readFile`, `open`, `File::open`).
    FilePath,
    /// Outbound network request (`fetch`, `requests.get`, `http.get`).
    NetworkRequest,
}

impl fmt::Display for TaintSinkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqlQuery => write!(f, "SQL_QUERY"),
            Self::ShellCommand => write!(f, "SHELL_COMMAND"),
            Self::DynamicCode => write!(f, "DYNAMIC_CODE"),
            Self::FilePath => write!(f, "FILE_PATH"),
            Self::NetworkRequest => write!(f, "NETWORK_REQUEST"),
        }
    }
}

/// Role of an individual step along a taint propagation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintStepRole {
    /// The untrusted origin where taint entered the program.
    Source,
    /// An intermediate variable assignment or string propagation.
    Propagation,
    /// A validating, sanitizing, or casting guard that neutralizes taint.
    Sanitizer,
    /// The vulnerable operation where tainted data executes unsafely.
    Sink,
}

impl fmt::Display for TaintStepRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => write!(f, "SOURCE"),
            Self::Propagation => write!(f, "PROPAGATE"),
            Self::Sanitizer => write!(f, "SANITIZER"),
            Self::Sink => write!(f, "SINK"),
        }
    }
}

/// A single step in an in-engine taint flow trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlowStep {
    /// 1-based sequential step order.
    pub step_index: usize,
    /// Semantic role in data flow.
    pub role: TaintStepRole,
    /// Line number in target source file.
    pub line_number: usize,
    /// Identifier of the variable involved.
    pub variable_name: String,
    /// Code expression snippet.
    pub expression: String,
    /// Human-readable explanation.
    pub description: String,
}

/// A verified taint vulnerability detected through end-to-end data flow tracking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintVulnerability {
    /// Rule identifier (e.g. `SENTRA-TAINT-001`).
    pub rule_id: &'static str,
    /// Rule name.
    pub rule_name: &'static str,
    /// Associated Common Weakness Enumeration ID.
    pub cwe_id: &'static str,
    /// Type of vulnerable sink.
    pub sink_kind: TaintSinkKind,
    /// Assessed severity level.
    pub severity: Severity,
    /// Workspace-relative file path.
    pub file_path: String,
    /// Line number of the vulnerable sink.
    pub sink_line: usize,
    /// Code expression at the vulnerable sink.
    pub sink_expression: String,
    /// Complete step-by-step data flow path from source to sink.
    pub flow_steps: Vec<TaintFlowStep>,
}

impl TaintVulnerability {
    /// Formats the taint path into a Markdown table with visual role badges.
    pub fn to_markdown_trace(&self) -> String {
        if self.flow_steps.is_empty() {
            return String::new();
        }

        let mut out =
            String::from("\n#### In-Engine Taint Data-Flow Path (Pure-Rust Semantic Trace)\n\n");
        out.push_str("| Step | Role | Line | Variable | Code Context | Explanation |\n");
        out.push_str("| :---: | :--- | :---: | :--- | :--- | :--- |\n");

        for step in &self.flow_steps {
            let badge = match step.role {
                TaintStepRole::Source => "`🔴 SOURCE`",
                TaintStepRole::Propagation => "`🟡 PROPAGATE`",
                TaintStepRole::Sanitizer => "`🟢 SANITIZER`",
                TaintStepRole::Sink => "`💥 SINK`",
            };

            out.push_str(&format!(
                "| {} | {} | `{}` | `{}` | `{}` | {} |\n",
                step.step_index,
                badge,
                step.line_number,
                step.variable_name,
                step.expression.replace('`', "'"),
                step.description
            ));
        }

        out
    }
}
