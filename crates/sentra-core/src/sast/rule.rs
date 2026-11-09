//! SAST and Secret Scanning Rule Definitions (REQ-F05, REQ-F07, EXTENSIONS.md).

use serde::{Deserialize, Serialize};

use crate::domain::finding::Severity;

/// Classification category of a static security check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleCategory {
    /// Secrets, credentials, private keys, or API tokens.
    Secret,
    /// SQL injection antipatterns.
    SqlInjection,
    /// OS command injection antipatterns.
    CommandInjection,
    /// Arbitrary dynamic code evaluation (eval / Function).
    DangerousEval,
    /// Unsound or unverified Rust unsafe blocks.
    UnsoundUnsafe,
    /// Path traversal or unvalidated filesystem access.
    PathTraversal,
}

impl RuleCategory {
    /// Human-readable category label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Secret => "SECRET_LEAK",
            Self::SqlInjection => "SQL_INJECTION",
            Self::CommandInjection => "COMMAND_INJECTION",
            Self::DangerousEval => "DANGEROUS_EVAL",
            Self::UnsoundUnsafe => "UNSOUND_UNSAFE",
            Self::PathTraversal => "PATH_TRAVERSAL",
        }
    }
}

/// Static analysis rule descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SastRule {
    /// Stable rule identifier (e.g. `SENTRA-SEC-001`).
    pub id: &'static str,
    /// Concise rule name.
    pub name: &'static str,
    /// Security rule category.
    pub category: RuleCategory,
    /// Default assessed severity.
    pub severity: Severity,
    /// Associated Common Weakness Enumeration (CWE) identifier.
    pub cwe_id: &'static str,
    /// Full description of the risk.
    pub description: &'static str,
    /// Recommended remediation guidance.
    pub recommendation: &'static str,
}

/// Rule registry for built-in SAST and secret scanning checks.
pub static BUILTIN_RULES: &[SastRule] = &[
    SastRule {
        id: "SENTRA-SEC-001",
        name: "AwsAccessKeyId",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-798",
        description: "Hardcoded AWS Access Key ID detected. Embedding cloud credentials in source code enables unauthorized infrastructure compromise.",
        recommendation: "Rotate the leaked key immediately in AWS IAM and load credentials from environment variables, AWS Secrets Manager, or IAM instance profiles.",
    },
    SastRule {
        id: "SENTRA-SEC-002",
        name: "GitHubAccessToken",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-798",
        description: "Hardcoded GitHub Personal Access Token or OAuth token detected. Leaked tokens grant unauthorized access to repositories, organizations, or CI workflows.",
        recommendation: "Revoke the exposed token on GitHub immediately and inject repository access tokens via GitHub Actions secrets or secret managers.",
    },
    SastRule {
        id: "SENTRA-SEC-003",
        name: "PrivateKeyHeader",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-312",
        description: "Unencrypted cryptographic private key block found in source tree. Storing private keys in plaintext compromises cryptographic identity and confidentiality.",
        recommendation: "Remove the private key from source control, revoke the affected key pair, and load keys from secured secret vaults or HSMs.",
    },
    SastRule {
        id: "SENTRA-SEC-004",
        name: "SlackApiToken",
        category: RuleCategory::Secret,
        severity: Severity::High,
        cwe_id: "CWE-798",
        description: "Hardcoded Slack bot or user token detected. Leaked tokens enable unauthorized messaging, workspace data exfiltration, or channel surveillance.",
        recommendation: "Revoke the Slack token via the Slack API portal and pass it through environment variables.",
    },
    SastRule {
        id: "SENTRA-SEC-005",
        name: "HardcodedGenericSecret",
        category: RuleCategory::Secret,
        severity: Severity::High,
        cwe_id: "CWE-798",
        description: "Variable assignment with high-entropy literal secret or API key detected. Hardcoded secrets in code files risk exposure across forks, logs, and artifacts.",
        recommendation: "Extract credentials to `.env` (ignored by git) or dedicated configuration stores.",
    },
    SastRule {
        id: "SENTRA-SAST-001",
        name: "SqlInjectionStringInterpolation",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "SQL query constructed via string formatting, template literals, or string concatenation. Direct string interpolation in SQL statements allows attackers to alter query logic.",
        recommendation: "Use parameterized queries or prepared statements (`$1`, `?`, or ORM query builders) instead of dynamic string concatenation.",
    },
    SastRule {
        id: "SENTRA-SAST-002",
        name: "OsCommandInjection",
        category: RuleCategory::CommandInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-78",
        description: "Shell command execution with interpolated dynamic arguments. Shell wrappers (`sh -c`, `cmd /c`, `exec`) parse metacharacters, allowing arbitrary OS command injection.",
        recommendation: "Pass arguments as discrete elements to `Command::arg(...)` or `execFile` without invoking an intermediate system shell.",
    },
    SastRule {
        id: "SENTRA-SAST-003",
        name: "DangerousEvalExecution",
        category: RuleCategory::DangerousEval,
        severity: Severity::High,
        cwe_id: "CWE-95",
        description: "Dynamic code execution via `eval()`, `new Function()`, or `exec()` detected. Dynamic evaluation permits untrusted strings to execute arbitrary code with full application privileges.",
        recommendation: "Replace dynamic evaluation with static lookup tables, JSON parsers, or safe domain-specific expression interpreters.",
    },
    SastRule {
        id: "SENTRA-SAST-004",
        name: "NakedRustUnsafeBlock",
        category: RuleCategory::UnsoundUnsafe,
        severity: Severity::Medium,
        cwe_id: "CWE-119",
        description: "Rust `unsafe` block without an explicit `// SAFETY:` rationale comment. Per Rust memory-safety guidelines, every unsafe block must document the invariants upheld.",
        recommendation: "Add a comment immediately preceding or inside the block documenting why the unsafe operation is sound (e.g. `// SAFETY: Pointer is non-null and correctly aligned`).",
    },
    SastRule {
        id: "SENTRA-SAST-005",
        name: "InsecurePathTraversal",
        category: RuleCategory::PathTraversal,
        severity: Severity::High,
        cwe_id: "CWE-22",
        description: "Filesystem path constructed directly from unvalidated request parameters. Attackers can supply `..` components to read or overwrite arbitrary host files.",
        recommendation: "Validate and canonicalize all user-supplied paths against a strict root boundary before performing filesystem operations.",
    },
    SastRule {
        id: "SENTRA-TAINT-001",
        name: "SqlInjectionViaTaintFlow",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "Unsanitized user-controlled input traced from source to database execution sink through data-flow tracking.",
        recommendation: "Use parameterized queries or prepared statements ($1, ?, or ORM methods) and validate/cast inputs before execution.",
    },
    SastRule {
        id: "SENTRA-TAINT-002",
        name: "CommandInjectionViaTaintFlow",
        category: RuleCategory::CommandInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-78",
        description: "Unsanitized user or external input traced to OS process/shell execution sink.",
        recommendation: "Avoid shell invocation; pass arguments as discrete array elements directly to the binary executor.",
    },
    SastRule {
        id: "SENTRA-TAINT-003",
        name: "DynamicCodeEvalViaTaintFlow",
        category: RuleCategory::DangerousEval,
        severity: Severity::Critical,
        cwe_id: "CWE-95",
        description: "Untrusted external data flow reached dynamic code evaluation (eval / Function).",
        recommendation: "Eliminate dynamic code execution in favor of static parser or serialization routines.",
    },
    SastRule {
        id: "SENTRA-TAINT-004",
        name: "PathTraversalViaTaintFlow",
        category: RuleCategory::PathTraversal,
        severity: Severity::High,
        cwe_id: "CWE-22",
        description: "Unsanitized user input traced from source to filesystem path read/write operation.",
        recommendation: "Canonicalize and validate paths against an explicit allowlisted base directory before filesystem access.",
    },
];

/// Finds a rule by its stable ID.
pub fn find_rule_by_id(id: &str) -> Option<&'static SastRule> {
    BUILTIN_RULES.iter().find(|r| r.id == id)
}
