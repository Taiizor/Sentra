//! Embedded AppSec Skill Catalog and Cognitive Playbooks (REQ-F17, ADR-0004, EXTENSIONS.md).
//!
//! Provides a compiled-in, zero-dependency repository of AppSec cognitive skills,
//! threat modeling templates, and reasoning frameworks. Skills are maintained as
//! individual `SKILL.md` documents under `crates/sentra-core/assets/skills/` and
//! compiled directly into the binary via `include_str!`.

use std::fmt;

/// Categorization of AppSec skills.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SkillCategory {
    /// REST, GraphQL, and gRPC API security testing (OWASP API Top 10).
    ApiSecurity,
    /// Repository-grounded threat modeling and STRIDE analysis.
    ThreatModeling,
    /// Authentication, JWT, OAuth2, and session hygiene.
    Authentication,
    /// CI/CD workflow pipeline hardening and supply chain risk.
    CiCdSecurity,
    /// Web framework specific security (Django, Laravel, Spring Boot, Go).
    Framework,
    /// AI agent, tool, and instruction safety audits.
    AgentSafety,
    /// ADR-0004 three-tier vulnerability reproduction and patch synthesis.
    Remediation,
    /// Comprehensive whitebox code review and attack surface analysis.
    CodeReview,
}

impl SkillCategory {
    /// Returns the canonical kebab-case name of the category.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ApiSecurity => "api-security",
            Self::ThreatModeling => "threat-modeling",
            Self::Authentication => "authentication",
            Self::CiCdSecurity => "ci-cd-security",
            Self::Framework => "framework-security",
            Self::AgentSafety => "agent-safety",
            Self::Remediation => "remediation",
            Self::CodeReview => "code-review",
        }
    }
}

impl fmt::Display for SkillCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Metadata and cognitive playbook specification for an AppSec skill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillDefinition {
    /// Unique kebab-case identifier (e.g. `api-security-testing`).
    pub id: &'static str,
    /// Human-readable title.
    pub name: &'static str,
    /// Summary description of the skill and its trigger conditions.
    pub description: &'static str,
    /// Skill category.
    pub category: SkillCategory,
    /// Complete Markdown specification (`SKILL.md`) compiled into the binary.
    pub content: &'static str,
    /// Search and indexing tags.
    pub tags: &'static [&'static str],
}

/// All built-in skills compiled directly into the binary via `include_str!`.
pub static BUILTIN_SKILLS: &[SkillDefinition] = &[
    SkillDefinition {
        id: "api-security-testing",
        name: "API Security Testing",
        description: "Security-test REST, GraphQL, or gRPC APIs for OWASP API Security Top 10 flaws — BOLA/IDOR, Mass Assignment, BFLA, and unbounded resource consumption.",
        category: SkillCategory::ApiSecurity,
        tags: &[
            "api",
            "owasp",
            "bola",
            "idor",
            "rest",
            "graphql",
            "grpc",
            "mass-assignment",
        ],
        content: include_str!("../../assets/skills/api-security-testing/SKILL.md"),
    },
    SkillDefinition {
        id: "application-security-testing",
        name: "Application Security Testing",
        description: "Comprehensive AppSec assessment across source code, web apps, APIs, and CI pipelines with ranked remediation plans.",
        category: SkillCategory::CodeReview,
        tags: &[
            "appsec",
            "assessment",
            "audit",
            "pentest",
            "vulnerability-scan",
        ],
        content: include_str!("../../assets/skills/application-security-testing/SKILL.md"),
    },
    SkillDefinition {
        id: "attack-tree-construction",
        name: "Attack Tree Construction",
        description: "Build comprehensive attack trees to visualize threat paths, identify defense gaps, and quantify risk likelihood.",
        category: SkillCategory::ThreatModeling,
        tags: &[
            "attack-tree",
            "threat-modeling",
            "defense-gaps",
            "risk-paths",
        ],
        content: include_str!("../../assets/skills/attack-tree-construction/SKILL.md"),
    },
    SkillDefinition {
        id: "auth-implementation-patterns",
        name: "Auth Implementation Patterns",
        description: "Master authentication and authorization patterns including JWT, OAuth2, session management, PKCE, timing attacks, and RBAC.",
        category: SkillCategory::Authentication,
        tags: &[
            "auth",
            "jwt",
            "oauth2",
            "session",
            "rbac",
            "pkce",
            "timing-attacks",
        ],
        content: include_str!("../../assets/skills/auth-implementation-patterns/SKILL.md"),
    },
    SkillDefinition {
        id: "ci-cd-security",
        name: "CI/CD Pipeline Security",
        description: "Audit GitHub Actions workflow files for security vulnerabilities — pull_request_target, script template injection, write-all permissions, and secret exfiltration.",
        category: SkillCategory::CiCdSecurity,
        tags: &[
            "ci-cd",
            "github-actions",
            "supply-chain",
            "pull-request-target",
            "injection",
        ],
        content: include_str!("../../assets/skills/ci-cd-security/SKILL.md"),
    },
    SkillDefinition {
        id: "ci-security-scanning-with-strix",
        name: "CI Security Scanning with Strix",
        description: "Add automated diff-scoped AI security scanning and PR blocking gates to CI/CD pipelines.",
        category: SkillCategory::CiCdSecurity,
        tags: &["ci-cd", "strix", "sast", "dast", "pr-scan", "sarif"],
        content: include_str!("../../assets/skills/ci-security-scanning-with-strix/SKILL.md"),
    },
    SkillDefinition {
        id: "golang-security",
        name: "Golang Security Best Practices",
        description: "Security best practices and vulnerability prevention for Golang — ZipSlip, broken ciphers, SSH host keys, exec shell wrappers, and os.Root path traversal protection.",
        category: SkillCategory::Framework,
        tags: &[
            "go",
            "golang",
            "zipslip",
            "crypto",
            "exec",
            "path-traversal",
        ],
        content: include_str!("../../assets/skills/golang-security/SKILL.md"),
    },
    SkillDefinition {
        id: "django-security",
        name: "Django Security Patterns",
        description: "Django security best practices, raw SQL injection prevention, template XSS safe filter bypasses, CSRF protection, and settings configuration.",
        category: SkillCategory::Framework,
        tags: &[
            "django",
            "python",
            "sql-injection",
            "csrf",
            "xss",
            "settings",
        ],
        content: include_str!("../../assets/skills/django-security/SKILL.md"),
    },
    SkillDefinition {
        id: "laravel-security",
        name: "Laravel Security Patterns",
        description: "Laravel security best practices — raw query injection, Blade unescaped XSS, mass assignment unguarding, and debug mode.",
        category: SkillCategory::Framework,
        tags: &[
            "laravel",
            "php",
            "eloquent",
            "blade",
            "mass-assignment",
            "debug-mode",
        ],
        content: include_str!("../../assets/skills/laravel-security/SKILL.md"),
    },
    SkillDefinition {
        id: "springboot-security",
        name: "Spring Boot Security Patterns",
        description: "Spring Boot security best practices — SpEL injection prevention, CSRF disablement pitfalls, Actuator exposure, and CORS wildcards.",
        category: SkillCategory::Framework,
        tags: &["spring-boot", "java", "spel", "actuator", "csrf", "cors"],
        content: include_str!("../../assets/skills/springboot-security/SKILL.md"),
    },
    SkillDefinition {
        id: "skill-security",
        name: "AI Agent Skill Security Audit",
        description: "Audit an AI agent skill for security risks before installing or trusting it — prompt injection, credential harvesting, and description-vs-behavior mismatch.",
        category: SkillCategory::AgentSafety,
        tags: &[
            "agent-security",
            "prompt-injection",
            "credential-theft",
            "supply-chain",
            "ast",
        ],
        content: include_str!("../../assets/skills/skill-security/SKILL.md"),
    },
    SkillDefinition {
        id: "solidity-security",
        name: "Solidity Smart Contract Security",
        description: "Solidity security patterns — tx.origin phishing bypass, low-level call value reentrancy, checks-effects-interactions, and integer overflow.",
        category: SkillCategory::Framework,
        tags: &[
            "solidity",
            "smart-contracts",
            "reentrancy",
            "ethereum",
            "web3",
        ],
        content: include_str!("../../assets/skills/solidity-security/SKILL.md"),
    },
    SkillDefinition {
        id: "google-cloud-waf-security",
        name: "Google Cloud Workload Security",
        description: "Security guidance for Cloud workloads — blocking link-local metadata endpoints (169.254.169.254), enforcing IMDSv2, and IAM isolation.",
        category: SkillCategory::Framework,
        tags: &["cloud", "gcp", "waf", "metadata-endpoint", "ssrf", "iam"],
        content: include_str!("../../assets/skills/google-cloud-waf-security/SKILL.md"),
    },
    SkillDefinition {
        id: "stride-analysis-patterns",
        name: "STRIDE Threat Analysis Patterns",
        description: "Systematic STRIDE methodology application to evaluate system security, calculate defense-in-depth scores, and map controls.",
        category: SkillCategory::ThreatModeling,
        tags: &[
            "stride",
            "threat-modeling",
            "spoofing",
            "tampering",
            "elevation-of-privilege",
        ],
        content: include_str!("../../assets/skills/stride-analysis-patterns/SKILL.md"),
    },
    SkillDefinition {
        id: "security-threat-model",
        name: "Repository Threat Modeling",
        description: "Repository-grounded threat modeling that enumerates trust boundaries, assets, attacker capabilities, abuse paths, and produces a Mermaid flowchart.",
        category: SkillCategory::ThreatModeling,
        tags: &["threat-model", "trust-boundaries", "data-flow", "mermaid"],
        content: include_str!("../../assets/skills/security-threat-model/SKILL.md"),
    },
    SkillDefinition {
        id: "threat-mitigation-mapping",
        name: "Threat Mitigation Mapping",
        description: "Map identified threats to appropriate security controls, defense-in-depth layers, and validation mechanisms.",
        category: SkillCategory::ThreatModeling,
        tags: &["mitigation", "controls", "defense-in-depth", "validation"],
        content: include_str!("../../assets/skills/threat-mitigation-mapping/SKILL.md"),
    },
    SkillDefinition {
        id: "owasp-top-10-testing",
        name: "OWASP Top 10 Security Testing",
        description: "Systematic testing against the OWASP Top 10 categories including SSRF, misconfiguration, and cryptographic failures.",
        category: SkillCategory::CodeReview,
        tags: &[
            "owasp",
            "web-security",
            "ssrf",
            "injection",
            "crypto-failure",
        ],
        content: include_str!("../../assets/skills/owasp-top-10-testing/SKILL.md"),
    },
    SkillDefinition {
        id: "security-and-hardening",
        name: "Security and Hardening",
        description: "Hardening practices for input handling, authentication, sensitive data storage, and external integrations.",
        category: SkillCategory::CodeReview,
        tags: &[
            "hardening",
            "input-validation",
            "secure-storage",
            "sanitization",
        ],
        content: include_str!("../../assets/skills/security-and-hardening/SKILL.md"),
    },
    SkillDefinition {
        id: "security-audit",
        name: "Security Audit and Codebase Review",
        description: "Comprehensive vulnerability review workflow for codebases, APIs, CLI tools, and background daemons.",
        category: SkillCategory::CodeReview,
        tags: &[
            "audit",
            "code-review",
            "penetration-testing",
            "vulnerability",
        ],
        content: include_str!("../../assets/skills/security-audit/SKILL.md"),
    },
    SkillDefinition {
        id: "security-best-practices",
        name: "Language Security Best Practices",
        description: "Language and framework specific secure-by-default coding patterns across Python, TypeScript, and Go.",
        category: SkillCategory::CodeReview,
        tags: &[
            "best-practices",
            "secure-coding",
            "python",
            "typescript",
            "go",
        ],
        content: include_str!("../../assets/skills/security-best-practices/SKILL.md"),
    },
    SkillDefinition {
        id: "security-review",
        name: "Security Review Checklist",
        description: "Checklist and patterns for adding auth, user input processing, secrets management, and payment integrations.",
        category: SkillCategory::CodeReview,
        tags: &["checklist", "secrets", "user-input", "review"],
        content: include_str!("../../assets/skills/security-review/SKILL.md"),
    },
    SkillDefinition {
        id: "security-scan",
        name: "Agent Configuration Security Scan",
        description: "Audit agent configurations, MCP servers, hooks, and prompt settings for injection risks.",
        category: SkillCategory::AgentSafety,
        tags: &[
            "agent-scan",
            "mcp-audit",
            "configuration-hygiene",
            "injection",
        ],
        content: include_str!("../../assets/skills/security-scan/SKILL.md"),
    },
    SkillDefinition {
        id: "fix-security-vulnerabilities-with-strix",
        name: "Three-Tier Patch Remediation",
        description: "Three-tier vulnerability patch remediation contract — reproduction test oracle, minimal safe diff, and analytical invariant proof.",
        category: SkillCategory::Remediation,
        tags: &[
            "patch",
            "remediation",
            "adr-0004",
            "test-oracle",
            "diff",
            "invariant-proof",
        ],
        content: include_str!(
            "../../assets/skills/fix-security-vulnerabilities-with-strix/SKILL.md"
        ),
    },
    SkillDefinition {
        id: "find-security-vulnerabilities-in-code",
        name: "Whitebox Code Security Review",
        description: "White-box AI security review that traces source-to-sink data flow, checks authorization models, and eliminates static analysis false positives.",
        category: SkillCategory::CodeReview,
        tags: &[
            "whitebox",
            "dataflow",
            "taint",
            "idor",
            "injection",
            "authorization",
        ],
        content: include_str!("../../assets/skills/find-security-vulnerabilities-in-code/SKILL.md"),
    },
];

/// Returns all built-in skills.
pub fn list_builtin_skills() -> &'static [SkillDefinition] {
    BUILTIN_SKILLS
}

/// Finds a built-in skill by unique ID or alias.
pub fn find_skill_by_id(id: &str) -> Option<&'static SkillDefinition> {
    let needle = id.trim().to_ascii_lowercase();
    BUILTIN_SKILLS.iter().find(|s| s.id == needle)
}

/// Searches built-in skills by keyword match against ID, name, description, and tags.
pub fn search_skills(query: &str) -> Vec<&'static SkillDefinition> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return BUILTIN_SKILLS.iter().collect();
    }
    BUILTIN_SKILLS
        .iter()
        .filter(|s| {
            s.id.contains(&q)
                || s.name.to_ascii_lowercase().contains(&q)
                || s.description.to_ascii_lowercase().contains(&q)
                || s.category.as_str().contains(&q)
                || s.tags.iter().any(|t| t.contains(&q))
        })
        .collect()
}
