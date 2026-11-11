//! Embedded agent skill catalog (REQ-F17, EXTENSIONS.md).
//!
//! The bundled skills are third-party Agent Skills playbooks vendored from the
//! upstream repositories recorded in `crates/sentra-core/assets/skills-lock.json`
//! (see `NOTICE` for sources, pinned commits, and licenses). They are guidance
//! for AI coding agents, not Sentra contracts, and several of them drive
//! third-party tools such as Strix or AgentShield.
//!
//! `build.rs` embeds every file of every `assets/skills/<id>/` directory
//! (`SKILL.md` plus `references/`, `scripts/`, `rules/`, license files, and so
//! on) with `include_bytes!`, normalizing CRLF to LF in text files. Each
//! skill's `description` is read from its `SKILL.md` frontmatter at build
//! time, so the catalog and the shipped playbook cannot disagree. The catalog
//! only adds Sentra-side metadata: a display title, a category, and tags.

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
    /// Language, framework, and platform specific security guidance.
    Framework,
    /// AI agent, tool, and instruction safety audits.
    AgentSafety,
    /// Fixing reported vulnerabilities and re-testing the fix.
    Remediation,
    /// Whitebox code review and attack surface analysis.
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

/// Metadata and playbook of a built-in skill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillDefinition {
    /// Unique kebab-case identifier (e.g. `api-security-testing`); equals the
    /// skill directory name and the `name` field of its `SKILL.md`.
    pub id: &'static str,
    /// Human-readable title.
    pub name: &'static str,
    /// The `description` from the `SKILL.md` frontmatter (what the skill does
    /// and when an agent should use it).
    pub description: &'static str,
    /// Skill category.
    pub category: SkillCategory,
    /// Complete `SKILL.md` (frontmatter included, LF line endings).
    pub content: &'static str,
    /// Search and indexing tags.
    pub tags: &'static [&'static str],
}

impl SkillDefinition {
    /// Every file of the skill directory as `(relative path, bytes)` pairs.
    ///
    /// Paths use `/` separators and are relative to the skill directory
    /// (`SKILL.md`, `references/checklist.md`, `LICENSE`, ...). Text files have
    /// LF line endings. Installers must write all of them under `<dest>/<id>/`
    /// so the links inside `SKILL.md` resolve.
    pub fn files(&self) -> &'static [(&'static str, &'static [u8])] {
        embedded_skill(self.id).map_or(&[], |skill| skill.files)
    }
}

/// One skill directory embedded by `build.rs`.
struct EmbeddedSkill {
    id: &'static str,
    description: &'static str,
    skill_md: &'static str,
    files: &'static [(&'static str, &'static [u8])],
}

mod embedded {
    use super::EmbeddedSkill;

    include!(concat!(env!("OUT_DIR"), "/embedded_skills.rs"));
}

use embedded::EMBEDDED_SKILLS;

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Compile-time lookup used by the catalog table below; an id without an
/// `assets/skills/<id>/` directory is a build error.
const fn embedded(id: &str) -> &'static EmbeddedSkill {
    let mut i = 0;
    while i < EMBEDDED_SKILLS.len() {
        if str_eq(EMBEDDED_SKILLS[i].id, id) {
            return &EMBEDDED_SKILLS[i];
        }
        i += 1;
    }
    panic!("BUILTIN_SKILLS references a skill id that has no assets/skills/<id>/ directory");
}

fn embedded_skill(id: &str) -> Option<&'static EmbeddedSkill> {
    let needle = id.trim().to_ascii_lowercase();
    EMBEDDED_SKILLS.iter().find(|skill| skill.id == needle)
}

macro_rules! builtin_skill {
    (
        id: $id:literal,
        name: $name:literal,
        category: $category:expr,
        tags: [$($tag:literal),* $(,)?] $(,)?
    ) => {
        SkillDefinition {
            id: $id,
            name: $name,
            description: embedded($id).description,
            category: $category,
            content: embedded($id).skill_md,
            tags: &[$($tag),*],
        }
    };
}

/// All built-in skills, compiled into the binary by `build.rs`.
pub static BUILTIN_SKILLS: &[SkillDefinition] = &[
    builtin_skill! {
        id: "api-security-testing",
        name: "API Security Testing",
        category: SkillCategory::ApiSecurity,
        tags: ["api", "owasp", "bola", "idor", "rest", "graphql", "grpc", "mass-assignment", "strix"],
    },
    builtin_skill! {
        id: "application-security-testing",
        name: "Application Security Testing",
        category: SkillCategory::CodeReview,
        tags: ["appsec", "assessment", "audit", "pentest", "vulnerability-scan", "strix"],
    },
    builtin_skill! {
        id: "attack-tree-construction",
        name: "Attack Tree Construction",
        category: SkillCategory::ThreatModeling,
        tags: ["attack-tree", "threat-modeling", "defense-gaps", "risk-paths"],
    },
    builtin_skill! {
        id: "auth-implementation-patterns",
        name: "Auth Implementation Patterns",
        category: SkillCategory::Authentication,
        tags: ["auth", "jwt", "oauth2", "session", "rbac", "pkce", "timing-attacks"],
    },
    builtin_skill! {
        id: "ci-cd-security",
        name: "CI/CD Pipeline Security",
        category: SkillCategory::CiCdSecurity,
        tags: ["ci-cd", "github-actions", "supply-chain", "pull-request-target", "injection"],
    },
    builtin_skill! {
        id: "ci-security-scanning-with-strix",
        name: "CI Security Scanning with Strix",
        category: SkillCategory::CiCdSecurity,
        tags: ["ci-cd", "strix", "sast", "dast", "pr-scan", "sarif"],
    },
    builtin_skill! {
        id: "golang-security",
        name: "Golang Security Best Practices",
        category: SkillCategory::Framework,
        tags: ["go", "golang", "zipslip", "crypto", "exec", "path-traversal"],
    },
    builtin_skill! {
        id: "django-security",
        name: "Django Security Patterns",
        category: SkillCategory::Framework,
        tags: ["django", "python", "sql-injection", "csrf", "xss", "settings"],
    },
    builtin_skill! {
        id: "laravel-security",
        name: "Laravel Security Patterns",
        category: SkillCategory::Framework,
        tags: ["laravel", "php", "eloquent", "blade", "mass-assignment", "debug-mode"],
    },
    builtin_skill! {
        id: "springboot-security",
        name: "Spring Boot Security Patterns",
        category: SkillCategory::Framework,
        tags: ["spring-boot", "java", "spel", "actuator", "csrf", "cors"],
    },
    builtin_skill! {
        id: "skill-security",
        name: "AI Agent Skill Security Audit",
        category: SkillCategory::AgentSafety,
        tags: ["agent-security", "prompt-injection", "credential-theft", "supply-chain", "ast", "yara"],
    },
    builtin_skill! {
        id: "solidity-security",
        name: "Solidity Smart Contract Security",
        category: SkillCategory::Framework,
        tags: ["solidity", "smart-contracts", "reentrancy", "ethereum", "web3"],
    },
    builtin_skill! {
        id: "google-cloud-waf-security",
        name: "Google Cloud Workload Security",
        category: SkillCategory::Framework,
        tags: ["cloud", "gcp", "well-architected", "iam", "network-security", "data-protection"],
    },
    builtin_skill! {
        id: "stride-analysis-patterns",
        name: "STRIDE Threat Analysis Patterns",
        category: SkillCategory::ThreatModeling,
        tags: ["stride", "threat-modeling", "spoofing", "tampering", "elevation-of-privilege"],
    },
    builtin_skill! {
        id: "security-threat-model",
        name: "Repository Threat Modeling",
        category: SkillCategory::ThreatModeling,
        tags: ["threat-model", "trust-boundaries", "data-flow", "mermaid"],
    },
    builtin_skill! {
        id: "threat-mitigation-mapping",
        name: "Threat Mitigation Mapping",
        category: SkillCategory::ThreatModeling,
        tags: ["mitigation", "controls", "defense-in-depth", "validation"],
    },
    builtin_skill! {
        id: "owasp-top-10-testing",
        name: "OWASP Top 10 Security Testing",
        category: SkillCategory::CodeReview,
        tags: ["owasp", "web-security", "ssrf", "injection", "crypto-failure", "strix"],
    },
    builtin_skill! {
        id: "security-and-hardening",
        name: "Security and Hardening",
        category: SkillCategory::CodeReview,
        tags: ["hardening", "input-validation", "secure-storage", "sanitization"],
    },
    builtin_skill! {
        id: "security-audit",
        name: "Security Audit and Codebase Review",
        category: SkillCategory::CodeReview,
        tags: ["audit", "code-review", "penetration-testing", "vulnerability"],
    },
    builtin_skill! {
        id: "security-best-practices",
        name: "Language Security Best Practices",
        category: SkillCategory::CodeReview,
        tags: ["best-practices", "secure-coding", "python", "typescript", "go"],
    },
    builtin_skill! {
        id: "security-review",
        name: "Security Review Checklist",
        category: SkillCategory::CodeReview,
        tags: ["checklist", "secrets", "user-input", "review"],
    },
    builtin_skill! {
        id: "security-scan",
        name: "Agent Configuration Security Scan",
        category: SkillCategory::AgentSafety,
        tags: ["agent-scan", "mcp-audit", "configuration-hygiene", "injection", "agentshield"],
    },
    builtin_skill! {
        id: "fix-security-vulnerabilities-with-strix",
        name: "Fix Vulnerabilities Found by Strix",
        category: SkillCategory::Remediation,
        tags: ["patch", "remediation", "root-cause", "retest", "strix"],
    },
    builtin_skill! {
        id: "find-security-vulnerabilities-in-code",
        name: "Whitebox Code Security Review with Strix",
        category: SkillCategory::CodeReview,
        tags: ["whitebox", "dataflow", "taint", "idor", "injection", "authorization", "strix"],
    },
];

/// Returns all built-in skills.
pub fn list_builtin_skills() -> &'static [SkillDefinition] {
    BUILTIN_SKILLS
}

/// Finds a built-in skill by its ID (case-insensitive, surrounding whitespace ignored).
pub fn find_skill_by_id(id: &str) -> Option<&'static SkillDefinition> {
    let needle = id.trim().to_ascii_lowercase();
    BUILTIN_SKILLS.iter().find(|s| s.id == needle)
}

/// Returns every embedded file of a built-in skill as `(relative path, bytes)`
/// pairs, or `None` for an unknown ID.
///
/// The ID is matched like [`find_skill_by_id`]. Paths are relative to the
/// skill directory, use `/` separators, never contain `..`, and are sorted by
/// their UTF-8 bytes; `SKILL.md` is always present. Text files have LF line
/// endings.
pub fn skill_files(id: &str) -> Option<&'static [(&'static str, &'static [u8])]> {
    embedded_skill(id).map(|skill| skill.files)
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

/// Computes the `computedHash` that `skills-lock.json` version 2 records for a
/// skill folder (vercel-labs/skills README, "Lock File Content Hash"):
///
/// 1. `files` are `(path, content)` pairs with `/`-separated paths relative to
///    the skill folder (callers leave out `metadata.json` files and `.git`,
///    `__pycache__`, `__pypackages__` folders);
/// 2. a text file (no NUL byte) has every CRLF replaced by LF;
/// 3. files are sorted by the UTF-8 bytes of their paths;
/// 4. each file feeds `path`, NUL, the decimal content length (after step 2),
///    NUL, and the content into one SHA-256;
/// 5. the result is the lowercase hex digest.
pub fn skill_folder_hash(files: &[(&str, &[u8])]) -> String {
    let mut entries: Vec<(&[u8], std::borrow::Cow<'_, [u8]>)> = files
        .iter()
        .map(|(path, content)| (path.as_bytes(), normalize_text_line_endings(content)))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut hasher = crate::common::crypto::Sha256Stream::new();
    for (path, content) in &entries {
        hasher.update(path);
        hasher.update(b"\0");
        hasher.update(content.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(content);
    }
    hasher.finalize_hex()
}

fn normalize_text_line_endings(content: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if content.contains(&0) || !content.windows(2).any(|w| w == b"\r\n") {
        return std::borrow::Cow::Borrowed(content);
    }
    let mut out = Vec::with_capacity(content.len());
    for (i, &byte) in content.iter().enumerate() {
        if byte == b'\r' && content.get(i + 1) == Some(&b'\n') {
            continue;
        }
        out.push(byte);
    }
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const ASSET_LOCK: &str = include_str!("../../assets/skills-lock.json");
    const NOTICE: &str = include_str!("../../../../NOTICE");
    const MIT_GRANT: &str =
        "Permission is hereby granted, free of charge, to any person obtaining a copy";
    const APACHE_HEADER: &str = "Apache License";
    const APACHE_VERSION: &str = "Version 2.0, January 2004";

    fn lock() -> serde_json::Value {
        serde_json::from_str(ASSET_LOCK).expect("assets/skills-lock.json is valid JSON")
    }

    fn file<'a>(files: &'a [(&str, &'static [u8])], path: &str) -> Option<&'a [u8]> {
        files.iter().find(|(p, _)| *p == path).map(|(_, c)| *c)
    }

    #[test]
    fn catalog_and_embedded_directories_match_one_to_one() {
        let catalog: BTreeSet<&str> = BUILTIN_SKILLS.iter().map(|s| s.id).collect();
        assert_eq!(catalog.len(), BUILTIN_SKILLS.len(), "duplicate catalog ids");
        let embedded: BTreeSet<&str> = EMBEDDED_SKILLS.iter().map(|s| s.id).collect();
        assert_eq!(
            catalog, embedded,
            "every assets/skills/<id>/ needs a BUILTIN_SKILLS entry and vice versa"
        );
    }

    #[test]
    fn catalog_text_is_derived_from_skill_md() {
        for skill in BUILTIN_SKILLS {
            let files = skill_files(skill.id).expect("embedded");
            assert_eq!(
                file(files, "SKILL.md"),
                Some(skill.content.as_bytes()),
                "{}",
                skill.id
            );
            assert!(
                !skill.description.is_empty() && skill.description.chars().count() <= 1024,
                "{}",
                skill.id
            );
            for marker in ['"', '\'', '>', '|'] {
                assert!(
                    !skill.description.starts_with(marker),
                    "{}: unparsed YAML scalar",
                    skill.id
                );
            }
            let frontmatter = skill.content.split("\n---").next().unwrap_or_default();
            assert!(
                frontmatter.contains(&format!("name: {}", skill.id))
                    || frontmatter.contains(&format!("name: \"{}\"", skill.id))
            );
        }
        // Folded block scalar (`description: >-`).
        assert_eq!(
            find_skill_by_id("google-cloud-waf-security").map(|s| s.description),
            Some(
                "Generates security-focused guidance for Google Cloud workloads based on the design principles and \
                 recommendations in the Google Cloud Well-Architected Framework (WAF). Use this skill to evaluate \
                 workloads, identify security requirements, and provide actionable recommendations for IAM, network \
                 security, data protection, and operational security."
            )
        );
        // Double-quoted scalar.
        let golang = find_skill_by_id("golang-security").expect("golang-security");
        assert!(
            golang
                .description
                .starts_with("Security best practices and vulnerability prevention for Golang")
        );
    }

    #[test]
    fn embedded_files_are_complete_and_portable() {
        let mut total = 0;
        for skill in BUILTIN_SKILLS {
            let files = skill.files();
            assert!(file(files, "SKILL.md").is_some(), "{}", skill.id);
            let mut previous: Option<&str> = None;
            for (path, content) in files {
                assert!(
                    !path.is_empty() && !path.starts_with('/') && !path.contains('\\'),
                    "{}: {path}",
                    skill.id
                );
                assert!(
                    path.split('/')
                        .all(|part| !part.is_empty() && part != "." && part != ".."),
                    "{path}"
                );
                if let Some(prev) = previous {
                    assert!(
                        prev.as_bytes() < path.as_bytes(),
                        "{}: files are not sorted",
                        skill.id
                    );
                }
                previous = Some(path);
                if !content.contains(&0) {
                    assert!(
                        !content.windows(2).any(|w| w == b"\r\n"),
                        "{}/{path} kept CRLF",
                        skill.id
                    );
                }
                total += 1;
            }
        }
        // Supporting files are shipped, not only SKILL.md.
        assert!(total > BUILTIN_SKILLS.len());
        let golang = skill_files("golang-security").expect("golang-security");
        assert!(file(golang, "references/injection.md").is_some());
        let scanner = skill_files(" Skill-Security ").expect("case-insensitive lookup");
        assert!(file(scanner, "scripts/scan.py").is_some());
        assert!(file(scanner, "rules/malware.yar").is_some());
        assert!(skill_files("no-such-skill").is_none());
    }

    /// Markdown inline links and reference definitions with a relative target,
    /// outside fenced code blocks and inline code spans.
    fn relative_links(markdown: &str) -> Vec<(usize, String)> {
        let mut links = Vec::new();
        let mut fence: Option<&str> = None;
        for (index, line) in markdown.lines().enumerate() {
            let trimmed = line.trim_start();
            for marker in ["```", "~~~"] {
                if trimmed.starts_with(marker) {
                    fence = match fence {
                        Some(open) if open == marker => None,
                        None => Some(marker),
                        other => other,
                    };
                }
            }
            if fence.is_some() || trimmed.starts_with("```") || trimmed.starts_with("~~~") {
                continue;
            }
            let mut text = String::new();
            let mut in_code = false;
            for c in line.chars() {
                if c == '`' {
                    in_code = !in_code;
                } else if !in_code {
                    text.push(c);
                }
            }
            let mut targets = Vec::new();
            let mut rest = text.as_str();
            while let Some(pos) = rest.find("](") {
                let after = &rest[pos + 2..];
                let end = after.find(')').unwrap_or(after.len());
                targets.push(after[..end].to_string());
                rest = &after[end..];
            }
            let definition = text.trim_start();
            if definition.starts_with('[')
                && let Some(pos) = definition.find("]:")
            {
                targets.push(definition[pos + 2..].to_string());
            }
            for target in targets {
                let target = target.split_whitespace().next().unwrap_or_default();
                let target = target.trim_start_matches('<').trim_end_matches('>');
                let is_external = target.split_once(':').is_some_and(|(scheme, _)| {
                    !scheme.is_empty()
                        && scheme
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                });
                if target.is_empty()
                    || is_external
                    || target.starts_with('#')
                    || target.starts_with('/')
                {
                    continue;
                }
                let path = target.split(['#', '?']).next().unwrap_or_default();
                if !path.is_empty() {
                    links.push((index + 1, path.replace("%20", " ")));
                }
            }
        }
        links
    }

    fn resolve(base_file: &str, target: &str) -> Option<String> {
        let mut parts: Vec<&str> = base_file.split('/').collect();
        parts.pop();
        for part in target.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                other => parts.push(other),
            }
        }
        Some(parts.join("/"))
    }

    #[test]
    fn link_scanner_finds_and_resolves_relative_links() {
        let md = "See [a](./references/a.md#x) and [b](../b.md).\n```\n[c](c.md)\n```\n`[d](d.md)` [e](https://x.test) [f](#g)\n[h]: docs/h.md \"t\"\n";
        let links: Vec<String> = relative_links(md).into_iter().map(|(_, t)| t).collect();
        assert_eq!(links, ["./references/a.md", "../b.md", "docs/h.md"]);
        assert_eq!(
            resolve("SKILL.md", "./references/a.md").as_deref(),
            Some("references/a.md")
        );
        assert_eq!(
            resolve("references/x.md", "../SKILL.md").as_deref(),
            Some("SKILL.md")
        );
        assert_eq!(resolve("SKILL.md", "../outside.md"), None);
    }

    #[test]
    fn every_relative_markdown_link_resolves_to_an_embedded_file() {
        let mut broken = Vec::new();
        let mut checked = 0;
        for skill in BUILTIN_SKILLS {
            let files = skill.files();
            let paths: BTreeSet<&str> = files.iter().map(|(p, _)| *p).collect();
            for (path, content) in files.iter().filter(|(p, _)| p.ends_with(".md")) {
                let text = std::str::from_utf8(content).expect("markdown is UTF-8");
                for (line, target) in relative_links(text) {
                    checked += 1;
                    let ok = resolve(path, &target).is_some_and(|resolved| {
                        let dir = format!("{}/", resolved.trim_end_matches('/'));
                        paths.contains(resolved.as_str())
                            || paths.iter().any(|p| p.starts_with(&dir))
                    });
                    if !ok {
                        broken.push(format!("{}/{path}:{line} -> {target}", skill.id));
                    }
                }
            }
        }
        assert!(checked > 0, "no relative links were checked");
        assert!(
            broken.is_empty(),
            "unresolved relative links:\n{}",
            broken.join("\n")
        );
    }

    #[test]
    fn skill_folder_hash_matches_upstream_test_vectors() {
        // vercel-labs/skills README, "Lock File Content Hash".
        assert_eq!(
            skill_folder_hash(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            skill_folder_hash(&[("SKILL.md", b"# hi\n")]),
            "93c36952d8843b33e68ae970ebabcc03e1687c9bb0dd1ecaf357060318952f55"
        );
        let vector = "b22c4d22aa319d2924312fa18fcbfedc88fa89c74dbd8f298c683e1caf7b7f24";
        assert_eq!(
            skill_folder_hash(&[("docs/b.md", b"b\n"), ("SKILL.md", b"a\n")]),
            vector
        );
        assert_eq!(
            skill_folder_hash(&[("docs/b.md", b"b\r\n"), ("SKILL.md", b"a\r\n")]),
            vector
        );
        assert_ne!(
            skill_folder_hash(&[("bin", b"\0\r\n")]),
            skill_folder_hash(&[("bin", b"\0\n")])
        );
    }

    #[test]
    fn asset_lock_is_v2_pinned_and_matches_embedded_content() {
        let lock = lock();
        assert_eq!(
            lock["version"], 2,
            "assets/skills-lock.json must be lock version 2"
        );
        let entries = lock["skills"].as_object().expect("skills map");
        let locked: BTreeSet<&str> = entries.keys().map(String::as_str).collect();
        let catalog: BTreeSet<&str> = BUILTIN_SKILLS.iter().map(|s| s.id).collect();
        assert_eq!(locked, catalog, "lock entries and embedded skills differ");

        for (id, entry) in entries {
            let str_field = |key: &str| {
                entry[key]
                    .as_str()
                    .unwrap_or_else(|| panic!("{id}: missing {key}"))
            };
            let reference = str_field("ref");
            assert!(
                reference.len() == 40
                    && reference
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{id}: ref must be a full lowercase commit SHA"
            );
            assert_eq!(str_field("sourceType"), "github", "{id}");
            assert!(
                str_field("source").split('/').count() == 2,
                "{id}: source must be owner/repo"
            );
            let skill_path = str_field("skillPath");
            assert!(
                skill_path.ends_with(&format!("{id}/SKILL.md")),
                "{id}: skillPath {skill_path}"
            );

            let vendored: Vec<&str> = entry["sentra"]["vendoredFiles"]
                .as_array()
                .unwrap_or_else(|| panic!("{id}: missing sentra.vendoredFiles"))
                .iter()
                .map(|v| v.as_str().expect("string"))
                .collect();
            let files = skill_files(id).expect("embedded");
            for path in &vendored {
                assert!(
                    file(files, path).is_some(),
                    "{id}: vendored file {path} is not embedded"
                );
            }
            let upstream: Vec<(&str, &[u8])> = files
                .iter()
                .filter(|(p, _)| !vendored.contains(p))
                .map(|(p, c)| (*p, *c))
                .collect();
            assert_eq!(
                skill_folder_hash(&upstream),
                str_field("computedHash"),
                "{id}: embedded content does not match computedHash; re-run scripts/sync-skills.ps1"
            );
        }
    }

    #[test]
    fn every_third_party_skill_ships_its_license() {
        let lock = lock();
        let entries = lock["skills"].as_object().expect("skills map");
        for (id, entry) in entries {
            let sentra = &entry["sentra"];
            let license = sentra["license"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: missing sentra.license"));
            let license_file = sentra["licenseFile"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: missing sentra.licenseFile"));
            let text = file(skill_files(id).expect("embedded"), license_file)
                .unwrap_or_else(|| panic!("{id}: license file {license_file} is not embedded"));
            let text = std::str::from_utf8(text).expect("license is UTF-8");
            match license {
                "MIT" => {
                    assert!(text.contains(MIT_GRANT), "{id}: not an MIT license text");
                    assert!(
                        text.contains("Copyright"),
                        "{id}: MIT license without copyright line"
                    );
                }
                "Apache-2.0" => {
                    assert!(
                        text.contains(APACHE_HEADER) && text.contains(APACHE_VERSION),
                        "{id}: not Apache-2.0"
                    );
                }
                other => panic!(
                    "{id}: license {other} has no verification rule; review it before bundling"
                ),
            }
        }
    }

    /// One numbered NOTICE entry: its `field -> value` map plus the
    /// `- <skill>` list that follows `Skills:`.
    type NoticeEntry<'a> = (BTreeMap<&'a str, &'a str>, Vec<&'a str>);

    fn notice_entries() -> Vec<NoticeEntry<'static>> {
        parse_notice(NOTICE)
    }

    /// Parses the numbered NOTICE entries, which are separated by blank lines.
    ///
    /// `NOTICE` is an ordinary `text=auto` file, so Git checks it out with
    /// CRLF on Windows hosts that set `core.autocrlf` (GitHub-hosted Windows
    /// runners do). Lines therefore come from `str::lines`, which ends a line
    /// at LF or CRLF, and a blank or whitespace-only line ends an entry;
    /// splitting on a literal `"\n\n"` would never match CRLF text and would
    /// merge the whole file into one block. A field repeated inside one entry
    /// fails the test instead of silently overwriting the earlier value, so
    /// entries that run together cannot misattribute a skill.
    fn parse_notice(text: &str) -> Vec<NoticeEntry<'_>> {
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let mut entries = Vec::new();
        for block in lines.split(|line| line.is_empty()) {
            let mut fields = BTreeMap::new();
            let mut repeated = Vec::new();
            let mut skills = Vec::new();
            for &line in block {
                if let Some(skill) = line.strip_prefix("- ") {
                    skills.push(skill.trim());
                } else if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim();
                    if fields.insert(key, value.trim()).is_some() {
                        repeated.push(key);
                    }
                }
            }
            if fields.contains_key("Source") && !skills.is_empty() {
                assert!(
                    repeated.is_empty(),
                    "NOTICE entry for {} repeats field(s) {repeated:?}; \
                     separate entries with a blank line",
                    fields["Source"]
                );
                entries.push((fields, skills));
            }
        }
        entries
    }

    #[test]
    fn notice_parser_is_line_ending_agnostic() {
        // The checked-in NOTICE, whatever line endings this checkout has,
        // must parse identically as LF and as CRLF text.
        let lf = NOTICE.replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        let lf_entries = parse_notice(&lf);
        assert!(!lf_entries.is_empty(), "NOTICE has no skill entries");
        assert_eq!(parse_notice(&crlf), lf_entries);
        assert_eq!(parse_notice(NOTICE), lf_entries);
    }

    #[test]
    fn notice_parser_separates_crlf_entries() {
        let text = "1. a/one\r\n   Source:    https://github.com/a/one\r\n   \
                    License:   MIT\r\n   Skills:\r\n   - one\r\n   - uno\r\n\r\n\
                    2. b/two\r\n   Source:    https://github.com/b/two\r\n   \
                    License:   Apache-2.0\r\n   Skills:\r\n   - two\r\n   \r\n\
                    3. c/three\n   Source:    https://github.com/c/three\n   \
                    License:   MIT\n   Skills:\n   - three\n";
        let entries = parse_notice(text);
        let summary: Vec<(&str, &str, &[&str])> = entries
            .iter()
            .map(|(fields, skills)| (fields["Source"], fields["License"], skills.as_slice()))
            .collect();
        assert_eq!(
            summary,
            [
                ("https://github.com/a/one", "MIT", &["one", "uno"][..]),
                ("https://github.com/b/two", "Apache-2.0", &["two"][..]),
                ("https://github.com/c/three", "MIT", &["three"][..]),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "repeats field(s) [\"Source\", \"License\", \"Skills\"]")]
    fn notice_parser_rejects_entries_that_run_together() {
        parse_notice(
            "1. a/one\r\n   Source:    https://github.com/a/one\r\n   License:   MIT\r\n   \
             Skills:\r\n   - one\r\n\
             2. b/two\r\n   Source:    https://github.com/b/two\r\n   License:   MIT\r\n   \
             Skills:\r\n   - two\r\n",
        );
    }

    #[test]
    fn notice_attributes_every_bundled_skill() {
        let lock = lock();
        let notice = notice_entries();
        for (id, entry) in lock["skills"].as_object().expect("skills map") {
            let source = entry["source"].as_str().expect("source");
            let reference = entry["ref"].as_str().expect("ref");
            let license = entry["sentra"]["license"].as_str().expect("license");
            let (fields, _) = notice
                .iter()
                .find(|(_, skills)| skills.contains(&id.as_str()))
                .unwrap_or_else(|| panic!("NOTICE does not list skill {id}"));
            assert_eq!(
                fields.get("Source").copied(),
                Some(format!("https://github.com/{source}").as_str()),
                "{id}"
            );
            assert_eq!(
                fields.get("Commit").copied(),
                Some(reference),
                "{id}: NOTICE commit differs from the lock"
            );
            let notice_license = fields.get("License").copied().unwrap_or_default();
            assert!(
                notice_license.starts_with(license),
                "{id}: NOTICE license `{notice_license}` != {license}"
            );
        }
    }
}
