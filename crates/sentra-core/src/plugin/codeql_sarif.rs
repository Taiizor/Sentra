//! Normalisation of CodeQL SARIF into the `sentra codeql analyze|import` result contract
//! (REQ-F05, ADR-0011).
//!
//! The same code reads the SARIF that Sentra's own host analysis writes and SARIF
//! produced elsewhere (a local CodeQL run, GitHub Actions). Results are candidate
//! claims: nothing here admits evidence or stores findings.
//!
//! - Only runs whose `tool.driver.name` is `CodeQL` are accepted.
//! - Rule metadata is looked up in `tool.driver.rules` and in every
//!   `tool.extensions[].rules` (CodeQL puts query-pack rules in extensions).
//! - Severity follows GitHub's documented `security-severity` thresholds (>= 9.0
//!   critical, >= 7.0 high, >= 4.0 medium, > 0 low); without a score,
//!   `problem.severity` maps `error` to medium, `warning` to low and `recommendation`
//!   to info, and without that the SARIF `level` maps the same way (`note`/`none` to
//!   info, absent to low because SARIF's default level is `warning`).
//! - Paths must be relative URIs that stay inside the workspace after `.`/`..`
//!   resolution; absolute paths, URIs with a scheme and escaping paths are dropped and
//!   counted. Paths are checked lexically; files are not opened.
//! - The document is read in one streaming pass with fixed bounds (see the model
//!   section below), so memory does not grow with the number of results or rules.
//! - Fingerprints combine `primaryLocationLineHash` with
//!   `primaryLocationStartColumnFingerprint` (or the start column), so two results of
//!   one rule on one line stay distinct.
//! - The rules each run declares (CodeQL lists every query it ran, also those without
//!   results) are reported per language, so a consumer can tell which rules a SARIF
//!   covered.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    marker::PhantomData,
    path::Path,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::common::crypto::sha256_digest;

/// Largest SARIF document accepted by `sentra codeql import` (64 MiB).
pub const CODEQL_SARIF_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Largest SARIF document read back from Sentra's own host analysis (256 MiB).
pub const CODEQL_ANALYSIS_SARIF_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Default cap on the number of findings returned.
pub const DEFAULT_CODEQL_MAX_RESULTS: usize = 5_000;

/// Largest accepted `--max-results`.
pub const MAX_CODEQL_MAX_RESULTS: usize = 100_000;

const MAX_MESSAGE_CHARS: usize = 4_000;
const MAX_SHORT_TEXT_CHARS: usize = 300;
const MAX_TAGS: usize = 64;
const MAX_WARNINGS: usize = 50;

/// Normalised severity of a CodeQL result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeQlSeverity {
    /// Informational.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl CodeQlSeverity {
    /// Lower-case label used in the JSON contract.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Maps a CodeQL result to a severity.
///
/// `security_severity` (a CVSS-like score in `0.0..=10.0`) wins when present: >= 9.0
/// critical, >= 7.0 high, >= 4.0 medium, > 0 low, otherwise info (GitHub's documented
/// thresholds). Without it `problem_severity` maps `error` to medium, `warning` to low
/// and `recommendation`/`note` to info; without that the SARIF `level` maps the same
/// way, and a missing level counts as SARIF's default `warning` (low).
pub fn codeql_severity(
    security_severity: Option<f64>,
    problem_severity: Option<&str>,
    level: Option<&str>,
) -> CodeQlSeverity {
    if let Some(score) = security_severity.filter(|s| s.is_finite()) {
        return if score >= 9.0 {
            CodeQlSeverity::Critical
        } else if score >= 7.0 {
            CodeQlSeverity::High
        } else if score >= 4.0 {
            CodeQlSeverity::Medium
        } else if score > 0.0 {
            CodeQlSeverity::Low
        } else {
            CodeQlSeverity::Info
        };
    }
    let label = problem_severity.or(level).map(str::to_ascii_lowercase);
    match label.as_deref() {
        Some("error") => CodeQlSeverity::Medium,
        Some("recommendation" | "note" | "none") => CodeQlSeverity::Info,
        _ => CodeQlSeverity::Low,
    }
}

/// CWE identifiers (`CWE-79`) from CodeQL tags such as `external/cwe/cwe-079`.
pub fn cwe_ids_from_tags<S: AsRef<str>>(tags: &[S]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let tag = tag.as_ref();
        let lower = tag.to_ascii_lowercase();
        let Some(digits) = lower.strip_prefix("external/cwe/cwe-") else {
            continue;
        };
        if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(number) = digits.parse::<u32>() else {
            continue;
        };
        let id = format!("CWE-{number}");
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// Workspace-relative form of a SARIF artifact URI, or `None` when it is absolute,
/// carries a scheme or drive letter, or escapes the workspace.
///
/// Percent-escapes are decoded, backslashes become `/`, and `.`/`..` segments are
/// resolved lexically.
pub fn workspace_relative_uri(uri: &str) -> Option<String> {
    let decoded = percent_decode(uri)?;
    let text = decoded.replace('\\', "/");
    if text.is_empty() || text.starts_with('/') || text.contains('\0') {
        return None;
    }
    // A scheme (`file:`) or drive letter (`C:`) before the first separator.
    let first = text.split('/').next().unwrap_or_default();
    if first.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in text.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

fn percent_decode(input: &str) -> Option<String> {
    if !input.contains('%') {
        return Some(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let text = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Stable fingerprint used when SARIF has no `primaryLocationLineHash`: lowercase hex
/// SHA-256 of `rule_id`, `path`, `start_line` and `message`, joined by NUL bytes.
pub fn fallback_fingerprint(rule_id: &str, path: &str, start_line: u32, message: &str) -> String {
    let material = format!("{rule_id}\0{path}\0{start_line}\0{message}");
    sha256_digest(material.as_bytes())
}

/// One normalised CodeQL result (`findings[]` of the JSON contract).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CodeQlFinding {
    /// Query id, e.g. `py/sql-injection`.
    pub rule_id: String,
    /// Human-readable query name (`properties.name`, else `shortDescription.text`).
    pub rule_name: Option<String>,
    /// Result message text (bounded).
    pub message: String,
    /// Normalised severity.
    pub severity: CodeQlSeverity,
    /// `security-severity` score when present.
    pub security_severity: Option<f64>,
    /// Rule `problem.severity` when present.
    pub problem_severity: Option<String>,
    /// Rule `precision` when present.
    pub precision: Option<String>,
    /// CWE ids from the rule tags (`CWE-79`).
    pub cwe: Vec<String>,
    /// Rule tags as given (bounded).
    pub tags: Vec<String>,
    /// Workspace-relative path with forward slashes.
    pub path: String,
    /// 1-based start line (1 when the result has no region).
    pub start_line: u32,
    /// 1-based end line (the start line when absent).
    pub end_line: u32,
    /// Start column when present.
    pub start_column: Option<u32>,
    /// End column when present.
    pub end_column: Option<u32>,
    /// See [`codeql_result_fingerprint`]: `primaryLocationLineHash` joined with the start
    /// column fingerprint (or column), else [`fallback_fingerprint`].
    pub fingerprint: String,
    /// Rule `helpUri` when present.
    pub help_uri: Option<String>,
    /// CodeQL language id when it can be determined.
    pub language: Option<String>,
}

/// Tool that produced the SARIF (`tool.driver`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQlSourceTool {
    /// Driver name (`CodeQL`).
    pub name: String,
    /// Driver `semanticVersion`, else `version`.
    pub version: Option<String>,
}

/// Normalised content of one SARIF document.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct CodeQlSarifSummary {
    /// Findings kept (at most `max_results`).
    pub findings: Vec<CodeQlFinding>,
    /// Every result in the document.
    pub results_total: usize,
    /// Results dropped because their path is absolute or escapes the workspace.
    pub results_outside_workspace: usize,
    /// Results dropped because they have no file location or rule id.
    pub results_without_location: usize,
    /// Whether findings were cut at `max_results`.
    pub truncated: bool,
    /// Notes about the document (bounded).
    pub warnings: Vec<String>,
    /// Driver of the first run.
    pub source_tool: Option<CodeQlSourceTool>,
    /// Rule ids that ran, per CodeQL language id ([`UNKNOWN_LANGUAGE`] when it cannot be
    /// determined): every rule the runs declare in `tool.driver.rules` and
    /// `tool.extensions[].rules`, plus the rule of every finding.
    pub rule_ids: BTreeMap<String, BTreeSet<String>>,
}

/// Options for [`normalize_codeql_sarif`].
#[derive(Clone, Debug)]
pub struct CodeQlSarifOptions {
    /// Most findings kept.
    pub max_results: usize,
    /// Language assigned when a result's language cannot be determined.
    pub default_language: Option<String>,
}

impl Default for CodeQlSarifOptions {
    fn default() -> Self {
        Self {
            max_results: DEFAULT_CODEQL_MAX_RESULTS,
            default_language: None,
        }
    }
}

/// Why a SARIF document was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeQlSarifError {
    /// The document is larger than the limit (`sarif_too_large`).
    TooLarge {
        /// Observed size in bytes (at least `limit + 1`).
        size: u64,
        /// Accepted maximum in bytes.
        limit: u64,
    },
    /// The document is not valid SARIF JSON (`sarif_invalid`).
    Invalid(String),
    /// A run was produced by another tool, or there are no runs (`sarif_not_codeql`).
    NotCodeQl(String),
    /// The file could not be read (`io_error`).
    Io(String),
}

impl CodeQlSarifError {
    /// Stable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "sarif_too_large",
            Self::Invalid(_) => "sarif_invalid",
            Self::NotCodeQl(_) => "sarif_not_codeql",
            Self::Io(_) => "io_error",
        }
    }
}

impl fmt::Display for CodeQlSarifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size, limit } => write!(
                f,
                "the SARIF file is larger than the {limit}-byte limit ({size} bytes or more)"
            ),
            Self::Invalid(reason) => write!(f, "the file is not valid SARIF JSON: {reason}"),
            Self::NotCodeQl(reason) => write!(f, "the SARIF was not produced by CodeQL: {reason}"),
            Self::Io(reason) => write!(f, "the SARIF file could not be read: {reason}"),
        }
    }
}

impl std::error::Error for CodeQlSarifError {}

/// Reads a SARIF file of at most `limit` bytes.
pub fn read_sarif_file(path: &Path, limit: u64) -> Result<Vec<u8>, CodeQlSarifError> {
    let metadata = std::fs::metadata(path).map_err(|e| CodeQlSarifError::Io(e.to_string()))?;
    if !metadata.is_file() {
        return Err(CodeQlSarifError::Io("not a regular file".into()));
    }
    if metadata.len() > limit {
        return Err(CodeQlSarifError::TooLarge {
            size: metadata.len(),
            limit,
        });
    }
    let file = std::fs::File::open(path).map_err(|e| CodeQlSarifError::Io(e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| CodeQlSarifError::Io(e.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(CodeQlSarifError::TooLarge {
            size: bytes.len() as u64,
            limit,
        });
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Bounded, streaming SARIF model.
//
// A document is read in one pass without building a tree of it. Runs are processed
// and dropped one at a time; results are classified while they are read and only
// those that can become findings (at most `max_results`) are kept; every array that
// could otherwise grow without bound (locations, rules, extensions, tags) keeps only
// its first elements, and rule and result properties are read into fixed fields
// instead of a generic JSON value. Memory therefore follows the kept findings and
// rules, not the number of elements in the document: a 64 MiB file of empty results
// costs no more than a few of them.
// ---------------------------------------------------------------------------

/// Most runs read from one document; later runs are skipped and the findings are
/// marked truncated. (GitHub code scanning accepts at most 20 runs per SARIF file.)
pub const MAX_SARIF_RUNS: usize = 1_000;

/// Most `tool.extensions` entries (query, library and model packs) read per run.
const MAX_EXTENSIONS: usize = 32;

/// Most rules read per tool component (the driver or one extension).
const MAX_RULES_PER_COMPONENT: usize = 4_000;

/// Most rule ids reported per language.
const MAX_RULE_IDS_PER_LANGUAGE: usize = 10_000;

/// Language bucket of rules and results whose language cannot be determined.
pub const UNKNOWN_LANGUAGE: &str = "unknown";

/// A JSON array of which only the first `N` elements are kept; later elements are
/// read and discarded. `seen` counts every element.
struct CappedVec<T, const N: usize> {
    items: Vec<T>,
    seen: usize,
}

impl<T, const N: usize> CappedVec<T, N> {
    fn dropped(&self) -> bool {
        self.seen > self.items.len()
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for CappedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CappedVisitor<T, const N: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for CappedVisitor<T, N> {
            type Value = CappedVec<T, N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                let mut seen = 0_usize;
                loop {
                    if items.len() < N {
                        match seq.next_element::<T>()? {
                            Some(item) => items.push(item),
                            None => break,
                        }
                    } else if seq.next_element::<IgnoredAny>()?.is_none() {
                        break;
                    }
                    seen += 1;
                }
                Ok(CappedVec { items, seen })
            }
        }

        deserializer.deserialize_seq(CappedVisitor(PhantomData))
    }
}

/// Shape of a loosely typed property value.
enum Loose {
    Text(String),
    Number(f64),
    Texts(Vec<String>),
    Other,
}

/// Accepts any JSON value; arrays keep at most [`MAX_TAGS`] string elements and
/// objects are skipped, so a property of an unexpected type never rejects the document.
struct LooseVisitor;

impl<'de> Visitor<'de> for LooseVisitor {
    type Value = Loose;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<Loose, E> {
        Ok(Loose::Other)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Loose, E> {
        Ok(Loose::Number(value as f64))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Loose, E> {
        Ok(Loose::Number(value as f64))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Loose, E> {
        Ok(Loose::Number(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Loose, E> {
        Ok(Loose::Text(value.to_string()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Loose, E> {
        Ok(Loose::Text(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Other)
    }

    fn visit_none<E: de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Other)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Loose, D::Error> {
        deserializer.deserialize_any(LooseVisitor)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Loose, A::Error> {
        let mut texts = Vec::new();
        while let Some(item) = seq.next_element::<LenientString>()? {
            if let Some(text) = item.0
                && texts.len() < MAX_TAGS
            {
                texts.push(text);
            }
        }
        Ok(Loose::Texts(texts))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Loose, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
}

/// A property used only when it is a JSON string; any other value reads as absent.
#[derive(Default)]
struct LenientString(Option<String>);

impl<'de> Deserialize<'de> for LenientString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(match deserializer.deserialize_any(LooseVisitor)? {
            Loose::Text(text) => Some(text),
            _ => None,
        }))
    }
}

/// A score used only when it is a number or a numeric string.
#[derive(Default)]
struct LenientScore(Option<f64>);

impl<'de> Deserialize<'de> for LenientScore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(match deserializer.deserialize_any(LooseVisitor)? {
            Loose::Text(text) => text.trim().parse::<f64>().ok(),
            Loose::Number(number) => Some(number),
            _ => None,
        }))
    }
}

/// The string elements (at most [`MAX_TAGS`]) of a property that should be an array of
/// strings; any other value reads as empty.
#[derive(Default)]
struct LenientTexts(Vec<String>);

impl<'de> Deserialize<'de> for LenientTexts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(match deserializer.deserialize_any(LooseVisitor)? {
            Loose::Texts(texts) => texts,
            _ => Vec::new(),
        }))
    }
}

#[derive(Deserialize)]
struct Tool {
    driver: Option<Component>,
    extensions: Option<CappedVec<Component, MAX_EXTENSIONS>>,
}

#[derive(Deserialize)]
struct Component {
    name: Option<String>,
    #[serde(rename = "semanticVersion")]
    semantic_version: Option<String>,
    version: Option<String>,
    rules: Option<CappedVec<Rule, MAX_RULES_PER_COMPONENT>>,
}

impl Component {
    fn rule_list(&self) -> &[Rule] {
        self.rules
            .as_ref()
            .map(|r| r.items.as_slice())
            .unwrap_or_default()
    }
}

#[derive(Deserialize)]
struct Rule {
    id: Option<String>,
    name: Option<String>,
    #[serde(rename = "shortDescription")]
    short_description: Option<Text>,
    #[serde(rename = "helpUri")]
    help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: Option<RuleConfiguration>,
    properties: Option<RuleProperties>,
}

/// The rule properties Sentra reads (CodeQL writes them as `properties.<key>`).
#[derive(Deserialize)]
struct RuleProperties {
    #[serde(default)]
    name: LenientString,
    #[serde(rename = "problem.severity", default)]
    problem_severity: LenientString,
    #[serde(default)]
    precision: LenientString,
    #[serde(rename = "security-severity", default)]
    security_severity: LenientScore,
    #[serde(default)]
    tags: LenientTexts,
}

#[derive(Deserialize)]
struct RuleConfiguration {
    level: Option<String>,
}

#[derive(Deserialize)]
struct Text {
    text: Option<String>,
}

#[derive(Deserialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(rename = "ruleIndex")]
    rule_index: Option<i64>,
    rule: Option<RuleReference>,
    level: Option<String>,
    message: Option<Text>,
    /// Only the first (primary) location is read.
    locations: Option<CappedVec<Location, 1>>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: Option<PartialFingerprints>,
    properties: Option<ResultProperties>,
}

impl SarifResult {
    fn physical_location(&self) -> Option<&PhysicalLocation> {
        self.locations
            .as_ref()
            .and_then(|l| l.items.first())
            .and_then(|l| l.physical_location.as_ref())
    }
}

#[derive(Deserialize)]
struct PartialFingerprints {
    #[serde(rename = "primaryLocationLineHash", default)]
    line_hash: LenientString,
    #[serde(rename = "primaryLocationStartColumnFingerprint", default)]
    start_column: LenientString,
}

#[derive(Deserialize)]
struct ResultProperties {
    #[serde(rename = "security-severity", default)]
    security_severity: LenientScore,
}

#[derive(Deserialize)]
struct RuleReference {
    id: Option<String>,
    index: Option<i64>,
    #[serde(rename = "toolComponent")]
    tool_component: Option<ComponentReference>,
}

#[derive(Deserialize)]
struct ComponentReference {
    index: Option<i64>,
}

#[derive(Deserialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: Option<PhysicalLocation>,
}

#[derive(Deserialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: Option<ArtifactLocation>,
    region: Option<Region>,
}

#[derive(Deserialize)]
struct ArtifactLocation {
    uri: Option<String>,
}

#[derive(Deserialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: Option<u32>,
    #[serde(rename = "endLine")]
    end_line: Option<u32>,
    #[serde(rename = "startColumn")]
    start_column: Option<u32>,
    #[serde(rename = "endColumn")]
    end_column: Option<u32>,
}

/// Rule metadata resolved for one result.
struct RuleView<'a> {
    rule: Option<&'a Rule>,
    component_name: Option<&'a str>,
}

/// A score in `0.0..=10.0`, else `None`.
fn valid_score(score: Option<f64>) -> Option<f64> {
    score.filter(|s| s.is_finite() && (0.0..=10.0).contains(s))
}

fn rule_tags(rule: Option<&Rule>) -> Vec<String> {
    rule.and_then(|r| r.properties.as_ref())
        .map(|p| {
            p.tags
                .0
                .iter()
                .map(|tag| bounded_text(tag, MAX_SHORT_TEXT_CHARS))
                .take(MAX_TAGS)
                .collect()
        })
        .unwrap_or_default()
}

/// Removes control characters other than newline and tab and truncates to `max` chars.
fn bounded_text(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let mut cut: String = cleaned.chars().take(max).collect();
        cut.push_str("...");
        cut
    }
}

fn optional_text(text: Option<&str>, max: usize) -> Option<String> {
    text.map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| bounded_text(t, max))
}

/// CodeQL language id for a rule id prefix (`py/...`) or query pack name
/// (`codeql/python-queries`).
pub fn codeql_language_hint(rule_id: &str, component_name: Option<&str>) -> Option<String> {
    if let Some(name) = component_name
        && let Some(rest) = name.strip_prefix("codeql/")
    {
        let language = rest
            .strip_suffix("-queries")
            .or_else(|| rest.strip_suffix("-all"))
            .unwrap_or(rest);
        if let Some(language) = canonical_language_id(language) {
            return Some(language.to_string());
        }
    }
    let prefix = rule_id.split('/').next()?;
    let language = match prefix {
        "actions" => "actions",
        "cpp" | "c" => "cpp",
        "cs" => "csharp",
        "go" => "go",
        "java" | "kotlin" => "java",
        "js" => "javascript",
        "py" => "python",
        "rb" => "ruby",
        "rust" => "rust",
        "swift" => "swift",
        _ => return None,
    };
    Some(language.to_string())
}

fn canonical_language_id(name: &str) -> Option<&'static str> {
    Some(match name {
        "actions" => "actions",
        "cpp" => "cpp",
        "csharp" => "csharp",
        "go" => "go",
        "java" => "java",
        "javascript" => "javascript",
        "python" => "python",
        "ruby" => "ruby",
        "rust" => "rust",
        "swift" => "swift",
        _ => return None,
    })
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS && !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

fn component_version(component: &Component) -> Option<String> {
    component
        .semantic_version
        .as_deref()
        .or(component.version.as_deref())
        .and_then(|v| optional_text(Some(v), 64))
}

/// State of one normalisation: the summary built so far and the limits applied.
struct Sink<'o> {
    options: &'o CodeQlSarifOptions,
    summary: CodeQlSarifSummary,
    versions: Vec<String>,
    runs_read: usize,
    runs_skipped: usize,
    rules_dropped: bool,
    rule_ids_dropped: bool,
    rejected: Option<CodeQlSarifError>,
}

impl<'o> Sink<'o> {
    fn new(options: &'o CodeQlSarifOptions) -> Self {
        Self {
            options,
            summary: CodeQlSarifSummary::default(),
            versions: Vec::new(),
            runs_read: 0,
            runs_skipped: 0,
            rules_dropped: false,
            rule_ids_dropped: false,
            rejected: None,
        }
    }

    /// Counts one result and keeps it when it can become a finding.
    fn classify(&mut self, result: SarifResult, kept: &mut Vec<(SarifResult, String)>) {
        self.summary.results_total += 1;
        let uri = result
            .physical_location()
            .and_then(|p| p.artifact_location.as_ref())
            .and_then(|a| a.uri.as_deref());
        let Some(uri) = uri else {
            self.summary.results_without_location += 1;
            return;
        };
        let Some(path) = workspace_relative_uri(uri) else {
            self.summary.results_outside_workspace += 1;
            return;
        };
        if self.summary.findings.len() + kept.len() >= self.options.max_results {
            self.summary.truncated = true;
            return;
        }
        kept.push((result, path));
    }

    /// Records that `rule_id` ran for its language.
    fn note_rule(&mut self, rule_id: Option<&str>, component_name: Option<&str>) {
        let Some(rule_id) = optional_text(rule_id, MAX_SHORT_TEXT_CHARS) else {
            return;
        };
        let language = codeql_language_hint(&rule_id, component_name)
            .or_else(|| self.options.default_language.clone())
            .unwrap_or_else(|| UNKNOWN_LANGUAGE.to_string());
        self.note_rule_id(language, rule_id);
    }

    fn note_rule_id(&mut self, language: String, rule_id: String) {
        let ids = self.summary.rule_ids.entry(language).or_default();
        if ids.len() < MAX_RULE_IDS_PER_LANGUAGE {
            ids.insert(rule_id);
        } else if !ids.contains(&rule_id) {
            self.rule_ids_dropped = true;
        }
    }

    /// Checks the run's tool and turns its kept results into findings.
    fn finish_run(
        &mut self,
        tool: Option<Tool>,
        kept: Vec<(SarifResult, String)>,
    ) -> Result<(), CodeQlSarifError> {
        let name = tool
            .as_ref()
            .and_then(|t| t.driver.as_ref())
            .and_then(|d| d.name.as_deref())
            .map(str::trim);
        if !name.is_some_and(|n| n.eq_ignore_ascii_case("codeql")) {
            let shown = name
                .map(|n| format!("'{}'", bounded_text(n, 80)))
                .unwrap_or_else(|| "no driver name".into());
            return Err(CodeQlSarifError::NotCodeQl(format!(
                "run {} has tool.driver.name {shown}; only CodeQL SARIF is accepted",
                self.runs_read
            )));
        }
        let Some(tool) = tool else {
            return Ok(());
        };
        let driver = tool.driver.as_ref();
        if let Some(driver) = driver {
            let version = component_version(driver);
            if self.summary.source_tool.is_none() {
                self.summary.source_tool = Some(CodeQlSourceTool {
                    name: "CodeQL".into(),
                    version: version.clone(),
                });
            }
            if let Some(version) = version
                && !self.versions.contains(&version)
            {
                self.versions.push(version);
            }
        }
        let extensions: &[Component] = tool
            .extensions
            .as_ref()
            .map(|e| e.items.as_slice())
            .unwrap_or_default();
        let driver_rules: &[Rule] = driver.map(Component::rule_list).unwrap_or_default();
        if tool.extensions.as_ref().is_some_and(CappedVec::dropped)
            || driver
                .into_iter()
                .chain(extensions)
                .any(|c| c.rules.as_ref().is_some_and(CappedVec::dropped))
        {
            self.rules_dropped = true;
        }
        let mut by_id: BTreeMap<&str, RuleView<'_>> = BTreeMap::new();
        for rule in driver_rules {
            if let Some(id) = rule.id.as_deref() {
                by_id.entry(id).or_insert(RuleView {
                    rule: Some(rule),
                    component_name: None,
                });
            }
            self.note_rule(rule.id.as_deref(), None);
        }
        for extension in extensions {
            for rule in extension.rule_list() {
                if let Some(id) = rule.id.as_deref() {
                    by_id.entry(id).or_insert(RuleView {
                        rule: Some(rule),
                        component_name: extension.name.as_deref(),
                    });
                }
                self.note_rule(rule.id.as_deref(), extension.name.as_deref());
            }
        }

        let options = self.options;
        for (result, path) in kept {
            let view = resolve_rule(&result, driver_rules, extensions, &by_id);
            let rule_id = result
                .rule_id
                .as_deref()
                .or_else(|| result.rule.as_ref().and_then(|r| r.id.as_deref()))
                .or_else(|| view.rule.and_then(|r| r.id.as_deref()))
                .and_then(|id| optional_text(Some(id), MAX_SHORT_TEXT_CHARS));
            let Some(rule_id) = rule_id else {
                self.summary.results_without_location += 1;
                continue;
            };
            let finding = build_finding(&result, &view, rule_id, path, options);
            let language = finding
                .language
                .clone()
                .unwrap_or_else(|| UNKNOWN_LANGUAGE.to_string());
            self.note_rule_id(language, finding.rule_id.clone());
            self.summary.findings.push(finding);
        }
        Ok(())
    }

    /// Adds the document-level warnings and returns the summary.
    fn finish(mut self) -> CodeQlSarifSummary {
        let warnings = &mut self.summary.warnings;
        if self.versions.len() > 1 {
            push_warning(
                warnings,
                format!(
                    "the SARIF runs were produced by different CodeQL versions: {}",
                    self.versions.join(", ")
                ),
            );
        }
        if self.summary.results_outside_workspace > 0 {
            push_warning(
                warnings,
                format!(
                    "{} result(s) dropped: their path is absolute or outside the workspace",
                    self.summary.results_outside_workspace
                ),
            );
        }
        if self.summary.results_without_location > 0 {
            push_warning(
                warnings,
                format!(
                    "{} result(s) dropped: no rule id or no file location",
                    self.summary.results_without_location
                ),
            );
        }
        if self.summary.truncated {
            push_warning(
                warnings,
                format!(
                    "findings truncated at {} (max results)",
                    self.options.max_results
                ),
            );
        }
        if self.runs_skipped > 0 {
            push_warning(
                warnings,
                format!(
                    "only the first {MAX_SARIF_RUNS} runs were read; {} later run(s) were skipped, so the findings are incomplete",
                    self.runs_skipped
                ),
            );
            self.summary.truncated = true;
        }
        if self.rules_dropped {
            push_warning(
                warnings,
                format!(
                    "rule metadata was read for at most {MAX_EXTENSIONS} tool extensions and {MAX_RULES_PER_COMPONENT} rules per tool component; results of other rules have no rule metadata"
                ),
            );
        }
        if self.rule_ids_dropped {
            push_warning(
                warnings,
                format!(
                    "at most {MAX_RULE_IDS_PER_LANGUAGE} rule ids are listed per language; the list of rules that ran is incomplete"
                ),
            );
        }
        self.summary
    }
}

/// Reads a run's `results` array, classifying every result as it is read.
struct ResultsSeed<'a, 'o> {
    sink: &'a mut Sink<'o>,
    kept: &'a mut Vec<(SarifResult, String)>,
}

impl<'de> DeserializeSeed<'de> for ResultsSeed<'_, '_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de> Visitor<'de> for ResultsSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of SARIF results")
    }

    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(result) = seq.next_element::<SarifResult>()? {
            self.sink.classify(result, self.kept);
        }
        Ok(())
    }
}

/// Reads one run and hands it to the sink when its object ends.
struct RunSeed<'a, 'o> {
    sink: &'a mut Sink<'o>,
}

impl<'de> DeserializeSeed<'de> for RunSeed<'_, '_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RunSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a SARIF run object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut tool: Option<Tool> = None;
        let mut kept: Vec<(SarifResult, String)> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "tool" => tool = map.next_value::<Option<Tool>>()?,
                "results" => map.next_value_seed(ResultsSeed {
                    sink: &mut *self.sink,
                    kept: &mut kept,
                })?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        match self.sink.finish_run(tool, kept) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.sink.rejected = Some(error);
                Err(de::Error::custom("the SARIF run was rejected"))
            }
        }
    }
}

/// Reads the `runs` array; `true` when it is an array.
struct RunsSeed<'a, 'o> {
    sink: &'a mut Sink<'o>,
}

impl<'de> DeserializeSeed<'de> for RunsSeed<'_, '_> {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de> Visitor<'de> for RunsSeed<'_, '_> {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of SARIF runs")
    }

    fn visit_none<E: de::Error>(self) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_unit<E: de::Error>(self) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        loop {
            if self.sink.runs_read < MAX_SARIF_RUNS {
                let run = seq.next_element_seed(RunSeed {
                    sink: &mut *self.sink,
                })?;
                if run.is_none() {
                    break;
                }
                self.sink.runs_read += 1;
            } else if seq.next_element::<IgnoredAny>()?.is_none() {
                break;
            } else {
                self.sink.runs_skipped += 1;
            }
        }
        Ok(true)
    }
}

/// Reads the top-level SARIF log object; `true` when it has a `runs` array.
struct RootSeed<'a, 'o> {
    sink: &'a mut Sink<'o>,
}

impl<'de> Visitor<'de> for RootSeed<'_, '_> {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a SARIF log object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut has_runs = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "runs" {
                has_runs |= map.next_value_seed(RunsSeed {
                    sink: &mut *self.sink,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(has_runs)
    }
}

/// Parses and normalises one CodeQL SARIF document in a single streaming pass.
///
/// Every run must be a CodeQL run (`sarif_not_codeql` otherwise, reported for the first
/// run that is not). At most [`MAX_SARIF_RUNS`] runs are read; results are counted as
/// they are read and only those that become findings are kept.
pub fn normalize_codeql_sarif(
    bytes: &[u8],
    options: &CodeQlSarifOptions,
) -> Result<CodeQlSarifSummary, CodeQlSarifError> {
    let mut sink = Sink::new(options);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = (&mut deserializer).deserialize_map(RootSeed { sink: &mut sink });
    let has_runs = match parsed.and_then(|has_runs| deserializer.end().map(|()| has_runs)) {
        Ok(has_runs) => has_runs,
        Err(error) => {
            return Err(sink
                .rejected
                .take()
                .unwrap_or_else(|| CodeQlSarifError::Invalid(error.to_string())));
        }
    };
    if !has_runs {
        return Err(CodeQlSarifError::Invalid(
            "the document has no `runs` array".into(),
        ));
    }
    if sink.runs_read == 0 {
        return Err(CodeQlSarifError::NotCodeQl(
            "the document contains no runs, so its tool cannot be confirmed as CodeQL".into(),
        ));
    }
    Ok(sink.finish())
}

fn index(value: Option<i64>) -> Option<usize> {
    value.and_then(|i| usize::try_from(i).ok())
}

fn resolve_rule<'a>(
    result: &SarifResult,
    driver_rules: &'a [Rule],
    extensions: &'a [Component],
    by_id: &BTreeMap<&str, RuleView<'a>>,
) -> RuleView<'a> {
    if let Some(reference) = &result.rule
        && let Some(rule_index) = index(reference.index)
    {
        match reference.tool_component.as_ref().map(|c| index(c.index)) {
            Some(Some(component)) => {
                if let Some(extension) = extensions.get(component)
                    && let Some(rule) = extension.rule_list().get(rule_index)
                {
                    return RuleView {
                        rule: Some(rule),
                        component_name: extension.name.as_deref(),
                    };
                }
            }
            Some(None) => {}
            None => {
                if let Some(rule) = driver_rules.get(rule_index) {
                    return RuleView {
                        rule: Some(rule),
                        component_name: None,
                    };
                }
            }
        }
    }
    if let Some(rule_index) = index(result.rule_index)
        && let Some(rule) = driver_rules.get(rule_index)
    {
        return RuleView {
            rule: Some(rule),
            component_name: None,
        };
    }
    let id = result
        .rule_id
        .as_deref()
        .or_else(|| result.rule.as_ref().and_then(|r| r.id.as_deref()));
    if let Some(view) = id.and_then(|id| by_id.get(id)) {
        return RuleView {
            rule: view.rule,
            component_name: view.component_name,
        };
    }
    RuleView {
        rule: None,
        component_name: None,
    }
}

/// A partial fingerprint value Sentra keeps: non-empty printable ASCII, at most 96 bytes.
fn fingerprint_part(value: &LenientString) -> Option<&str> {
    value
        .0
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty() && f.len() <= 96 && f.chars().all(|c| c.is_ascii_graphic()))
}

/// Fingerprint of a result: `primaryLocationLineHash`, joined with `|` to
/// `primaryLocationStartColumnFingerprint` (or, without that, to `c<start column>`), so
/// two results of one rule on one line stay apart; without a line hash, the
/// [`fallback_fingerprint`].
pub fn codeql_result_fingerprint(
    line_hash: Option<&str>,
    start_column_fingerprint: Option<&str>,
    start_column: Option<u32>,
    fallback: impl FnOnce() -> String,
) -> String {
    match (line_hash, start_column_fingerprint, start_column) {
        (Some(line), Some(column), _) => format!("{line}|{column}"),
        (Some(line), None, Some(column)) => format!("{line}|c{column}"),
        (Some(line), None, None) => line.to_string(),
        (None, ..) => fallback(),
    }
}

fn build_finding(
    result: &SarifResult,
    view: &RuleView<'_>,
    rule_id: String,
    path: String,
    options: &CodeQlSarifOptions,
) -> CodeQlFinding {
    let rule = view.rule;
    let rule_properties = rule.and_then(|r| r.properties.as_ref());
    let security_severity = valid_score(
        result
            .properties
            .as_ref()
            .and_then(|p| p.security_severity.0),
    )
    .or_else(|| valid_score(rule_properties.and_then(|p| p.security_severity.0)));
    let problem_severity = optional_text(
        rule_properties.and_then(|p| p.problem_severity.0.as_deref()),
        64,
    );
    let precision = optional_text(rule_properties.and_then(|p| p.precision.0.as_deref()), 64);
    let level = result.level.as_deref().or_else(|| {
        rule.and_then(|r| r.default_configuration.as_ref())
            .and_then(|c| c.level.as_deref())
    });
    let severity = codeql_severity(security_severity, problem_severity.as_deref(), level);
    let tags = rule_tags(rule);
    let cwe = cwe_ids_from_tags(&tags);
    let rule_name = optional_text(
        rule_properties.and_then(|p| p.name.0.as_deref()),
        MAX_SHORT_TEXT_CHARS,
    )
    .or_else(|| {
        optional_text(
            rule.and_then(|r| r.short_description.as_ref())
                .and_then(|d| d.text.as_deref()),
            MAX_SHORT_TEXT_CHARS,
        )
    })
    .or_else(|| {
        optional_text(rule.and_then(|r| r.name.as_deref()), MAX_SHORT_TEXT_CHARS)
            .filter(|name| *name != rule_id)
    });
    let message = optional_text(
        result.message.as_ref().and_then(|m| m.text.as_deref()),
        MAX_MESSAGE_CHARS,
    )
    .or_else(|| rule_name.clone())
    .unwrap_or_else(|| rule_id.clone());
    let region = result.physical_location().and_then(|p| p.region.as_ref());
    let start_line = region
        .and_then(|r| r.start_line)
        .filter(|l| *l >= 1)
        .unwrap_or(1);
    let end_line = region
        .and_then(|r| r.end_line)
        .filter(|l| *l >= start_line)
        .unwrap_or(start_line);
    let start_column = region.and_then(|r| r.start_column);
    let end_column = region.and_then(|r| r.end_column);
    let fingerprints = result.partial_fingerprints.as_ref();
    let fingerprint = codeql_result_fingerprint(
        fingerprints.and_then(|f| fingerprint_part(&f.line_hash)),
        fingerprints.and_then(|f| fingerprint_part(&f.start_column)),
        start_column,
        || fallback_fingerprint(&rule_id, &path, start_line, &message),
    );
    let help_uri = optional_text(rule.and_then(|r| r.help_uri.as_deref()), 2_000)
        .filter(|uri| uri.starts_with("https://") || uri.starts_with("http://"));
    let language =
        codeql_language_hint(&rule_id, view.component_name).or(options.default_language.clone());
    CodeQlFinding {
        rule_id,
        rule_name,
        message,
        severity,
        security_severity,
        problem_severity,
        precision,
        cwe,
        tags,
        path,
        start_line,
        end_line,
        start_column,
        end_column,
        fingerprint,
        help_uri,
        language,
    }
}

/// Outcome of one language in a host analysis or import.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeQlLanguageStatus {
    /// Analysed (for an import: present in the imported SARIF).
    Analyzed,
    /// Not analysed; `reason` says why.
    Skipped,
    /// Analysis was attempted and failed; `reason` says how.
    Failed,
}

/// `languages[]` entry of the JSON contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQlLanguageOutcome {
    /// CodeQL language id.
    pub language: String,
    /// Outcome.
    pub status: CodeQlLanguageStatus,
    /// Why the language was skipped or failed; `None` when analysed.
    pub reason: Option<String>,
    /// Results kept for this language.
    pub results: usize,
    /// Time spent on this language (host analysis only).
    pub duration_ms: Option<u64>,
    /// Rule ids CodeQL ran for this language, sorted (empty when it was skipped or
    /// failed). CodeQL lists every query it ran in the SARIF, including queries without
    /// results, so a consumer can resolve earlier findings of exactly these rules.
    #[serde(default)]
    pub rules: Vec<String>,
}

/// JSON document printed by `sentra codeql analyze --json` and `sentra codeql import --json`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CodeQlResultReport {
    /// Always 1.
    pub schema_version: u8,
    /// `codeql analyze` or `codeql import`.
    pub command: &'static str,
    /// Workspace path (forward slashes).
    pub workspace: String,
    /// Version reported by the CodeQL CLI Sentra ran (`None` for imports).
    pub codeql_version: Option<String>,
    /// Query suite (`code-scanning` or `security-extended`; `None` for imports).
    pub suite: Option<String>,
    /// Whether query packs could be downloaded.
    pub pack_download_allowed: bool,
    /// Always false: Sentra runs CodeQL only in build-mode none and never builds or
    /// runs the project (see ADR-0011 for what this does and does not cover).
    pub target_code_executed: bool,
    /// Per-language outcome.
    pub languages: Vec<CodeQlLanguageOutcome>,
    /// Normalised findings (candidate claims).
    pub findings: Vec<CodeQlFinding>,
    /// Every SARIF result seen.
    pub results_total: usize,
    /// Results dropped because their path is absolute or escapes the workspace.
    pub results_outside_workspace: usize,
    /// Whether findings were cut at `--max-results`.
    pub truncated: bool,
    /// Notes for the operator.
    pub warnings: Vec<String>,
    /// Driver of the SARIF (`CodeQL` and its version).
    pub source_tool: Option<CodeQlSourceTool>,
}

/// Normalises a CodeQL SARIF file produced elsewhere for `sentra codeql import`.
///
/// The file is limited to [`CODEQL_SARIF_MAX_BYTES`]; `workspace` must be an existing
/// directory and is only used as the root the SARIF paths are relative to. Every
/// language the SARIF ran rules for or has findings of is listed with status
/// `analyzed`, its result count and the rules that ran, so a SARIF whose results are
/// all gone still lists its languages.
pub fn import_codeql_sarif(
    sarif: &Path,
    workspace: &Path,
    max_results: usize,
) -> Result<CodeQlResultReport, CodeQlSarifError> {
    let bytes = read_sarif_file(sarif, CODEQL_SARIF_MAX_BYTES)?;
    let summary = normalize_codeql_sarif(
        &bytes,
        &CodeQlSarifOptions {
            max_results,
            default_language: None,
        },
    )?;
    let mut counts: BTreeMap<String, usize> = summary
        .rule_ids
        .keys()
        .map(|language| (language.clone(), 0))
        .collect();
    for finding in &summary.findings {
        let language = finding
            .language
            .clone()
            .unwrap_or_else(|| UNKNOWN_LANGUAGE.to_string());
        *counts.entry(language).or_default() += 1;
    }
    let languages = counts
        .into_iter()
        .map(|(language, results)| CodeQlLanguageOutcome {
            rules: summary
                .rule_ids
                .get(&language)
                .map(|ids| ids.iter().cloned().collect())
                .unwrap_or_default(),
            language,
            status: CodeQlLanguageStatus::Analyzed,
            reason: None,
            results,
            duration_ms: None,
        })
        .collect();
    Ok(CodeQlResultReport {
        schema_version: 1,
        command: "codeql import",
        workspace: display_path(workspace),
        codeql_version: None,
        suite: None,
        pack_download_allowed: false,
        target_code_executed: false,
        languages,
        findings: summary.findings,
        results_total: summary.results_total,
        results_outside_workspace: summary.results_outside_workspace,
        truncated: summary.truncated,
        warnings: summary.warnings,
        source_tool: summary.source_tool,
    })
}

/// Display form of a path: no Windows `\\?\` verbatim prefix, forward slashes.
pub(crate) fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let plain = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text.into_owned()
    };
    plain.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_thresholds_follow_github() {
        assert_eq!(
            codeql_severity(Some(9.0), None, None),
            CodeQlSeverity::Critical
        );
        assert_eq!(codeql_severity(Some(8.9), None, None), CodeQlSeverity::High);
        assert_eq!(codeql_severity(Some(7.0), None, None), CodeQlSeverity::High);
        assert_eq!(
            codeql_severity(Some(6.9), None, None),
            CodeQlSeverity::Medium
        );
        assert_eq!(
            codeql_severity(Some(4.0), None, None),
            CodeQlSeverity::Medium
        );
        assert_eq!(codeql_severity(Some(3.9), None, None), CodeQlSeverity::Low);
        assert_eq!(codeql_severity(Some(0.1), None, None), CodeQlSeverity::Low);
        assert_eq!(codeql_severity(Some(0.0), None, None), CodeQlSeverity::Info);
        // The score wins over problem.severity.
        assert_eq!(
            codeql_severity(Some(9.8), Some("recommendation"), Some("note")),
            CodeQlSeverity::Critical
        );
        assert_eq!(
            codeql_severity(None, Some("error"), None),
            CodeQlSeverity::Medium
        );
        assert_eq!(
            codeql_severity(None, Some("warning"), None),
            CodeQlSeverity::Low
        );
        assert_eq!(
            codeql_severity(None, Some("recommendation"), Some("error")),
            CodeQlSeverity::Info
        );
        assert_eq!(
            codeql_severity(None, None, Some("error")),
            CodeQlSeverity::Medium
        );
        assert_eq!(
            codeql_severity(None, None, Some("note")),
            CodeQlSeverity::Info
        );
        assert_eq!(codeql_severity(None, None, None), CodeQlSeverity::Low);
    }

    #[test]
    fn cwe_tags_are_normalised_and_deduplicated() {
        let tags = [
            "security",
            "external/cwe/cwe-079",
            "external/cwe/cwe-79",
            "external/cwe/cwe-116",
            "external/cwe/cwe-",
            "external/cwe/cwe-12a",
            "External/CWE/CWE-0022",
        ];
        assert_eq!(cwe_ids_from_tags(&tags), ["CWE-79", "CWE-116", "CWE-22"]);
    }

    #[test]
    fn uris_must_stay_inside_the_workspace() {
        assert_eq!(
            workspace_relative_uri("src/app.js").as_deref(),
            Some("src/app.js")
        );
        assert_eq!(
            workspace_relative_uri("./src//a.py").as_deref(),
            Some("src/a.py")
        );
        assert_eq!(
            workspace_relative_uri("src\\win\\a.cs").as_deref(),
            Some("src/win/a.cs")
        );
        assert_eq!(workspace_relative_uri("a/../b.rb").as_deref(), Some("b.rb"));
        assert_eq!(
            workspace_relative_uri("my%20dir/a%2Bb.js").as_deref(),
            Some("my dir/a+b.js")
        );
        assert_eq!(
            workspace_relative_uri("src/a:b.js").as_deref(),
            Some("src/a:b.js")
        );
        for rejected in [
            "",
            "/etc/passwd",
            "//server/share/a.js",
            "\\\\server\\share\\a.js",
            "file:///C:/repo/a.js",
            "C:/repo/a.js",
            "C:\\repo\\a.js",
            "c:a.js",
            "https://example.com/a.js",
            "../outside.js",
            "a/../../outside.js",
            "%2e%2e/outside.js",
            "..%2fescape.js",
            "%ZZ.js",
            ".",
            "a/..",
        ] {
            assert_eq!(workspace_relative_uri(rejected), None, "{rejected:?}");
        }
    }

    #[test]
    fn fallback_fingerprint_is_stable_and_separated() {
        let a = fallback_fingerprint("js/x", "a.js", 3, "m");
        assert_eq!(a, fallback_fingerprint("js/x", "a.js", 3, "m"));
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, fallback_fingerprint("js/x", "a.js", 4, "m"));
        // NUL separators keep field boundaries apart.
        assert_ne!(
            fallback_fingerprint("ab", "c", 1, "m"),
            fallback_fingerprint("a", "bc", 1, "m")
        );
    }

    #[test]
    fn language_hints_come_from_packs_or_rule_prefixes() {
        assert_eq!(
            codeql_language_hint("x/y", Some("codeql/python-queries")).as_deref(),
            Some("python")
        );
        assert_eq!(
            codeql_language_hint("js/xss", None).as_deref(),
            Some("javascript")
        );
        assert_eq!(
            codeql_language_hint("cs/sql", None).as_deref(),
            Some("csharp")
        );
        assert_eq!(codeql_language_hint("custom/rule", None), None);
    }

    #[test]
    fn bounded_text_strips_controls_and_truncates() {
        assert_eq!(bounded_text("a\u{1b}[31mb\nc", 100), "a[31mb\nc");
        assert_eq!(bounded_text("abcdef", 3), "abc...");
    }
}
