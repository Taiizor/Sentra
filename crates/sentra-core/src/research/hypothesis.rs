//! Vulnerability hypotheses, fingerprinting, and deduplication (REQ-F04, REQ-F05, Autonomous Research Specification).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, str::FromStr};

use crate::{
    common::crypto::sha256_prefixed,
    domain::{
        finding::Confidence,
        id::{CampaignId, HypothesisId, TaskId},
        time::TimestampUtc,
    },
    research::error::ResearchError,
};

/// Specific category of software vulnerability hypothesized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityCategory {
    /// Out-of-bounds write or read on stack or heap buffer (CWE-119 / CWE-120).
    BufferOverflow,
    /// Dereference of memory after it has been freed (CWE-416).
    UseAfterFree,
    /// Arithmetic overflow or underflow leading to wraparound or truncate (CWE-190).
    IntegerOverflow,
    /// Dereference of null pointer causing panic or denial of service (CWE-476).
    NullPointerDereference,
    /// Unsanitized input constructed into OS system command (CWE-78).
    CommandInjection,
    /// Unescaped query parameter injection (CWE-89).
    SqlInjection,
    /// Path manipulation allowing file system escape (CWE-22).
    PathTraversal,
    /// Server-side request forgery to internal endpoints (CWE-918).
    Ssrf,
    /// Authentication or authorization control bypass (CWE-287 / CWE-306).
    AuthenticationBypass,
    /// Sensitive data or secret leak in error/response (CWE-200).
    InformationDisclosure,
    /// Format string specifier vulnerability (CWE-134).
    FormatString,
    /// Concurrency or time-of-check to time-of-use flaw (CWE-362).
    RaceCondition,
    /// Business logic or state machine violation.
    LogicFlaw,
    /// CI/CD workflow, runner takeover, or supply chain manipulation flaw (CWE-829 / CWE-284).
    CiCdPipelineFlaw,
    /// Cryptographic failure, weak algorithm, or side-channel leak (OWASP A04:2025 / CWE-327 / CWE-208).
    CryptographicFailure,
    /// Broken access control, IDOR, or BOLA/BFLA (OWASP A01:2025 / CWE-284 / CWE-639).
    BrokenAccessControl,
    /// Prompt injection, jailbreak, or agent guardrail bypass (OWASP LLM01 / CWE-693).
    AgentPromptInjection,
    /// Mishandling of exceptional conditions or fail-open behavior (OWASP A10:2025 / CWE-754).
    MishandledExceptions,
}

impl VulnerabilityCategory {
    /// Returns a static string representation of the category.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BufferOverflow => "buffer_overflow",
            Self::UseAfterFree => "use_after_free",
            Self::IntegerOverflow => "integer_overflow",
            Self::NullPointerDereference => "null_pointer_dereference",
            Self::CommandInjection => "command_injection",
            Self::SqlInjection => "sql_injection",
            Self::PathTraversal => "path_traversal",
            Self::Ssrf => "ssrf",
            Self::AuthenticationBypass => "authentication_bypass",
            Self::InformationDisclosure => "information_disclosure",
            Self::FormatString => "format_string",
            Self::RaceCondition => "race_condition",
            Self::LogicFlaw => "logic_flaw",
            Self::CiCdPipelineFlaw => "cicd_pipeline_flaw",
            Self::CryptographicFailure => "cryptographic_failure",
            Self::BrokenAccessControl => "broken_access_control",
            Self::AgentPromptInjection => "agent_prompt_injection",
            Self::MishandledExceptions => "mishandled_exceptions",
        }
    }
}

/// Lifecycle status of an individual vulnerability hypothesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    /// Hypothesis formulated and ready for prioritization.
    Proposed,
    /// Currently being investigated or tested with a PoC.
    Investigating,
    /// Successfully reproduced and confirmed with executable evidence.
    Reproduced,
    /// Evaluated and proven to be benign or unreachable.
    Refuted,
    /// Investigation concluded without definitive proof either way.
    Inconclusive,
}

/// Falsifiable vulnerability hypothesis generated during research exploration (REQ-F04).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hypothesis {
    /// Unique identifier for this hypothesis.
    pub id: HypothesisId,
    /// Research campaign managing this hypothesis.
    pub campaign_id: CampaignId,
    /// Task that formulated this hypothesis.
    pub created_by_task: TaskId,
    /// Hypothesized vulnerability category.
    pub category: VulnerabilityCategory,
    /// Target file path relative to workspace root.
    pub target_file: String,
    /// Optional symbol or function name.
    pub target_symbol: Option<String>,
    /// Optional line number.
    pub target_line: Option<u32>,
    /// Stated precondition required to trigger the vulnerability.
    pub precondition: String,
    /// Expected security impact if the hypothesis is true.
    pub expected_impact: String,
    /// Observable oracle description (e.g. crash signal, memory error, panic message).
    pub oracle_description: String,
    /// Current investigation status.
    pub status: HypothesisStatus,
    /// Subjective confidence assessment.
    pub confidence: Confidence,
    /// Deterministic canonical fingerprint for deduplication.
    pub fingerprint: String,
    /// Formulation timestamp.
    pub created_at: TimestampUtc,
}

impl Hypothesis {
    /// Computes a canonical SHA-256 fingerprint for this target and category.
    pub fn compute_fingerprint(
        target_file: &str,
        target_symbol: Option<&str>,
        target_line: Option<u32>,
        category: VulnerabilityCategory,
    ) -> String {
        let sym = target_symbol.unwrap_or("");
        let line = target_line.map(|l| l.to_string()).unwrap_or_default();
        let payload = format!("{}:{}:{}:{}", target_file, sym, line, category.as_str());
        sha256_prefixed(payload.as_bytes())
    }

    /// Constructs a new hypothesis with computed fingerprint.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign_id: CampaignId,
        created_by_task: TaskId,
        category: VulnerabilityCategory,
        target_file: impl Into<String>,
        target_symbol: Option<String>,
        target_line: Option<u32>,
        precondition: impl Into<String>,
        expected_impact: impl Into<String>,
        oracle_description: impl Into<String>,
        confidence: Confidence,
        now: TimestampUtc,
    ) -> Self {
        let file = target_file.into();
        let fp = Self::compute_fingerprint(&file, target_symbol.as_deref(), target_line, category);

        Self {
            id: HypothesisId::new(),
            campaign_id,
            created_by_task,
            category,
            target_file: file,
            target_symbol,
            target_line,
            precondition: precondition.into(),
            expected_impact: expected_impact.into(),
            oracle_description: oracle_description.into(),
            status: HypothesisStatus::Proposed,
            confidence,
            fingerprint: fp,
            created_at: now,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct HypothesisPayload {
    id: String,
    campaign_id: String,
    created_by_task: String,
    category: VulnerabilityCategory,
    target_file: String,
    target_symbol: Option<String>,
    target_line: Option<u32>,
    precondition: String,
    expected_impact: String,
    oracle_description: String,
    status: HypothesisStatus,
    confidence: Confidence,
    fingerprint: String,
    created_at: String,
}

impl Serialize for Hypothesis {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = HypothesisPayload {
            id: self.id.to_string(),
            campaign_id: self.campaign_id.to_string(),
            created_by_task: self.created_by_task.to_string(),
            category: self.category,
            target_file: self.target_file.clone(),
            target_symbol: self.target_symbol.clone(),
            target_line: self.target_line,
            precondition: self.precondition.clone(),
            expected_impact: self.expected_impact.clone(),
            oracle_description: self.oracle_description.clone(),
            status: self.status,
            confidence: self.confidence,
            fingerprint: self.fingerprint.clone(),
            created_at: self.created_at.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Hypothesis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = HypothesisPayload::deserialize(deserializer)?;
        let id = HypothesisId::from_str(&payload.id).map_err(serde::de::Error::custom)?;
        let campaign_id =
            CampaignId::from_str(&payload.campaign_id).map_err(serde::de::Error::custom)?;
        let created_by_task =
            TaskId::from_str(&payload.created_by_task).map_err(serde::de::Error::custom)?;
        let created_at =
            TimestampUtc::from_str(&payload.created_at).map_err(serde::de::Error::custom)?;

        Ok(Self {
            id,
            campaign_id,
            created_by_task,
            category: payload.category,
            target_file: payload.target_file,
            target_symbol: payload.target_symbol,
            target_line: payload.target_line,
            precondition: payload.precondition,
            expected_impact: payload.expected_impact,
            oracle_description: payload.oracle_description,
            status: payload.status,
            confidence: payload.confidence,
            fingerprint: payload.fingerprint,
            created_at,
        })
    }
}

/// Deduplication registry ensuring unique investigation paths across research tasks (REQ-F05).
#[derive(Clone, Debug, Default)]
pub struct HypothesisDeduplicator {
    fingerprints: HashMap<String, HypothesisId>,
}

impl HypothesisDeduplicator {
    /// Creates an empty deduplicator.
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }

    /// Checks if a hypothesis has already been registered.
    pub fn is_duplicate(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains_key(fingerprint)
    }

    /// Registers a hypothesis, failing closed if a duplicate fingerprint already exists.
    pub fn register(&mut self, hypothesis: &Hypothesis) -> Result<(), ResearchError> {
        if let Some(existing_id) = self.fingerprints.get(&hypothesis.fingerprint) {
            return Err(ResearchError::duplicate_hypothesis(
                existing_id.to_string(),
                &hypothesis.fingerprint,
            ));
        }

        self.fingerprints
            .insert(hypothesis.fingerprint.clone(), hypothesis.id);
        Ok(())
    }

    /// Returns the number of unique hypotheses tracked.
    pub fn count(&self) -> usize {
        self.fingerprints.len()
    }
}
