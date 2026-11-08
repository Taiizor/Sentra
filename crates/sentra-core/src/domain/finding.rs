//! Domain models for security findings, vulnerability classifications, and reachability.
//!
//! Complies with requirements:
//! - F-05: Normalized scanner and agent signals with provenance.
//! - F-06: Explicit finding status machine (Candidate, Validated, Rejected, Inconclusive) with transition reasons.
//! - F-07: Separation of dependency presence from demonstrated runtime reachability.
//! - F-10: Separation of exploitability and impact from confidence and severity.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

use crate::{
    domain::{
        error::DomainError,
        id::{FindingId, SessionId, TaskId},
        time::TimestampUtc,
    },
    storage::BlobId,
};

/// Severity classification for security findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Informational finding with no immediate security impact.
    Informational = 0,
    /// Low severity security risk or minor hygiene issue.
    Low = 1,
    /// Medium severity risk under specific conditions.
    Medium = 2,
    /// High severity vulnerability likely exploitable.
    High = 3,
    /// Critical severity vulnerability allowing arbitrary takeover or catastrophic impact.
    Critical = 4,
}

impl Severity {
    /// Returns the uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "INFORMATIONAL",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Confidence level in a reported candidate finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    /// Preliminary or heuristic detection requiring validation.
    Tentative = 0,
    /// Confirmed via pattern or standard advisory rule match.
    Confirmed = 1,
    /// High confidence backed by structural evidence or multiple independent indicators.
    High = 2,
}

impl Confidence {
    /// Returns the uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tentative => "TENTATIVE",
            Self::Confirmed => "CONFIRMED",
            Self::High => "HIGH",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Demonstrated reachability of a vulnerable component (Requirement F-07).
///
/// Dependency presence in a package manifest or lockfile must remain strictly
/// distinct from demonstrated runtime reachability or execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reachability {
    /// Present in dependencies/lockfile only; no code execution or import proved.
    PresentOnly = 0,
    /// Syntactically imported or referenced in target code.
    SyntacticallyReferenced = 1,
    /// Reachable via static call graph from an active execution path.
    ReachableCallPath = 2,
    /// Dynamically triggered or demonstrated in execution/PoC.
    DemonstratedRuntime = 3,
    /// Reachability could not be evaluated or remains unknown.
    Unknown = 4,
}

impl Reachability {
    /// Returns the uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PresentOnly => "PRESENT_ONLY",
            Self::SyntacticallyReferenced => "SYNTACTICALLY_REFERENCED",
            Self::ReachableCallPath => "REACHABLE_CALL_PATH",
            Self::DemonstratedRuntime => "DEMONSTRATED_RUNTIME",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for Reachability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Lifecycle status of a security finding (Requirement F-06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingStatus {
    /// Initial signal emitted by scanner, advisory check, or agent before independent verification.
    Candidate = 0,
    /// Verified by independent test oracle, PoC, or dynamic execution.
    Validated = 1,
    /// Confirmed to be false positive, mitigated, or inapplicable.
    Rejected = 2,
    /// Analysis inconclusive; neither validated nor rejected.
    Inconclusive = 3,
}

impl FindingStatus {
    /// Returns the uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::Validated => "VALIDATED",
            Self::Rejected => "REJECTED",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Record of an authoritative state transition for a finding (Requirement F-06).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusTransitionEntry {
    /// Origin status prior to the transition.
    pub from: FindingStatus,
    /// Destination status resulting from the transition.
    pub to: FindingStatus,
    /// Mandatory justification or empirical reason for the transition.
    pub reason: String,
    /// Timestamp when the transition was evaluated and applied.
    pub timestamp: TimestampUtc,
}

#[derive(Serialize, Deserialize)]
struct StatusTransitionPayload {
    from: FindingStatus,
    to: FindingStatus,
    reason: String,
    timestamp: String,
}

impl Serialize for StatusTransitionEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = StatusTransitionPayload {
            from: self.from,
            to: self.to,
            reason: self.reason.clone(),
            timestamp: self.timestamp.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StatusTransitionEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = StatusTransitionPayload::deserialize(deserializer)?;
        let timestamp =
            TimestampUtc::from_str(&payload.timestamp).map_err(serde::de::Error::custom)?;
        Ok(Self {
            from: payload.from,
            to: payload.to,
            reason: payload.reason,
            timestamp,
        })
    }
}

/// Source provenance of a finding (Requirement F-05).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum FindingSource {
    /// RustSec / Cargo.lock advisory matching.
    CargoLockAdvisory {
        /// Identifier of the security advisory (e.g. `RUSTSEC-2023-0001`).
        advisory_id: String,
        /// Name of the affected package.
        package: String,
        /// Version of the package found in the manifest or lockfile.
        version: String,
    },
    /// Static code analysis engine or scanner.
    StaticAnalysis {
        /// Name of the static analysis engine (e.g. `semgrep`).
        engine: String,
        /// Rule identifier that matched.
        rule_id: String,
    },
    /// Dynamic research agent or fuzzer.
    DynamicAnalysis {
        /// Role of the discovering agent.
        agent_role: String,
        /// Test oracle or reproduction identifier.
        oracle_id: String,
    },
    /// Manual operator finding.
    Manual {
        /// Username or identifier of the operator.
        author: String,
    },
}

/// Location of a finding within the target codebase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetLocation {
    /// Canonical workspace-relative file path.
    pub path: String,
    /// Starting line number (1-based, inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    /// Ending line number (1-based, inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
}

/// Normalized, evidence-backed security finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    id: FindingId,
    session_id: SessionId,
    task_id: TaskId,
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    reachability: Reachability,
    status: FindingStatus,
    source: FindingSource,
    location: Option<TargetLocation>,
    evidence_blob_id: Option<BlobId>,
    history: Vec<StatusTransitionEntry>,
    created_at: TimestampUtc,
    updated_at: TimestampUtc,
}

#[derive(Serialize, Deserialize)]
struct FindingPayload {
    id: String,
    session_id: String,
    task_id: String,
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    reachability: Reachability,
    status: FindingStatus,
    source: FindingSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<TargetLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_blob_id: Option<String>,
    history: Vec<StatusTransitionEntry>,
    created_at: String,
    updated_at: String,
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = FindingPayload {
            id: self.id.to_string(),
            session_id: self.session_id.to_string(),
            task_id: self.task_id.to_string(),
            title: self.title.clone(),
            description: self.description.clone(),
            severity: self.severity,
            confidence: self.confidence,
            reachability: self.reachability,
            status: self.status,
            source: self.source.clone(),
            location: self.location.clone(),
            evidence_blob_id: self.evidence_blob_id.as_ref().map(|b| b.to_string()),
            history: self.history.clone(),
            created_at: self.created_at.to_string(),
            updated_at: self.updated_at.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = FindingPayload::deserialize(deserializer)?;
        let id = FindingId::from_str(&payload.id).map_err(serde::de::Error::custom)?;
        let session_id =
            SessionId::from_str(&payload.session_id).map_err(serde::de::Error::custom)?;
        let task_id = TaskId::from_str(&payload.task_id).map_err(serde::de::Error::custom)?;
        let evidence_blob_id = match payload.evidence_blob_id {
            Some(s) => Some(BlobId::from_str(&s).map_err(serde::de::Error::custom)?),
            None => None,
        };
        let created_at =
            TimestampUtc::from_str(&payload.created_at).map_err(serde::de::Error::custom)?;
        let updated_at =
            TimestampUtc::from_str(&payload.updated_at).map_err(serde::de::Error::custom)?;

        Ok(Self {
            id,
            session_id,
            task_id,
            title: payload.title,
            description: payload.description,
            severity: payload.severity,
            confidence: payload.confidence,
            reachability: payload.reachability,
            status: payload.status,
            source: payload.source,
            location: payload.location,
            evidence_blob_id,
            history: payload.history,
            created_at,
            updated_at,
        })
    }
}

impl Finding {
    /// Creates a new candidate finding with initial provenance and reachability classification.
    #[allow(clippy::too_many_arguments)]
    pub fn new_candidate(
        id: FindingId,
        session_id: SessionId,
        task_id: TaskId,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        reachability: Reachability,
        source: FindingSource,
        location: Option<TargetLocation>,
        evidence_blob_id: Option<BlobId>,
        created_at: TimestampUtc,
    ) -> Self {
        Self {
            id,
            session_id,
            task_id,
            title: title.into(),
            description: description.into(),
            severity,
            confidence,
            reachability,
            status: FindingStatus::Candidate,
            source,
            location,
            evidence_blob_id,
            history: Vec::new(),
            created_at,
            updated_at: created_at,
        }
    }

    /// Returns the unique finding identifier.
    pub fn id(&self) -> FindingId {
        self.id
    }

    /// Returns the session ID within which the finding was recorded.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the task ID that produced the finding.
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the concise finding title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the detailed vulnerability description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the assessed severity level.
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the confidence level in this finding.
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the demonstrated reachability level.
    pub fn reachability(&self) -> Reachability {
        self.reachability
    }

    /// Returns the current finding status.
    pub fn status(&self) -> FindingStatus {
        self.status
    }

    /// Returns the finding source provenance.
    pub fn source(&self) -> &FindingSource {
        &self.source
    }

    /// Returns the target code location, if applicable.
    pub fn location(&self) -> Option<&TargetLocation> {
        self.location.as_ref()
    }

    /// Returns the content-addressed evidence blob identifier, if stored.
    pub fn evidence_blob_id(&self) -> Option<&BlobId> {
        self.evidence_blob_id.as_ref()
    }

    /// Returns the audit history of status transitions.
    pub fn history(&self) -> &[StatusTransitionEntry] {
        &self.history
    }

    /// Returns the timestamp when the finding was created.
    pub fn created_at(&self) -> TimestampUtc {
        self.created_at
    }

    /// Returns the timestamp when the finding was last updated.
    pub fn updated_at(&self) -> TimestampUtc {
        self.updated_at
    }

    /// Transitions the finding status, recording the mandatory justification reason (Requirement F-06).
    pub fn transition_status(
        &mut self,
        new_status: FindingStatus,
        reason: impl Into<String>,
        now: TimestampUtc,
    ) -> Result<(), DomainError> {
        let reason_str = reason.into();
        if reason_str.trim().is_empty() {
            return Err(DomainError::InvalidMetadata(
                "A non-empty justification reason is required for finding status transitions"
                    .to_string(),
            ));
        }

        if self.status == new_status {
            return Ok(());
        }

        let entry = StatusTransitionEntry {
            from: self.status,
            to: new_status,
            reason: reason_str,
            timestamp: now,
        };

        self.status = new_status;
        self.history.push(entry);
        self.updated_at = now;
        Ok(())
    }

    /// Updates demonstrated reachability (e.g. from PresentOnly to ReachableCallPath or DemonstratedRuntime).
    pub fn update_reachability(&mut self, reachability: Reachability, now: TimestampUtc) {
        self.reachability = reachability;
        self.updated_at = now;
    }
}
