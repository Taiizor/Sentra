use super::{CheckpointResult, PersistenceError, PersistenceErrorKind as Kind};
use crate::{
    ApprovalId, AssessmentCompleteness, CostUsd, EventId, Identifier, OperatingMode,
    OperationAction, SecurityClassification, SessionId, SessionMetadata, SessionState,
    TimestampUtc,
};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, sync::Arc};

pub(super) fn invalid() -> PersistenceError {
    PersistenceError::new(Kind::InvalidValue)
}
pub(super) fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}
pub(super) fn integer(value: u64) -> Result<i64, PersistenceError> {
    i64::try_from(value).map_err(|_| invalid())
}
pub(super) fn unsigned(value: i64) -> Result<u64, PersistenceError> {
    u64::try_from(value).map_err(|_| invalid())
}
pub(super) fn time_text(time: TimestampUtc) -> Result<String, PersistenceError> {
    if time.as_epoch_millis() > 253_402_300_799_999 {
        return Err(invalid());
    }
    Ok(time.to_rfc3339())
}
pub(super) fn parse_time(value: &str) -> Result<TimestampUtc, PersistenceError> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || !bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            19 => *b == b'.',
            23 => *b == b'Z',
            _ => b.is_ascii_digit(),
        })
        || &value[..4] < "1970"
    {
        return Err(invalid());
    }
    let time = TimestampUtc::from_rfc3339(value).map_err(|_| invalid())?;
    if time_text(time)? != value {
        return Err(invalid());
    }
    Ok(time)
}
pub(super) fn parse_id(value: &str) -> Result<Identifier, PersistenceError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(invalid());
    }
    let id = Identifier::from_str(value).map_err(|_| invalid())?;
    if id.as_bytes().iter().all(|byte| *byte == 0) || id.to_string() != value {
        return Err(invalid());
    }
    Ok(id)
}
pub(super) fn event_text(id: EventId) -> Result<String, PersistenceError> {
    parse_id(&id.to_string())?;
    Ok(id.to_string())
}
pub(super) fn class(value: &str) -> Result<SecurityClassification, PersistenceError> {
    let class = SecurityClassification::from_str(value).map_err(|_| invalid())?;
    if class.as_str() != value {
        return Err(invalid());
    }
    Ok(class)
}
pub(super) fn state(value: &str) -> Result<SessionState, PersistenceError> {
    [
        SessionState::Created,
        SessionState::Scoped,
        SessionState::Planned,
        SessionState::Running,
        SessionState::WaitingForApproval,
        SessionState::Paused,
        SessionState::Completed,
        SessionState::Failed,
        SessionState::Cancelled,
    ]
    .into_iter()
    .find(|state| state.as_str() == value)
    .ok_or_else(invalid)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MetadataDto {
    session_id: String,
    created_at: String,
    workspace_root: String,
    mode: String,
    operator_id: String,
    policy_digest: String,
    completeness: String,
}
impl MetadataDto {
    pub fn from_domain(metadata: &SessionMetadata) -> Result<Self, PersistenceError> {
        parse_id(&metadata.session_id.to_string())?;
        if !valid_text(&metadata.workspace_root)
            || !valid_text(&metadata.operator_id)
            || !valid_text(&metadata.policy_digest)
        {
            return Err(invalid());
        }
        Ok(Self {
            session_id: metadata.session_id.to_string(),
            created_at: time_text(metadata.created_at_utc)?,
            workspace_root: metadata.workspace_root.clone(),
            mode: metadata.operating_mode.as_str().into(),
            operator_id: metadata.operator_id.clone(),
            policy_digest: metadata.policy_digest.clone(),
            completeness: metadata.completeness.as_str().into(),
        })
    }
    pub fn domain(&self) -> Result<SessionMetadata, PersistenceError> {
        let mode = match self.mode.as_str() {
            "CONTINUOUS_REVIEW" => OperatingMode::ContinuousReview,
            "DEEP_SECURITY_RESEARCH" => OperatingMode::DeepSecurityResearch,
            _ => return Err(invalid()),
        };
        let completeness = match self.completeness.as_str() {
            "COMPLETE" => AssessmentCompleteness::Complete,
            "PARTIAL" => AssessmentCompleteness::Partial,
            "UNSUPPORTED" => AssessmentCompleteness::Unsupported,
            _ => return Err(invalid()),
        };
        let mut metadata = SessionMetadata::new(
            SessionId::from_bytes(*parse_id(&self.session_id)?.as_bytes()),
            parse_time(&self.created_at)?,
            &self.workspace_root,
            mode,
            &self.operator_id,
            &self.policy_digest,
        )
        .map_err(|_| invalid())?;
        metadata.completeness = completeness;
        if Self::from_domain(&metadata)? != *self {
            return Err(invalid());
        }
        Ok(metadata)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub version: u8,
    pub metadata: MetadataDto,
    pub generation: u64,
    pub revision: String,
    pub classification_floor: String,
    pub budget_limit_micro_usd: u64,
}
impl Snapshot {
    pub fn validate(&self) -> Result<SessionMetadata, PersistenceError> {
        if self.version != 1 || self.generation == 0 || !valid_text(&self.revision) {
            return Err(invalid());
        }
        integer(self.generation)?;
        integer(self.budget_limit_micro_usd)?;
        class(&self.classification_floor)?;
        self.metadata.domain()
    }
    pub fn json(&self) -> Result<String, PersistenceError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| invalid())
    }
    pub fn from_json(json: &str) -> Result<Self, PersistenceError> {
        let snapshot: Self = serde_json::from_str(json).map_err(|_| invalid())?;
        snapshot.validate()?;
        Ok(snapshot)
    }
    pub fn matches(&self, metadata: &SessionMetadata) -> Result<bool, PersistenceError> {
        let mut supplied = MetadataDto::from_domain(metadata)?;
        supplied.completeness = self.metadata.completeness.clone();
        Ok(supplied == self.metadata)
    }
}

/// Current intent supplied for comparison with authoritative persisted context.
/// This struct itself conveys no approval or issuance provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalIntent<'a> {
    /// Expected session metadata, compared to the stored security snapshot.
    pub session: &'a SessionMetadata,
    /// Exact persistent generation.
    pub context_generation: u64,
    /// Actual target revision established by the trusted controller.
    pub target_revision: &'a str,
    /// Classification must meet the stored floor and match the approval.
    pub classification: SecurityClassification,
    /// Complete typed operation, canonically compared on every attempt.
    pub action: &'a OperationAction,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StoredApproval {
    pub id: String,
    pub session: String,
    pub generation: u64,
    pub revision: String,
    pub state: String,
    pub action_name: String,
    pub action_digest: String,
    pub classification: String,
    pub created: String,
    pub expires: String,
    pub issued: Option<String>,
    pub token: Option<String>,
}

/// Private local receipt over a durable issued record. It cannot be constructed or
/// deserialized by a caller. Reopening requires explicit privileged recovery.
#[derive(Clone)]
pub struct PersistentApprovalGrant {
    pub(super) seal: Arc<()>,
    pub(super) snapshot: Snapshot,
    pub(super) approval: StoredApproval,
}
impl PersistentApprovalGrant {
    /// Non-secret request correlation identity; possession alone grants nothing.
    pub fn request_id(&self) -> ApprovalId {
        ApprovalId::from_bytes(
            *parse_id(&self.approval.id)
                .expect("validated internal receipt")
                .as_bytes(),
        )
    }
}

/// Current persisted session projection, not a filesystem or execution capability.
#[derive(Clone)]
pub struct SessionRecord {
    /// Reconstructed existing domain metadata.
    pub metadata: SessionMetadata,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Monotonic persisted context generation.
    pub context_generation: u64,
    /// Registered revision.
    pub target_revision: String,
    /// Minimum classification.
    pub classification_floor: SecurityClassification,
    /// Fixed-point total reservation/spend ceiling.
    pub budget_limit: CostUsd,
}

/// Audit projection. Sensitive details are accessible only through explicit fields.
#[derive(Clone)]
pub struct AuditRecord {
    /// Unique event identity.
    pub event_id: EventId,
    /// Session identity.
    pub session_id: SessionId,
    /// Monotonic per-session sequence.
    pub sequence_number: u64,
    /// Structured event kind.
    pub event_kind: String,
    /// Event data classification.
    pub classification: SecurityClassification,
    /// UTC timestamp.
    pub timestamp: TimestampUtc,
    /// Canonical descriptor, explicitly not a cryptographic digest.
    pub action_digest: Option<String>,
    /// Structured inert JSON, not evaluated code.
    pub details_json: String,
}

/// Committed approval-consumption record; not an execution backend authorization.
#[derive(Clone)]
pub struct ConsumptionRecord {
    /// Approval identity consumed by this commit.
    pub request_id: ApprovalId,
    /// Sequence of the atomically committed audit event.
    pub audit_sequence: u64,
}

/// Explicit settlement outcome for a budget reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementStatus {
    /// Confirmed successful completion with verified final actual usage.
    /// Unused reservation difference is released from `budget_used`.
    Completed(CostUsd),
    /// Confirmed cancellation with verified final actual usage.
    /// Unused reservation difference is released from `budget_used`.
    CancelledWithUsage(CostUsd),
    /// Confirmed cancellation where final usage could not be verified.
    /// The full upper-bound reservation is retained in `budget_used`.
    CancelledUncertain,
    /// Uncertain completion or unconfirmed partial usage.
    /// Reservation remains active in `RESERVED` state and full upper bound is retained in `budget_used`.
    UncertainPartial,
}

impl SettlementStatus {
    /// Returns the verified actual cost, if final usage is known.
    pub fn actual_cost(&self) -> Option<CostUsd> {
        match self {
            Self::Completed(cost) | Self::CancelledWithUsage(cost) => Some(*cost),
            Self::CancelledUncertain | Self::UncertainPartial => None,
        }
    }

    /// Whether this status represents a confirmed cancellation.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::CancelledWithUsage(_) | Self::CancelledUncertain)
    }

    /// Whether this status confirms completion or cancellation.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::UncertainPartial)
    }
}

/// Persisted reservation, including explicit unknown final usage.
#[derive(Clone)]
pub struct BudgetRecord {
    /// Reservation identity.
    pub reservation_id: Identifier,
    /// Upper-bound reservation.
    pub reserved: CostUsd,
    /// Observed final spend; None remains unknown, including on cancellation.
    pub actual: Option<CostUsd>,
    /// RESERVED, SETTLED, CANCELLED or EXPIRED.
    pub state: String,
}

/// A committed transition with separately reported post-commit checkpoint progress.
#[derive(Clone, Debug)]
pub struct TransitionRecord {
    /// Corresponding committed audit event sequence.
    pub audit_sequence: u64,
    /// Terminal transitions attempt PASSIVE after commit; failure cannot undo the commit.
    pub checkpoint: Option<Result<CheckpointResult, PersistenceError>>,
}

macro_rules! redacted_debug {
    ($($name:ident),+) => { $(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([redacted])")) }
    })+ };
}
redacted_debug!(
    PersistentApprovalGrant,
    SessionRecord,
    AuditRecord,
    ConsumptionRecord,
    BudgetRecord
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_unicode_identifiers_timestamps_and_numeric_limits_fail_without_panics() {
        for id in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "éééééééé-éééé-éééé-éééé-éééééé",
            "00000000-0000-4000-8000-00000000000X",
        ] {
            assert!(parse_id(id).is_err());
        }
        for time in [
            "",
            "éééé-11-14T22:13:20.000Z",
            "2023-02-31T22:13:20.000Z",
            "2023-11-14T99:13:20.000Z",
            "1969-12-31T23:59:59.999Z",
        ] {
            assert!(parse_time(time).is_err());
        }
        assert!(time_text(TimestampUtc::from_epoch_millis(u64::MAX)).is_err());
        assert!(integer(u64::MAX).is_err());
        assert!(unsigned(-1).is_err());
        assert_eq!(
            parse_time("2023-11-14T22:13:20.000Z")
                .unwrap()
                .as_epoch_secs(),
            1_700_000_000
        );
    }
}
