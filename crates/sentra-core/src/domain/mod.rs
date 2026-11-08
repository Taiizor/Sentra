//! Core domain models, type-safe identifiers, classifications, and errors.

/// Security classification levels and flow validation.
pub mod classification;
/// Domain and state transition error types.
pub mod error;
/// Normalized security findings and vulnerability classifications.
pub mod finding;
/// 128-bit type-safe identifiers for sessions, tasks, approvals, and events.
pub mod id;
/// Immutable UTC timestamps with millisecond precision.
pub mod time;

pub use classification::SecurityClassification;
pub use error::{DomainError, SessionTransitionError};
pub use finding::{
    Confidence, Finding, FindingSource, FindingStatus, Reachability, Severity,
    StatusTransitionEntry, TargetLocation,
};
pub use id::{
    ApprovalId, AttemptId, EventId, EvidenceId, ExecutionId, FindingId, Identifier, ManifestId,
    ReservationId, SessionId, TaskId,
};
pub use time::TimestampUtc;
