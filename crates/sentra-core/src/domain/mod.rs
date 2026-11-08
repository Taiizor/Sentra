//! Core domain models, type-safe identifiers, classifications, and errors.

/// Security classification levels and flow validation.
pub mod classification;
/// Domain and state transition error types.
pub mod error;
/// 128-bit type-safe identifiers for sessions, tasks, approvals, and events.
pub mod id;
/// Immutable UTC timestamps with millisecond precision.
pub mod time;

pub use classification::SecurityClassification;
pub use error::{DomainError, SessionTransitionError};
pub use id::{
    ApprovalId, AttemptId, EventId, EvidenceId, ExecutionId, Identifier, ManifestId,
    ReservationId, SessionId, TaskId,
};
pub use time::TimestampUtc;
