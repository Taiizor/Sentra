//! # Sentra Core Engine Foundation
//!
//! Sentra is an open-source, dual-mode security research platform for autonomous
//! repository security analysis and verified patch generation.
//!
//! This crate provides the foundational domain models, session lifecycle state machine,
//! immutable audit trail event types, security classification lattices, and default-deny
//! policy authorization engine.
//!
//! In accordance with Phase 1 constraints and ADR-0004, untrusted code execution is strictly
//! disabled and fail-closed by default.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

/// Audit trail event models and kinds.
pub mod audit;
/// Common utilities including clock abstractions.
pub mod common;
/// Core domain models, identifiers, and classifications.
pub mod domain;
/// Host-side evidence verification boundary and artifact admission filters.
pub mod evidence;
/// Fail-closed execution engine and backend contracts.
pub mod execution;
/// Local SQLite connection, migration and durable repository primitives.
pub mod persistence;
/// Security policy engine, decisions, and approval brokers.
pub mod policy;
/// Integrated Core Service coordination foundation.
pub mod service;
/// Session lifecycle, state machine, and metadata.
pub mod session;
/// Canonical workspace boundaries, indirection quarantine and metadata-only discovery.
pub mod workspace;

pub use audit::{AuditEvent, AuditEventKind};
pub use common::{Clock, MockClock, SystemClock};
pub use domain::{
    ApprovalId, AttemptId, DomainError, EventId, EvidenceId, ExecutionId, Identifier, ManifestId,
    ReservationId, SecurityClassification, SessionId, SessionTransitionError, TaskId, TimestampUtc,
};
pub use evidence::{
    EvidenceArtifact, EvidenceEnvelope, EvidenceMetadata, EvidenceVerificationError,
    EvidenceVerificationErrorKind, EvidenceVerifier, IntegrityVerificationStatus,
    MAX_EVIDENCE_SIZE_BYTES,
};
pub use execution::{
    BackendCapabilities, ExecutionBackend, ExecutionEngine, ExecutionError, ExecutionErrorKind,
    ExecutionRequest, ExecutionResult, ExecutionScope, ExecutionStatus, FailClosedBackend,
    ResourceLimits, ResourceUsage, SyntheticFixtureBackend,
};
pub use policy::{
    ApprovalAuthority, ApprovalBroker, ApprovalGrant, ApprovalRequest, BudgetPolicyConfig, CostUsd,
    DenialReason, OperationAction, PolicyDecision, PolicyEngine,
};
pub use service::{
    CancellationPhase, CancellationReason, CancellationReport, CoreService, CoreServiceConfig,
    CoreServiceHarness, ServiceError, ServiceErrorKind, ServicePolicyDecision, TaskExecutionReport,
    TaskExecutionRequest,
};
pub use session::{
    AssessmentCompleteness, OperatingMode, SessionMetadata, SessionState, SessionStateMachine,
};
