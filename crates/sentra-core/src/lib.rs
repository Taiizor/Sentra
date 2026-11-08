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

/// Dependency vulnerability advisories and lockfile auditing.
pub mod advisory;
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
/// Immutable input manifests, canonical source snapshots, and content hashing.
pub mod manifest;
/// Local SQLite connection, migration and durable repository primitives.
pub mod persistence;
/// Security policy engine, decisions, and approval brokers.
pub mod policy;
/// Integrated Core Service coordination foundation.
pub mod service;
/// Session lifecycle, state machine, and metadata.
pub mod session;
/// Content-addressed storage (CAS), blob publication, and quota management.
pub mod storage;
/// Canonical workspace boundaries, indirection quarantine and metadata-only discovery.
pub mod workspace;

pub use advisory::{
    Advisory, AdvisoryAuditResult, AdvisoryDatabase, AdvisoryError, AdvisoryErrorKind,
    AdvisoryMatch, PackageRecord, SemverVersion, VersionReq, parse_cargo_lock,
};
pub use audit::{AuditEvent, AuditEventKind};
pub use common::{
    Clock, MockClock, Sha256Stream, SystemClock, sha256_bytes, sha256_digest, sha256_prefixed,
};
pub use domain::{
    ApprovalId, AttemptId, Confidence, DomainError, EventId, EvidenceId, ExecutionId, Finding,
    FindingId, FindingSource, FindingStatus, Identifier, ManifestId, Reachability, ReservationId,
    SecurityClassification, SessionId, SessionTransitionError, Severity, TargetLocation, TaskId,
    TimestampUtc,
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
pub use manifest::{
    ManifestError, ManifestErrorKind, OperationManifest, SnapshotLimits, SourceFileRole,
    SourceSnapshot, SourceSnapshotEntry, capture_source_snapshot,
};
pub use policy::{
    ApprovalAuthority, ApprovalBroker, ApprovalGrant, ApprovalRequest, BudgetPolicyConfig, CostUsd,
    DenialReason, OperationAction, PolicyDecision, PolicyEngine,
};
pub use service::{
    AdmitResultRequest, CancellationPhase, CancellationReason, CancellationReport, CoreService,
    CoreServiceConfig, CoreServiceHarness, LocalAuditReport, ReconciledAttempt, ServiceError,
    ServiceErrorKind, ServicePolicyDecision, SessionResumeReport, TaskExecutionReport,
    TaskExecutionRequest,
};
pub use session::{
    AssessmentCompleteness, OperatingMode, SessionMetadata, SessionState, SessionStateMachine,
};
pub use storage::{
    BlobId, BlobMetadata, BlobStore, FileSystemCasBlobStore, StorageError, StorageErrorKind,
    StorageLimits, StorageUsage,
};
