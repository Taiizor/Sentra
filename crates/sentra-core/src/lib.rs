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
/// Source snapshot differential analysis, narrow Rust hunk extraction, and revision invalidation.
pub mod diff;
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
/// Subprocess plugin SDK, versioned adapter protocols, and capability fencing.
pub mod plugin;
/// Security policy engine, decisions, and approval brokers.
pub mod policy;
/// Capability-scoped model provider abstraction and privacy-preserving gateway.
pub mod provider;
/// Deep security research campaigns, Scout/Analyst task fanout, and coverage ledgers.
pub mod research;
/// Integrated Core Service coordination foundation.
pub mod service;
/// Session lifecycle, state machine, and metadata.
pub mod session;
/// Content-addressed storage (CAS), blob publication, and quota management.
pub mod storage;
/// Verification bundle lifecycle, disposable worker containment, and benchmark evaluation.
pub mod verification;
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
pub use diff::{
    DiffError, DiffErrorKind, DiffHunk, DiffLine, DiffSummary, FileContentDiff, FileDelta,
    FileDeltaKind, HunkLimits, RevisionBinding, SnapshotDiff, compare_snapshots, compute_line_diff,
    reconcile_findings_anti_regression, validate_patch_approval_invalidation,
};
pub use domain::{
    ApprovalId, AttemptId, CampaignId, Confidence, DomainError, EventId, EvidenceId, ExecutionId,
    Finding, FindingId, FindingSource, FindingStatus, HypothesisId, Identifier, ManifestId,
    Reachability, ReservationId, SecurityClassification, SessionId, SessionTransitionError,
    Severity, TargetLocation, TaskId, TimestampUtc,
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
pub use plugin::{
    AdapterFamily, HostStatus, PluginCapability, PluginError, PluginErrorKind, PluginHost,
    PluginManifest, PluginQuotas, PluginRequest, PluginResponse, SampleAdapter, SampleAdapterMode,
    decode_frame, encode_frame,
};
pub use policy::{
    ApprovalAuthority, ApprovalBroker, ApprovalGrant, ApprovalRequest, BudgetPolicyConfig, CostUsd,
    DenialReason, OperationAction, PolicyDecision, PolicyEngine,
};
pub use provider::{
    Body as ProviderBody, Capabilities as ProviderCapabilities, DataClass as ProviderDataClass,
    Diagnostic as ProviderDiagnostic, DiagnosticCode as ProviderDiagnosticCode,
    ErrorKind as ProviderErrorKind, Failure as ProviderFailure, Feature as ProviderFeature,
    Format as ProviderFormat, Gateway as ProviderGateway, Ledger as ProviderLedger,
    LocalInferenceEndpointProvider, LocalStatus as ProviderLocalStatus,
    Location as ProviderLocation, Model as ProviderModel, Operation as ProviderOperation,
    Policy as ProviderPolicy, Progress as ProviderProgress, Provider, Rates as ProviderRates,
    RedactionFilter, Request as ProviderRequest, Response as ProviderResponse,
    Script as ProviderScript, SharedTrace, SyntheticMockProvider, Terminal as ProviderTerminal,
    Trace as ProviderTrace, Usage as ProviderUsage, Value as ProviderValue,
    VirtualControl as ProviderVirtualControl, full_model,
};
pub use research::{
    ApproachRunMetrics, ApproachSummary, Campaign, CampaignLimits, CampaignStatus,
    CampaignStopReason, CampaignTask, CoverageLedger, CoverageSummary, CoveredRegion,
    CrashArtifact, FuzzEngine, FuzzRunConfig, FuzzTarget, Hypothesis, HypothesisDeduplicator,
    HypothesisStatus, ReferenceCrashTarget, ResearchApproach, ResearchError, ResearchErrorKind,
    ResearchRole, ResearchTaskStatus, RoleCapability, SanitizerType, SkipReason, SkippedRegion,
    TriMethodComparisonMatrix, VulnerabilityCategory, assert_patch_verifier_independent,
    assert_peer_approval_forbidden, generate_reference_tri_method_matrix, minimize_input,
    reference_root_cause_targets,
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
pub use verification::{
    AttemptDenominator, ChangeCase, ChangeCaseCategory, ConfusionMatrix, ContainmentLevel,
    CorpusEvaluationReport, EgressPolicy, PatchVerificationOutcome, TestRunEvidence, TestStatus,
    VerificationBundle, VerificationInput, WorkerArchitecture, WorkerError, WorkerErrorKind,
    WorkerProfile, WorkerReadinessReport, WorkerResourceCaps, evaluate_corpus,
    reference_20_case_corpus,
};
