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
/// Dashboard core services, multi-tenant session isolation, and RBAC authorization.
pub mod dashboard;
/// Source snapshot differential analysis, narrow Rust hunk extraction, and revision invalidation.
pub mod diff;
/// Core domain models, identifiers, and classifications.
pub mod domain;
/// Host-side evidence verification boundary and artifact admission filters.
pub mod evidence;
/// Fail-closed execution engine and backend contracts.
pub mod execution;
/// Standard vulnerability reporting and format adapters (OASIS SARIF v2.1.0).
pub mod export;
/// Remote-worker fleet management, multi-user hosting security audit, and target matrix.
pub mod fleet;
/// Continuous hosted integrations, authenticated webhook intake, and delivery deduplication.
pub mod hosted;
/// Immutable input manifests, canonical source snapshots, and content hashing.
pub mod manifest;
/// Local Model Context Protocol (MCP) server, stdio transport, and shared application services.
pub mod mcp;
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
    AdvisoryMatch, LockfileKind, PackageRecord, SemverVersion, VersionReq,
    discover_workspace_lockfiles, parse_bun_lock, parse_cargo_lock, parse_deno_lock,
    parse_lockfile_content, parse_package_lock, parse_pnpm_lock, parse_yarn_lock,
};
pub use audit::{AuditEvent, AuditEventKind};
pub use common::{
    Clock, MockClock, Sha256Stream, SystemClock, constant_time_eq, hmac_sha256, hmac_sha256_hex,
    sha256_bytes, sha256_digest, sha256_prefixed,
};
pub use dashboard::{
    AuditLogView, CampaignLedgerView, DashboardAction, DashboardError, DashboardErrorKind,
    DashboardOverview, DashboardService, FindingView, IsolationLevel, PatchBundleView,
    SessionSummaryView, TenantContext, TenantId, UserRole, enforce_rbac,
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
pub use export::{
    SARIF_SCHEMA_V2_1_0, SARIF_VERSION_2_1_0, SarifArtifactLocation, SarifDriver, SarifLevel,
    SarifLocation, SarifLog, SarifMessage, SarifPhysicalLocation, SarifRegion,
    SarifReportingConfiguration, SarifResult, SarifRule, SarifRun, SarifTool,
    export_audit_to_sarif, export_audit_to_sarif_json, generate_sarif_json, generate_sarif_report,
    severity_to_sarif_level, severity_to_security_score,
};
pub use fleet::{
    AdapterActionCapability, AuditStatus, EvidenceMethod, FleetError, FleetErrorKind, HostPlatform,
    MultiUserAuditReport, MultiUserSecurityAudit, RemoteWorkerId, RemoteWorkerNode, SupportMatrix,
    SupportedTargetTuple, TargetLanguage, WorkerFleetManager, WorkerState,
};
pub use hosted::{
    DEFAULT_MAX_DRIFT_SECS, DEFAULT_MAX_LEDGER_CAPACITY, DeliveryLedger, DeliveryRecord,
    DraftPrProposal, EventKind, ForkSecurityProfile, HostedCredentials, HostedPermission,
    HostedProvider, PrAction, ProposalStatus, PullRequestPayload, PushPayload, StaleHeadGuard,
    WebhookError, WebhookErrorKind, WebhookEvent, WebhookIntake, validate_commit_sha,
    verify_github_signature, verify_gitlab_token,
};
pub use manifest::{
    ManifestError, ManifestErrorKind, OperationManifest, SnapshotLimits, SourceFileRole,
    SourceSnapshot, SourceSnapshotEntry, capture_source_snapshot,
};
pub use mcp::{
    DEFAULT_MAX_LINE_BYTES, McpErrorCode, McpErrorObject, McpRequest, McpResponse, McpServer,
    RequestId, ToolDefinition, canonical_tool_definitions, process_transport_line,
    verify_transport_allowed,
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
