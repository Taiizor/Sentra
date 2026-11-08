//! Core Service orchestrator coordinating session, workspace, policy, persistence, execution, and evidence.

use std::{path::Path, sync::Arc};

use crate::{
    Clock, CostUsd, EventId, EvidenceArtifact, EvidenceEnvelope, EvidenceVerifier,
    ExecutionBackend, ExecutionEngine, ExecutionError, ExecutionId, ExecutionRequest,
    ExecutionResult, ExecutionScope, ExecutionStatus, Identifier, ManifestId, OperatingMode,
    OperationAction, PolicyEngine, ResourceLimits, ResourceUsage, SecurityClassification,
    SessionId, SessionMetadata, SessionState, TaskId, TimestampUtc,
    manifest::{OperationManifest, SnapshotLimits, SourceSnapshot, capture_source_snapshot},
    persistence::{
        ApprovalIntent, ManifestKind, ManifestRecord, PersistenceRepository,
        PersistentApprovalAuthority, PersistentApprovalGrant, SessionRecord, SettlementStatus,
    },
    service::{
        config::CoreServiceConfig,
        error::ServiceError,
        lifecycle::{CancellationReason, CancellationReport, SessionResumeReport},
    },
    workspace::{DiscoveryLimits, DiscoveryResult, WorkspaceBoundary},
};

/// High-level policy decision returned by the service layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServicePolicyDecision {
    /// Operation is authorized to proceed.
    Granted,
    /// Operation was rejected by default-deny policy or classification rules.
    Denied {
        /// Reason explaining the denial.
        reason: String,
    },
    /// Operation is sensitive and requires explicit operator approval.
    NeedsApproval {
        /// Canonical action name.
        action_name: &'static str,
        /// Descriptive summary of the operation requiring authorization.
        description: String,
    },
}

/// Comprehensive parameters for executing a task through `CoreService`.
#[derive(Clone)]
pub struct TaskExecutionRequest {
    /// Target session identifier.
    pub session_id: SessionId,
    /// Task DAG identifier.
    pub task_id: TaskId,
    /// Security execution scope.
    pub scope: ExecutionScope,
    /// Concrete action to be executed.
    pub action: OperationAction,
    /// Security classification level.
    pub classification: SecurityClassification,
    /// Optional upper-bound resource limits.
    pub resource_limits: Option<ResourceLimits>,
    /// Estimated cost for budget reservation.
    pub estimated_cost: CostUsd,
    /// Optional pre-issued persistent approval grant.
    pub grant: Option<PersistentApprovalGrant>,
    /// Evidence envelopes to verify and admit upon completion.
    pub evidence_envelopes: Vec<EvidenceEnvelope>,
}

impl TaskExecutionRequest {
    /// Constructs a basic synthetic task execution request.
    pub fn synthetic(
        session_id: SessionId,
        task_id: TaskId,
        action: OperationAction,
        estimated_cost: CostUsd,
    ) -> Self {
        Self {
            session_id,
            task_id,
            scope: ExecutionScope::SyntheticFixture,
            action,
            classification: SecurityClassification::Internal,
            resource_limits: None,
            estimated_cost,
            grant: None,
            evidence_envelopes: Vec::new(),
        }
    }
}

/// Comprehensive outcome report for an executed task.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskExecutionReport {
    /// Unique execution identifier.
    pub execution_id: ExecutionId,
    /// Parent research session.
    pub session_id: SessionId,
    /// Associated DAG task identity.
    pub task_id: TaskId,
    /// Execution lifecycle status.
    pub status: ExecutionStatus,
    /// Process exit code, if applicable.
    pub exit_code: Option<i32>,
    /// Measured resource utilization.
    pub resource_usage: ResourceUsage,
    /// Admitted and verified evidence artifacts.
    pub admitted_evidence: Vec<EvidenceArtifact>,
    /// Final budget settlement status.
    pub settlement: SettlementStatus,
    /// Completion timestamp.
    pub completed_at: TimestampUtc,
}

/// The integrated Core Engine Service.
///
/// Serves as the central coordination boundary for the Sentra platform, integrating
/// session lifecycles, workspace boundaries, default-deny policy enforcement,
/// durable SQLite persistence, fail-closed task execution, and host evidence verification.
///
/// # Security Invariants
/// 1. Untrusted target code execution is strictly disabled fail-closed.
/// 2. Workspace boundary canonicalization and symlink/junction quarantine are non-negotiable.
/// 3. Approvals have private issuance provenance and exact canonical binding, single-use, and atomically consumed.
/// 4. Budget settlement on uncertain, timed-out, or failed outcomes preserves conservative reservation hold.
/// 5. Execution result validation exhaustively checks status consistency and correlation (F-551-01, F-551-05).
/// 6. Evidence verification enforces 50 MiB bounds, exact byte length matching, and media types.
pub struct CoreService {
    config: CoreServiceConfig,
    repository: PersistenceRepository,
    authority: PersistentApprovalAuthority,
    policy_engine: PolicyEngine,
    execution_engine: ExecutionEngine,
    evidence_verifier: EvidenceVerifier,
    clock: Arc<dyn Clock>,
}

impl CoreService {
    /// Constructs a new `CoreService` instance with all backing components.
    pub fn new(
        config: CoreServiceConfig,
        repository: PersistenceRepository,
        authority: PersistentApprovalAuthority,
        policy_engine: PolicyEngine,
        execution_backend: Arc<dyn ExecutionBackend>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let policy_engine = policy_engine.for_service(config.max_auto_budget);
        let evidence_verifier = if let Some(ref types) = config.allowed_media_types {
            EvidenceVerifier::new()
                .with_max_size(config.max_evidence_size_bytes)
                .with_allowed_media_types(types.clone())
        } else {
            EvidenceVerifier::new().with_max_size(config.max_evidence_size_bytes)
        };

        Self {
            config,
            repository,
            authority,
            policy_engine,
            execution_engine: ExecutionEngine::new(execution_backend),
            evidence_verifier,
            clock,
        }
    }

    /// Accessor for service configuration.
    pub fn config(&self) -> &CoreServiceConfig {
        &self.config
    }

    /// Accessor for the active clock.
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Returns the declared capabilities of the underlying execution backend.
    pub fn execution_capabilities(&self) -> crate::BackendCapabilities {
        self.execution_engine.capabilities()
    }

    // -------------------------------------------------------------------------
    // Session Management
    // -------------------------------------------------------------------------

    /// Creates and persists a new research session.
    ///
    /// Validates the canonical project root, transitions the session state machine
    /// from `Created` to `Scoped`, and registers the durable session record.
    pub fn create_session(
        &self,
        workspace_root: &str,
        operating_mode: OperatingMode,
        operator_id: &str,
        classification_floor: SecurityClassification,
        target_revision: &str,
        budget_limit: CostUsd,
    ) -> Result<SessionId, ServiceError> {
        let session_id = SessionId::new();

        // Step 1: Validate workspace root canonicalization and boundary.
        let boundary = WorkspaceBoundary::establish(
            Path::new(workspace_root),
            session_id,
            classification_floor,
        )
        .map_err(ServiceError::workspace)?;

        let canonical_root_str =
            boundary.root().canonical_path().to_str().ok_or_else(|| {
                ServiceError::session("Canonical workspace root is not valid UTF-8")
            })?;

        // Step 2: Construct and validate session metadata.
        let now = self.clock.now();
        let metadata = SessionMetadata::new(
            session_id,
            now,
            canonical_root_str,
            operating_mode,
            operator_id,
            "policy:default-v1",
        )
        .map_err(|e| ServiceError::session(e.to_string()))?;

        // Step 3: Register session in persistent repository.
        let event_id = EventId::new();
        let record = self
            .authority
            .register_session_with_policy(
                &metadata,
                target_revision,
                classification_floor,
                (budget_limit, &self.policy_engine),
                event_id,
                &self.clock,
            )
            .map_err(ServiceError::persistence)?;

        // Step 4: Advance state from Created to Scoped
        let transition_event = EventId::new();
        self.repository
            .transition_session(
                record.metadata.session_id,
                SessionState::Created,
                SessionState::Scoped,
                transition_event,
                &self.clock,
            )
            .map_err(ServiceError::persistence)?;

        Ok(session_id)
    }

    /// Retrieves an existing session record by identifier.
    pub fn get_session(&self, session_id: SessionId) -> Result<SessionRecord, ServiceError> {
        self.repository
            .session(session_id)
            .map_err(ServiceError::persistence)?
            .ok_or_else(|| ServiceError::session(format!("Session '{session_id}' not found")))
    }

    pub(super) fn local_session(&self) -> Result<SessionRecord, ServiceError> {
        self.repository
            .local_session()
            .map_err(ServiceError::persistence)
    }

    /// Transitions a session to a new lifecycle state.
    pub fn transition_session(
        &self,
        session_id: SessionId,
        target_state: SessionState,
        _reason: &str,
    ) -> Result<(), ServiceError> {
        let session = self.get_session(session_id)?;

        // Validate state machine edge
        if !session.state.can_transition_to(target_state) {
            return Err(ServiceError::invalid_state(format!(
                "Invalid transition from '{:?}' to '{:?}'",
                session.state, target_state
            )));
        }

        let event_id = EventId::new();
        self.repository
            .transition_session(
                session_id,
                session.state,
                target_state,
                event_id,
                &self.clock,
            )
            .map_err(ServiceError::persistence)?;

        Ok(())
    }

    /// Returns the total committed and currently reserved cost for a session.
    pub fn budget_used(&self, session_id: SessionId) -> Result<CostUsd, ServiceError> {
        self.repository
            .budget_used(session_id)
            .map_err(ServiceError::persistence)
    }

    /// Returns a reference to the underlying persistent repository.
    pub fn repository(&self) -> &PersistenceRepository {
        &self.repository
    }

    /// Returns a reference to the privileged persistent authority.
    pub fn authority(&self) -> &PersistentApprovalAuthority {
        &self.authority
    }

    /// Resumes an interrupted session, reconciling outstanding attempts, holding uncertain effects,
    /// and advancing context generation atomically.
    pub fn resume_session(
        &self,
        session_id: SessionId,
    ) -> Result<SessionResumeReport, ServiceError> {
        // 1. Acquire exclusive session admission lock.
        // Serializes concurrent resume operations and prevents concurrent dispatches.
        let _admission = self
            .repository
            .session_admission(session_id, true)
            .map_err(ServiceError::persistence)?;

        // 2. Atomically reconcile attempts, tasks, and advance epoch within one transaction.
        self.repository
            .reconcile_and_resume_session(session_id, &self.clock)
            .map_err(ServiceError::persistence)
    }

    // -------------------------------------------------------------------------
    // Workspace Operations
    // -------------------------------------------------------------------------

    /// Performs metadata-only file discovery within the authorized workspace.
    ///
    /// Never executes target build scripts, procedural macros, or native binaries.
    /// Quarantines symlinks and NTFS junctions fail-closed.
    pub fn discover_workspace(
        &self,
        session_id: SessionId,
        limits: Option<DiscoveryLimits>,
    ) -> Result<DiscoveryResult, ServiceError> {
        let session = self.get_session(session_id)?;
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot perform discovery on a terminal session",
            ));
        }

        let boundary = WorkspaceBoundary::establish(
            Path::new(&session.metadata.workspace_root),
            session_id,
            session.classification_floor,
        )
        .map_err(ServiceError::workspace)?;

        let discovery_limits = limits.unwrap_or_default();
        let result = boundary
            .discover(&discovery_limits)
            .map_err(ServiceError::workspace)?;

        Ok(result)
    }

    /// Captures a frozen, deterministic source snapshot of the workspace, computes its
    /// cryptographic SHA-256 digest, and persists it as an immutable `ManifestRecord` (REQ-F01/F02).
    pub fn capture_source_snapshot(
        &self,
        session_id: SessionId,
        limits: Option<&SnapshotLimits>,
    ) -> Result<(ManifestRecord, SourceSnapshot), ServiceError> {
        let session = self.get_session(session_id)?;
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot capture source snapshot on a terminal session",
            ));
        }

        let _admission = self
            .repository
            .session_admission(session_id, false)
            .map_err(ServiceError::persistence)?;

        let boundary = WorkspaceBoundary::establish(
            Path::new(&session.metadata.workspace_root),
            session_id,
            session.classification_floor,
        )
        .map_err(ServiceError::workspace)?;

        let snapshot_limits = limits.cloned().unwrap_or_default();
        let snapshot = capture_source_snapshot(&boundary, &snapshot_limits, &self.clock)
            .map_err(|e| ServiceError::invalid_state(e.to_string()))?;

        let canonical_json = snapshot
            .to_canonical_json()
            .map_err(|e| ServiceError::invalid_state(e.to_string()))?;

        let manifest_id = ManifestId::new();
        let record = self
            .repository
            .create_manifest(
                manifest_id,
                session_id,
                ManifestKind::SourceSnapshot,
                &snapshot.aggregate_digest,
                &canonical_json,
                &self.clock,
            )
            .map_err(ServiceError::persistence)?;

        Ok((record, snapshot))
    }

    /// Creates and persists an immutable operation manifest bound to an optional source snapshot.
    pub fn create_operation_manifest(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        action: &OperationAction,
        source_snapshot_digest: Option<&str>,
    ) -> Result<ManifestRecord, ServiceError> {
        let session = self.get_session(session_id)?;
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot create operation manifest on a terminal session",
            ));
        }

        let created_at = self.clock.now().to_rfc3339();

        let op_manifest = OperationManifest {
            version: OperationManifest::SCHEMA_VERSION,
            session_id: session_id.to_string(),
            task_id: task_id.to_string(),
            action_name: action.action_name().to_string(),
            action_digest: action.action_digest(),
            source_snapshot_digest: source_snapshot_digest.map(|s| s.to_string()),
            classification: session.classification_floor.as_str().to_string(),
            created_at,
        };

        let canonical_json = op_manifest
            .to_canonical_json()
            .map_err(|e| ServiceError::invalid_state(e.to_string()))?;
        let content_digest = op_manifest
            .content_digest()
            .map_err(|e| ServiceError::invalid_state(e.to_string()))?;

        let manifest_id = ManifestId::new();
        self.repository
            .create_manifest(
                manifest_id,
                session_id,
                ManifestKind::Operation,
                &content_digest,
                &canonical_json,
                &self.clock,
            )
            .map_err(ServiceError::persistence)
    }

    // -------------------------------------------------------------------------
    // Policy and Approval Coordination
    // -------------------------------------------------------------------------

    /// Evaluates an operation action against session context, classification, and policy.
    pub fn evaluate_action(
        &self,
        session_id: SessionId,
        action: &OperationAction,
        classification: SecurityClassification,
        grant: Option<&PersistentApprovalGrant>,
    ) -> Result<ServicePolicyDecision, ServiceError> {
        let amount = match action {
            OperationAction::InvokeProvider { estimated_cost, .. } => *estimated_cost,
            _ => CostUsd::ZERO,
        };
        let context = match self.authority.execution_context(
            session_id,
            classification,
            action,
            amount,
            &self.policy_engine,
        ) {
            Ok(context) => context,
            Err(error) if error.kind == crate::persistence::PersistenceErrorKind::PolicyDenied => {
                return Ok(ServicePolicyDecision::Denied {
                    reason: "Authoritative context or policy denied".into(),
                });
            }
            Err(error) => return Err(ServiceError::persistence(error)),
        };
        match self
            .repository
            .preview_execution(&context, grant, &self.clock)
        {
            Ok(crate::persistence::ExecutionPreview::Granted) => Ok(ServicePolicyDecision::Granted),
            Ok(crate::persistence::ExecutionPreview::NeedsApproval) => {
                Ok(ServicePolicyDecision::NeedsApproval {
                    action_name: action.action_name(),
                    description: "Explicit approval required".into(),
                })
            }
            Ok(crate::persistence::ExecutionPreview::Denied) => Ok(ServicePolicyDecision::Denied {
                reason: "Approval or authoritative context invalid".into(),
            }),
            Err(error) => Err(ServiceError::persistence(error)),
        }
    }

    /// Submits a request for human approval and stores the pending intent.
    pub fn request_approval(
        &self,
        session_id: SessionId,
        action: &OperationAction,
        classification: SecurityClassification,
    ) -> Result<crate::ApprovalId, ServiceError> {
        let session = self.get_session(session_id)?;
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot request approval on a terminal session",
            ));
        }

        let intent = ApprovalIntent {
            session: &session.metadata,
            context_generation: session.context_generation,
            target_revision: &session.target_revision,
            classification,
            action,
        };

        let approval_id = crate::ApprovalId::new();
        let event_id = EventId::new();
        self.repository
            .request_approval(approval_id, &intent, event_id, &self.clock)
            .map_err(ServiceError::persistence)?;

        Ok(approval_id)
    }

    /// Issues a single-use persistent approval grant for an existing approval request.
    pub fn issue_approval(
        &self,
        session_id: SessionId,
        request_id: crate::ApprovalId,
        action: &OperationAction,
        classification: SecurityClassification,
    ) -> Result<PersistentApprovalGrant, ServiceError> {
        let session = self.get_session(session_id)?;
        let intent = ApprovalIntent {
            session: &session.metadata,
            context_generation: session.context_generation,
            target_revision: &session.target_revision,
            classification,
            action,
        };

        let event_id = EventId::new();
        let grant = self
            .authority
            .issue_grant(
                request_id,
                &intent,
                &session.metadata.operator_id,
                event_id,
                &self.clock,
            )
            .map_err(ServiceError::persistence)?;

        Ok(grant)
    }

    // -------------------------------------------------------------------------
    // Task Execution Workflow (Full Integration)
    // -------------------------------------------------------------------------

    /// Executes an authorized task through the complete Core Engine pipeline.
    ///
    /// # Pipeline Stages
    /// 1. Session verification & state validation.
    /// 2. Atomic single-use approval consumption (if sensitive/grant supplied).
    /// 3. Budget reservation against session limit.
    /// 4. Task dispatch to execution engine.
    /// 5. Exhaustive result validation (F-551-01 status consistency, F-551-05 correlation).
    /// 6. Evidence structural verification (50 MiB ceiling, length check, media types).
    /// 7. Final budget settlement & audit logging.
    pub fn execute_task(
        &self,
        req: TaskExecutionRequest,
    ) -> Result<TaskExecutionReport, ServiceError> {
        let session = self.get_session(req.session_id)?;
        if !session.state.allows_execution() {
            return Err(ServiceError::invalid_state(
                "Session is not eligible for task admission",
            ));
        }
        let context = self
            .authority
            .execution_context(
                req.session_id,
                req.classification,
                &req.action,
                req.estimated_cost,
                &self.policy_engine,
            )
            .map_err(|error| match error.kind {
                crate::persistence::PersistenceErrorKind::PolicyDenied => {
                    ServiceError::policy_denied("Authoritative policy denied")
                }
                _ => ServiceError::persistence(error),
            })?;
        if (context.requires_approval() || req.scope.is_untrusted()) && req.grant.is_none() {
            return Err(ServiceError::policy_denied("Explicit approval required"));
        }
        let reservation_id = Identifier::new_sequential(0x5345_4e54_5241_0007);
        let prepared = self
            .repository
            .reserve_budget_and_consume_approval(
                crate::persistence::PrepareExecutionRequest {
                    reservation_id,
                    context: context.clone(),
                    grant: req.grant.as_ref(),
                    reservation_event: EventId::new(),
                    consumption_event: EventId::new(),
                },
                &self.clock,
            )
            .map_err(|e| match e.kind {
                crate::persistence::PersistenceErrorKind::BudgetExceeded => {
                    ServiceError::budget_exceeded("Budget exhausted")
                }
                crate::persistence::PersistenceErrorKind::InvalidApproval
                | crate::persistence::PersistenceErrorKind::ApprovalReused
                | crate::persistence::PersistenceErrorKind::ApprovalExpired
                | crate::persistence::PersistenceErrorKind::ContextMismatch => {
                    ServiceError::approval_invalid("Approval or context mismatch")
                }
                crate::persistence::PersistenceErrorKind::PolicyDenied => {
                    ServiceError::policy_denied("Authoritative context denied")
                }
                _ => ServiceError::persistence(e),
            })?;

        // Step 3: Construct Execution Request
        let execution_id = ExecutionId::new();
        let request = ExecutionRequest {
            execution_id,
            session_id: req.session_id,
            task_id: req.task_id,
            scope: req.scope,
            action: context.action().clone(),
            target_revision: context.target_revision().into(),
            resource_limits: req.resource_limits.unwrap_or_default(),
            classification: req.classification,
            created_at: self.clock.now(),
        };

        // Step 4: Dispatch Execution Request
        let exec_result: Result<ExecutionResult, ExecutionError> =
            self.execution_engine.dispatch(&request);
        // Release the lifecycle fence after synchronous dispatch, before settlement.
        drop(prepared);

        let exec_result = match exec_result {
            Ok(res) => res,
            Err(exec_err) => {
                // On dispatch error (e.g. BackendUnavailable, BackendFault, CorrelationMismatch):
                // Preserve conservative budget reservation! Zero budget is released.
                // F-561-03: Never silently ignore budget settlement failure!
                if let Err(settle_err) = self.authority.settle_budget_for_session(
                    context.session_id(),
                    reservation_id,
                    SettlementStatus::CancelledUncertain,
                    EventId::new(),
                    &self.clock,
                ) {
                    return Err(ServiceError::execution_with_settlement_failure(
                        exec_err, settle_err,
                    ));
                }

                return Err(ServiceError::execution(exec_err));
            }
        };

        // Step 5: Verify Evidence Envelopes
        let mut admitted_evidence = Vec::new();
        for envelope in &req.evidence_envelopes {
            match self.evidence_verifier.verify_envelope(envelope) {
                Ok(artifact) => admitted_evidence.push(artifact),
                Err(ev_err) => {
                    // Evidence validation failure: abort and settle budget conservatively
                    // F-561-03: Never silently ignore budget settlement failure!
                    if let Err(settle_err) = self.authority.settle_budget_for_session(
                        context.session_id(),
                        reservation_id,
                        SettlementStatus::UncertainPartial,
                        EventId::new(),
                        &self.clock,
                    ) {
                        return Err(ServiceError::evidence_with_settlement_failure(
                            ev_err, settle_err,
                        ));
                    }
                    return Err(ServiceError::evidence(ev_err));
                }
            }
        }

        // Step 6: Settle Budget
        // No actual monetary usage is supplied by this backend contract. An
        // estimate is a reservation bound, never a measurement of actual usage.
        let settlement = match exec_result.status {
            ExecutionStatus::TimedOut | ExecutionStatus::Cancelled => {
                SettlementStatus::CancelledUncertain
            }
            ExecutionStatus::Completed | ExecutionStatus::Failed => {
                SettlementStatus::UncertainPartial
            }
        };
        if let Err(secondary) = self.authority.settle_budget_for_session(
            context.session_id(),
            reservation_id,
            settlement,
            EventId::new(),
            &self.clock,
        ) {
            return Err(if exec_result.status == ExecutionStatus::Completed {
                ServiceError::persistence(secondary)
            } else {
                ServiceError::outcome_with_settlement_failure(
                    exec_result.status,
                    exec_result.exit_code,
                    secondary,
                )
            });
        }

        Ok(TaskExecutionReport {
            execution_id: exec_result.execution_id,
            session_id: req.session_id,
            task_id: req.task_id,
            status: exec_result.status,
            exit_code: exec_result.exit_code,
            resource_usage: exec_result.resource_usage,
            admitted_evidence,
            settlement,
            completed_at: exec_result.completed_at,
        })
    }

    // -------------------------------------------------------------------------
    // Cancellation and Backend Lifecycle (Section 5 / F-551-02)
    // -------------------------------------------------------------------------

    /// Requests and reconciles task cancellation.
    ///
    /// Implements the formal cancellation contract. In Phase 1 synthetic execution,
    /// marks termination confirmed and settles budget conservatively (`CancelledUncertain`).
    pub fn cancel_task(
        &self,
        session_id: SessionId,
        execution_id: ExecutionId,
        reason: CancellationReason,
        reservation_id: Option<Identifier>,
    ) -> Result<CancellationReport, ServiceError> {
        let session = self.get_session(session_id)?;
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot cancel task on a terminal session",
            ));
        }

        let now = self.clock.now();
        let report = CancellationReport::simulated_synthetic(execution_id, reason, now);

        // Conservative budget settlement on cancellation (if reservation exists)
        if let Some(res_id) = reservation_id {
            self.authority
                .settle_budget_for_session(
                    session_id,
                    res_id,
                    report.settlement_status,
                    EventId::new(),
                    &self.clock,
                )
                .map_err(ServiceError::persistence)?;
        }

        Ok(report)
    }
}

impl std::fmt::Debug for TaskExecutionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskExecutionRequest([redacted])")
    }
}
