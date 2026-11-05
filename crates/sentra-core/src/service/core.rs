//! Core Service orchestrator coordinating session, workspace, policy, persistence, execution, and evidence.

use std::{path::Path, sync::Arc};

use crate::{
    Clock, CostUsd, EventId, EvidenceArtifact, EvidenceEnvelope, EvidenceVerifier,
    ExecutionBackend, ExecutionEngine, ExecutionError, ExecutionId, ExecutionRequest,
    ExecutionResult, ExecutionScope, ExecutionStatus, Identifier, OperatingMode, OperationAction,
    PolicyDecision, PolicyEngine, ResourceLimits, ResourceUsage, SecurityClassification, SessionId,
    SessionMetadata, SessionState, TaskId, TimestampUtc,
    persistence::{
        ApprovalIntent, PersistenceRepository, PersistentApprovalAuthority,
        PersistentApprovalGrant, SessionRecord, SettlementStatus,
    },
    service::{
        config::CoreServiceConfig,
        error::ServiceError,
        lifecycle::{CancellationReason, CancellationReport},
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
#[derive(Clone, Debug)]
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
/// 3. Approvals are cryptographically bound, single-use, and atomically consumed.
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
            .register_session(
                &metadata,
                target_revision,
                classification_floor,
                budget_limit,
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
        let session = self.get_session(session_id)?;
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot evaluate policy on a terminal session",
            ));
        }

        // Security classification floor enforcement
        if classification < session.classification_floor {
            return Ok(ServicePolicyDecision::Denied {
                reason: format!(
                    "Classification '{classification:?}' is below session floor '{:?}'",
                    session.classification_floor
                ),
            });
        }

        // Evaluate using default-deny policy engine
        let decision = self.policy_engine.evaluate(
            &session.metadata,
            classification,
            action,
            None,
            &self.clock,
        );

        match decision {
            PolicyDecision::Granted => Ok(ServicePolicyDecision::Granted),
            PolicyDecision::Denied { reason } => Ok(ServicePolicyDecision::Denied {
                reason: reason.to_string(),
            }),
            PolicyDecision::NeedsApproval { request, .. } => {
                if grant.is_some() {
                    // Caller presented a grant; it will be validated and consumed during task execution
                    Ok(ServicePolicyDecision::Granted)
                } else {
                    Ok(ServicePolicyDecision::NeedsApproval {
                        action_name: action.action_name(),
                        description: request.explanation,
                    })
                }
            }
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
        if session.state.is_terminal() {
            return Err(ServiceError::invalid_state(
                "Cannot execute task on a terminal session",
            ));
        }

        // Step 1: Policy & Approval Verification
        let requires_approval = req.action.is_sensitive() || req.scope.is_untrusted();
        if requires_approval && req.grant.is_none() {
            return Err(ServiceError::policy_denied(format!(
                "Action '{}' requires an approval grant",
                req.action.action_name()
            )));
        }

        // If a grant is provided, atomically consume it (guarantees single-use)
        if let Some(ref g) = req.grant {
            let intent = ApprovalIntent {
                session: &session.metadata,
                context_generation: session.context_generation,
                target_revision: &session.target_revision,
                classification: req.classification,
                action: &req.action,
            };
            let consume_event = EventId::new();
            self.repository
                .consume_approval(g, &intent, consume_event, &self.clock)
                .map_err(|e| {
                    ServiceError::approval_invalid(format!("Approval consumption failed: {e}"))
                })?;
        }

        // Step 2: Reserve Budget
        let reservation_id = Identifier::new_sequential(0x5345_4e54_5241_0007);
        let event_id = EventId::new();
        let model_id = match &req.action {
            OperationAction::InvokeProvider { model_id, .. } => model_id.as_str(),
            _ => "synthetic-task",
        };
        self.repository
            .reserve_budget(
                reservation_id,
                req.session_id,
                model_id,
                req.estimated_cost,
                event_id,
                &self.clock,
            )
            .map_err(|e| {
                ServiceError::budget_exceeded(format!("Budget reservation failed: {e}"))
            })?;

        // Step 3: Construct Execution Request
        let execution_id = ExecutionId::new();
        let request = ExecutionRequest {
            execution_id,
            session_id: req.session_id,
            task_id: req.task_id,
            scope: req.scope,
            action: req.action,
            target_revision: session.target_revision.clone(),
            resource_limits: req.resource_limits.unwrap_or_default(),
            classification: req.classification,
            created_at: self.clock.now(),
        };

        // Step 4: Dispatch Execution Request
        let exec_result: Result<ExecutionResult, ExecutionError> =
            self.execution_engine.dispatch(&request);

        let exec_result = match exec_result {
            Ok(res) => res,
            Err(exec_err) => {
                // On dispatch error (e.g. BackendUnavailable, BackendFault, CorrelationMismatch):
                // Preserve conservative budget reservation! Zero budget is released.
                let _ = self.authority.settle_budget(
                    reservation_id,
                    SettlementStatus::CancelledUncertain,
                    EventId::new(),
                    &self.clock,
                );

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
                    let _ = self.authority.settle_budget(
                        reservation_id,
                        SettlementStatus::UncertainPartial,
                        EventId::new(),
                        &self.clock,
                    );
                    return Err(ServiceError::evidence(ev_err));
                }
            }
        }

        // Step 6: Settle Budget
        let settlement = match exec_result.status {
            ExecutionStatus::Completed => {
                // Completed: release unconsumed difference
                SettlementStatus::Completed(req.estimated_cost)
            }
            ExecutionStatus::TimedOut | ExecutionStatus::Cancelled => {
                // Uncertain / timed out: preserve conservative reservation ceiling
                SettlementStatus::CancelledUncertain
            }
            ExecutionStatus::Failed => {
                // Application failure with recorded usage
                SettlementStatus::CancelledWithUsage(req.estimated_cost)
            }
        };

        self.authority
            .settle_budget(reservation_id, settlement, EventId::new(), &self.clock)
            .map_err(ServiceError::persistence)?;

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
                .settle_budget(
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
