//! Independent 5.6.2.2.1 verification. Owned inert fixtures; no production hooks.
#![forbid(unsafe_code)]

use rusqlite::Connection;
use sentra_core::{
    BackendCapabilities, Clock, CoreService, CoreServiceConfig, CostUsd, EventId, EvidenceEnvelope,
    EvidenceId, EvidenceMetadata, ExecutionBackend, ExecutionError, ExecutionErrorKind,
    ExecutionRequest, ExecutionResult, ExecutionStatus, Identifier, MockClock, OperatingMode,
    OperationAction, PolicyEngine, ResourceUsage, SecurityClassification as Class, ServiceError,
    ServiceErrorKind, SessionId, SessionState, TaskExecutionRequest, TaskId, TimestampUtc,
    persistence::{
        ExecutionContext, PersistenceError, PersistenceErrorKind as Kind, PersistenceRepository,
        PersistentApprovalAuthority, PersistentApprovalGrant, PrepareExecutionRequest,
        SqliteConnectionManager,
    },
    service::ServicePrimaryError,
};
use std::{
    error::Error,
    fs,
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
};

static NEXT: AtomicU64 = AtomicU64::new(1);
fn event() -> EventId {
    EventId::for_test_sequence(90_000_000 + NEXT.fetch_add(1, Ordering::Relaxed))
}
fn amount(value: u64) -> CostUsd {
    CostUsd::from_micro_usd(value)
}
fn metadata_action() -> OperationAction {
    OperationAction::DiscoverMetadata {
        relative_path: "owned metadata".into(),
    }
}
fn tool() -> OperationAction {
    OperationAction::ExecuteTool {
        tool_id: "owned:inert".into(),
        untrusted: false,
        arguments: vec!["REVIEW_PRIVATE_ARGUMENT".into()],
    }
}

struct Directory {
    root: PathBuf,
    base: PathBuf,
}
impl Directory {
    fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/independent-562221-fixtures");
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let root = base.join(format!(
            "owned-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root, base }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let root = fs::canonicalize(&self.root).unwrap();
        assert!(root.starts_with(&self.base) && root != self.base);
        let result = fs::remove_dir_all(root);
        assert!(
            result.is_ok() || thread::panicking(),
            "owned fixture cleanup failed"
        );
    }
}
struct Backend {
    mode: usize,
    calls: AtomicUsize,
}
impl ExecutionBackend for Backend {
    fn name(&self) -> &'static str {
        "independent-inert-observer"
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_synthetic: true,
            supports_untrusted: false,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Inert test-only result producer",
        }
    }
    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        assert!(request.scope.is_synthetic());
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode == 1 {
            return Err(ExecutionError {
                kind: ExecutionErrorKind::BackendFault,
                message: "REVIEW_PRIVATE_BACKEND E:/private/token".into(),
            });
        }
        assert_ne!(self.mode, 5, "owned backend panic");
        let status = match self.mode {
            2 => ExecutionStatus::Failed,
            3 => ExecutionStatus::TimedOut,
            4 => ExecutionStatus::Cancelled,
            _ => ExecutionStatus::Completed,
        };
        Ok(ExecutionResult {
            execution_id: request.execution_id,
            status,
            exit_code: match status {
                ExecutionStatus::Completed => Some(0),
                ExecutionStatus::Failed => Some(7),
                _ => None,
            },
            resource_usage: ResourceUsage::zero(),
            evidence_descriptors: vec![],
            completed_at: request.created_at,
        })
    }
}
struct Fixture {
    service: CoreService,
    repo: PersistenceRepository,
    authority: PersistentApprovalAuthority,
    manager: SqliteConnectionManager,
    backend: Arc<Backend>,
    clock: Arc<MockClock>,
    directory: Directory,
}
impl Fixture {
    fn new(mode: usize) -> Self {
        let directory = Directory::new();
        let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
        let manager =
            SqliteConnectionManager::open(&directory.root.join("owned.db"), &clock).unwrap();
        let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
        let backend = Arc::new(Backend {
            mode,
            calls: AtomicUsize::new(0),
        });
        let service = CoreService::new(
            CoreServiceConfig::default(),
            repo.clone(),
            authority.clone(),
            PolicyEngine::new(),
            backend.clone(),
            clock.clone(),
        );
        Self {
            service,
            repo,
            authority,
            manager,
            backend,
            clock,
            directory,
        }
    }
    fn session(&self) -> SessionId {
        self.service
            .create_session(
                self.directory.root.to_str().unwrap(),
                OperatingMode::ContinuousReview,
                "owned-review-controller",
                Class::Internal,
                "revision-A",
                amount(100),
            )
            .unwrap()
    }
    fn context(&self, session: SessionId, action: &OperationAction) -> ExecutionContext {
        self.authority
            .execution_context(
                session,
                Class::Internal,
                action,
                amount(7),
                &PolicyEngine::new(),
            )
            .unwrap()
    }
    fn grant(&self, session: SessionId, action: &OperationAction) -> PersistentApprovalGrant {
        let id = self
            .service
            .request_approval(session, action, Class::Internal)
            .unwrap();
        self.service
            .issue_approval(session, id, action, Class::Internal)
            .unwrap()
    }
    fn request(
        &self,
        session: SessionId,
        action: OperationAction,
        grant: Option<PersistentApprovalGrant>,
    ) -> TaskExecutionRequest {
        let mut request = TaskExecutionRequest::synthetic(
            session,
            TaskId::for_test_sequence(562221),
            action,
            amount(7),
        );
        request.grant = grant;
        request
    }
    fn raw(&self) -> Connection {
        Connection::open(self.directory.root.join("owned.db")).unwrap()
    }
    fn counts(&self) -> (i64, i64) {
        let db = self.raw();
        (
            db.query_row("SELECT count(*) FROM budget_reservations", [], |r| r.get(0))
                .unwrap(),
            db.query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
                .unwrap(),
        )
    }
    fn state(&self, grant: &PersistentApprovalGrant) -> String {
        self.raw()
            .query_row(
                "SELECT state FROM approval_requests WHERE request_id=?1",
                [grant.request_id().to_string()],
                |r| r.get(0),
            )
            .unwrap()
    }
    fn prepare(
        &self,
        context: ExecutionContext,
        grant: Option<&PersistentApprovalGrant>,
    ) -> Result<sentra_core::persistence::PreparedExecution, PersistenceError> {
        self.repo.reserve_budget_and_consume_approval(
            PrepareExecutionRequest {
                context,
                grant,
                reservation_id: Identifier::new_deterministic(
                    562221,
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ),
                reservation_event: event(),
                consumption_event: event(),
            },
            &self.clock,
        )
    }
}

#[test]
fn independent_real_lifecycle_pause_wait_terminal_and_resume_boundaries() {
    for target in [
        SessionState::Paused,
        SessionState::WaitingForApproval,
        SessionState::Completed,
        SessionState::Failed,
        SessionState::Cancelled,
    ] {
        let f = Fixture::new(0);
        let id = f.session();
        let action = tool();
        let grant = f.grant(id, &action);
        if matches!(
            target,
            SessionState::Paused | SessionState::WaitingForApproval | SessionState::Completed
        ) {
            f.service
                .transition_session(id, SessionState::Planned, "owned lifecycle")
                .unwrap();
            if target != SessionState::WaitingForApproval {
                f.service
                    .transition_session(id, SessionState::Running, "owned lifecycle")
                    .unwrap();
            }
        }
        f.service
            .transition_session(id, target, "owned lifecycle")
            .unwrap();
        let before = f.counts();
        assert_eq!(
            f.service
                .execute_task(f.request(id, action.clone(), Some(grant.clone())))
                .unwrap_err()
                .kind,
            ServiceErrorKind::InvalidState
        );
        assert_eq!(f.counts(), before);
        assert_eq!(f.state(&grant), "ISSUED");
        assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
        if target == SessionState::Paused {
            f.service
                .transition_session(id, SessionState::Running, "explicit resume")
                .unwrap();
            f.service
                .execute_task(f.request(id, action, Some(grant)))
                .unwrap();
        } else if target.is_terminal() {
            assert!(
                f.service
                    .transition_session(id, SessionState::Running, "forbidden")
                    .is_err()
            );
        }
    }
}

#[test]
fn independent_context_generation_rotates_on_repeated_owner_registration() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let old = f.context(id, &action);
    let record = f.service.get_session(id).unwrap();
    let updated = f
        .authority
        .register_session(
            &record.metadata,
            &record.target_revision,
            record.classification_floor,
            record.budget_limit,
            event(),
            &f.clock,
        )
        .unwrap();
    assert_eq!(updated.context_generation, record.context_generation + 1);
    let before = f.counts();
    assert_eq!(
        f.prepare(old, Some(&grant)).unwrap_err().kind,
        Kind::ContextMismatch
    );
    assert_eq!(before, f.counts());
    assert_eq!(f.state(&grant), "ISSUED");
}

#[test]
fn independent_simultaneous_old_and_current_contexts_have_only_current_winner() {
    let f = Fixture::new(0);
    let id = f.session();
    let old = f.context(id, &metadata_action());
    let record = f.service.get_session(id).unwrap();
    f.authority
        .register_session(
            &record.metadata,
            "revision-B",
            Class::Internal,
            record.budget_limit,
            event(),
            &f.clock,
        )
        .unwrap();
    let current = f.context(id, &metadata_action());
    let barrier = Barrier::new(3);
    let (old_result, current_result) = thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            f.prepare(old, None)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            f.prepare(current, None)
        });
        barrier.wait();
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(old_result.unwrap_err().kind, Kind::ContextMismatch);
    assert!(current_result.is_ok());
    assert_eq!(f.repo.budget_used(id).unwrap(), amount(7));
    assert_eq!(f.counts().0, 1);
}

#[test]
fn independent_cross_session_prepare_preserves_both_owners_and_matching_grant() {
    let f = Fixture::new(0);
    let a = f.session();
    let b = f.session();
    let action = tool();
    let grant = f.grant(a, &action);
    let before = f.counts();
    assert_eq!(
        f.prepare(f.context(b, &action), Some(&grant))
            .unwrap_err()
            .kind,
        Kind::ContextMismatch
    );
    assert_eq!(before, f.counts());
    assert_eq!(f.state(&grant), "ISSUED");
    assert_eq!(f.repo.budget_used(a).unwrap(), CostUsd::ZERO);
    assert_eq!(f.repo.budget_used(b).unwrap(), CostUsd::ZERO);
    let prepared = f.prepare(f.context(a, &action), Some(&grant)).unwrap();
    let reservation = prepared.budget.reservation_id;
    drop(prepared);
    assert_eq!(f.repo.budget_used(a).unwrap(), amount(7));
    assert_eq!(f.repo.budget_used(b).unwrap(), CostUsd::ZERO);
    let db = f.raw();
    let owner: String = db
        .query_row(
            "SELECT session_id FROM budget_reservations WHERE reservation_id=?1",
            [reservation.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owner, a.to_string());
    let audits = f.repo.audit_events(a, 0, 100).unwrap();
    let last = &audits[audits.len() - 2..];
    assert!(last.iter().all(|e| e.session_id == a));
    assert_eq!(last[0].event_kind, "BudgetReserved");
    assert_eq!(last[1].event_kind, "ApprovalConsumed");
    assert_eq!(last[1].sequence_number, last[0].sequence_number + 1);
    assert_eq!(
        f.prepare(f.context(a, &action), Some(&grant))
            .unwrap_err()
            .kind,
        Kind::ApprovalReused
    );
}

#[test]
fn independent_budget_wait_then_context_change_rejects_old_approval() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let old = f.context(id, &action);
    let fill = f
        .authority
        .execution_context(
            id,
            Class::Internal,
            &metadata_action(),
            amount(100),
            &PolicyEngine::new(),
        )
        .unwrap();
    drop(f.prepare(fill, None).unwrap());
    let before = f.counts();
    assert_eq!(
        f.prepare(old.clone(), Some(&grant)).unwrap_err().kind,
        Kind::BudgetExceeded
    );
    assert_eq!(before, f.counts());
    assert_eq!(f.state(&grant), "ISSUED");
    let record = f.service.get_session(id).unwrap();
    f.authority
        .register_session(
            &record.metadata,
            "revision-B",
            Class::Restricted,
            amount(200),
            event(),
            &f.clock,
        )
        .unwrap();
    let before = f.counts();
    assert_eq!(
        f.prepare(old, Some(&grant)).unwrap_err().kind,
        Kind::ContextMismatch
    );
    assert_eq!(before, f.counts());
    assert_eq!(f.state(&grant), "ISSUED");
}

#[test]
fn independent_sql_settlement_fault_keeps_both_typed_causes_and_rolls_back_cleanup() {
    for (mode, evidence) in [
        (1, false),
        (0, true),
        (2, false),
        (3, false),
        (4, false),
        (0, false),
    ] {
        let f = Fixture::new(mode);
        let id = f.session();
        let action = tool();
        let grant = f.grant(id, &action);
        f.raw().execute_batch("CREATE TRIGGER owned_settlement_fault BEFORE INSERT ON audit_events WHEN NEW.event_kind='BudgetUsageUnknown' BEGIN SELECT RAISE(ABORT,'owned SQL statement fault'); END").unwrap();
        let mut request = f.request(id, action, Some(grant.clone()));
        if evidence {
            request.evidence_envelopes.push(EvidenceEnvelope::new(
                EvidenceMetadata {
                    evidence_id: EvidenceId::for_test_sequence(562221),
                    session_id: id,
                    task_id: request.task_id,
                    producer_role: "owned".into(),
                    media_type: "REVIEW_PRIVATE_MEDIA".into(),
                    payload_length_bytes: 0,
                    declared_sha256: None,
                    classification: Class::Internal,
                    created_at: f.clock.now(),
                },
                vec![],
            ));
        }
        let error = f.service.execute_task(request).unwrap_err();
        if mode == 0 && !evidence {
            assert_eq!(error.kind, ServiceErrorKind::Persistence);
            assert!(error.secondary_error().is_none());
            assert!(
                matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(p)) if p.sqlite_code==Some(1811))
            );
        } else {
            assert_eq!(error.secondary_error().unwrap().kind, Kind::Database);
            assert_eq!(error.secondary_error().unwrap().sqlite_code, Some(1811));
            match error.primary_error().unwrap() {
                ServicePrimaryError::Execution(e) => {
                    assert_eq!(e.kind, ExecutionErrorKind::BackendFault)
                }
                ServicePrimaryError::Evidence(e) => assert_eq!(
                    e.kind,
                    sentra_core::EvidenceVerificationErrorKind::InvalidMediaType
                ),
                ServicePrimaryError::Outcome(e) => assert_eq!(
                    e.status,
                    match mode {
                        2 => ExecutionStatus::Failed,
                        3 => ExecutionStatus::TimedOut,
                        _ => ExecutionStatus::Cancelled,
                    }
                ),
                other => panic!("unexpected primary {other:?}"),
            }
        }
        assert!(error.source().is_some());
        assert!(
            !format!(
                "{error} {error:?} {:?} {:?}",
                error.primary_error(),
                error.source()
            )
            .contains("REVIEW_PRIVATE")
        );
        let state: (String, Option<i64>) = f
            .raw()
            .query_row(
                "SELECT state,actual_cost_micro_usd FROM budget_reservations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("RESERVED".into(), None));
        assert_eq!(f.state(&grant), "CONSUMED");
        assert_eq!(f.repo.budget_used(id).unwrap(), amount(7));
        assert!(
            f.repo
                .audit_events(id, 0, 100)
                .unwrap()
                .iter()
                .all(|e| e.event_kind != "BudgetUsageUnknown")
        );
    }
}

#[test]
fn independent_error_accessors_sanitize_constructor_bypass_and_keep_secondary_numbers() {
    let secondary = PersistenceError {
        kind: Kind::RollbackFailed,
        sqlite_code: Some(1811),
        rollback_code: Some(10),
        attempts: Some(5),
    };
    let mut error = ServiceError::execution_with_settlement_failure(
        ExecutionError {
            kind: ExecutionErrorKind::InvalidRequest,
            message: "REVIEW_PRIVATE_RAW_TOKEN".into(),
        },
        secondary.clone(),
    );
    error.message = "REVIEW_PRIVATE_MUTATED_SUMMARY".into();
    assert_eq!(error.secondary_error(), Some(&secondary));
    let original = error
        .source()
        .unwrap()
        .downcast_ref::<ExecutionError>()
        .unwrap();
    assert_eq!(original.kind, ExecutionErrorKind::InvalidRequest);
    assert!(
        !format!(
            "{error:?} {error} {original:?} {original} {:?}",
            error.primary_error()
        )
        .contains("REVIEW_PRIVATE")
    );
}

#[test]
fn independent_backend_unwind_releases_fence_without_refunding_or_reusing_approval() {
    let f = Fixture::new(5);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.service
            .execute_task(f.request(id, action.clone(), Some(grant.clone())))
    }));
    assert!(result.is_err());
    assert_eq!(f.state(&grant), "CONSUMED");
    assert_eq!(f.repo.budget_used(id).unwrap(), amount(7));
    assert_eq!(
        f.service
            .execute_task(f.request(id, action, Some(grant)))
            .unwrap_err()
            .kind,
        ServiceErrorKind::ApprovalInvalid
    );
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 1);
    let record = f.service.get_session(id).unwrap();
    f.authority
        .register_session(
            &record.metadata,
            "after-unwind",
            Class::Internal,
            record.budget_limit,
            event(),
            &f.clock,
        )
        .unwrap();
    f.manager.integrity_check().unwrap();
}

#[test]
fn observation_policy_rule_changes_without_context_registration_leave_old_context_valid() {
    let f = Fixture::new(0);
    let id = f.session();
    let mut policy = PolicyEngine::new();
    policy.set_max_auto_budget(amount(10));
    let old = f
        .authority
        .execution_context(id, Class::Internal, &metadata_action(), amount(7), &policy)
        .unwrap();
    assert!(!old.requires_approval());
    policy.set_max_auto_budget(amount(1));
    let fresh = f
        .authority
        .execution_context(id, Class::Internal, &metadata_action(), amount(7), &policy)
        .unwrap();
    assert!(fresh.requires_approval());
    assert_eq!(old.context_generation(), fresh.context_generation());
    // Characterize the boundary accurately: rules are frozen at mint, not stored
    // or hot-reloaded by the session. The trusted owner must re-register policy.
    assert_eq!(
        f.prepare(fresh, None).unwrap_err().kind,
        Kind::InvalidApproval
    );
    drop(f.prepare(old, None).unwrap());
}

#[test]
fn observation_closed_database_policy_preview_returns_denied_instead_of_typed_error() {
    let f = Fixture::new(0);
    let id = f.session();
    f.manager.shutdown().unwrap();
    assert_eq!(
        f.service.get_session(id).unwrap_err().kind,
        ServiceErrorKind::Persistence
    );
    assert!(matches!(
        f.service
            .evaluate_action(id, &metadata_action(), Class::Internal, None)
            .unwrap(),
        sentra_core::ServicePolicyDecision::Denied { .. }
    ));
}
