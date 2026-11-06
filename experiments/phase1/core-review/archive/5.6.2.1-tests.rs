//! Independent 5.6.2.1 verification. No production changes or fault-injection hooks.
//! Run `cargo test --test independent_core_review_tests --offline review_ -- --ignored --test-threads=1`.
//! Assertions specify required secure behavior; failures must remain visible as findings.
#![forbid(unsafe_code)]

use rusqlite::Connection;
use sentra_core::{
    ApprovalId, BackendCapabilities, CoreService, CoreServiceConfig, CostUsd, EventId,
    EvidenceEnvelope, EvidenceId, EvidenceMetadata, ExecutionBackend, ExecutionError,
    ExecutionErrorKind, ExecutionRequest, ExecutionResult, ExecutionScope, ExecutionStatus,
    Identifier, MockClock, OperatingMode, OperationAction, PolicyDecision, PolicyEngine,
    ResourceUsage, SecurityClassification as Class, ServiceErrorKind, SessionId, SessionState,
    TaskExecutionRequest, TaskId, TimestampUtc,
    persistence::{
        ApprovalIntent, PersistenceErrorKind as Kind, PersistenceRepository,
        PersistentApprovalGrant, PrepareExecutionRequest, SqliteConnectionManager,
    },
};
use std::{
    error::Error,
    fs,
    io::{BufRead, Write},
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(1);
fn event() -> EventId {
    EventId::for_test_sequence(8_000_000 + NEXT.fetch_add(1, Ordering::Relaxed))
}
fn id() -> Identifier {
    Identifier::new_deterministic(5621, NEXT.fetch_add(1, Ordering::Relaxed))
}
fn tool() -> OperationAction {
    OperationAction::ExecuteTool {
        tool_id: "synthetic:noop".into(),
        untrusted: false,
        arguments: vec![],
    }
}
fn metadata_action() -> OperationAction {
    OperationAction::DiscoverMetadata {
        relative_path: "synthetic metadata".into(),
    }
}

struct OwnedDirectory {
    root: PathBuf,
    base: PathBuf,
    db: PathBuf,
    workspace: PathBuf,
}
impl OwnedDirectory {
    fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/independent-5621-fixtures");
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let root = base.join(format!(
            "owned-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        Self {
            db: root.join("review.db"),
            root,
            base,
            workspace,
        }
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if let Ok(root) = fs::canonicalize(&self.root) {
            assert!(root.starts_with(&self.base) && root != self.base);
            let result = fs::remove_dir_all(root);
            assert!(
                result.is_ok() || thread::panicking(),
                "owned review cleanup failed"
            );
        }
    }
}

struct ObserverBackend {
    manager: SqliteConnectionManager,
    calls: AtomicUsize,
    close_on_dispatch: AtomicBool,
    fault: AtomicBool,
    result_status: AtomicUsize,
    park_before_effect: bool,
}
impl ExecutionBackend for ObserverBackend {
    fn name(&self) -> &'static str {
        "owned-review-observer"
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: true,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Owned in-process observer; no target workload or external side effect",
        }
    }
    fn execute(&self, req: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        assert!(req.scope.is_synthetic());
        if self.park_before_effect {
            println!("OWNED_5621_READY_AFTER_COMMIT_BEFORE_EFFECT");
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            std::io::stdin().lock().read_line(&mut input).unwrap();
            panic!("parent must terminate this owned fixture before its effect");
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.close_on_dispatch.load(Ordering::SeqCst) {
            self.manager.shutdown().unwrap();
        }
        if self.fault.load(Ordering::SeqCst) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::BackendFault,
                "REVIEW_SECRET_BACKEND_TOKEN at E:/synthetic/private/source",
            ));
        }
        let status = match self.result_status.load(Ordering::SeqCst) {
            1 => ExecutionStatus::Failed,
            2 => ExecutionStatus::TimedOut,
            3 => ExecutionStatus::Cancelled,
            _ => ExecutionStatus::Completed,
        };
        Ok(ExecutionResult {
            execution_id: req.execution_id,
            status,
            exit_code: match status {
                ExecutionStatus::Completed => Some(0),
                ExecutionStatus::Failed => Some(7),
                _ => None,
            },
            resource_usage: ResourceUsage::zero(),
            evidence_descriptors: vec![],
            completed_at: req.created_at,
        })
    }
}

struct Fixture {
    service: CoreService,
    repo: PersistenceRepository,
    manager: SqliteConnectionManager,
    backend: Arc<ObserverBackend>,
    clock: Arc<MockClock>,
    directory: OwnedDirectory,
}
impl Fixture {
    fn new() -> Self {
        let directory = OwnedDirectory::new();
        let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
        let manager = SqliteConnectionManager::open(&directory.db, &clock).unwrap();
        let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
        let backend = Arc::new(ObserverBackend {
            manager: manager.clone(),
            calls: AtomicUsize::new(0),
            close_on_dispatch: AtomicBool::new(false),
            fault: AtomicBool::new(false),
            result_status: AtomicUsize::new(0),
            park_before_effect: false,
        });
        let service = CoreService::new(
            CoreServiceConfig::default(),
            repo.clone(),
            authority,
            PolicyEngine::new(),
            backend.clone(),
            clock.clone(),
        );
        Self {
            service,
            repo,
            manager,
            backend,
            clock,
            directory,
        }
    }
    fn session(&self, budget: u64) -> SessionId {
        self.service
            .create_session(
                self.directory.workspace.to_str().unwrap(),
                OperatingMode::ContinuousReview,
                "owned-review-operator",
                Class::Internal,
                "revision-A",
                CostUsd::from_micro_usd(budget),
            )
            .unwrap()
    }
    fn grant(&self, session: SessionId, action: &OperationAction) -> PersistentApprovalGrant {
        let request = self
            .service
            .request_approval(session, action, Class::Internal)
            .unwrap();
        self.service
            .issue_approval(session, request, action, Class::Internal)
            .unwrap()
    }
    fn request(
        &self,
        session: SessionId,
        action: OperationAction,
        grant: Option<PersistentApprovalGrant>,
        amount: u64,
    ) -> TaskExecutionRequest {
        TaskExecutionRequest {
            session_id: session,
            task_id: TaskId::for_test_sequence(5621),
            scope: ExecutionScope::SyntheticFixture,
            action,
            classification: Class::Internal,
            resource_limits: None,
            estimated_cost: CostUsd::from_micro_usd(amount),
            grant,
            evidence_envelopes: vec![],
        }
    }
    fn raw(&self) -> Connection {
        Connection::open(&self.directory.db).unwrap()
    }
    fn counts(&self) -> (i64, i64) {
        let raw = self.raw();
        (
            raw.query_row("SELECT count(*) FROM budget_reservations", [], |r| r.get(0))
                .unwrap(),
            raw.query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
                .unwrap(),
        )
    }
    fn approval_state(&self, grant: &PersistentApprovalGrant) -> String {
        self.raw()
            .query_row(
                "SELECT state FROM approval_requests WHERE request_id=?1",
                [grant.request_id().to_string()],
                |r| r.get(0),
            )
            .unwrap()
    }
}

fn intent<'a>(
    record: &'a sentra_core::persistence::SessionRecord,
    action: &'a OperationAction,
) -> ApprovalIntent<'a> {
    ApprovalIntent {
        session: &record.metadata,
        context_generation: record.context_generation,
        target_revision: &record.target_revision,
        classification: Class::Internal,
        action,
    }
}
fn prepare<'a>(
    session: SessionId,
    grant: Option<(&'a PersistentApprovalGrant, &'a ApprovalIntent<'a>)>,
    amount: u64,
) -> PrepareExecutionRequest<'a> {
    PrepareExecutionRequest {
        reservation_id: id(),
        session_id: session,
        model_id: "owned-fixture",
        amount: CostUsd::from_micro_usd(amount),
        grant_and_intent: grant,
        reservation_event: event(),
        consumption_event: event(),
    }
}
fn malformed_envelope(session: SessionId) -> EvidenceEnvelope {
    EvidenceEnvelope::new(
        EvidenceMetadata {
            evidence_id: EvidenceId::for_test_sequence(5621),
            session_id: session,
            task_id: TaskId::for_test_sequence(5621),
            producer_role: "owned-review".into(),
            media_type: "REVIEW_SECRET_MEDIA_TOKEN".into(),
            payload_length_bytes: 0,
            declared_sha256: None,
            classification: Class::Internal,
            created_at: TimestampUtc::from_epoch_secs(1_700_000_000),
        },
        vec![],
    )
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_public_context_registration_cannot_lower_trusted_floor() {
    let f = Fixture::new();
    let session = f.session(100);
    let record = f.service.get_session(session).unwrap();
    let mut outcomes = Vec::new();
    for through_broker in [false, true] {
        let (engine, authority) = PolicyEngine::with_authority(Default::default());
        authority
            .set_session_context(&record.metadata, "revision-A", Class::Restricted)
            .unwrap();
        assert!(matches!(
            engine.evaluate(
                &record.metadata,
                Class::Public,
                &metadata_action(),
                None,
                &f.clock
            ),
            PolicyDecision::Denied { .. }
        ));
        let changed = if through_broker {
            engine.broker().set_session_context(
                &record.metadata,
                "untrusted-overwrite",
                Class::Public,
            )
        } else {
            engine.register_session_context(&record.metadata, "untrusted-overwrite", Class::Public)
        };
        let denied = matches!(
            engine.evaluate(
                &record.metadata,
                Class::Public,
                &metadata_action(),
                None,
                &f.clock
            ),
            PolicyDecision::Denied { .. }
        );
        outcomes.push(changed.is_err() || denied);
    }
    assert!(
        outcomes.iter().all(|secure| *secure),
        "request-side PolicyEngine and broker setters lowered a trusted Restricted floor to Public: {outcomes:?}"
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_same_context_synchronization_does_not_invalidate_issued_memory_grant() {
    let f = Fixture::new();
    let session = f.session(100);
    let record = f.service.get_session(session).unwrap();
    let action = tool();
    let (engine, authority) = PolicyEngine::with_authority(Default::default());
    authority
        .set_session_context(&record.metadata, &record.target_revision, Class::Internal)
        .unwrap();
    let request = engine
        .broker()
        .request_approval(&record.metadata, Class::Internal, &action, &f.clock)
        .unwrap();
    let grant = authority
        .issue_grant(&request.request_id, "owner", &f.clock)
        .unwrap();
    engine
        .register_session_context(&record.metadata, &record.target_revision, Class::Internal)
        .unwrap();
    assert!(
        engine
            .broker()
            .verify_and_consume(
                Some(&grant),
                &record.metadata,
                Class::Internal,
                &action,
                &f.clock
            )
            .is_ok(),
        "a no-op synchronization rotated generation and invalidated the issued grant"
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_atomic_prepare_cannot_consume_a_while_reserving_for_b() {
    let f = Fixture::new();
    let a = f.session(100);
    let b = f.session(100);
    let action = tool();
    let grant = f.grant(a, &action);
    let record = f.service.get_session(a).unwrap();
    let bound = intent(&record, &action);
    let before = f.counts();
    let result = f
        .repo
        .reserve_budget_and_consume_approval(prepare(b, Some((&grant, &bound)), 7), &f.clock);
    let intact = f.approval_state(&grant) == "ISSUED" && f.counts() == before;
    assert!(
        result.is_err() && intact,
        "one transaction consumed session A approval while charging session B; A={}, B={}",
        f.repo.budget_used(a).unwrap().as_micro_usd(),
        f.repo.budget_used(b).unwrap().as_micro_usd()
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_no_grant_prepare_revalidates_context_after_policy_decision() {
    let f = Fixture::new();
    let session = f.session(100);
    let old = f.service.get_session(session).unwrap();
    let action = metadata_action();
    let engine = PolicyEngine::new();
    engine
        .register_session_context(&old.metadata, &old.target_revision, Class::Internal)
        .unwrap();
    assert!(matches!(
        engine.evaluate(&old.metadata, Class::Internal, &action, None, &f.clock),
        PolicyDecision::Granted
    ));
    let (_, authority) = PersistenceRepository::with_authority(f.manager.clone());
    authority
        .register_session(
            &old.metadata,
            "revision-B",
            Class::Restricted,
            old.budget_limit,
            event(),
            &f.clock,
        )
        .unwrap();
    let result = f
        .repo
        .reserve_budget_and_consume_approval(prepare(session, None, 7), &f.clock);
    assert!(
        result.is_err(),
        "the no-grant prepare request cannot express or recheck the authorized generation/revision/classification"
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_paused_session_cannot_dispatch_new_work() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    for state in [
        SessionState::Planned,
        SessionState::Running,
        SessionState::Paused,
    ] {
        f.service
            .transition_session(session, state, "owned pause fixture")
            .unwrap();
    }
    let result = f
        .service
        .execute_task(f.request(session, action, Some(grant.clone()), 7));
    assert!(
        result.is_err()
            && f.backend.calls.load(Ordering::SeqCst) == 0
            && f.approval_state(&grant) == "ISSUED",
        "PAUSED state was treated as execution-eligible"
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_provider_action_cost_cannot_be_under_reserved() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = OperationAction::InvokeProvider {
        model_id: "deterministic-no-provider".into(),
        estimated_cost: CostUsd::from_micro_usd(200),
    };
    let result = f.service.execute_task(f.request(session, action, None, 0));
    assert!(
        result.is_err() && f.backend.calls.load(Ordering::SeqCst) == 0,
        "canonical action declares 200 micro-USD against a 100 limit but caller reserves/settles zero"
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure behavior and may expose a finding"]
fn review_prepare_debug_does_not_disclose_authorization_parameters() {
    let f = Fixture::new();
    let session = f.session(100);
    let mut action = tool();
    if let OperationAction::ExecuteTool { arguments, .. } = &mut action {
        arguments.push("REVIEW_SECRET_APPROVED_ARGUMENT".into());
    }
    let grant = f.grant(session, &action);
    let record = f.service.get_session(session).unwrap();
    let bound = intent(&record, &action);
    let request = prepare(session, Some((&grant, &bound)), 7);
    assert!(
        !format!("{request:?}").contains("REVIEW_SECRET_APPROVED_ARGUMENT"),
        "PrepareExecutionRequest derived Debug exposes its ApprovalIntent/action arguments"
    );
}

#[test]
#[ignore = "Explicit independent review; a preview must not claim an unrelated grant is valid"]
fn review_policy_preview_does_not_grant_with_another_sessions_receipt() {
    let f = Fixture::new();
    let a = f.session(100);
    let b = f.session(100);
    let action = tool();
    let grant = f.grant(a, &action);
    let decision = f
        .service
        .evaluate_action(b, &action, Class::Internal, Some(&grant))
        .unwrap();
    assert!(
        !matches!(decision, sentra_core::ServicePolicyDecision::Granted),
        "evaluate_action returned Granted based only on Some(grant), without binding it to session B"
    );
}

#[test]
#[ignore = "Explicit independent review; test-only statement fault injection"]
fn review_either_audit_failure_rolls_back_approval_budget_and_sequence() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let record = f.service.get_session(session).unwrap();
    let bound = intent(&record, &action);
    let duplicate: String = f
        .raw()
        .query_row(
            "SELECT event_id FROM audit_events ORDER BY sequence_number LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let duplicate: EventId = duplicate.parse().unwrap();
    let before = f.counts();
    for fail_consumption_audit in [false, true] {
        let mut request = prepare(session, Some((&grant, &bound)), 7);
        if fail_consumption_audit {
            request.consumption_event = duplicate;
        } else {
            request.reservation_event = duplicate;
        }
        assert!(
            f.repo
                .reserve_budget_and_consume_approval(request, &f.clock)
                .is_err()
        );
        assert_eq!(f.approval_state(&grant), "ISSUED");
        assert_eq!(f.counts(), before);
        assert_eq!(f.repo.budget_used(session).unwrap(), CostUsd::ZERO);
    }
    let result = f
        .repo
        .reserve_budget_and_consume_approval(prepare(session, Some((&grant, &bound)), 7), &f.clock)
        .unwrap();
    let audit = f.repo.audit_events(session, 0, 1000).unwrap();
    assert_eq!(audit[audit.len() - 2].event_kind, "BudgetReserved");
    assert_eq!(audit[audit.len() - 1].event_kind, "ApprovalConsumed");
    assert_eq!(
        result.1.unwrap().audit_sequence,
        audit.last().unwrap().sequence_number
    );
    assert!(
        audit
            .windows(2)
            .all(|w| w[1].sequence_number == w[0].sequence_number + 1)
    );
    assert_eq!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &bound)), 7),
                &f.clock
            )
            .unwrap_err()
            .kind,
        Kind::ApprovalReused
    );
    assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 7);
}

#[test]
#[ignore = "Explicit independent review; test-only SQLite trigger, never a production fault hook"]
fn review_approval_update_failure_rolls_back_prior_reservation_and_audit() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let record = f.service.get_session(session).unwrap();
    let bound = intent(&record, &action);
    let before = f.counts();
    f.raw().execute_batch("CREATE TRIGGER owned_review_reject_consumption BEFORE UPDATE OF state ON approval_requests WHEN NEW.state='CONSUMED' BEGIN SELECT RAISE(ABORT,'owned review statement fault'); END").unwrap();
    let error = f
        .repo
        .reserve_budget_and_consume_approval(prepare(session, Some((&grant, &bound)), 7), &f.clock)
        .unwrap_err();
    assert_eq!(error.sqlite_code, Some(1811));
    assert_eq!(f.counts(), before);
    assert_eq!(f.approval_state(&grant), "ISSUED");
    f.raw()
        .execute_batch("DROP TRIGGER owned_review_reject_consumption")
        .unwrap();
    f.repo
        .reserve_budget_and_consume_approval(prepare(session, Some((&grant, &bound)), 7), &f.clock)
        .unwrap();
}

#[test]
#[ignore = "Explicit independent review; deterministic boundary checks"]
fn review_invalid_expired_and_stale_approvals_do_not_reserve_or_consume() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let record = f.service.get_session(session).unwrap();
    let before = f.counts();
    let changed = OperationAction::ExecuteTool {
        tool_id: "synthetic:other".into(),
        untrusted: false,
        arguments: vec![],
    };
    let mismatched = intent(&record, &changed);
    assert!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &mismatched)), 7),
                &f.clock
            )
            .is_err()
    );
    let mut bad_generation = intent(&record, &action);
    bad_generation.context_generation += 1;
    assert!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &bad_generation)), 7),
                &f.clock
            )
            .is_err()
    );
    let mut bad_revision = intent(&record, &action);
    bad_revision.target_revision = "revision-B";
    assert!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &bad_revision)), 7),
                &f.clock
            )
            .is_err()
    );
    let bound = intent(&record, &action);
    f.clock.advance_seconds(3600);
    assert_eq!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &bound)), 7),
                &f.clock
            )
            .unwrap_err()
            .kind,
        Kind::ApprovalExpired
    );
    assert_eq!(f.counts(), before);
    assert_eq!(f.approval_state(&grant), "ISSUED");
}

#[test]
#[ignore = "Explicit independent review; budget exhaustion must not burn approval"]
fn review_budget_denial_preserves_issued_grant_for_exact_retry() {
    let f = Fixture::new();
    let session = f.session(10);
    let action = tool();
    let grant = f.grant(session, &action);
    let record = f.service.get_session(session).unwrap();
    let bound = intent(&record, &action);
    let before = f.counts();
    assert_eq!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &bound)), 11),
                &f.clock
            )
            .unwrap_err()
            .kind,
        Kind::BudgetExceeded
    );
    assert_eq!(f.counts(), before);
    assert_eq!(f.approval_state(&grant), "ISSUED");
    f.repo
        .reserve_budget_and_consume_approval(prepare(session, Some((&grant, &bound)), 7), &f.clock)
        .unwrap();
    assert_eq!(f.approval_state(&grant), "CONSUMED");
}

#[test]
#[ignore = "Explicit independent review; deterministic thread barriers"]
fn review_atomic_consumption_and_budget_contention_are_serialized() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let record = f.service.get_session(session).unwrap();
    let bound = intent(&record, &action);
    let barrier = Arc::new(Barrier::new(9));
    let results = thread::scope(|scope| {
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                let f = &f;
                let bound = &bound;
                let grant = &grant;
                scope.spawn(move || {
                    barrier.wait();
                    f.repo.reserve_budget_and_consume_approval(
                        prepare(session, Some((grant, bound)), 7),
                        &f.clock,
                    )
                })
            })
            .collect();
        barrier.wait();
        jobs.into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_err_and(|e| e.kind == Kind::ApprovalReused))
            .count(),
        7
    );
    assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 7);
    let barrier = Arc::new(Barrier::new(9));
    let results = thread::scope(|scope| {
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                let f = &f;
                scope.spawn(move || {
                    barrier.wait();
                    f.repo
                        .reserve_budget_and_consume_approval(prepare(session, None, 40), &f.clock)
                })
            })
            .collect();
        barrier.wait();
        jobs.into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 2);
    assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 87);
}

#[test]
#[ignore = "Explicit independent review; independent connection barrier"]
fn review_atomic_prepare_separate_connections_have_one_winner() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let barrier = Arc::new(Barrier::new(3));
    let results = thread::scope(|scope| {
        let jobs: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let f = &f;
                let grant = &grant;
                let action = &action;
                scope.spawn(move || {
                    let manager = SqliteConnectionManager::open(&f.directory.db, &f.clock).unwrap();
                    let (repo, authority) = PersistenceRepository::with_authority(manager);
                    let record = repo.session(session).unwrap().unwrap();
                    let bound = intent(&record, action);
                    let restored = authority
                        .recover_issued_grant(
                            grant.request_id(),
                            &bound,
                            "owned connection",
                            event(),
                            &f.clock,
                        )
                        .unwrap();
                    barrier.wait();
                    repo.reserve_budget_and_consume_approval(
                        prepare(session, Some((&restored, &bound)), 7),
                        &f.clock,
                    )
                })
            })
            .collect();
        barrier.wait();
        jobs.into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 7);
}

#[test]
#[ignore = "Explicit independent review; actual service denial before all side effects"]
fn review_service_denials_never_call_backend_or_mutate_budget_approval() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let before = f.counts();
    let mut below = f.request(session, action.clone(), Some(grant.clone()), 7);
    below.classification = Class::Public;
    let unknown = f.request(
        session,
        OperationAction::UnknownOperation {
            operation_name: "unregistered".into(),
        },
        Some(grant.clone()),
        7,
    );
    let missing = f.request(session, action.clone(), None, 7);
    let mut malformed = f.request(session, action.clone(), Some(grant.clone()), 7);
    malformed.session_id = SessionId::for_test_sequence(0);
    for request in [below, unknown, missing, malformed] {
        assert!(f.service.execute_task(request).is_err());
    }
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.counts(), before);
    assert_eq!(f.approval_state(&grant), "ISSUED");
    f.service
        .transition_session(session, SessionState::Cancelled, "owned terminal fixture")
        .unwrap();
    assert!(
        f.service
            .execute_task(f.request(session, action, Some(grant), 7))
            .is_err()
    );
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "Explicit independent review; real managed shutdown is the test-only failure source"]
fn review_actual_execution_and_evidence_settlement_failures_are_observable() {
    for evidence_failure in [false, true] {
        let f = Fixture::new();
        let session = f.session(100);
        let action = tool();
        let grant = f.grant(session, &action);
        f.backend.close_on_dispatch.store(true, Ordering::SeqCst);
        f.backend.fault.store(!evidence_failure, Ordering::SeqCst);
        let mut request = f.request(session, action, Some(grant), 7);
        if evidence_failure {
            request.evidence_envelopes.push(malformed_envelope(session));
        }
        let error = f.service.execute_task(request).unwrap_err();
        assert_eq!(
            error.kind,
            if evidence_failure {
                ServiceErrorKind::EvidenceWithSettlementFailure
            } else {
                ServiceErrorKind::ExecutionWithSettlementFailure
            }
        );
        assert!(error.has_settlement_failure());
        assert!(error.secondary_error().unwrap().contains("Closed"));
        let (state, actual): (String, Option<i64>) = f
            .raw()
            .query_row(
                "SELECT state,actual_cost_micro_usd FROM budget_reservations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "RESERVED");
        assert_eq!(actual, None);
    }
}

#[test]
#[ignore = "Explicit independent review; verifies that successful cleanup does not invent a secondary error"]
fn review_successful_settlement_preserves_unknown_usage_without_compound_error() {
    for evidence_failure in [false, true] {
        let f = Fixture::new();
        let session = f.session(100);
        let action = tool();
        let grant = f.grant(session, &action);
        f.backend.fault.store(!evidence_failure, Ordering::SeqCst);
        let mut request = f.request(session, action, Some(grant), 7);
        if evidence_failure {
            request.evidence_envelopes.push(malformed_envelope(session));
        }
        let error = f.service.execute_task(request).unwrap_err();
        assert!(!error.has_settlement_failure());
        assert_eq!(error.secondary_error(), None);
        assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 7);
        let actual: Option<i64> = f
            .raw()
            .query_row(
                "SELECT actual_cost_micro_usd FROM budget_reservations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(actual, None);
    }
}

#[test]
#[ignore = "Explicit independent review; asserts secure error formatting"]
fn review_compound_execution_error_redacts_backend_sensitive_message() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    f.backend.close_on_dispatch.store(true, Ordering::SeqCst);
    f.backend.fault.store(true, Ordering::SeqCst);
    let error = f
        .service
        .execute_task(f.request(session, action, Some(grant), 7))
        .unwrap_err();
    assert!(
        !format!("{error} {error:?}").contains("REVIEW_SECRET_BACKEND_TOKEN"),
        "compound service diagnostics disclose the backend message canary"
    );
}

#[test]
#[ignore = "Explicit independent review; asserts secure error formatting"]
fn review_compound_evidence_error_redacts_untrusted_metadata() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    f.backend.close_on_dispatch.store(true, Ordering::SeqCst);
    let mut request = f.request(session, action, Some(grant), 7);
    request.evidence_envelopes.push(malformed_envelope(session));
    let error = f.service.execute_task(request).unwrap_err();
    assert!(
        !format!("{error} {error:?}").contains("REVIEW_SECRET_MEDIA_TOKEN"),
        "compound service diagnostics disclose untrusted evidence metadata"
    );
}

#[test]
#[ignore = "Explicit independent review; checks existing typed error introspection"]
fn review_compound_error_keeps_typed_primary_source() {
    let mut typed = Vec::new();
    for evidence_failure in [false, true] {
        let f = Fixture::new();
        let session = f.session(100);
        let action = tool();
        let grant = f.grant(session, &action);
        f.backend.close_on_dispatch.store(true, Ordering::SeqCst);
        f.backend.fault.store(!evidence_failure, Ordering::SeqCst);
        let mut request = f.request(session, action, Some(grant), 7);
        if evidence_failure {
            request.evidence_envelopes.push(malformed_envelope(session));
        }
        let error = f.service.execute_task(request).unwrap_err();
        typed.push(error.source().is_some());
    }
    assert!(
        typed.iter().all(|preserved| *preserved),
        "both primary error objects were flattened into strings and Error::source is absent: {typed:?}"
    );
}

#[test]
#[ignore = "Explicit independent review; tests each non-success result branch with actual settlement failure"]
fn review_non_success_results_keep_primary_outcome_when_settlement_fails() {
    let mut outcomes = Vec::new();
    for status in 1..=3 {
        let f = Fixture::new();
        let session = f.session(100);
        let action = tool();
        let grant = f.grant(session, &action);
        f.backend.close_on_dispatch.store(true, Ordering::SeqCst);
        f.backend.result_status.store(status, Ordering::SeqCst);
        let error = f
            .service
            .execute_task(f.request(session, action, Some(grant), 7))
            .unwrap_err();
        outcomes.push((
            error.kind.clone(),
            error.is_execution() && error.has_settlement_failure(),
        ));
        let actual: Option<i64> = f
            .raw()
            .query_row(
                "SELECT actual_cost_micro_usd FROM budget_reservations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(actual, None);
    }
    assert!(
        outcomes.iter().all(|(_, preserved)| *preserved),
        "Failed, TimedOut and Cancelled outcomes were erased into persistence-only errors: {outcomes:?}"
    );
}

struct OwnedChild {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
}
impl OwnedChild {
    fn start(f: &Fixture, session: SessionId, grant: &PersistentApprovalGrant, mode: &str) -> Self {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "owned_5621_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SENTRA_5621_DB", &f.directory.db)
            .env("SENTRA_5621_MODE", mode)
            .env("SENTRA_5621_SESSION", session.to_string())
            .env("SENTRA_5621_APPROVAL", grant.request_id().to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }
    fn ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("owned child readiness deadline");
            if line.contains("OWNED_5621_READY") {
                return;
            }
        }
    }
    fn terminate(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.child.wait().unwrap().success());
    }
    fn outcome(&self) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(30))
                .expect("owned child outcome deadline");
            if line.contains("OWNED_5621_OUTCOME=") {
                return line;
            }
        }
    }
    fn release(&mut self) {
        writeln!(self.child.stdin.as_mut().unwrap(), "GO").unwrap();
    }
    fn success(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(Instant::now() < deadline, "owned child exit deadline");
            thread::yield_now();
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
#[ignore = "Explicit independent review; kills only the owned repository test executable"]
fn review_real_process_exit_after_prepare_preserves_pair_but_cannot_replay() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let mut child = OwnedChild::start(&f, session, &grant, "after-prepare");
    child.ready();
    // Ready is emitted only by the backend after the atomic prepare method returned.
    assert_eq!(f.approval_state(&grant), "CONSUMED");
    assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 7);
    child.terminate();
    f.manager.integrity_check().unwrap();
    let raw = f.raw();
    let (state, actual): (String, Option<i64>) = raw
        .query_row(
            "SELECT state,actual_cost_micro_usd FROM budget_reservations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "RESERVED");
    assert_eq!(actual, None);
    let audit = f.repo.audit_events(session, 0, 100).unwrap();
    assert_eq!(audit[audit.len() - 2].event_kind, "BudgetReserved");
    assert_eq!(audit.last().unwrap().event_kind, "ApprovalConsumed");
    assert!(
        audit
            .windows(2)
            .all(|w| w[1].sequence_number == w[0].sequence_number + 1)
    );
    let record = f.service.get_session(session).unwrap();
    let bound = intent(&record, &action);
    assert_eq!(
        f.repo
            .reserve_budget_and_consume_approval(
                prepare(session, Some((&grant, &bound)), 7),
                &f.clock
            )
            .unwrap_err()
            .kind,
        Kind::ApprovalReused
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM budget_reservations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
#[ignore = "Explicit independent review; two owned processes race the new atomic method"]
fn review_atomic_prepare_cross_process_has_one_consumption_and_reservation() {
    let f = Fixture::new();
    let session = f.session(100);
    let action = tool();
    let grant = f.grant(session, &action);
    let mut first = OwnedChild::start(&f, session, &grant, "atomic-race");
    let mut second = OwnedChild::start(&f, session, &grant, "atomic-race");
    first.ready();
    second.ready();
    first.release();
    second.release();
    let outcomes = [first.outcome(), second.outcome()];
    first.success();
    second.success();
    assert_eq!(
        outcomes.iter().filter(|s| s.contains("=Consumed")).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|s| s.contains("=ApprovalReused"))
            .count(),
        1
    );
    assert_eq!(f.counts().0, 1);
    assert_eq!(f.repo.budget_used(session).unwrap().as_micro_usd(), 7);
    let audit = f.repo.audit_events(session, 0, 100).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.event_kind == "BudgetReserved")
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.event_kind == "ApprovalConsumed")
            .count(),
        1
    );
    f.manager.integrity_check().unwrap();
}

#[test]
#[ignore = "Owned subprocess helper; explicitly launched only by the process-boundary parent test"]
fn owned_5621_process() {
    let db = PathBuf::from(
        std::env::var_os("SENTRA_5621_DB").expect("owned fixture environment required"),
    );
    let allowed = fs::canonicalize(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/independent-5621-fixtures"),
    )
    .unwrap();
    assert!(
        fs::canonicalize(db.parent().unwrap())
            .unwrap()
            .starts_with(allowed)
    );
    let session: SessionId = std::env::var("SENTRA_5621_SESSION")
        .unwrap()
        .parse()
        .unwrap();
    let approval: ApprovalId = std::env::var("SENTRA_5621_APPROVAL")
        .unwrap()
        .parse()
        .unwrap();
    let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
    let manager = SqliteConnectionManager::open(&db, &clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
    let record = repo.session(session).unwrap().unwrap();
    let action = tool();
    let bound = intent(&record, &action);
    let grant = authority
        .recover_issued_grant(
            approval,
            &bound,
            "owned child",
            EventId::for_test_sequence(60_000_000 + u64::from(std::process::id()) * 10),
            &clock,
        )
        .unwrap();
    let mode = std::env::var("SENTRA_5621_MODE").unwrap();
    if mode == "atomic-race" {
        println!("OWNED_5621_READY_BEFORE_ATOMIC_PREPARE");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().lock().read_line(&mut input).unwrap();
        assert_eq!(input.trim(), "GO");
        let mut request = prepare(session, Some((&grant, &bound)), 7);
        request.reservation_id = Identifier::new_deterministic(5621, u64::from(std::process::id()));
        request.reservation_event =
            EventId::for_test_sequence(60_000_001 + u64::from(std::process::id()) * 10);
        request.consumption_event =
            EventId::for_test_sequence(60_000_002 + u64::from(std::process::id()) * 10);
        let result = repo.reserve_budget_and_consume_approval(request, &clock);
        println!(
            "OWNED_5621_OUTCOME={}",
            match result {
                Ok(_) => "Consumed".into(),
                Err(e) => format!("{:?}", e.kind),
            }
        );
        manager.quarantine_in_place().unwrap();
        return;
    }
    assert_eq!(mode, "after-prepare");
    let backend = Arc::new(ObserverBackend {
        manager,
        calls: AtomicUsize::new(0),
        close_on_dispatch: AtomicBool::new(false),
        fault: AtomicBool::new(false),
        result_status: AtomicUsize::new(0),
        park_before_effect: true,
    });
    let service = CoreService::new(
        CoreServiceConfig::default(),
        repo,
        authority,
        PolicyEngine::new(),
        backend,
        clock.clone(),
    );
    let request = TaskExecutionRequest {
        session_id: session,
        task_id: TaskId::for_test_sequence(5621),
        scope: ExecutionScope::SyntheticFixture,
        action,
        classification: Class::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(7),
        grant: Some(grant),
        evidence_envelopes: vec![],
    };
    let _ = service.execute_task(request);
    panic!("parent must terminate owned child before execute_task returns");
}
