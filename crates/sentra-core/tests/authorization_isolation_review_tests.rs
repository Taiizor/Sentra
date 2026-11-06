//! Independent 5.6.2.2.1 verification and 5.6.2.2.2 regressions.
//! The two former characterization cases now assert the remediated behavior.
//! Owned inert fixtures; no production hooks.
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
    gate: std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
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
        if let Some((entered, release)) = self.gate.lock().unwrap().take() {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
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
            gate: Default::default(),
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

fn changed_policy() -> PolicyEngine {
    PolicyEngine::with_config(sentra_core::BudgetPolicyConfig::new(amount(1)))
}
fn bind_policy(
    f: &Fixture,
    id: SessionId,
    policy: &PolicyEngine,
) -> sentra_core::persistence::SessionRecord {
    let record = f.service.get_session(id).unwrap();
    f.authority
        .register_session_with_policy(
            &record.metadata,
            &record.target_revision,
            record.classification_floor,
            (record.budget_limit, policy),
            event(),
            &f.clock,
        )
        .unwrap()
}
fn policy_context(
    f: &Fixture,
    id: SessionId,
    action: &OperationAction,
    policy: &PolicyEngine,
) -> ExecutionContext {
    f.authority
        .execution_context(id, Class::Internal, action, amount(7), policy)
        .unwrap()
}
fn image(f: &Fixture) -> Vec<Vec<Vec<String>>> {
    let db = f.raw();
    [
        "schema_migrations",
        "sessions",
        "session_security_snapshots",
        "approval_requests",
        "budget_reservations",
        "audit_events",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get_ref(column).map(|value| format!("{value:?}")))
                    .collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<Vec<String>>>>()
            .unwrap()
    })
    .collect()
}

#[test]
fn policy_change_invalidates_automatic_context_pending_request_and_issued_approval() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = metadata_action();
    let grant = f.grant(id, &action);
    let pending = f
        .service
        .request_approval(id, &action, Class::Internal)
        .unwrap();
    let old = f.context(id, &action);
    let version = old.context_generation();
    let changed = changed_policy();
    let new = bind_policy(&f, id, &changed);
    assert_eq!(new.context_generation, version + 1);
    let before = image(&f);
    assert_eq!(
        f.prepare(old, None).unwrap_err().kind,
        Kind::ContextMismatch
    );
    let fresh = policy_context(&f, id, &action, &changed);
    assert!(fresh.requires_approval());
    assert_eq!(
        f.prepare(fresh.clone(), Some(&grant)).unwrap_err().kind,
        Kind::ContextMismatch
    );
    assert!(
        f.service
            .issue_approval(id, pending, &action, Class::Internal)
            .is_err()
    );
    assert_eq!(
        f.prepare(fresh, None).unwrap_err().kind,
        Kind::InvalidApproval
    );
    assert_eq!(image(&f), before);
    assert_eq!(f.state(&grant), "ISSUED");
    let error = f
        .service
        .execute_task(f.request(id, action.clone(), None))
        .unwrap_err();
    assert!(
        matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(e)) if e.kind==Kind::PolicyMismatch)
    );
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
    let new_grant = f.grant(id, &action);
    drop(
        f.prepare(policy_context(&f, id, &action, &changed), Some(&new_grant))
            .unwrap(),
    );
    assert_eq!(
        f.prepare(policy_context(&f, id, &action, &changed), Some(&new_grant))
            .unwrap_err()
            .kind,
        Kind::ApprovalReused
    );
}

#[test]
fn unchanged_effective_policy_is_a_non_mutating_registration_and_keeps_valid_grant() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let old = f.context(id, &action);
    let before = image(&f);
    // These currently reserved knobs never relax mandatory sensitivity/egress.
    let config = sentra_core::BudgetPolicyConfig {
        require_approval_for_external_egress: false,
        require_approval_for_untrusted_tools: false,
        max_request_ceiling: None,
        ..Default::default()
    };
    let equivalent = PolicyEngine::with_config(config);
    let record = bind_policy(&f, id, &equivalent);
    assert_eq!(record.context_generation, old.context_generation());
    assert_eq!(image(&f), before);
    let fresh = policy_context(&f, id, &action, &equivalent);
    assert_eq!(fresh.policy_version(), old.policy_version());
    assert!(fresh.requires_approval());
    drop(f.prepare(old, Some(&grant)).unwrap());
    assert_eq!(f.state(&grant), "CONSUMED");
}

#[test]
fn policy_aba_never_restores_old_context_or_approval() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let old = f.context(id, &action);
    bind_policy(&f, id, &changed_policy());
    let current = bind_policy(&f, id, &PolicyEngine::new());
    assert_eq!(current.context_generation, old.context_generation() + 2);
    let fresh = f.context(id, &action);
    assert_eq!(fresh.policy_version(), old.policy_version());
    assert_eq!(
        f.prepare(old, Some(&grant)).unwrap_err().kind,
        Kind::ContextMismatch
    );
    assert_eq!(
        f.prepare(fresh, Some(&grant)).unwrap_err().kind,
        Kind::ContextMismatch
    );
    assert_eq!(f.state(&grant), "ISSUED");
    assert_eq!(f.repo.budget_used(id).unwrap(), CostUsd::ZERO);
}

#[test]
fn immutable_policy_clone_and_different_engine_cannot_override_registered_rules() {
    let f = Fixture::new(0);
    let id = f.session();
    let policy = PolicyEngine::new();
    let mut untrusted_copy = policy.config().clone();
    untrusted_copy.max_auto_budget = amount(1);
    let proposed = PolicyEngine::with_config(untrusted_copy);
    let before = image(&f);
    assert_eq!(
        f.authority
            .execution_context(
                id,
                Class::Internal,
                &metadata_action(),
                amount(7),
                &proposed
            )
            .unwrap_err()
            .kind,
        Kind::PolicyMismatch
    );
    assert_eq!(image(&f), before);
    assert!(!policy_context(&f, id, &metadata_action(), &policy).requires_approval());
}

#[test]
fn policy_update_cannot_race_live_service_dispatch_and_old_service_cannot_dispatch_afterward() {
    struct Release(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let f = Fixture::new(0);
    let id = f.session();
    let session = f.service.get_session(id).unwrap();
    let changed = changed_policy();
    let (entered, ready) = std::sync::mpsc::channel();
    let (release, proceed) = std::sync::mpsc::channel();
    *f.backend.gate.lock().unwrap() = Some((entered, proceed));
    thread::scope(|scope| {
        let task = scope.spawn(|| {
            f.service
                .execute_task(f.request(id, metadata_action(), None))
        });
        let release = Release(Some(release));
        ready
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let before = image(&f);
        assert_eq!(
            f.authority
                .register_session_with_policy(
                    &session.metadata,
                    &session.target_revision,
                    session.classification_floor,
                    (session.budget_limit, &changed),
                    event(),
                    &f.clock
                )
                .unwrap_err()
                .kind,
            Kind::ContextBusy
        );
        assert_eq!(image(&f), before);
        drop(release);
        task.join().unwrap().unwrap();
    });
    bind_policy(&f, id, &changed);
    let before = image(&f);
    assert!(
        f.service
            .execute_task(f.request(id, metadata_action(), None))
            .is_err()
    );
    assert_eq!(image(&f), before);
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 1);
    let service = CoreService::new(
        CoreServiceConfig::default().with_max_auto_budget(amount(1)),
        f.repo.clone(),
        f.authority.clone(),
        changed,
        f.backend.clone(),
        f.clock.clone(),
    );
    assert_eq!(
        service
            .execute_task(f.request(id, metadata_action(), None))
            .unwrap_err()
            .kind,
        ServiceErrorKind::PolicyDenied
    );
    let grant = f.grant(id, &metadata_action());
    service
        .execute_task(f.request(id, metadata_action(), Some(grant)))
        .unwrap();
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn policy_binding_is_persistent_across_separate_manager_reconstruction() {
    let f = Fixture::new(0);
    let id = f.session();
    let changed = changed_policy();
    let record = bind_policy(&f, id, &changed);
    let manager =
        SqliteConnectionManager::open(&f.directory.root.join("owned.db"), &f.clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
    assert_eq!(
        authority
            .execution_context(
                id,
                Class::Internal,
                &metadata_action(),
                amount(7),
                &PolicyEngine::new()
            )
            .unwrap_err()
            .kind,
        Kind::PolicyMismatch
    );
    let current = authority
        .execution_context(id, Class::Internal, &metadata_action(), amount(7), &changed)
        .unwrap();
    assert_eq!(current.context_generation(), record.context_generation);
    assert!(current.requires_approval());
    assert_eq!(
        repo.session(id).unwrap().unwrap().context_generation,
        record.context_generation
    );
    manager.shutdown().unwrap();
}

#[test]
fn legacy_unbound_snapshot_requires_explicit_owner_policy_binding_without_data_recreation() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    f.raw().execute("UPDATE session_security_snapshots SET snapshot_json=json_remove(json_set(snapshot_json,'$.version',1),'$.policy_identity') WHERE session_id=?1",[id.to_string()]).unwrap();
    let record = f.service.get_session(id).unwrap();
    let before = image(&f);
    let error = f
        .service
        .evaluate_action(id, &action, Class::Internal, None)
        .unwrap_err();
    assert!(
        matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(e)) if e.kind==Kind::PolicyMismatch)
    );
    assert_eq!(
        f.authority
            .register_session(
                &record.metadata,
                &record.target_revision,
                record.classification_floor,
                record.budget_limit,
                event(),
                &f.clock
            )
            .unwrap_err()
            .kind,
        Kind::PolicyMismatch
    );
    assert_eq!(image(&f), before);
    let upgraded = bind_policy(&f, id, &PolicyEngine::new());
    assert_eq!(upgraded.context_generation, record.context_generation + 1);
    let old_version:i64=f.raw().query_row("SELECT json_extract(snapshot_json,'$.version') FROM session_security_snapshots WHERE session_id=?1 AND context_generation=1",[id.to_string()],|r|r.get(0)).unwrap();
    assert_eq!(old_version, 1);
    assert_eq!(
        f.prepare(f.context(id, &action), Some(&grant))
            .unwrap_err()
            .kind,
        Kind::ContextMismatch
    );
    assert_eq!(f.state(&grant), "ISSUED");
    f.manager.integrity_check().unwrap();
}

#[test]
fn preview_all_decisions_are_non_consuming_and_leave_every_persistent_table_unchanged() {
    let f = Fixture::new(0);
    let id = f.session();
    let other = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let foreign = f.grant(other, &action);
    let before = image(&f);
    for _ in 0..3 {
        assert!(matches!(
            f.service
                .evaluate_action(id, &metadata_action(), Class::Internal, None)
                .unwrap(),
            sentra_core::ServicePolicyDecision::Granted
        ));
        assert!(matches!(
            f.service
                .evaluate_action(id, &action, Class::Internal, None)
                .unwrap(),
            sentra_core::ServicePolicyDecision::NeedsApproval { .. }
        ));
        assert!(matches!(
            f.service
                .evaluate_action(id, &action, Class::Internal, Some(&grant))
                .unwrap(),
            sentra_core::ServicePolicyDecision::Granted
        ));
        assert!(matches!(
            f.service
                .evaluate_action(id, &action, Class::Internal, Some(&foreign))
                .unwrap(),
            sentra_core::ServicePolicyDecision::Denied { .. }
        ));
        assert!(matches!(
            f.service
                .evaluate_action(id, &metadata_action(), Class::Public, None)
                .unwrap(),
            sentra_core::ServicePolicyDecision::Denied { .. }
        ));
        assert!(matches!(
            f.service
                .evaluate_action(
                    id,
                    &OperationAction::UnknownOperation {
                        operation_name: "owned unknown".into()
                    },
                    Class::Internal,
                    None
                )
                .unwrap(),
            sentra_core::ServicePolicyDecision::Denied { .. }
        ));
    }
    assert_eq!(image(&f), before);
    assert_eq!(f.state(&grant), "ISSUED");
    assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
    f.service
        .execute_task(f.request(id, action.clone(), Some(grant.clone())))
        .unwrap();
    let before = image(&f);
    assert!(matches!(
        f.service
            .evaluate_action(id, &action, Class::Internal, Some(&grant))
            .unwrap(),
        sentra_core::ServicePolicyDecision::Denied { .. }
    ));
    assert_eq!(image(&f), before);
}

#[test]
fn preview_missing_and_corrupt_authoritative_state_propagates_typed_failure() {
    for fault in [
        "missing-session",
        "missing-snapshot",
        "malformed-snapshot",
        "malformed-policy",
    ] {
        let f = Fixture::new(0);
        let id = f.session();
        match fault {
            "missing-snapshot" => {
                f.raw()
                    .execute(
                        "DELETE FROM session_security_snapshots WHERE session_id=?1",
                        [id.to_string()],
                    )
                    .unwrap();
            }
            "malformed-snapshot" => {
                f.raw().execute("UPDATE session_security_snapshots SET snapshot_json='{}' WHERE session_id=?1",[id.to_string()]).unwrap();
            }
            "malformed-policy" => {
                f.raw().execute("UPDATE session_security_snapshots SET snapshot_json=json_set(snapshot_json,'$.policy_identity','REVIEW_PRIVATE_POLICY') WHERE session_id=?1",[id.to_string()]).unwrap();
            }
            _ => {}
        }
        let before = image(&f);
        let requested = if fault == "missing-session" {
            SessionId::for_test_sequence(999_562_222)
        } else {
            id
        };
        let error = f
            .service
            .evaluate_action(requested, &metadata_action(), Class::Internal, None)
            .unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::Persistence);
        let expected = if fault == "missing-session" {
            Kind::ContextMismatch
        } else {
            Kind::Integrity
        };
        assert!(
            matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(e)) if e.kind==expected)
        );
        assert!(!format!("{error} {error:?} {:?}", error.source()).contains("REVIEW_PRIVATE"));
        assert_eq!(image(&f), before);
        assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn preview_second_stage_storage_corruption_is_not_an_ordinary_grant_denial() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    f.raw()
        .execute(
            "UPDATE approval_requests SET action_name='' WHERE request_id=?1",
            [grant.request_id().to_string()],
        )
        .unwrap();
    let before = image(&f);
    let error = f
        .service
        .evaluate_action(id, &action, Class::Internal, Some(&grant))
        .unwrap_err();
    assert_eq!(error.kind, ServiceErrorKind::Persistence);
    assert!(
        matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(e)) if e.kind==Kind::Integrity)
    );
    assert_eq!(image(&f), before);
    assert_eq!(f.state(&grant), "ISSUED");
}

#[test]
fn failed_policy_registration_audit_rolls_back_epoch_and_preserves_legitimate_grant() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    let old = f.context(id, &action);
    let record = f.service.get_session(id).unwrap();
    let duplicate: String = f
        .raw()
        .query_row(
            "SELECT event_id FROM audit_events ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let before = image(&f);
    let changed = changed_policy();
    let error = f
        .authority
        .register_session_with_policy(
            &record.metadata,
            &record.target_revision,
            record.classification_floor,
            (record.budget_limit, &changed),
            duplicate.parse().unwrap(),
            &f.clock,
        )
        .unwrap_err();
    assert_eq!(error.kind, Kind::Database);
    assert!(error.sqlite_code.is_some());
    assert_eq!(image(&f), before);
    assert_eq!(
        f.authority
            .execution_context(id, Class::Internal, &action, amount(7), &changed)
            .unwrap_err()
            .kind,
        Kind::PolicyMismatch
    );
    drop(f.prepare(old, Some(&grant)).unwrap());
    assert_eq!(f.state(&grant), "CONSUMED");
}

#[test]
fn preview_sql_read_error_retains_extended_code_without_disclosing_sql_diagnostics() {
    let f = Fixture::new(0);
    let id = f.session();
    let action = tool();
    let grant = f.grant(id, &action);
    // Owned test schema fault: the first context read still works, but the
    // subsequent approval SELECT fails with a real SQLite error code.
    f.raw()
        .execute_batch("ALTER TABLE approval_requests RENAME TO owned_unavailable_approvals")
        .unwrap();
    let before = f.counts();
    let record = f.service.get_session(id).unwrap();
    let error = f
        .service
        .evaluate_action(id, &action, Class::Internal, Some(&grant))
        .unwrap_err();
    assert_eq!(error.kind, ServiceErrorKind::Persistence);
    assert!(
        matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(e)) if e.kind==Kind::Database && e.sqlite_code==Some(1))
    );
    assert!(!format!("{error} {error:?} {:?}", error.source()).contains("approval_requests"));
    assert_eq!(f.counts(), before);
    let after = f.service.get_session(id).unwrap();
    assert_eq!(
        (
            after.metadata,
            after.state,
            after.context_generation,
            after.target_revision,
            after.classification_floor,
            after.budget_limit
        ),
        (
            record.metadata,
            record.state,
            record.context_generation,
            record.target_revision,
            record.classification_floor,
            record.budget_limit
        )
    );
    let state: String = f
        .raw()
        .query_row(
            "SELECT state FROM owned_unavailable_approvals WHERE request_id=?1",
            [grant.request_id().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "ISSUED");
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
fn regression_different_immutable_policy_requires_registration_and_invalidates_old_context() {
    let f = Fixture::new(0);
    let id = f.session();
    let policy = PolicyEngine::new();
    let old = f
        .authority
        .execution_context(id, Class::Internal, &metadata_action(), amount(7), &policy)
        .unwrap();
    assert!(!old.requires_approval());
    let changed = PolicyEngine::with_config(sentra_core::BudgetPolicyConfig::new(amount(1)));
    assert_eq!(
        f.authority
            .execution_context(id, Class::Internal, &metadata_action(), amount(7), &changed)
            .unwrap_err()
            .kind,
        Kind::PolicyMismatch
    );
    let session = f.service.get_session(id).unwrap();
    f.authority
        .register_session_with_policy(
            &session.metadata,
            &session.target_revision,
            session.classification_floor,
            (session.budget_limit, &changed),
            event(),
            &f.clock,
        )
        .unwrap();
    let fresh = f
        .authority
        .execution_context(id, Class::Internal, &metadata_action(), amount(7), &changed)
        .unwrap();
    assert!(fresh.requires_approval());
    assert!(old.context_generation() < fresh.context_generation());
    assert_ne!(old.policy_version(), fresh.policy_version());
    assert_eq!(
        f.prepare(fresh, None).unwrap_err().kind,
        Kind::InvalidApproval
    );
    assert_eq!(
        f.prepare(old, None).unwrap_err().kind,
        Kind::ContextMismatch
    );
}

#[test]
fn regression_closed_database_policy_preview_preserves_typed_error() {
    let f = Fixture::new(0);
    let id = f.session();
    f.manager.shutdown().unwrap();
    assert_eq!(
        f.service.get_session(id).unwrap_err().kind,
        ServiceErrorKind::Persistence
    );
    let error = f
        .service
        .evaluate_action(id, &metadata_action(), Class::Internal, None)
        .unwrap_err();
    assert_eq!(error.kind, ServiceErrorKind::Persistence);
    assert!(
        matches!(error.primary_error(),Some(ServicePrimaryError::Persistence(e)) if e.kind==Kind::Closed)
    );
}
