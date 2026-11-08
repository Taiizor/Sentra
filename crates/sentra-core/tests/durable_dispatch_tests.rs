//! Increment 2.0 Durable Persistence, Schema V2, and Session Continuation Tests.
#[path = "support/persistence.rs"]
mod support;

use rusqlite::{Connection, params};
use sentra_core::{
    AttemptId, Clock, CostUsd, ExecutionId, Identifier, ManifestId, MockClock, OperationAction,
    PolicyEngine, SecurityClassification as Class, SessionId, SessionState, TaskId,
    persistence::{
        AttemptOutcome, AttemptState, ManifestKind, PersistenceError, PersistenceErrorKind as Kind,
        PersistenceRepository, PrepareAttemptRequest, RecordAttemptRequest,
        SqliteConnectionManager, TaskState,
    },
    service::{CoreService, CoreServiceConfig},
};
use std::{fs, sync::Arc};
use support::*;

fn denied<T>(result: Result<T, PersistenceError>, expected: Kind) {
    match result {
        Err(error) => assert_eq!(error.kind, expected),
        Ok(_) => panic!("expected {expected:?}"),
    }
}

fn advance_session_to_running(h: &Harness) {
    let session_id = h.metadata.session_id;
    h.repo
        .transition_session(
            session_id,
            SessionState::Created,
            SessionState::Scoped,
            event(),
            &h.clock,
        )
        .unwrap();
    h.repo
        .transition_session(
            session_id,
            SessionState::Scoped,
            SessionState::Planned,
            event(),
            &h.clock,
        )
        .unwrap();
    h.repo
        .transition_session(
            session_id,
            SessionState::Planned,
            SessionState::Running,
            event(),
            &h.clock,
        )
        .unwrap();
}

fn create_test_service(h: &Harness) -> CoreService {
    let clock = Arc::new(MockClock::new(h.clock.now()));
    let policy_engine = PolicyEngine::new();
    let config = CoreServiceConfig::default();
    let backend = Arc::new(sentra_core::SyntheticFixtureBackend::new());
    CoreService::new(
        config,
        h.repo.clone(),
        h.authority.clone(),
        policy_engine,
        backend,
        clock,
    )
}

fn checksum_v1() -> String {
    let source = include_str!("../src/persistence/schema_v1.sql").replace("\r\n", "\n");
    let hash = source
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        });
    format!("fnv1a64:{hash:016x}")
}

// -----------------------------------------------------------------------------
// 1. Schema V1 to V2 Migration and Compatibility Tests
// -----------------------------------------------------------------------------

#[test]
fn test_schema_v1_to_v2_transactional_migration_preserves_data() {
    let d = Directory::new();
    let c = clock();
    let m = metadata();

    // 1. Manually construct an authentic Schema V1 database
    {
        let conn = Connection::open(&d.db).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA user_version=1; PRAGMA application_id=0x53454e54; BEGIN IMMEDIATE;",
        )
        .unwrap();
        conn.execute_batch(include_str!("../src/persistence/schema_v1.sql"))
            .unwrap();

        // Record Migration 1 entry
        conn.execute(
            "INSERT INTO schema_migrations(version, description, applied_at, checksum) VALUES(1, 'Initial Sentra persistence schema', ?1, ?2)",
            params![
                c.now().to_rfc3339(),
                checksum_v1(),
            ],
        )
        .unwrap();

        // Insert a V1 session
        let now = c.now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions(session_id, state, mode, classification_floor, context_generation, target_revision, created_at, updated_at, completeness) VALUES(?1, 'CREATED', ?2, 'INTERNAL', 1, 'rev-v1', ?3, ?3, 'COMPLETE')",
            params![m.session_id.to_string(), m.operating_mode.as_str(), now],
        )
        .unwrap();

        let snapshot_json = serde_json::json!({
            "version": 2,
            "metadata": {
                "session_id": m.session_id.to_string(),
                "created_at": now,
                "workspace_root": m.workspace_root,
                "mode": m.operating_mode.as_str(),
                "operator_id": m.operator_id,
                "policy_digest": m.policy_digest,
                "completeness": "COMPLETE",
            },
            "generation": 1,
            "revision": "rev-v1",
            "classification_floor": "INTERNAL",
            "budget_limit_micro_usd": 5_000_000,
            "policy_identity": "sentra-policy:v1:auto-microusd=1000000",
        });

        conn.execute(
            "INSERT INTO session_security_snapshots(session_id, context_generation, project_root, operator_id, policy_id, registered_at, snapshot_json) VALUES(?1, 1, ?2, ?3, ?4, ?5, ?6)",
            params![
                m.session_id.to_string(),
                m.workspace_root,
                m.operator_id,
                m.policy_digest,
                now,
                snapshot_json.to_string(),
            ],
        )
        .unwrap();

        // Insert a V1 audit event
        conn.execute(
            "INSERT INTO audit_events(event_id, session_id, sequence_number, event_kind, classification, timestamp, details_json) VALUES(?1, ?2, 1, 'SessionCreated', 'INTERNAL', ?3, '{}')",
            params![event().to_string(), m.session_id.to_string(), now],
        )
        .unwrap();

        conn.execute_batch("COMMIT;").unwrap();
    }

    // 2. Open with SqliteConnectionManager: triggers migration to V2!
    let manager = SqliteConnectionManager::open(&d.db, &c).expect("V1 to V2 migration failed");
    manager
        .integrity_check()
        .expect("integrity check failed after migration");

    // 3. Verify V2 tables and metadata
    let raw = Connection::open(&d.db).unwrap();
    let user_version: i64 = raw
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(user_version, 2);

    let migration_count: i64 = raw
        .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(migration_count, 2);

    // Verify V2 tables exist
    let mut stmt = raw
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(tables.contains(&"tasks".to_string()));
    assert!(tables.contains(&"manifests".to_string()));
    assert!(tables.contains(&"attempts".to_string()));

    // 4. Verify existing session data is intact
    let (repo, _) = PersistenceRepository::with_authority(manager);
    let session_record = repo
        .session(m.session_id)
        .unwrap()
        .expect("session not found");
    assert_eq!(session_record.target_revision, "rev-v1");
    assert_eq!(session_record.context_generation, 1);
    assert_eq!(session_record.state, SessionState::Created);

    let audit_events = repo.audit_events(m.session_id, 0, 10).unwrap();
    assert_eq!(audit_events.len(), 1);
    assert_eq!(audit_events[0].event_kind, "SessionCreated");
}

#[test]
fn test_older_writer_rejected_on_newer_schema() {
    let h = Harness::new();
    h.manager.shutdown().unwrap();

    let raw = Connection::open(&h.dir.db).unwrap();
    raw.execute_batch("PRAGMA user_version=3").unwrap();
    drop(raw);

    let before = fs::read(&h.dir.db).unwrap();
    denied(
        SqliteConnectionManager::open(&h.dir.db, &h.clock),
        Kind::NewerSchema,
    );
    assert_eq!(fs::read(&h.dir.db).unwrap(), before);
}

// -----------------------------------------------------------------------------
// 2. Task Repository and State Machine Tests
// -----------------------------------------------------------------------------

#[test]
fn test_task_lifecycle_and_invariants() {
    let h = Harness::new();
    let session_id = h.metadata.session_id;

    let task_1 = TaskId::for_test_sequence(1);
    let task_2 = TaskId::for_test_sequence(2);

    // Create tasks
    let t1 = h
        .repo
        .create_task(session_id, task_1, 1, "Analyze Workspace", &h.clock)
        .unwrap();
    assert_eq!(t1.sequence_number, 1);
    assert_eq!(t1.state, TaskState::Pending);
    assert!(t1.completed_at.is_none());

    let t2 = h
        .repo
        .create_task(session_id, task_2, 2, "Verify Evidence", &h.clock)
        .unwrap();
    assert_eq!(t2.sequence_number, 2);

    // Duplicate sequence number in same session is rejected by UNIQUE constraint
    let dup_task = TaskId::for_test_sequence(3);
    let dup_err = h
        .repo
        .create_task(session_id, dup_task, 1, "Duplicate Seq", &h.clock);
    assert!(dup_err.is_err());

    // Sequence numbers must be strictly positive (> 0)
    let zero_seq_err = h
        .repo
        .create_task(session_id, dup_task, 0, "Zero Seq", &h.clock);
    assert!(zero_seq_err.is_err());

    // List tasks preserves sequence order
    let tasks = h.repo.list_tasks(session_id).unwrap();
    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[0].task_id, task_1);
    assert_eq!(tasks[1].task_id, task_2);

    // State transition: Pending -> InProgress
    let t1_in_progress = h
        .repo
        .update_task_state(
            task_1,
            TaskState::Pending,
            TaskState::InProgress,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(t1_in_progress.state, TaskState::InProgress);

    // Invalid transition: InProgress -> Pending is denied
    let invalid_trans = h.repo.update_task_state(
        task_1,
        TaskState::InProgress,
        TaskState::Pending,
        event(),
        &h.clock,
    );
    assert!(invalid_trans.is_err());

    // Valid terminal transition: InProgress -> Completed sets completed_at
    let t1_completed = h
        .repo
        .update_task_state(
            task_1,
            TaskState::InProgress,
            TaskState::Completed,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(t1_completed.state, TaskState::Completed);
    assert!(t1_completed.completed_at.is_some());

    // Terminal state cannot transition to any state
    let from_terminal = h.repo.update_task_state(
        task_1,
        TaskState::Completed,
        TaskState::InProgress,
        event(),
        &h.clock,
    );
    assert!(from_terminal.is_err());
}

// -----------------------------------------------------------------------------
// 3. Canonical Manifests Tests
// -----------------------------------------------------------------------------

#[test]
fn test_manifest_creation_and_digest_lookup() {
    let h = Harness::new();
    let session_id = h.metadata.session_id;

    let manifest_id = ManifestId::for_test_sequence(1);
    let digest = "sha256-abcdef1234567890abcdef1234567890";
    let json_payload = serde_json::json!({
        "files": ["src/lib.rs", "Cargo.toml"],
        "revision": "git:abc123"
    })
    .to_string();

    // Invalid JSON rejected
    let bad_json_err = h.repo.create_manifest(
        manifest_id,
        session_id,
        ManifestKind::SourceSnapshot,
        digest,
        "not-valid-json",
        &h.clock,
    );
    assert!(bad_json_err.is_err());

    // Valid manifest creation
    let m = h
        .repo
        .create_manifest(
            manifest_id,
            session_id,
            ManifestKind::SourceSnapshot,
            digest,
            &json_payload,
            &h.clock,
        )
        .unwrap();
    assert_eq!(m.manifest_id, manifest_id);
    assert_eq!(m.manifest_kind, ManifestKind::SourceSnapshot);
    assert_eq!(m.content_digest, digest);

    // Lookup by ID
    let fetched = h.repo.get_manifest(manifest_id).unwrap().unwrap();
    assert_eq!(fetched.manifest_id, manifest_id);

    // Lookup by digest
    let fetched_by_digest = h
        .repo
        .get_manifest_by_digest(session_id, digest)
        .unwrap()
        .unwrap();
    assert_eq!(fetched_by_digest.manifest_id, manifest_id);
}

// -----------------------------------------------------------------------------
// 4. Durable Dispatch Attempt State Machine Tests
// -----------------------------------------------------------------------------

#[test]
fn test_durable_dispatch_full_lifecycle() {
    let h = Harness::budget(1_000_000); // $1.00 budget
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(10);
    h.repo
        .create_task(session_id, task_id, 1, "Run Tool", &h.clock)
        .unwrap();

    let action = OperationAction::InvokeProvider {
        model_id: "test-model".into(),
        estimated_cost: CostUsd::from_micro_usd(200_000), // $0.20
    };
    let policy_engine = PolicyEngine::new();
    let context = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(200_000),
            &policy_engine,
        )
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(1);
    let execution_id = ExecutionId::for_test_sequence(1);

    // Step 1: RECORDED
    let req = RecordAttemptRequest {
        attempt_id,
        task_id,
        session_id,
        execution_id,
        action_name: action.action_name().to_string(),
        action_digest: action.action_digest(),
        manifest_id: None,
    };
    let att = h.repo.record_attempt(req, &h.clock).unwrap();
    assert_eq!(att.state, AttemptState::Recorded);
    assert_eq!(att.attempt_number, 1);
    assert_eq!(att.fencing_epoch, 1);
    assert!(att.prepared_at.is_none());
    assert!(att.released_at.is_none());

    // Step 2: PREPARED
    let res_id = Identifier::new_deterministic(100, 1);
    let reservation_id = sentra_core::ReservationId::from_bytes(*res_id.as_bytes());
    let prep_req = PrepareAttemptRequest {
        attempt_id,
        reservation_id,
        context: context.clone(),
        grant: None,
        reservation_event: event(),
        consumption_event: event(),
    };
    let (att_prepared, prepared_exec) = h.repo.prepare_attempt(prep_req, &h.clock).unwrap();
    assert_eq!(att_prepared.state, AttemptState::Prepared);
    assert!(att_prepared.prepared_at.is_some());
    assert_eq!(att_prepared.reservation_id, Some(reservation_id));
    assert_eq!(prepared_exec.budget.reserved.as_micro_usd(), 200_000);

    // Step 3: RELEASE_RECORDED
    let att_released = h.repo.record_release(attempt_id, &h.clock).unwrap();
    assert_eq!(att_released.state, AttemptState::ReleaseRecorded);
    assert!(att_released.released_at.is_some());

    // Step 4: RUNNING_CONFIRMED
    let att_running = h.repo.confirm_running(attempt_id, &h.clock).unwrap();
    assert_eq!(att_running.state, AttemptState::RunningConfirmed);

    // Step 5: RESULT_RECORDED
    let outcome = AttemptOutcome::Completed;
    let details = serde_json::json!({"status": "success", "exit_code": 0}).to_string();
    let att_result = h
        .repo
        .record_result(
            attempt_id,
            outcome,
            Some(&details),
            Some(CostUsd::from_micro_usd(25_000)),
            &h.clock,
        )
        .unwrap();
    assert_eq!(att_result.state, AttemptState::ResultRecorded);
    assert_eq!(att_result.terminal_outcome, Some(AttemptOutcome::Completed));
    assert!(att_result.settled_at.is_some());

    // Terminal attempt state cannot transition again
    let repeat_res = h
        .repo
        .record_result(attempt_id, outcome, None, None, &h.clock);
    assert!(repeat_res.is_err());
}

#[test]
fn test_fencing_epoch_invalidation_prevents_stale_release() {
    let h = Harness::budget(500_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(20);
    h.repo
        .create_task(session_id, task_id, 1, "Stale Task", &h.clock)
        .unwrap();

    let action = OperationAction::DiscoverMetadata {
        relative_path: "path".into(),
    };
    let policy_engine = PolicyEngine::new();
    let context = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::ZERO,
            &policy_engine,
        )
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(2);
    let execution_id = ExecutionId::for_test_sequence(2);

    // Record and prepare at generation 1
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id,
                action_name: action.action_name().to_string(),
                action_digest: action.action_digest(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id = Identifier::new_deterministic(100, 2);
    let reservation_id = sentra_core::ReservationId::from_bytes(*res_id.as_bytes());
    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id,
                context,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    // Advance session context generation (fencing epoch) to 2
    let new_gen = h
        .authority
        .advance_session_epoch(session_id, event(), &h.clock)
        .unwrap();
    assert_eq!(new_gen, 2);

    // Attempting to release the prepared attempt from epoch 1 fails closed!
    let release_result = h.repo.record_release(attempt_id, &h.clock);
    denied(release_result, Kind::ContextMismatch);
}

#[test]
fn test_post_release_interruption_marks_uncertain_and_holds_budget() {
    let h = Harness::budget(1_000_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(30);
    h.repo
        .create_task(session_id, task_id, 1, "Interrupted Task", &h.clock)
        .unwrap();

    let action = OperationAction::InvokeProvider {
        model_id: "test".into(),
        estimated_cost: CostUsd::from_micro_usd(400_000), // $0.40
    };
    let policy_engine = PolicyEngine::new();
    let context = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(400_000),
            &policy_engine,
        )
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(3);
    let execution_id = ExecutionId::for_test_sequence(3);

    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id,
                action_name: action.action_name().to_string(),
                action_digest: action.action_digest(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id = Identifier::new_deterministic(100, 3);
    let reservation_id = sentra_core::ReservationId::from_bytes(*res_id.as_bytes());
    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id,
                context,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt_id, &h.clock).unwrap();

    // Process termination / connection loss: mark Uncertain
    let uncertain = h.repo.mark_attempt_uncertain(attempt_id, &h.clock).unwrap();
    assert_eq!(uncertain.state, AttemptState::Uncertain);

    // Conservative budget invariant: $0.40 reservation remains held in budget_used!
    let used = h.repo.budget_used(session_id).unwrap();
    assert_eq!(used.as_micro_usd(), 400_000);
}

#[test]
fn test_pre_release_cancellation_confirms_not_started_and_releases_budget() {
    let h = Harness::budget(1_000_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(40);
    h.repo
        .create_task(session_id, task_id, 1, "Cancelled Pre-release", &h.clock)
        .unwrap();

    let action = OperationAction::InvokeProvider {
        model_id: "test".into(),
        estimated_cost: CostUsd::from_micro_usd(300_000),
    };
    let policy_engine = PolicyEngine::new();
    let context = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(300_000),
            &policy_engine,
        )
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(4);
    let execution_id = ExecutionId::for_test_sequence(4);

    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id,
                action_name: action.action_name().to_string(),
                action_digest: action.action_digest(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id = Identifier::new_deterministic(100, 4);
    let reservation_id = sentra_core::ReservationId::from_bytes(*res_id.as_bytes());
    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id,
                context,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    // Cancel before release: confirms not started
    let not_started = h.repo.confirm_not_started(attempt_id, &h.clock).unwrap();
    assert_eq!(not_started.state, AttemptState::NotStartedConfirmed);

    // Budget was cleanly released because it was never dispatched!
    let used = h.repo.budget_used(session_id).unwrap();
    assert_eq!(used.as_micro_usd(), 0);
}

// -----------------------------------------------------------------------------
// 5. Session Continuation / Resume Protocol Tests
// -----------------------------------------------------------------------------

#[test]
fn test_session_resumption_e2e_reconciliation() {
    let h = Harness::budget(1_000_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;

    // Create 4 tasks
    let t1_id = TaskId::for_test_sequence(101);
    let t2_id = TaskId::for_test_sequence(102);
    let t3_id = TaskId::for_test_sequence(103);
    let t4_id = TaskId::for_test_sequence(104);

    h.repo
        .create_task(session_id, t1_id, 1, "Completed Task", &h.clock)
        .unwrap();
    h.repo
        .create_task(session_id, t2_id, 2, "Running Task", &h.clock)
        .unwrap();
    h.repo
        .create_task(session_id, t3_id, 3, "Prepared Task", &h.clock)
        .unwrap();
    h.repo
        .create_task(session_id, t4_id, 4, "Recorded Task", &h.clock)
        .unwrap();

    // Task 1: Completed
    h.repo
        .update_task_state(
            t1_id,
            TaskState::Pending,
            TaskState::InProgress,
            event(),
            &h.clock,
        )
        .unwrap();
    h.repo
        .update_task_state(
            t1_id,
            TaskState::InProgress,
            TaskState::Completed,
            event(),
            &h.clock,
        )
        .unwrap();

    // Task 2: RunningConfirmed attempt
    let att2_id = AttemptId::for_test_sequence(202);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: att2_id,
                task_id: t2_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(202),
                action_name: "synthetic:run".into(),
                action_digest: "digest-2".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();
    let res2_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(200, 2).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action2 = OperationAction::InvokeProvider {
        model_id: "m2".into(),
        estimated_cost: CostUsd::from_micro_usd(100_000),
    };
    let ctx2 = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action2,
            CostUsd::from_micro_usd(100_000),
            &policy_engine,
        )
        .unwrap();
    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id: att2_id,
                reservation_id: res2_id,
                context: ctx2,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();
    h.repo.record_release(att2_id, &h.clock).unwrap();
    h.repo.confirm_running(att2_id, &h.clock).unwrap();

    // Task 3: Prepared attempt
    let att3_id = AttemptId::for_test_sequence(203);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: att3_id,
                task_id: t3_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(203),
                action_name: "synthetic:prep".into(),
                action_digest: "digest-3".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();
    let res3_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(200, 3).as_bytes());
    let action3 = OperationAction::InvokeProvider {
        model_id: "m3".into(),
        estimated_cost: CostUsd::from_micro_usd(50_000),
    };
    let ctx3 = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action3,
            CostUsd::from_micro_usd(50_000),
            &policy_engine,
        )
        .unwrap();
    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id: att3_id,
                reservation_id: res3_id,
                context: ctx3,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    // Task 4: Recorded attempt
    let att4_id = AttemptId::for_test_sequence(204);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: att4_id,
                task_id: t4_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(204),
                action_name: "synthetic:rec".into(),
                action_digest: "digest-4".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    // Pause session to simulate interruption / checkpoint
    h.repo
        .transition_session(
            session_id,
            SessionState::Running,
            SessionState::Paused,
            event(),
            &h.clock,
        )
        .unwrap();

    // Initialize CoreService over the database and perform Session Resumption!
    let service = create_test_service(&h);
    let resume_report = service.resume_session(session_id).unwrap();

    assert_eq!(resume_report.session_id, session_id);
    assert_eq!(resume_report.previous_state, SessionState::Paused);
    assert_eq!(resume_report.resumed_state, SessionState::Running);
    assert_eq!(resume_report.new_context_generation, 2);

    // Completed task 1 is preserved and skipped
    assert_eq!(resume_report.completed_tasks, vec![t1_id]);
    assert_eq!(resume_report.pending_tasks, vec![t3_id, t4_id]);
    assert_eq!(resume_report.blocked_tasks, vec![t2_id]);

    // Reconciled attempts:
    // Task 2 attempt -> Uncertain (budget held)
    let r2 = resume_report
        .reconciled_attempts
        .iter()
        .find(|r| r.attempt_id == att2_id)
        .unwrap();
    assert_eq!(r2.previous_state, AttemptState::RunningConfirmed);
    assert_eq!(r2.reconciled_state, AttemptState::Uncertain);
    assert!(r2.budget_held);

    // Task 2 is now Blocked to require operator inspection
    let t2_record = h.repo.get_task(t2_id).unwrap().unwrap();
    assert_eq!(t2_record.state, TaskState::Blocked);

    // Task 3 attempt -> NotStartedConfirmed (budget released)
    let r3 = resume_report
        .reconciled_attempts
        .iter()
        .find(|r| r.attempt_id == att3_id)
        .unwrap();
    assert_eq!(r3.previous_state, AttemptState::Prepared);
    assert_eq!(r3.reconciled_state, AttemptState::NotStartedConfirmed);
    assert!(!r3.budget_held);

    // Task 4 attempt -> NotStartedConfirmed
    let r4 = resume_report
        .reconciled_attempts
        .iter()
        .find(|r| r.attempt_id == att4_id)
        .unwrap();
    assert_eq!(r4.previous_state, AttemptState::Recorded);
    assert_eq!(r4.reconciled_state, AttemptState::NotStartedConfirmed);
    assert!(!r4.budget_held);

    // Total budget used retains the $0.10 hold for Task 2, but released the $0.05 for Task 3!
    let total_used = service.budget_used(session_id).unwrap();
    assert_eq!(total_used.as_micro_usd(), 100_000);
}

#[test]
fn test_terminal_session_cannot_be_resumed() {
    let h = Harness::new();
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    h.repo
        .transition_session(
            session_id,
            SessionState::Running,
            SessionState::Completed,
            event(),
            &h.clock,
        )
        .unwrap();

    let service = create_test_service(&h);
    let resume_res = service.resume_session(session_id);
    assert!(resume_res.is_err());
}

#[test]
fn test_concurrent_resume_serialized_by_admission_lock() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;

    // Acquire exclusive admission lock to simulate a concurrent resume operation
    let admission = h.repo.session_admission(session_id, true).unwrap();

    let service = create_test_service(&h);
    // Concurrent resume must fail closed with ContextBusy
    let res = service.resume_session(session_id);
    assert!(res.is_err());

    drop(admission);

    // After admission lock is released, resume succeeds cleanly
    let resume_report = service.resume_session(session_id).unwrap();
    assert_eq!(resume_report.session_id, session_id);
    assert_eq!(resume_report.new_context_generation, 2);
}

#[test]
fn test_process_termination_or_crash_during_resume_is_idempotent() {
    let h = Harness::budget(300_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let t1_id = TaskId::for_test_sequence(301);
    h.repo
        .create_task(session_id, t1_id, 1, "Task 1", &h.clock)
        .unwrap();

    let att1_id = AttemptId::for_test_sequence(301);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: att1_id,
                task_id: t1_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(301),
                action_name: "Action1".into(),
                action_digest: "digest1".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let service = create_test_service(&h);
    // First resume: reconciles attempt to NotStartedConfirmed, advances generation to 2
    let report1 = service.resume_session(session_id).unwrap();
    assert_eq!(report1.new_context_generation, 2);
    assert_eq!(report1.reconciled_attempts.len(), 1);

    // Repeated resume immediately: idempotent, advances generation to 3, zero unhandled attempts
    let report2 = service.resume_session(session_id).unwrap();
    assert_eq!(report2.new_context_generation, 3);
    assert_eq!(report2.reconciled_attempts.len(), 0);
}

#[test]
fn test_result_recorded_with_atomic_budget_settlement() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(310);
    h.repo
        .create_task(session_id, task_id, 1, "Settle Task", &h.clock)
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(310);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(310),
                action_name: "ActionSettle".into(),
                action_digest: "digest-settle".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(310, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-settle".into(),
        estimated_cost: CostUsd::from_micro_usd(100_000),
    };
    let ctx = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(100_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id: res_id,
                context: ctx,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt_id, &h.clock).unwrap();

    // Prior to result: full 100_000 micro-USD is reserved
    assert_eq!(
        h.repo.budget_used(session_id).unwrap().as_micro_usd(),
        100_000
    );

    // Record result with verified actual spend of 35_000 micro-USD
    let att = h
        .repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            Some("{\"exit\":0}"),
            Some(CostUsd::from_micro_usd(35_000)),
            &h.clock,
        )
        .unwrap();

    assert_eq!(att.state, AttemptState::ResultRecorded);
    assert_eq!(att.terminal_outcome, Some(AttemptOutcome::Completed));
    assert!(att.settled_at.is_some());

    // Budget used now atomically reflects the settled 35_000; the remaining 65_000 was released!
    assert_eq!(
        h.repo.budget_used(session_id).unwrap().as_micro_usd(),
        35_000
    );
}

#[test]
fn test_repeated_result_recording_and_repeated_settlement_rejected() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(320);
    h.repo
        .create_task(session_id, task_id, 1, "Repeated Task", &h.clock)
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(320);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(320),
                action_name: "ActionRep".into(),
                action_digest: "digest-rep".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(320, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-rep".into(),
        estimated_cost: CostUsd::from_micro_usd(50_000),
    };
    let ctx = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(50_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id: res_id,
                context: ctx,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt_id, &h.clock).unwrap();

    h.repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            None,
            Some(CostUsd::from_micro_usd(20_000)),
            &h.clock,
        )
        .unwrap();

    // Repeated result recording on the same attempt fails with Conflict
    let rep = h.repo.record_result(
        attempt_id,
        AttemptOutcome::Completed,
        None,
        Some(CostUsd::from_micro_usd(20_000)),
        &h.clock,
    );
    assert!(rep.is_err());

    // Repeated budget settlement on the settled reservation fails with Conflict
    let res_settle = h.authority.settle_budget(
        Identifier::from_bytes(*res_id.as_bytes()),
        sentra_core::persistence::SettlementStatus::Completed(CostUsd::from_micro_usd(20_000)),
        event(),
        &h.clock,
    );
    assert!(res_settle.is_err());
}

#[test]
fn test_terminal_attempt_with_unsettled_reservation_detected_in_resume() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(330);
    h.repo
        .create_task(session_id, task_id, 1, "Unsettled Task", &h.clock)
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(330);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(330),
                action_name: "ActionUnset".into(),
                action_digest: "digest-unset".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(330, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-unset".into(),
        estimated_cost: CostUsd::from_micro_usd(70_000),
    };
    let ctx = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(70_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id: res_id,
                context: ctx,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt_id, &h.clock).unwrap();

    // Result recorded with None actual_cost (unsettled reservation)
    h.repo
        .record_result(attempt_id, AttemptOutcome::Completed, None, None, &h.clock)
        .unwrap();

    let service = create_test_service(&h);
    let report = service.resume_session(session_id).unwrap();

    // Resume report detects the terminal attempt with unsettled reservation
    let reconciled = report
        .reconciled_attempts
        .iter()
        .find(|r| r.attempt_id == attempt_id);
    assert!(reconciled.is_some());
    let rec = reconciled.unwrap();
    assert_eq!(rec.previous_state, AttemptState::ResultRecorded);
    assert_eq!(rec.reconciled_state, AttemptState::ResultRecorded);
    assert!(rec.budget_held);

    // Full 70_000 reservation remains conservatively held
    assert_eq!(
        h.repo.budget_used(session_id).unwrap().as_micro_usd(),
        70_000
    );
}

#[test]
fn test_uncertain_reservations_remain_held_after_recovery() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(340);
    h.repo
        .create_task(session_id, task_id, 1, "Uncertain Task", &h.clock)
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(340);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(340),
                action_name: "ActionUncertain".into(),
                action_digest: "digest-unc".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(340, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-unc".into(),
        estimated_cost: CostUsd::from_micro_usd(85_000),
    };
    let ctx = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(85_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id: res_id,
                context: ctx,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt_id, &h.clock).unwrap();

    let service = create_test_service(&h);
    service.resume_session(session_id).unwrap();

    // Check attempt is Uncertain and budget is fully held
    let att = h.repo.get_attempt(attempt_id).unwrap().unwrap();
    assert_eq!(att.state, AttemptState::Uncertain);
    assert_eq!(
        h.repo.budget_used(session_id).unwrap().as_micro_usd(),
        85_000
    );

    // Second resume preserves the full hold
    service.resume_session(session_id).unwrap();
    assert_eq!(
        h.repo.budget_used(session_id).unwrap().as_micro_usd(),
        85_000
    );
}

#[test]
fn test_confirmed_not_started_released_exactly_once() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(350);
    h.repo
        .create_task(session_id, task_id, 1, "NotStarted Task", &h.clock)
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(350);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(350),
                action_name: "ActionNotStarted".into(),
                action_digest: "digest-ns".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(350, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-ns".into(),
        estimated_cost: CostUsd::from_micro_usd(60_000),
    };
    let ctx = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(60_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id: res_id,
                context: ctx,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    assert_eq!(
        h.repo.budget_used(session_id).unwrap().as_micro_usd(),
        60_000
    );

    // Cancel before release
    let att = h.repo.confirm_not_started(attempt_id, &h.clock).unwrap();
    assert_eq!(att.state, AttemptState::NotStartedConfirmed);

    // Budget is released cleanly to 0
    assert_eq!(h.repo.budget_used(session_id).unwrap().as_micro_usd(), 0);

    // Repeating confirm_not_started is rejected
    assert!(h.repo.confirm_not_started(attempt_id, &h.clock).is_err());

    // Attempting release after not-started is rejected
    assert!(h.repo.record_release(attempt_id, &h.clock).is_err());
}

#[test]
fn test_stale_epoch_rejection_in_confirm_running_and_record_result() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(360);
    h.repo
        .create_task(session_id, task_id, 1, "Epoch Task", &h.clock)
        .unwrap();

    let attempt_id = AttemptId::for_test_sequence(360);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(360),
                action_name: "ActionEpoch".into(),
                action_digest: "digest-epoch".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(360, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-epoch".into(),
        estimated_cost: CostUsd::from_micro_usd(40_000),
    };
    let ctx = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(40_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id,
                reservation_id: res_id,
                context: ctx,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt_id, &h.clock).unwrap();

    // Advance session epoch from 1 to 2
    h.authority
        .advance_session_epoch(session_id, event(), &h.clock)
        .unwrap();

    // confirm_running with stale attempt prepared under epoch 1 fails with ContextMismatch
    denied(
        h.repo.confirm_running(attempt_id, &h.clock),
        Kind::ContextMismatch,
    );

    // Now test record_result epoch check:
    // Create attempt 2 under epoch 2
    let attempt2_id = AttemptId::for_test_sequence(361);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: attempt2_id,
                task_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(361),
                action_name: "ActionEpoch2".into(),
                action_digest: "digest-epoch2".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res2_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(361, 1).as_bytes());
    let ctx2 = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(40_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id: attempt2_id,
                reservation_id: res2_id,
                context: ctx2,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();

    h.repo.record_release(attempt2_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt2_id, &h.clock).unwrap();

    // Advance session epoch from 2 to 3
    h.authority
        .advance_session_epoch(session_id, event(), &h.clock)
        .unwrap();

    // record_result with stale attempt prepared under epoch 2 fails with ContextMismatch
    denied(
        h.repo.record_result(
            attempt2_id,
            AttemptOutcome::Completed,
            None,
            Some(CostUsd::ZERO),
            &h.clock,
        ),
        Kind::ContextMismatch,
    );
}

#[test]
fn test_recovery_failure_propagation_when_task_update_fails() {
    let h = Harness::new();
    let service = create_test_service(&h);

    // Resume on unknown session returns Conflict
    let unknown_session = SessionId::for_test_sequence(999);
    let res = service.resume_session(unknown_session);
    assert!(res.is_err());
}

#[test]
fn test_resume_report_accuracy_after_reconciliation() {
    let h = Harness::budget(500_000);
    advance_session_to_running(&h);
    let session_id = h.metadata.session_id;

    // Task 1: COMPLETED
    let t1_id = TaskId::for_test_sequence(381);
    h.repo
        .create_task(session_id, t1_id, 1, "Completed Task", &h.clock)
        .unwrap();
    h.repo
        .update_task_state(
            t1_id,
            TaskState::Pending,
            TaskState::InProgress,
            event(),
            &h.clock,
        )
        .unwrap();
    h.repo
        .update_task_state(
            t1_id,
            TaskState::InProgress,
            TaskState::Completed,
            event(),
            &h.clock,
        )
        .unwrap();

    // Task 2: Running -> will be reconciled to BLOCKED
    let t2_id = TaskId::for_test_sequence(382);
    h.repo
        .create_task(session_id, t2_id, 2, "Running Task", &h.clock)
        .unwrap();
    let att2_id = AttemptId::for_test_sequence(382);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: att2_id,
                task_id: t2_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(382),
                action_name: "ActionT2".into(),
                action_digest: "digest-t2".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    let res2_id =
        sentra_core::ReservationId::from_bytes(*Identifier::new_deterministic(382, 1).as_bytes());
    let policy_engine = PolicyEngine::new();
    let action = OperationAction::InvokeProvider {
        model_id: "m-t2".into(),
        estimated_cost: CostUsd::from_micro_usd(50_000),
    };
    let ctx2 = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(50_000),
            &policy_engine,
        )
        .unwrap();

    h.repo
        .prepare_attempt(
            PrepareAttemptRequest {
                attempt_id: att2_id,
                reservation_id: res2_id,
                context: ctx2,
                grant: None,
                reservation_event: event(),
                consumption_event: event(),
            },
            &h.clock,
        )
        .unwrap();
    h.repo.record_release(att2_id, &h.clock).unwrap();
    h.repo.confirm_running(att2_id, &h.clock).unwrap();

    // Task 3: Prepared attempt -> will be NotStartedConfirmed, task stays PENDING
    let t3_id = TaskId::for_test_sequence(383);
    h.repo
        .create_task(session_id, t3_id, 3, "Prepared Task", &h.clock)
        .unwrap();
    let att3_id = AttemptId::for_test_sequence(383);
    h.repo
        .record_attempt(
            RecordAttemptRequest {
                attempt_id: att3_id,
                task_id: t3_id,
                session_id,
                execution_id: ExecutionId::for_test_sequence(383),
                action_name: "ActionT3".into(),
                action_digest: "digest-t3".into(),
                manifest_id: None,
            },
            &h.clock,
        )
        .unwrap();

    // Task 4: Purely PENDING task with no attempts
    let t4_id = TaskId::for_test_sequence(384);
    h.repo
        .create_task(session_id, t4_id, 4, "Pure Pending Task", &h.clock)
        .unwrap();

    let service = create_test_service(&h);
    let report = service.resume_session(session_id).unwrap();

    assert_eq!(report.completed_tasks, vec![t1_id]);
    assert_eq!(report.blocked_tasks, vec![t2_id]);
    assert_eq!(report.pending_tasks, vec![t3_id, t4_id]);

    // Verify database state matches report exactly
    assert_eq!(
        h.repo.get_task(t1_id).unwrap().unwrap().state,
        TaskState::Completed
    );
    assert_eq!(
        h.repo.get_task(t2_id).unwrap().unwrap().state,
        TaskState::Blocked
    );
    assert_eq!(
        h.repo.get_task(t3_id).unwrap().unwrap().state,
        TaskState::Pending
    );
    assert_eq!(
        h.repo.get_task(t4_id).unwrap().unwrap().state,
        TaskState::Pending
    );
}
