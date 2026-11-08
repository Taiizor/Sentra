//! Integration tests for Increment 2.3: Result Admission, Settlement, and Replay Determinism (RM-3, F-14, R1-R7).

#[path = "support/persistence.rs"]
mod support;

use std::{fs, sync::Arc};

use rusqlite::Connection;
use sentra_core::{
    AttemptId, BlobId, BlobStore, Clock, CostUsd, EvidenceEnvelope, EvidenceId, EvidenceMetadata,
    ExecutionId, FileSystemCasBlobStore, Identifier, MockClock, OperationAction, PolicyEngine,
    ReservationId, SecurityClassification as Class, SessionId, SessionState, StorageLimits, TaskId,
    TimestampUtc,
    persistence::{
        AttemptOutcome, AttemptState, ManifestKind, PersistenceErrorKind as Kind,
        PrepareAttemptRequest, RecordAttemptRequest, TaskState,
    },
    service::{CoreService, CoreServiceConfig},
};
use support::*;

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

fn create_running_attempt(
    h: &Harness,
    attempt_seq: u64,
    task_seq: u64,
    cost_micro_usd: u64,
) -> (AttemptId, TaskId, ReservationId) {
    let session_id = h.metadata.session_id;
    let task_id = TaskId::for_test_sequence(task_seq);
    let attempt_id = AttemptId::for_test_sequence(attempt_seq);
    let res_ident = Identifier::new_deterministic(100, attempt_seq);
    let reservation_id = ReservationId::from_bytes(*res_ident.as_bytes());

    // Create task
    h.repo
        .create_task(session_id, task_id, 1, "security audit task", &h.clock)
        .unwrap();

    // Create manifest
    let manifest_id = sentra_core::ManifestId::for_test_sequence(attempt_seq + 2000);
    h.repo
        .create_manifest(
            manifest_id,
            session_id,
            ManifestKind::Operation,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "{\"action\": \"DISCOVER_METADATA\"}",
            &h.clock,
        )
        .unwrap();

    let action = OperationAction::DiscoverMetadata {
        relative_path: "src".to_string(),
    };
    let policy_engine = PolicyEngine::new();
    let context = h
        .authority
        .execution_context(
            session_id,
            Class::Internal,
            &action,
            CostUsd::from_micro_usd(cost_micro_usd),
            &policy_engine,
        )
        .unwrap();

    // Record attempt
    let execution_id = ExecutionId::for_test_sequence(attempt_seq + 3000);
    let record_req = RecordAttemptRequest {
        attempt_id,
        task_id,
        session_id,
        execution_id,
        action_name: "DISCOVER_METADATA".to_string(),
        action_digest: "action-digest-test".to_string(),
        manifest_id: Some(manifest_id),
    };
    h.repo.record_attempt(record_req, &h.clock).unwrap();

    // Prepare attempt
    let prep_req = PrepareAttemptRequest {
        attempt_id,
        reservation_id,
        context,
        grant: None,
        reservation_event: event(),
        consumption_event: event(),
    };
    h.repo.prepare_attempt(prep_req, &h.clock).unwrap();

    // Record release and confirm running
    h.repo.record_release(attempt_id, &h.clock).unwrap();
    h.repo.confirm_running(attempt_id, &h.clock).unwrap();

    (attempt_id, task_id, reservation_id)
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

fn sample_envelope(task_id: TaskId, session_id: SessionId, payload: &[u8]) -> EvidenceEnvelope {
    let metadata = EvidenceMetadata {
        evidence_id: EvidenceId::for_test_sequence(1),
        session_id,
        task_id,
        producer_role: "scanner".to_string(),
        media_type: "application/json".to_string(),
        payload_length_bytes: payload.len() as u64,
        declared_sha256: Some(sentra_core::common::crypto::sha256_digest(payload)),
        classification: Class::Internal,
        created_at: TimestampUtc::from_epoch_secs(1_700_000_000),
    };
    EvidenceEnvelope::new(metadata, payload.to_vec())
}

#[test]
fn test_record_result_atomic_transition_and_task_completion() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, task_id, res_id) = create_running_attempt(&h, 10, 20, 50_000);
    let details = serde_json::json!({"status": "success", "exit_code": 0}).to_string();

    let before_audits = h.audit_count();

    // Record result with verified actual spend of 35_000 micro-USD
    let attempt = h
        .repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            Some(&details),
            Some(CostUsd::from_micro_usd(35_000)),
            &h.clock,
        )
        .unwrap();

    assert_eq!(attempt.state, AttemptState::ResultRecorded);
    assert_eq!(attempt.terminal_outcome, Some(AttemptOutcome::Completed));
    assert_eq!(
        attempt.terminal_details_json.as_deref(),
        Some(details.as_str())
    );

    // Verify task state atomically updated to COMPLETED
    let task = h.repo.get_task(task_id).unwrap().unwrap();
    assert_eq!(task.state, TaskState::Completed);
    assert!(task.completed_at.is_some());

    // Verify budget reservation is settled in database
    let conn = Connection::open(&h.dir.db).unwrap();
    let (res_state, res_cost): (String, Option<i64>) = conn
        .query_row(
            "SELECT state, actual_cost_micro_usd FROM budget_reservations WHERE reservation_id=?1",
            [res_id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(res_state, "SETTLED");
    assert_eq!(res_cost, Some(35_000));

    // Verify audit log emitted exactly once
    assert_eq!(h.audit_count(), before_audits + 2); // BudgetSettled + AttemptResultRecorded
}

#[test]
fn test_record_result_atomic_transition_on_failure_and_timeout() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    // Case 1: Failure
    let (attempt1, task1, _) = create_running_attempt(&h, 30, 40, 25_000);
    h.repo
        .record_result(
            attempt1,
            AttemptOutcome::Failed,
            Some("{\"error\": \"compilation_failed\"}"),
            Some(CostUsd::from_micro_usd(25_000)),
            &h.clock,
        )
        .unwrap();

    let task1_record = h.repo.get_task(task1).unwrap().unwrap();
    assert_eq!(task1_record.state, TaskState::Failed);
    assert!(task1_record.completed_at.is_some());

    // Case 2: TimedOut
    let (attempt2, task2, _) = create_running_attempt(&h, 50, 60, 25_000);
    h.repo
        .record_result(
            attempt2,
            AttemptOutcome::TimedOut,
            Some("{\"timeout_seconds\": 30}"),
            Some(CostUsd::from_micro_usd(25_000)),
            &h.clock,
        )
        .unwrap();

    let task2_record = h.repo.get_task(task2).unwrap().unwrap();
    assert_eq!(task2_record.state, TaskState::Failed);
}

#[test]
fn test_record_result_atomic_transition_on_cancellation() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt, task, res_id) = create_running_attempt(&h, 70, 80, 40_000);
    h.repo
        .record_result(
            attempt,
            AttemptOutcome::Cancelled,
            Some("{\"reason\": \"user_requested\"}"),
            Some(CostUsd::from_micro_usd(10_000)),
            &h.clock,
        )
        .unwrap();

    let task_record = h.repo.get_task(task).unwrap().unwrap();
    assert_eq!(task_record.state, TaskState::Cancelled);

    let conn = Connection::open(&h.dir.db).unwrap();
    let res_state: String = conn
        .query_row(
            "SELECT state FROM budget_reservations WHERE reservation_id=?1",
            [res_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(res_state, "CANCELLED");
}

#[test]
fn test_record_result_exact_duplicate_is_idempotent_no_op() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, _task_id, res_id) = create_running_attempt(&h, 90, 100, 50_000);
    let details = serde_json::json!({"status": "success", "exit_code": 0}).to_string();
    let cost = Some(CostUsd::from_micro_usd(30_000));

    // First call: succeeds
    let first = h
        .repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            Some(&details),
            cost,
            &h.clock,
        )
        .unwrap();

    let audit_count_after_first = h.audit_count();

    // Replay identical call a SECOND time (Exact duplicate per R1-R7)
    let second = h
        .repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            Some(&details),
            cost,
            &h.clock,
        )
        .unwrap();

    assert_eq!(first.attempt_id, second.attempt_id);
    assert_eq!(first.state, second.state);
    assert_eq!(first.terminal_outcome, second.terminal_outcome);
    assert_eq!(first.terminal_details_json, second.terminal_details_json);

    // Verify duplicate no-op produced zero additional audit records
    assert_eq!(h.audit_count(), audit_count_after_first);

    // Verify budget was not double-deducted
    let conn = Connection::open(&h.dir.db).unwrap();
    let res_cost: Option<i64> = conn
        .query_row(
            "SELECT actual_cost_micro_usd FROM budget_reservations WHERE reservation_id=?1",
            [res_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(res_cost, Some(30_000));
}

#[test]
fn test_record_result_conflicting_outcome_denied_with_conflict() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, _, _) = create_running_attempt(&h, 110, 120, 50_000);
    let details = serde_json::json!({"status": "success"}).to_string();

    // First: record Completed
    h.repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            Some(&details),
            None,
            &h.clock,
        )
        .unwrap();

    // Conflicting replay: Attempt to change outcome to Failed
    let conflict_res = h.repo.record_result(
        attempt_id,
        AttemptOutcome::Failed,
        Some(&details),
        None,
        &h.clock,
    );

    assert_eq!(conflict_res.unwrap_err().kind, Kind::Conflict);

    // Verify original Completed outcome preserved intact
    let att = h.repo.get_attempt(attempt_id).unwrap().unwrap();
    assert_eq!(att.terminal_outcome, Some(AttemptOutcome::Completed));
}

#[test]
fn test_record_result_conflicting_details_denied_with_conflict() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, _, _) = create_running_attempt(&h, 130, 140, 50_000);

    h.repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            Some("{\"exit\": 0}"),
            None,
            &h.clock,
        )
        .unwrap();

    // Conflicting replay: different details
    let conflict = h.repo.record_result(
        attempt_id,
        AttemptOutcome::Completed,
        Some("{\"exit\": 1}"),
        None,
        &h.clock,
    );

    assert_eq!(conflict.unwrap_err().kind, Kind::Conflict);
}

#[test]
fn test_record_result_conflicting_cost_denied_with_conflict() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, _, _) = create_running_attempt(&h, 150, 160, 50_000);

    h.repo
        .record_result(
            attempt_id,
            AttemptOutcome::Completed,
            None,
            Some(CostUsd::from_micro_usd(20_000)),
            &h.clock,
        )
        .unwrap();

    // Conflicting replay: different actual cost
    let conflict = h.repo.record_result(
        attempt_id,
        AttemptOutcome::Completed,
        None,
        Some(CostUsd::from_micro_usd(40_000)),
        &h.clock,
    );

    assert_eq!(conflict.unwrap_err().kind, Kind::Conflict);
}

#[test]
fn test_record_result_on_uncertain_attempt_denied_with_conflict() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, _, _) = create_running_attempt(&h, 170, 180, 50_000);
    h.repo.mark_attempt_uncertain(attempt_id, &h.clock).unwrap();

    // Direct result recording on UNCERTAIN attempt fails closed
    let res = h
        .repo
        .record_result(attempt_id, AttemptOutcome::Completed, None, None, &h.clock);
    assert_eq!(res.unwrap_err().kind, Kind::Conflict);
}

#[test]
fn test_record_result_on_not_started_confirmed_denied_with_conflict() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let (attempt_id, _, _) = create_running_attempt(&h, 190, 200, 50_000);
    h.repo.confirm_not_started(attempt_id, &h.clock).unwrap();

    // Direct result recording on NOT_STARTED_CONFIRMED attempt fails closed
    let res = h
        .repo
        .record_result(attempt_id, AttemptOutcome::Completed, None, None, &h.clock);
    assert_eq!(res.unwrap_err().kind, Kind::Conflict);
}

#[test]
fn test_admit_task_result_core_service_integration_with_blobs() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let temp_cas = std::env::temp_dir().join(format!(
        "sentra-cas-res-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_cas).unwrap();
    let blob_store: Arc<dyn BlobStore> =
        Arc::new(FileSystemCasBlobStore::new(&temp_cas, StorageLimits::default()).unwrap());

    let service = create_test_service(&h).with_blob_store(Arc::clone(&blob_store));

    let (attempt_id, task_id, res_id) = create_running_attempt(&h, 210, 220, 50_000);

    let payload = b"{\"vulnerability\": \"RCE\", \"severity\": \"CRITICAL\"}";
    let envelope = sample_envelope(task_id, h.metadata.session_id, payload);

    let record = service
        .admit_task_result(
            h.metadata.session_id,
            attempt_id,
            AttemptOutcome::Completed,
            Some(0),
            None,
            &[envelope],
            Some(CostUsd::from_micro_usd(25_000)),
        )
        .unwrap();

    assert_eq!(record.state, AttemptState::ResultRecorded);
    assert_eq!(record.terminal_outcome, Some(AttemptOutcome::Completed));

    // Verify evidence was stored in BlobStore
    let expected_blob_id = BlobId::from_bytes(payload);
    assert!(blob_store.exists(&expected_blob_id));

    // Verify details JSON contains the blob digest
    let details = record.terminal_details_json.unwrap();
    assert!(details.contains(expected_blob_id.as_str()));

    // Verify task state is completed
    let task = h.repo.get_task(task_id).unwrap().unwrap();
    assert_eq!(task.state, TaskState::Completed);

    // Verify budget settled
    let conn = Connection::open(&h.dir.db).unwrap();
    let (res_state, res_cost): (String, Option<i64>) = conn
        .query_row(
            "SELECT state, actual_cost_micro_usd FROM budget_reservations WHERE reservation_id=?1",
            [res_id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(res_state, "SETTLED");
    assert_eq!(res_cost, Some(25_000));

    // Cleanup CAS temp directory
    let _ = fs::remove_dir_all(&temp_cas);
}

#[test]
fn test_admit_task_result_replay_determinism() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let service = create_test_service(&h);
    let (attempt_id, _task_id, _) = create_running_attempt(&h, 230, 240, 50_000);

    // First call
    let first = service
        .admit_task_result(
            h.metadata.session_id,
            attempt_id,
            AttemptOutcome::Completed,
            Some(0),
            None,
            &[],
            Some(CostUsd::from_micro_usd(15_000)),
        )
        .unwrap();

    // Replay call with exact same parameters
    let second = service
        .admit_task_result(
            h.metadata.session_id,
            attempt_id,
            AttemptOutcome::Completed,
            Some(0),
            None,
            &[],
            Some(CostUsd::from_micro_usd(15_000)),
        )
        .unwrap();

    assert_eq!(first.attempt_id, second.attempt_id);
    assert_eq!(first.terminal_outcome, second.terminal_outcome);
    assert_eq!(first.settled_at, second.settled_at);
}

#[test]
fn test_admit_task_result_terminal_session_fails_closed() {
    let h = Harness::budget(200_000);
    advance_session_to_running(&h);

    let service = create_test_service(&h);
    let (attempt_id, _, _) = create_running_attempt(&h, 250, 260, 50_000);

    // Cancel session
    h.repo
        .transition_session(
            h.metadata.session_id,
            SessionState::Running,
            SessionState::Cancelled,
            event(),
            &h.clock,
        )
        .unwrap();

    let err = service.admit_task_result(
        h.metadata.session_id,
        attempt_id,
        AttemptOutcome::Completed,
        Some(0),
        None,
        &[],
        None,
    );

    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("terminal"));
}
