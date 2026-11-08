//! Increment 5.4.2 native SQLite fixtures; every database belongs to this test run.
#[path = "support/persistence.rs"]
mod support;

use rusqlite::{Connection, params};
use sentra_core::{
    ApprovalId, Clock, CostUsd, EventId, Identifier, OperatingMode, OperationAction,
    SecurityClassification as Class, SessionId, SessionState, TimestampUtc,
    persistence::{
        ForeignKeyViolation, IntegrityReport, PersistenceError, PersistenceErrorKind as Kind,
        PersistenceRepository, PersistentApprovalGrant, SettlementStatus, SqliteConnectionManager,
    },
};
use std::{
    fs,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use support::*;

fn denied<T>(result: Result<T, PersistenceError>, expected: Kind) {
    match result {
        Err(error) => assert_eq!(error.kind, expected),
        Ok(_) => panic!("expected {expected:?}"),
    }
}

#[test]
fn connection_fresh_pragmas_schema_integrity_and_clean_shutdown() {
    let h = Harness::new();
    let settings = h.manager.settings().unwrap();
    assert_eq!(settings.sqlite_version, "3.46.0");
    assert!(settings.foreign_keys);
    assert_eq!(settings.journal_mode, "wal");
    assert_eq!(settings.synchronous, 2);
    assert_eq!(settings.busy_timeout_ms, 5000);
    assert_eq!(settings.wal_autocheckpoint, 1000);
    h.manager.integrity_check().unwrap();
    let raw = Connection::open(&h.dir.db).unwrap();
    let mut statement = raw
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let tables: Vec<String> = statement
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        tables,
        [
            "approval_requests",
            "attempts",
            "audit_events",
            "budget_reservations",
            "manifests",
            "schema_migrations",
            "session_security_snapshots",
            "sessions",
            "tasks",
        ]
    );
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM schema_migrations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    drop(statement);
    drop(raw);
    assert!(!h.manager.shutdown().unwrap().busy);
    assert_eq!(
        fs::metadata(h.dir.sidecar("-wal"))
            .map(|m| m.len())
            .unwrap_or(0),
        0
    );
    denied(h.repo.session(h.metadata.session_id), Kind::Closed);
}

#[test]
fn migration_repeated_initialization_preserves_supported_data() {
    let h = Harness::new();
    h.manager.shutdown().unwrap();
    let reopened = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(reopened.clone());
    let record = repo.session(h.metadata.session_id).unwrap().unwrap();
    assert_eq!(record.context_generation, 1);
    assert_eq!(record.state, SessionState::Created);
    assert_eq!(
        repo.audit_events(h.metadata.session_id, 0, 100)
            .unwrap()
            .len(),
        1
    );
    let mut updated = h.metadata.clone();
    updated.completeness = sentra_core::AssessmentCompleteness::Complete;
    authority
        .register_session(
            &updated,
            "revision-A",
            Class::Public,
            CostUsd::from_micro_usd(100),
            event(),
            &h.clock,
        )
        .unwrap();
    let raw = Connection::open(&h.dir.db).unwrap();
    assert_eq!(
        raw.query_row("SELECT completeness FROM sessions", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "COMPLETE"
    );
    assert_eq!(
        repo.session(updated.session_id)
            .unwrap()
            .unwrap()
            .metadata
            .completeness,
        updated.completeness
    );
    drop(raw);
    reopened.shutdown().unwrap();
}

#[test]
fn connection_invalid_paths_fail_without_creating_files() {
    let d = Directory::new();
    let c = clock();
    // Windows PathBuf::join normalizes parent traversal on verbatim paths. Build
    // the original caller spelling without that lexical transformation.
    let mut traversal = d.root.as_os_str().to_os_string();
    traversal.push("/../escape.db");
    for path in [
        d.root.clone(),
        d.root.join("missing/child.db"),
        traversal.into(),
        d.root.join("NUL.db"),
        d.root.join("bad.db:stream"),
        d.root.join("trailing. "),
        "relative.db".into(),
        "file:memory?mode=memory".into(),
    ] {
        let result = SqliteConnectionManager::open(&path, &c);
        assert!(
            result.as_ref().is_err_and(|e| e.kind == Kind::InvalidPath),
            "unexpected path result: {path:?} {result:?}"
        );
    }
    assert!(!d.db.exists());
}

#[test]
#[cfg(windows)]
fn windows_locked_database_initialization_fails_without_overwriting() {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    let h = Harness::new();
    h.manager.shutdown().unwrap();
    let original = fs::read(&h.dir.db).unwrap();
    let locked = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&h.dir.db)
        .unwrap();
    assert!(SqliteConnectionManager::open(&h.dir.db, &h.clock).is_err());
    drop(locked);
    assert_eq!(fs::read(&h.dir.db).unwrap(), original);
}

#[test]
#[cfg(windows)]
fn windows_static_symlink_database_parent_and_wal_are_rejected() {
    use std::os::windows::fs::{symlink_dir, symlink_file};
    let d = Directory::new();
    let real = d.root.join("real.db");
    fs::write(&real, b"untouched").unwrap();
    symlink_file(&real, &d.db)
        .expect("Windows symlink fixture requires the already available privilege");
    denied(
        SqliteConnectionManager::open(&d.db, &clock()),
        Kind::InvalidPath,
    );
    fs::remove_file(&d.db).unwrap();
    symlink_file(&real, d.sidecar("-wal")).unwrap();
    denied(
        SqliteConnectionManager::open(&d.db, &clock()),
        Kind::InvalidPath,
    );
    fs::remove_file(d.sidecar("-wal")).unwrap();
    let actual = d.root.join("actual");
    fs::create_dir(&actual).unwrap();
    let link = d.root.join("linked");
    symlink_dir(&actual, &link).unwrap();
    denied(
        SqliteConnectionManager::open(&link.join("data.db"), &clock()),
        Kind::InvalidPath,
    );
    fs::remove_dir(link).unwrap();
    assert_eq!(fs::read(real).unwrap(), b"untouched");
    assert!(!actual.join("data.db").exists());
}

#[test]
fn approval_all_action_parameter_changes_are_bound_without_consuming_original() {
    let pairs = [
        (
            OperationAction::ExecuteTool {
                tool_id: "fixture".into(),
                untrusted: false,
                arguments: vec!["one".into(), "two".into()],
            },
            OperationAction::ExecuteTool {
                tool_id: "fixture".into(),
                untrusted: false,
                arguments: vec!["one|two".into()],
            },
        ),
        (
            OperationAction::ExecuteTool {
                tool_id: "fixture".into(),
                untrusted: false,
                arguments: vec![],
            },
            OperationAction::ExecuteTool {
                tool_id: "fixture".into(),
                untrusted: true,
                arguments: vec![],
            },
        ),
        (
            OperationAction::InvokeProvider {
                model_id: "mock-A".into(),
                estimated_cost: CostUsd::from_micro_usd(10),
            },
            OperationAction::InvokeProvider {
                model_id: "mock-B".into(),
                estimated_cost: CostUsd::from_micro_usd(10),
            },
        ),
        (
            OperationAction::InvokeProvider {
                model_id: "mock-A".into(),
                estimated_cost: CostUsd::from_micro_usd(10),
            },
            OperationAction::InvokeProvider {
                model_id: "mock-A".into(),
                estimated_cost: CostUsd::from_micro_usd(11),
            },
        ),
        (
            OperationAction::ExportReport {
                destination: "private-A".into(),
                is_external: false,
                destination_classification: Some(Class::Restricted),
            },
            OperationAction::ExportReport {
                destination: "private-B".into(),
                is_external: false,
                destination_classification: Some(Class::Restricted),
            },
        ),
        (
            OperationAction::ExportReport {
                destination: "private-A".into(),
                is_external: false,
                destination_classification: Some(Class::Restricted),
            },
            OperationAction::ExportReport {
                destination: "private-A".into(),
                is_external: true,
                destination_classification: Some(Class::Restricted),
            },
        ),
    ];
    for (a, b) in pairs {
        let h = Harness::new();
        let grant = h.grant(&a);
        denied(
            h.repo
                .consume_approval(&grant, &intent(&h.metadata, &b), event(), &h.clock),
            Kind::ContextMismatch,
        );
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock)
            .unwrap();
    }
}

#[test]
fn approval_row_provenance_mutation_and_missing_snapshot_are_not_accepted() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let raw = Connection::open(&h.dir.db).unwrap();
    raw.execute(
        "UPDATE approval_requests SET receipt_token='forged' WHERE request_id=?1",
        [grant.request_id().to_string()],
    )
    .unwrap();
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::InvalidApproval,
    );
    // Deliberately corrupt only this disposable fixture through an independent
    // connection; the managed connection's FK enforcement remains enabled.
    raw.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM session_security_snapshots")
        .unwrap();
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::Integrity,
    );
    denied(h.repo.session(h.metadata.session_id), Kind::Halted);
    h.manager.quarantine_in_place().unwrap();
}

#[test]
fn budget_separate_connections_cannot_exceed_shared_limit() {
    let h = Harness::budget(10);
    let barrier = Arc::new(Barrier::new(3));
    let results = thread::scope(|scope| {
        let handles: Vec<_> = (1..=2)
            .map(|n| {
                let h = &h;
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let manager = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
                    let (repo, _) = PersistenceRepository::with_authority(manager);
                    barrier.wait();
                    repo.reserve_budget(
                        identifier(n),
                        h.metadata.session_id,
                        "mock",
                        CostUsd::from_micro_usd(6),
                        event(),
                        &h.clock,
                    )
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        6
    );
}

#[test]
#[cfg(windows)]
fn windows_unc_device_drive_relative_and_reserved_paths_are_rejected() {
    let c = clock();
    for path in [
        "//server/share/sentra.db",
        "//?/UNC/server/share/sentra.db",
        "//./pipe/sentra.db",
        "E:relative.db",
        "E:/NUL.db",
    ] {
        denied(
            SqliteConnectionManager::open(std::path::Path::new(path), &c),
            Kind::InvalidPath,
        );
    }
}

#[test]
fn migration_rejects_unrelated_database_without_overwriting() {
    let d = Directory::new();
    let raw = Connection::open(&d.db).unwrap();
    raw.execute_batch(
        "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('preserve')",
    )
    .unwrap();
    drop(raw);
    let before = fs::read(&d.db).unwrap();
    denied(
        SqliteConnectionManager::open(&d.db, &clock()),
        Kind::SchemaMetadata,
    );
    assert_eq!(fs::read(&d.db).unwrap(), before);
}

#[test]
fn migration_newer_schema_is_rejected_without_overwriting() {
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

#[test]
fn migration_drift_missing_history_and_unknown_trigger_fail_closed() {
    for sql in [
        "UPDATE schema_migrations SET checksum='forged'",
        "DELETE FROM schema_migrations",
        "CREATE TRIGGER unexpected AFTER UPDATE ON sessions BEGIN SELECT 1; END",
        "PRAGMA user_version=0",
    ] {
        let h = Harness::new();
        h.manager.shutdown().unwrap();
        let raw = Connection::open(&h.dir.db).unwrap();
        raw.execute_batch(sql).unwrap();
        drop(raw);
        denied(
            SqliteConnectionManager::open(&h.dir.db, &h.clock),
            Kind::SchemaMetadata,
        );
        assert!(h.dir.db.exists());
    }
}

#[test]
fn migrations_enforce_foreign_keys_audit_uniqueness_and_budget_checks() {
    let h = Harness::new();
    let raw = Connection::open(&h.dir.db).unwrap();
    raw.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    assert!(raw.execute("INSERT INTO audit_events SELECT ?1,session_id,sequence_number,event_kind,classification,timestamp,action_digest,details_json FROM audit_events LIMIT 1", [event().to_string()]).is_err());
    assert!(raw.execute("INSERT INTO audit_events SELECT ?1,'missing',100,event_kind,classification,timestamp,action_digest,details_json FROM audit_events LIMIT 1", [event().to_string()]).is_err());
    assert!(raw.execute("INSERT INTO budget_reservations(reservation_id,session_id,model_id,reserved_cost_micro_usd,state,reserved_at) VALUES(?1,?2,'mock',-1,'RESERVED',?3)",params![identifier(1).to_string(),h.metadata.session_id.to_string(),h.clock.now().to_rfc3339()]).is_err());
    drop(raw);
    h.manager.integrity_check().unwrap();
}

#[test]
fn audit_failure_rolls_back_state_and_no_success_is_reported() {
    let h = Harness::new();
    let original = h.repo.audit_events(h.metadata.session_id, 0, 10).unwrap();
    assert!(
        h.repo
            .transition_session(
                h.metadata.session_id,
                SessionState::Created,
                SessionState::Scoped,
                original[0].event_id,
                &h.clock
            )
            .is_err()
    );
    assert_eq!(
        h.repo
            .session(h.metadata.session_id)
            .unwrap()
            .unwrap()
            .state,
        SessionState::Created
    );
    assert_eq!(h.audit_count(), 1);
    let committed = h
        .repo
        .transition_session(
            h.metadata.session_id,
            SessionState::Created,
            SessionState::Scoped,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(committed.audit_sequence, 2);
    denied(
        h.repo.transition_session(
            h.metadata.session_id,
            SessionState::Created,
            SessionState::Completed,
            event(),
            &h.clock,
        ),
        Kind::Conflict,
    );
    assert_eq!(h.audit_count(), 2);
}

#[test]
fn persistent_original_a_to_b_probe_denied_then_a_succeeds_once() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let b = OperationAction::DiscoverMetadata {
        relative_path: "different metadata B".into(),
    };
    let before = h.audit_count();
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &b), event(), &h.clock),
        Kind::ContextMismatch,
    );
    assert_eq!(h.audit_count(), before);
    let consumed = h
        .repo
        .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock)
        .unwrap();
    assert_eq!(consumed.audit_sequence as usize, before + 1);
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::ApprovalReused,
    );
}

#[test]
fn approval_changes_to_action_arguments_target_revision_generation_or_class_are_denied() {
    let h = Harness::new();
    let a = OperationAction::ModifyCheckout {
        file_count: 1,
        target_paths: vec!["src/A.rs".into()],
    };
    let grant = h.grant(&a);
    for b in [
        action(),
        OperationAction::ModifyCheckout {
            file_count: 1,
            target_paths: vec!["src/B.rs".into()],
        },
        OperationAction::ModifyCheckout {
            file_count: 2,
            target_paths: vec!["src/A.rs".into(), "src/B.rs".into()],
        },
    ] {
        denied(
            h.repo
                .consume_approval(&grant, &intent(&h.metadata, &b), event(), &h.clock),
            Kind::ContextMismatch,
        );
    }
    let mut changed = intent(&h.metadata, &a);
    changed.target_revision = "revision-B";
    denied(
        h.repo.consume_approval(&grant, &changed, event(), &h.clock),
        Kind::ContextMismatch,
    );
    changed = intent(&h.metadata, &a);
    changed.context_generation = 2;
    denied(
        h.repo.consume_approval(&grant, &changed, event(), &h.clock),
        Kind::ContextMismatch,
    );
    changed = intent(&h.metadata, &a);
    changed.classification = Class::Confidential;
    denied(
        h.repo.consume_approval(&grant, &changed, event(), &h.clock),
        Kind::ContextMismatch,
    );
    h.repo
        .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock)
        .unwrap();
}

#[test]
fn approval_modified_session_metadata_is_not_trusted() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    for change in 0..6 {
        let mut metadata = h.metadata.clone();
        match change {
            0 => metadata.workspace_root = "E:/other-target".into(),
            1 => metadata.operator_id = "other".into(),
            2 => metadata.policy_digest = "different-policy".into(),
            3 => metadata.session_id = SessionId::for_test_sequence(999),
            4 => metadata.created_at_utc = metadata.created_at_utc.add_seconds(1),
            _ => metadata.operating_mode = OperatingMode::DeepSecurityResearch,
        }
        denied(
            h.repo
                .consume_approval(&grant, &intent(&metadata, &a), event(), &h.clock),
            Kind::ContextMismatch,
        );
    }
    h.repo
        .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock)
        .unwrap();
}

#[test]
fn approval_context_reregistration_rejects_old_generation_even_after_revision_aba() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    for revision in ["revision-B", "revision-A"] {
        h.authority
            .register_session(
                &h.metadata,
                revision,
                Class::Public,
                CostUsd::from_micro_usd(100),
                event(),
                &h.clock,
            )
            .unwrap();
    }
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::ContextMismatch,
    );
    let mut newer = intent(&h.metadata, &a);
    newer.context_generation = 3;
    denied(
        h.repo.consume_approval(&grant, &newer, event(), &h.clock),
        Kind::ContextMismatch,
    );
}

#[test]
fn approval_expiration_boundary_clock_reversal_and_revocation_fail_closed() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    h.clock.advance_seconds(3600);
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::ApprovalExpired,
    );
    h.clock
        .set_time(TimestampUtc::from_epoch_secs(1_699_999_999));
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::ApprovalExpired,
    );
    h.clock
        .set_time(TimestampUtc::from_epoch_secs(1_700_000_000));
    h.authority
        .revoke_grant(grant.request_id(), "controller", event(), &h.clock)
        .unwrap();
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::InvalidApproval,
    );
}

#[test]
fn approval_unknown_pending_missing_context_and_foreign_provenance_are_denied() {
    let h = Harness::new();
    let a = action();
    let i = intent(&h.metadata, &a);
    denied(
        h.authority.issue_grant(
            ApprovalId::for_test_sequence(99999),
            &i,
            "controller",
            event(),
            &h.clock,
        ),
        Kind::InvalidApproval,
    );
    let mut missing = intent(&h.metadata, &a);
    missing.context_generation = 0;
    denied(
        h.repo.request_approval(
            ApprovalId::for_test_sequence(88888),
            &missing,
            event(),
            &h.clock,
        ),
        Kind::ContextMismatch,
    );
    let grant = h.grant(&a);
    let (other_repo, other_authority) = PersistenceRepository::with_authority(h.manager.clone());
    denied(
        other_repo.consume_approval(&grant, &i, event(), &h.clock),
        Kind::InvalidApproval,
    );
    let recovered = other_authority
        .recover_issued_grant(grant.request_id(), &i, "controller", event(), &h.clock)
        .unwrap();
    denied(
        h.repo.consume_approval(&recovered, &i, event(), &h.clock),
        Kind::InvalidApproval,
    );
    h.repo
        .consume_approval(&grant, &i, event(), &h.clock)
        .unwrap();
}

#[test]
fn approval_failed_audit_does_not_consume_valid_receipt() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let duplicate = h.repo.audit_events(h.metadata.session_id, 0, 100).unwrap()[0].event_id;
    assert!(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), duplicate, &h.clock)
            .is_err()
    );
    h.repo
        .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock)
        .unwrap();
}

#[test]
fn approval_reopen_requires_privileged_recovery_and_replay_stays_rejected() {
    let h = Harness::new();
    let a = action();
    let old = h.grant(&a);
    h.manager.shutdown().unwrap();
    let manager = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
    denied(
        repo.consume_approval(&old, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::InvalidApproval,
    );
    let restored = authority
        .recover_issued_grant(
            old.request_id(),
            &intent(&h.metadata, &a),
            "controller",
            event(),
            &h.clock,
        )
        .unwrap();
    repo.consume_approval(&restored, &intent(&h.metadata, &a), event(), &h.clock)
        .unwrap();
    manager.shutdown().unwrap();
    let manager = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
    let (_, authority) = PersistenceRepository::with_authority(manager.clone());
    denied(
        authority.recover_issued_grant(
            old.request_id(),
            &intent(&h.metadata, &a),
            "controller",
            event(),
            &h.clock,
        ),
        Kind::ApprovalReused,
    );
    manager.shutdown().unwrap();
}

#[test]
fn approval_concurrent_matching_and_mismatching_consumers_preserve_single_use() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PersistenceRepository>();
    assert_send_sync::<PersistentApprovalGrant>();
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let barrier = Arc::new(Barrier::new(9));
    let results = thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|n| {
                let barrier = barrier.clone();
                let h = &h;
                let grant = &grant;
                scope.spawn(move || {
                    let a = if n % 2 == 0 {
                        action()
                    } else {
                        OperationAction::DiscoverMetadata {
                            relative_path: "mismatch".into(),
                        }
                    };
                    barrier.wait();
                    h.repo
                        .consume_approval(grant, &intent(&h.metadata, &a), event(), &h.clock)
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_err_and(|e| e.kind == Kind::ContextMismatch))
            .count(),
        4
    );
    assert_eq!(
        h.repo
            .audit_events(h.metadata.session_id, 0, 100)
            .unwrap()
            .iter()
            .filter(|e| e.event_kind == "ApprovalConsumed")
            .count(),
        1
    );
}

#[test]
fn approval_separate_connections_have_one_database_consumer() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let barrier = Arc::new(Barrier::new(3));
    let results = thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let h = &h;
            let a = &a;
            let grant = &grant;
            handles.push(scope.spawn(move || {
                let manager = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
                let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
                let receipt = authority
                    .recover_issued_grant(
                        grant.request_id(),
                        &intent(&h.metadata, a),
                        "controller",
                        event(),
                        &h.clock,
                    )
                    .unwrap();
                barrier.wait();
                repo.consume_approval(&receipt, &intent(&h.metadata, a), event(), &h.clock)
            }));
        }
        barrier.wait();
        handles
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_err_and(|e| e.kind == Kind::ApprovalReused))
            .count(),
        1
    );
    h.manager.integrity_check().unwrap();
}

#[test]
fn persistent_policy_denies_unknown_malformed_write_down_and_terminal_session() {
    let h = Harness::new();
    for a in [
        OperationAction::UnknownOperation {
            operation_name: "unknown".into(),
        },
        OperationAction::DiscoverMetadata {
            relative_path: "".into(),
        },
        OperationAction::ExportReport {
            destination: "synthetic".into(),
            is_external: false,
            destination_classification: Some(Class::Public),
        },
    ] {
        denied(
            h.repo.request_approval(
                ApprovalId::for_test_sequence(40000),
                &intent(&h.metadata, &a),
                event(),
                &h.clock,
            ),
            Kind::PolicyDenied,
        );
    }
    let a = action();
    let grant = h.grant(&a);
    let transition = h
        .repo
        .transition_session(
            h.metadata.session_id,
            SessionState::Created,
            SessionState::Cancelled,
            event(),
            &h.clock,
        )
        .unwrap();
    assert!(transition.checkpoint.unwrap().is_ok());
    denied(
        h.repo
            .consume_approval(&grant, &intent(&h.metadata, &a), event(), &h.clock),
        Kind::PolicyDenied,
    );
}

#[test]
fn budget_concurrent_reservations_cannot_overspend() {
    let h = Harness::budget(10);
    let barrier = Arc::new(Barrier::new(9));
    let results = thread::scope(|scope| {
        let handles: Vec<_> = (1..=8)
            .map(|n| {
                let h = &h;
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    h.repo.reserve_budget(
                        identifier(n),
                        h.metadata.session_id,
                        "deterministic-mock",
                        CostUsd::from_micro_usd(6),
                        event(),
                        &h.clock,
                    )
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_err_and(|e| e.kind == Kind::BudgetExceeded))
            .count(),
        7
    );
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        6
    );
    let audit = h.repo.audit_events(h.metadata.session_id, 0, 100).unwrap();
    assert_eq!(
        audit.iter().map(|e| e.sequence_number).collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn budget_unknown_cancelled_or_partial_usage_retains_full_reservation() {
    let h = Harness::budget(20);
    h.repo
        .reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "mock",
            CostUsd::from_micro_usd(8),
            event(),
            &h.clock,
        )
        .unwrap();
    let partial = h
        .authority
        .settle_budget(
            identifier(1),
            SettlementStatus::UncertainPartial,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(partial.actual, None);
    assert_eq!(partial.state, "RESERVED");
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        8
    );
    let unknown = h
        .authority
        .settle_budget(
            identifier(1),
            SettlementStatus::CancelledUncertain,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(unknown.actual, None);
    assert_eq!(unknown.state, "CANCELLED");
    let delayed_partial = h
        .authority
        .settle_budget(
            identifier(1),
            SettlementStatus::UncertainPartial,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(delayed_partial.state, "CANCELLED");
    assert_eq!(delayed_partial.actual, None);
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        8
    );
    let final_usage = h
        .authority
        .settle_budget(
            identifier(1),
            SettlementStatus::CancelledWithUsage(CostUsd::from_micro_usd(3)),
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(final_usage.actual, Some(CostUsd::from_micro_usd(3)));
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        3
    );
    denied(
        h.authority.settle_budget(
            identifier(1),
            SettlementStatus::Completed(CostUsd::ZERO),
            event(),
            &h.clock,
        ),
        Kind::Conflict,
    );
    h.repo
        .reserve_budget(
            identifier(2),
            h.metadata.session_id,
            "unpriced",
            CostUsd::ZERO,
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(
        h.authority
            .settle_budget(
                identifier(2),
                SettlementStatus::CancelledUncertain,
                event(),
                &h.clock,
            )
            .unwrap()
            .actual,
        None
    );
}

#[test]
fn budget_overflow_invalid_values_overruns_and_unsafe_limit_reduction_are_denied() {
    let h = Harness::budget(10);
    denied(
        h.repo.reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "mock",
            CostUsd::from_micro_usd(u64::MAX),
            event(),
            &h.clock,
        ),
        Kind::InvalidValue,
    );
    denied(
        h.repo.reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "",
            CostUsd::ZERO,
            event(),
            &h.clock,
        ),
        Kind::InvalidValue,
    );
    h.repo
        .reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "mock",
            CostUsd::from_micro_usd(8),
            event(),
            &h.clock,
        )
        .unwrap();
    denied(
        h.authority.settle_budget(
            identifier(1),
            SettlementStatus::Completed(CostUsd::from_micro_usd(9)),
            event(),
            &h.clock,
        ),
        Kind::InvalidValue,
    );
    denied(
        h.authority.register_session(
            &h.metadata,
            "revision-B",
            Class::Public,
            CostUsd::from_micro_usd(7),
            event(),
            &h.clock,
        ),
        Kind::BudgetExceeded,
    );
    assert_eq!(
        h.repo
            .session(h.metadata.session_id)
            .unwrap()
            .unwrap()
            .context_generation,
        1
    );
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        8
    );
}

#[test]
fn budget_audit_failure_rolls_back_reservation_and_settlement() {
    let h = Harness::new();
    let duplicate = h.repo.audit_events(h.metadata.session_id, 0, 100).unwrap()[0].event_id;
    assert!(
        h.repo
            .reserve_budget(
                identifier(1),
                h.metadata.session_id,
                "mock",
                CostUsd::from_micro_usd(8),
                duplicate,
                &h.clock
            )
            .is_err()
    );
    assert_eq!(
        h.repo.budget_used(h.metadata.session_id).unwrap(),
        CostUsd::ZERO
    );
    h.repo
        .reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "mock",
            CostUsd::from_micro_usd(8),
            event(),
            &h.clock,
        )
        .unwrap();
    assert!(
        h.authority
            .settle_budget(
                identifier(1),
                SettlementStatus::Completed(CostUsd::from_micro_usd(2)),
                duplicate,
                &h.clock
            )
            .is_err()
    );
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        8
    );
    h.authority
        .settle_budget(
            identifier(1),
            SettlementStatus::Completed(CostUsd::from_micro_usd(2)),
            event(),
            &h.clock,
        )
        .unwrap();
}

#[test]
fn audit_retains_security_context_and_redacts_ordinary_diagnostics() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let audit = h.repo.audit_events(h.metadata.session_id, 0, 100).unwrap();
    let details: serde_json::Value = serde_json::from_str(&audit[1].details_json).unwrap();
    assert_eq!(details["context_generation"], 1);
    assert_eq!(details["target_revision"], "revision-A");
    assert_eq!(details["policy_id"], "synthetic-policy");
    let diagnostics = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?}",
        h.manager,
        h.repo,
        h.authority,
        grant,
        audit,
        h.repo.session(h.metadata.session_id).unwrap()
    );
    for secret in [
        "synthetic-policy",
        "synthetic-operator",
        "approved metadata A",
        "revision-A",
        "private workspace",
        "local-correlation",
    ] {
        assert!(!diagnostics.contains(secret));
    }
    denied(
        h.repo.audit_events(h.metadata.session_id, 0, 0),
        Kind::InvalidValue,
    );
    denied(
        h.repo.audit_events(h.metadata.session_id, 0, 1001),
        Kind::InvalidValue,
    );
}

#[test]
fn recovery_corrupt_database_fails_closed_and_preserves_original_bytes() {
    let h = Harness::new();
    h.manager.shutdown().unwrap();
    let mut original = fs::read(&h.dir.db).unwrap();
    original[0..16].fill(b'X');
    fs::write(&h.dir.db, &original).unwrap();
    let error = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap_err();
    assert_eq!(error.kind, Kind::Integrity);
    assert_eq!(fs::read(&h.dir.db).unwrap(), original);
    assert!(!format!("{error:?} {error}").contains("Sentra veri"));
}

#[test]
fn quarantine_halts_closes_and_preserves_db_wal_and_shm_in_place() {
    let h = Harness::new();
    let archive = h.dir.root.join("already-quarantined.db");
    fs::write(&archive, b"collision must survive").unwrap();
    let db = fs::read(&h.dir.db).unwrap();
    let wal = fs::read(h.dir.sidecar("-wal")).unwrap();
    assert!(!wal.is_empty());
    assert!(h.dir.sidecar("-shm").is_file());
    let report = h.manager.quarantine_in_place().unwrap();
    assert!(
        report.operations_halted && report.managed_connection_closed && report.preserved_in_place
    );
    assert_eq!(report.recovery_files_present, [true, true, true, false]);
    assert_eq!(fs::read(&h.dir.db).unwrap(), db);
    assert_eq!(fs::read(h.dir.sidecar("-wal")).unwrap(), wal);
    assert!(h.dir.sidecar("-shm").is_file());
    assert_eq!(fs::read(archive).unwrap(), b"collision must survive");
    denied(h.repo.session(h.metadata.session_id), Kind::Halted);
    // Explicit owner-controlled reopening, NOT automatic quarantine restoration.
    let manager = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
    let (repo, _) = PersistenceRepository::with_authority(manager.clone());
    assert!(repo.session(h.metadata.session_id).unwrap().is_some());
    manager.integrity_check().unwrap();
    manager.shutdown().unwrap();
}

#[test]
fn wal_long_lived_reader_blocks_shutdown_then_release_allows_truncation() {
    let h = Harness::new();
    let reader = Connection::open(&h.dir.db).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM sessions")
        .unwrap();
    h.repo
        .transition_session(
            h.metadata.session_id,
            SessionState::Created,
            SessionState::Scoped,
            event(),
            &h.clock,
        )
        .unwrap();
    denied(h.manager.shutdown(), Kind::CheckpointBusy);
    let progress = h.manager.last_checkpoint().unwrap().unwrap();
    assert!(progress.busy);
    assert!(fs::metadata(h.dir.sidecar("-wal")).unwrap().len() > 0);
    assert!(h.repo.session(h.metadata.session_id).unwrap().is_some());
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    h.manager.shutdown().unwrap();
    assert_eq!(
        fs::metadata(h.dir.sidecar("-wal"))
            .map(|m| m.len())
            .unwrap_or(0),
        0
    );
}

#[test]
fn busy_timeout_is_real_and_distinct_from_stale_snapshot() {
    let h = Harness::new();
    let writer = Connection::open(&h.dir.db).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    // Independent connection with the same mandatory timeout; production retry
    // termination is tested separately without spending five full 5-second waits.
    let contender = Connection::open(&h.dir.db).unwrap();
    contender.busy_timeout(Duration::from_millis(5000)).unwrap();
    let start = Instant::now();
    let error = contender.execute_batch("BEGIN IMMEDIATE").unwrap_err();
    assert_eq!(error.sqlite_error().unwrap().extended_code, 5);
    assert!(start.elapsed() >= Duration::from_millis(4500));
    writer.execute_batch("ROLLBACK").unwrap();
    h.repo
        .transition_session(
            h.metadata.session_id,
            SessionState::Created,
            SessionState::Scoped,
            event(),
            &h.clock,
        )
        .unwrap();
}

// Only the repository-owned test executable is launched, never a discovered file.
// Pipes form deterministic barriers; deadlines bound failed fixture execution.
struct OwnedWorker {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
}
impl OwnedWorker {
    fn start(d: &Directory, mode: &str, slot: u64, approval: Option<ApprovalId>) -> Self {
        use std::io::BufRead;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "owned_persistence_process_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SENTRA_OWNED_FIXTURE_DB", &d.db)
            .env("SENTRA_OWNED_FIXTURE_MODE", mode)
            .env("SENTRA_OWNED_FIXTURE_SLOT", slot.to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());
        if let Some(id) = approval {
            command.env("SENTRA_OWNED_FIXTURE_APPROVAL", id.to_string());
        }
        let mut child = command.spawn().unwrap();
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
    fn expect(&self, marker: &str) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(30))
                .expect("owned child protocol deadline");
            if line.contains(marker) {
                return line;
            }
        }
    }
    fn release(&mut self) {
        use std::io::Write;
        writeln!(self.child.stdin.as_mut().unwrap(), "GO").unwrap();
    }
    fn success(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(Instant::now() < deadline, "owned worker exit deadline");
            thread::yield_now();
        }
    }
    fn terminate(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.child.wait().unwrap().success());
    }
}
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn approval_cross_process_exactly_one_consumes_and_audit_is_atomic() {
    let h = Harness::new();
    let a = action();
    let grant = h.grant(&a);
    let mut first = OwnedWorker::start(&h.dir, "consume", 1, Some(grant.request_id()));
    let mut second = OwnedWorker::start(&h.dir, "consume", 2, Some(grant.request_id()));
    first.expect("SENTRA_FIXTURE_READY");
    second.expect("SENTRA_FIXTURE_READY");
    first.release();
    second.release();
    let outcomes = [
        first.expect("SENTRA_FIXTURE_RESULT="),
        second.expect("SENTRA_FIXTURE_RESULT="),
    ];
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
    let audit = h.repo.audit_events(h.metadata.session_id, 0, 100).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.event_kind == "ApprovalConsumed")
            .count(),
        1
    );
    assert!(
        audit
            .windows(2)
            .all(|w| w[1].sequence_number == w[0].sequence_number + 1)
    );
}

#[test]
fn recovery_real_process_termination_preserves_committed_and_discards_uncommitted() {
    let h = Harness::new();
    h.manager.shutdown().unwrap();
    let mut worker = OwnedWorker::start(&h.dir, "crash", 3, None);
    worker.expect("SENTRA_FIXTURE_READY");
    worker.terminate();
    let manager = SqliteConnectionManager::open(&h.dir.db, &h.clock).unwrap();
    let (repo, _) = PersistenceRepository::with_authority(manager.clone());
    assert_eq!(
        repo.session(h.metadata.session_id).unwrap().unwrap().state,
        SessionState::Scoped
    );
    let audit = repo.audit_events(h.metadata.session_id, 0, 100).unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[1].event_kind, "SessionTransition");
    manager.integrity_check().unwrap();
    manager.shutdown().unwrap();
}

#[test]
fn migration_real_process_interruption_leaves_fresh_database_recoverable() {
    let d = Directory::new();
    let mut worker = OwnedWorker::start(&d, "migration-crash", 4, None);
    worker.expect("SENTRA_FIXTURE_READY");
    worker.terminate();
    let manager = SqliteConnectionManager::open(&d.db, &clock()).unwrap();
    manager.integrity_check().unwrap();
    let raw = Connection::open(&d.db).unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM schema_migrations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    drop(raw);
    manager.shutdown().unwrap();
}

#[test]
fn budget_settlement_status_completed_releases_difference_and_finalizes() {
    let h = Harness::budget(20);
    h.repo
        .reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "mock",
            CostUsd::from_micro_usd(10),
            event(),
            &h.clock,
        )
        .unwrap();
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        10
    );

    // Settle with completed actual usage of 6 micro USD
    let status = SettlementStatus::Completed(CostUsd::from_micro_usd(6));
    assert_eq!(status.actual_cost(), Some(CostUsd::from_micro_usd(6)));
    assert!(!status.is_cancelled());
    assert!(status.is_terminal());

    let record = h
        .authority
        .settle_budget(identifier(1), status, event(), &h.clock)
        .unwrap();
    assert_eq!(record.state, "SETTLED");
    assert_eq!(record.actual, Some(CostUsd::from_micro_usd(6)));
    assert_eq!(record.reserved, CostUsd::from_micro_usd(10));

    // Budget used drops from 10 to 6 (4 released)
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        6
    );

    // Repeated settlement fails with Conflict
    denied(
        h.authority
            .settle_budget(identifier(1), status, event(), &h.clock),
        Kind::Conflict,
    );

    // Audit event was written
    let events = h.repo.audit_events(h.metadata.session_id, 0, 100).unwrap();
    let settle_event = events
        .iter()
        .find(|e| e.event_kind == "BudgetSettled")
        .unwrap();
    assert!(
        settle_event
            .details_json
            .contains("\"status\":\"COMPLETED\"")
    );
    assert!(
        settle_event
            .details_json
            .contains("\"final_usage_known\":true")
    );
}

#[test]
fn budget_settlement_status_cancelled_with_usage_and_helpers() {
    let h = Harness::budget(30);
    h.repo
        .reserve_budget(
            identifier(1),
            h.metadata.session_id,
            "mock",
            CostUsd::from_micro_usd(15),
            event(),
            &h.clock,
        )
        .unwrap();

    let status = SettlementStatus::CancelledWithUsage(CostUsd::from_micro_usd(5));
    assert_eq!(status.actual_cost(), Some(CostUsd::from_micro_usd(5)));
    assert!(status.is_cancelled());
    assert!(status.is_terminal());

    let record = h
        .authority
        .settle_budget(identifier(1), status, event(), &h.clock)
        .unwrap();
    assert_eq!(record.state, "CANCELLED");
    assert_eq!(record.actual, Some(CostUsd::from_micro_usd(5)));

    // Budget used is now 5 (10 released)
    assert_eq!(
        h.repo
            .budget_used(h.metadata.session_id)
            .unwrap()
            .as_micro_usd(),
        5
    );

    // Helper method checks for all variants
    let uncertain = SettlementStatus::CancelledUncertain;
    assert_eq!(uncertain.actual_cost(), None);
    assert!(uncertain.is_cancelled());
    assert!(uncertain.is_terminal());

    let partial = SettlementStatus::UncertainPartial;
    assert_eq!(partial.actual_cost(), None);
    assert!(!partial.is_cancelled());
    assert!(!partial.is_terminal());
}

#[test]
fn runtime_integrity_check_detects_foreign_key_violations_and_halts_manager() {
    let h = Harness::new();
    h.manager.integrity_check().unwrap();

    // Directly insert an orphan foreign-key violation with FK enforcement disabled
    let raw = Connection::open(&h.dir.db).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    // Non-existent session_id in audit_events violates FK to sessions
    let orphan_event_id = EventId::for_test_sequence(99_999).to_string();
    let dummy_session_id = Identifier::from_bytes([9u8; 16]).to_string();
    raw.execute(
        "INSERT INTO audit_events(event_id,session_id,sequence_number,event_kind,classification,timestamp,details_json) VALUES(?1,?2,999,'OrphanEvent','PUBLIC',?3,'{}')",
        params![orphan_event_id, dummy_session_id, h.clock.now().to_rfc3339()],
    )
    .unwrap();
    drop(raw);

    // Manager integrity check must detect the foreign key violation
    let err = h.manager.integrity_check().unwrap_err();
    assert_eq!(err.kind, Kind::ForeignKeyViolation);
    assert_eq!(err.sqlite_code, Some(1)); // exactly 1 violation

    // The manager is now halted; subsequent writes fail closed
    let write_result = h.repo.transition_session(
        h.metadata.session_id,
        SessionState::Created,
        SessionState::Scoped,
        event(),
        &h.clock,
    );
    assert_eq!(write_result.unwrap_err().kind, Kind::Halted);

    // Subsequent settings read also fails with Halted
    assert_eq!(h.manager.settings().unwrap_err().kind, Kind::Halted);
}

#[test]
fn detailed_integrity_check_reports_structured_fk_violations() {
    let h = Harness::new();
    let initial_report: IntegrityReport = h.manager.detailed_integrity_check().unwrap();
    assert!(initial_report.integrity_ok);
    assert!(initial_report.foreign_key_violations.is_empty());
    assert!(initial_report.is_valid());

    // Inject two foreign key violations across different tables with FK disabled
    let raw = Connection::open(&h.dir.db).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    let dummy_session_id = Identifier::from_bytes([7u8; 16]).to_string();
    raw.execute(
        "INSERT INTO budget_reservations(reservation_id,session_id,model_id,reserved_cost_micro_usd,state,reserved_at) VALUES(?1,?2,'orphan-model',500,'RESERVED',?3)",
        params![identifier(99).to_string(), dummy_session_id, h.clock.now().to_rfc3339()],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO session_security_snapshots(session_id,context_generation,project_root,operator_id,policy_id,registered_at,snapshot_json) VALUES(?1,1,'/orphan','op','pol',?2,'{}')",
        params![dummy_session_id, h.clock.now().to_rfc3339()],
    )
    .unwrap();
    drop(raw);

    // Detailed integrity check must return structured report with both violations
    let report: IntegrityReport = h.manager.detailed_integrity_check().unwrap();
    assert!(report.integrity_ok);
    assert_eq!(report.foreign_key_violations.len(), 2);
    assert!(!report.is_valid());

    let first: &ForeignKeyViolation = &report.foreign_key_violations[0];
    assert_eq!(first.parent, "sessions");

    let tables: Vec<&str> = report
        .foreign_key_violations
        .iter()
        .map(|v| v.table.as_str())
        .collect();
    assert!(tables.contains(&"budget_reservations"));
    assert!(tables.contains(&"session_security_snapshots"));

    for violation in &report.foreign_key_violations {
        assert_eq!(violation.parent, "sessions");
    }

    // Detailed integrity check halts the manager when violations exist
    assert_eq!(h.manager.integrity_check().unwrap_err().kind, Kind::Halted);
}

#[test]
fn open_database_with_existing_foreign_key_violation_fails_closed() {
    let d = Directory::new();
    let manager = SqliteConnectionManager::open(&d.db, &clock()).unwrap();
    manager.shutdown().unwrap();

    // With connection closed, corrupt the foreign key relational integrity
    let raw = Connection::open(&d.db).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    let dummy_session = Identifier::from_bytes([5u8; 16]).to_string();
    raw.execute(
        "INSERT INTO audit_events(event_id,session_id,sequence_number,event_kind,classification,timestamp,details_json) VALUES(?1,?2,1,'Corrupt','PUBLIC',?3,'{}')",
        params![
            EventId::for_test_sequence(88_888).to_string(),
            dummy_session,
            clock().now().to_rfc3339()
        ],
    )
    .unwrap();
    drop(raw);

    // Opening the corrupted database must fail closed with ForeignKeyViolation
    let open_result = SqliteConnectionManager::open(&d.db, &clock());
    match open_result {
        Err(err) => {
            assert_eq!(err.kind, Kind::ForeignKeyViolation);
            assert_eq!(err.sqlite_code, Some(1));
        }
        Ok(_) => panic!("expected open to fail on foreign key violation"),
    }
}

#[test]
#[ignore = "Owned subprocess helper; the three parent tests execute it with explicit fixture pipes"]
fn owned_persistence_process_worker() {
    use std::{
        io::{BufRead, Write},
        str::FromStr,
    };
    let db = std::path::PathBuf::from(
        std::env::var_os("SENTRA_OWNED_FIXTURE_DB").expect("owned fixture only"),
    );
    // Refuse arbitrary input even when this helper is invoked manually.
    let allowed = fs::canonicalize(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/persistence-fixtures"),
    )
    .unwrap();
    assert!(
        fs::canonicalize(db.parent().unwrap())
            .unwrap()
            .starts_with(allowed)
    );
    let mode = std::env::var("SENTRA_OWNED_FIXTURE_MODE").unwrap();
    let slot: u64 = std::env::var("SENTRA_OWNED_FIXTURE_SLOT")
        .unwrap()
        .parse()
        .unwrap();
    let c = clock();
    let m = metadata();
    if mode == "migration-crash" {
        let db = Connection::open(db).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;BEGIN IMMEDIATE")
            .unwrap();
        // Interrupt the actual embedded migration DDL before its metadata/commit.
        db.execute_batch(include_str!("../src/persistence/schema_v1.sql"))
            .unwrap();
        println!("SENTRA_FIXTURE_READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();
        panic!("parent must terminate fixture");
    }
    let manager = SqliteConnectionManager::open(&db, &c).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
    if mode == "crash" {
        repo.transition_session(
            m.session_id,
            SessionState::Created,
            SessionState::Scoped,
            EventId::for_test_sequence(50_000 + slot * 100),
            &c,
        )
        .unwrap();
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("BEGIN IMMEDIATE;UPDATE sessions SET state='PLANNED'")
            .unwrap();
        raw.execute("INSERT INTO audit_events(event_id,session_id,sequence_number,event_kind,classification,timestamp,details_json) VALUES(?1,?2,3,'Uncommitted','PUBLIC',?3,'{}')",
            params![EventId::for_test_sequence(50_001+slot*100).to_string(),m.session_id.to_string(),c.now().to_rfc3339()]).unwrap();
        println!("SENTRA_FIXTURE_READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();
        panic!("parent must terminate fixture");
    }
    assert_eq!(mode, "consume");
    let id =
        Identifier::from_str(&std::env::var("SENTRA_OWNED_FIXTURE_APPROVAL").unwrap()).unwrap();
    let id = ApprovalId::from_bytes(*id.as_bytes());
    let a = action();
    let grant = authority
        .recover_issued_grant(
            id,
            &intent(&m, &a),
            "owned-process-controller",
            EventId::for_test_sequence(50_000 + slot * 100),
            &c,
        )
        .unwrap();
    println!("SENTRA_FIXTURE_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "GO");
    let result = repo.consume_approval(
        &grant,
        &intent(&m, &a),
        EventId::for_test_sequence(50_001 + slot * 100),
        &c,
    );
    println!(
        "SENTRA_FIXTURE_RESULT={}",
        match result {
            Ok(_) => "Consumed".into(),
            Err(error) => format!("{:?}", error.kind),
        }
    );
    manager.quarantine_in_place().unwrap();
}
