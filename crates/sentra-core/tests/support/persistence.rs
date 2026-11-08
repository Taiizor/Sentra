//! Owned synthetic fixtures only; no target repository content is read or run.
#![allow(dead_code)]
use sentra_core::{
    ApprovalId, Clock, CostUsd, EventId, Identifier, MockClock, OperatingMode, OperationAction,
    SecurityClassification as Class, SessionId, SessionMetadata, TimestampUtc,
    persistence::{
        ApprovalIntent, PersistenceRepository, PersistentApprovalAuthority,
        PersistentApprovalGrant, SqliteConnectionManager,
    },
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);
static EVENT: AtomicU64 = AtomicU64::new(1);

pub fn event() -> EventId {
    EventId::for_test_sequence(EVENT.fetch_add(1, Ordering::Relaxed))
}
pub fn identifier(value: u64) -> Identifier {
    Identifier::new_deterministic(542, value)
}
pub fn clock() -> MockClock {
    MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000))
}
pub fn metadata() -> SessionMetadata {
    SessionMetadata::new(
        SessionId::for_test_sequence(542),
        clock().now(),
        "E:/synthetic/private workspace",
        OperatingMode::ContinuousReview,
        "synthetic-operator",
        "synthetic-policy",
    )
    .unwrap()
}
pub fn action() -> OperationAction {
    OperationAction::DiscoverMetadata {
        relative_path: "approved metadata A".into(),
    }
}
pub fn intent<'a>(
    metadata: &'a SessionMetadata,
    action: &'a OperationAction,
) -> ApprovalIntent<'a> {
    ApprovalIntent {
        session: metadata,
        context_generation: 1,
        target_revision: "revision-A",
        classification: Class::Restricted,
        action,
    }
}

pub struct Directory {
    pub root: PathBuf,
    pub db: PathBuf,
    base: PathBuf,
}
impl Directory {
    pub fn new() -> Self {
        let base =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/persistence-fixtures");
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let root = base.join(format!(
            "owned-{}-{} Unicode İstanbul 日本語",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self {
            db: root.join("Sentra veri 日本語.db"),
            root,
            base,
        }
    }
    pub fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut path = self.db.as_os_str().to_os_string();
        path.push(suffix);
        path.into()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Both resolved targets are checked before the owned recursive cleanup.
        if let Ok(root) = fs::canonicalize(&self.root) {
            assert!(root.starts_with(&self.base) && root != self.base);
            if let Err(error) = fs::remove_dir_all(root) {
                assert!(
                    std::thread::panicking(),
                    "owned fixture cleanup failed: {error}"
                );
            }
        }
    }
}

pub struct Harness {
    pub repo: PersistenceRepository,
    pub authority: PersistentApprovalAuthority,
    pub manager: SqliteConnectionManager,
    pub metadata: SessionMetadata,
    pub clock: MockClock,
    pub dir: Directory,
}
impl Harness {
    pub fn new() -> Self {
        Self::budget(100)
    }
    pub fn budget(limit: u64) -> Self {
        let dir = Directory::new();
        let clock = clock();
        let metadata = metadata();
        let manager = SqliteConnectionManager::open(&dir.db, &clock).unwrap();
        let (repo, authority) = PersistenceRepository::with_authority(manager.clone());
        authority
            .register_session(
                &metadata,
                "revision-A",
                Class::Public,
                CostUsd::from_micro_usd(limit),
                event(),
                &clock,
            )
            .unwrap();
        Self {
            repo,
            authority,
            manager,
            metadata,
            clock,
            dir,
        }
    }
    pub fn grant(&self, action: &OperationAction) -> PersistentApprovalGrant {
        let id = ApprovalId::for_test_sequence(EVENT.fetch_add(1, Ordering::Relaxed));
        let intent = intent(&self.metadata, action);
        self.repo
            .request_approval(id, &intent, event(), &self.clock)
            .unwrap();
        self.authority
            .issue_grant(id, &intent, "synthetic-controller", event(), &self.clock)
            .unwrap()
    }
    pub fn audit_count(&self) -> usize {
        self.repo
            .audit_events(self.metadata.session_id, 0, 1000)
            .unwrap()
            .len()
    }
}
