//! Internal CLI-ready test harness for deterministic, offline Core Service testing.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    CostUsd, ExecutionBackend, ExecutionScope, MockClock, OperatingMode, OperationAction,
    PolicyEngine, SecurityClassification, SessionId, SyntheticFixtureBackend, TaskId, TimestampUtc,
    persistence::{PersistenceRepository, SqliteConnectionManager},
    service::{
        config::CoreServiceConfig,
        core::{CoreService, TaskExecutionReport},
        error::ServiceError,
    },
};

static HARNESS_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Fixture directory managing an isolated temporary SQLite database and workspace.
#[derive(Debug)]
pub struct HarnessDirectory {
    /// Workspace root directory.
    pub workspace_root: PathBuf,
    /// SQLite database path.
    pub db_path: PathBuf,
    base_dir: PathBuf,
}

impl HarnessDirectory {
    /// Creates a new isolated harness directory under `target/service-fixtures`.
    pub fn new() -> Self {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let base_dir = PathBuf::from(manifest_dir).join("../../target/service-fixtures");
        fs::create_dir_all(&base_dir).expect("failed to create base harness directory");
        let base_dir = fs::canonicalize(base_dir).expect("failed to canonicalize base directory");

        let id = HARNESS_COUNTER.fetch_add(1, Ordering::Relaxed);
        let run_dir = base_dir.join(format!("harness-{}-{}", std::process::id(), id));
        fs::create_dir(&run_dir).expect("failed to create harness run directory");

        let workspace_root = run_dir.join("workspace");
        fs::create_dir(&workspace_root).expect("failed to create harness workspace root");

        let db_path = run_dir.join("sentra_service.db");

        Self {
            workspace_root,
            db_path,
            base_dir,
        }
    }
}

impl Default for HarnessDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HarnessDirectory {
    fn drop(&mut self) {
        if let Ok(root) = fs::canonicalize(&self.workspace_root) {
            let parent = root.parent().unwrap_or(&root);
            if parent.starts_with(&self.base_dir) && parent != self.base_dir {
                let _ = fs::remove_dir_all(parent);
            }
        }
    }
}

/// Unified, CLI-ready test harness orchestrating end-to-end Core Service workflows.
pub struct CoreServiceHarness {
    /// Managed directory holding workspace and database.
    pub dir: HarnessDirectory,
    /// Integrated Core Service instance.
    pub service: CoreService,
    /// Controlled mock clock for deterministic time travel.
    pub clock: Arc<MockClock>,
}

impl CoreServiceHarness {
    /// Initializes a harness with `SyntheticFixtureBackend` and default configuration.
    pub fn new_synthetic() -> Self {
        Self::with_backend(Arc::new(SyntheticFixtureBackend::new()))
    }

    /// Initializes a harness with default `FailClosedBackend`.
    pub fn new_fail_closed() -> Self {
        Self::with_backend(Arc::new(crate::FailClosedBackend::new()))
    }

    /// Initializes a harness with a custom execution backend.
    pub fn with_backend(backend: Arc<dyn ExecutionBackend>) -> Self {
        let dir = HarnessDirectory::new();
        let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
        let manager = SqliteConnectionManager::open(&dir.db_path, clock.as_ref())
            .expect("failed to open harness SQLite database");
        let (repository, authority) = PersistenceRepository::with_authority(manager);

        let policy_engine = PolicyEngine::new();
        let config = CoreServiceConfig::default();

        let service = CoreService::new(
            config,
            repository,
            authority,
            policy_engine,
            backend,
            clock.clone(),
        );

        Self {
            dir,
            service,
            clock,
        }
    }

    /// Helper to create a standard session in continuous review mode.
    pub fn create_standard_session(&self) -> Result<SessionId, ServiceError> {
        let root_str = self
            .dir
            .workspace_root
            .to_str()
            .expect("valid unicode path");
        self.service.create_session(
            root_str,
            OperatingMode::ContinuousReview,
            "operator-test",
            SecurityClassification::Internal,
            "commit-abc12345",
            CostUsd::from_micro_usd(10_000_000), // $10.00
        )
    }

    /// Helper to execute a synthetic noop tool.
    pub fn execute_synthetic_noop(
        &self,
        session_id: SessionId,
    ) -> Result<TaskExecutionReport, ServiceError> {
        let task_id = TaskId::for_test_sequence(1);
        let action = OperationAction::ExecuteTool {
            tool_id: "synthetic:noop".to_string(),
            untrusted: false,
            arguments: vec![],
        };

        // ExecuteTool is sensitive, so request and issue an approval grant
        let approval_id =
            self.service
                .request_approval(session_id, &action, SecurityClassification::Internal)?;
        let grant = self.service.issue_approval(
            session_id,
            approval_id,
            &action,
            SecurityClassification::Internal,
        )?;

        self.service
            .execute_task(crate::service::TaskExecutionRequest {
                session_id,
                task_id,
                scope: ExecutionScope::SyntheticFixture,
                action,
                classification: SecurityClassification::Internal,
                resource_limits: None,
                estimated_cost: CostUsd::from_micro_usd(100_000), // $0.10
                grant: Some(grant),
                evidence_envelopes: vec![],
            })
    }

    /// Helper to create a dummy file inside the workspace for discovery testing.
    pub fn write_workspace_file(&self, relative_path: impl AsRef<Path>, content: &[u8]) {
        let full_path = self.dir.workspace_root.join(relative_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("failed to create parent directories");
        }
        fs::write(full_path, content).expect("failed to write workspace file");
    }
}
