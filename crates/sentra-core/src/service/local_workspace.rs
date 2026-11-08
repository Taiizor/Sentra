//! Local project initialization/inspection. No terminal, target content or execution.

use std::{fmt, fs, path::Path, sync::Arc};

use crate::{
    CostUsd, FailClosedBackend, OperatingMode, PolicyEngine, SecurityClassification, SessionId,
    SessionState, SystemClock, TimestampUtc,
    persistence::{PersistenceError, PersistenceRepository, SqliteConnectionManager},
    workspace::WorkspaceBoundary,
};

use super::{CoreService, CoreServiceConfig, ServiceError};

/// Payload-free local lifecycle failure category. Infrastructure failures are not
/// policy denials and an incomplete store is never silently adopted or repaired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalWorkspaceErrorKind {
    /// Workspace validation failed, including indirections or inaccessible roots.
    Workspace,
    /// Storage must have an existing ordinary parent outside the target root.
    StorageLocation,
    /// Database, locking, integrity or checkpoint operation failed.
    Persistence,
    /// Existing store is empty, ambiguous or has an unfinished initial session.
    Incomplete,
    /// The existing project belongs to a different canonical workspace.
    WorkspaceMismatch,
    /// The requested session is not the local project's session.
    SessionNotFound,
    /// Core service creation or inspection failed; inspect its typed source.
    Service,
}

/// Typed, redacted lifecycle error, including a distinct shutdown failure when
/// cleanup itself fails. No path, raw SQLite text or target data is retained.
#[derive(Debug)]
pub struct LocalWorkspaceError {
    /// Stable failure category.
    pub kind: LocalWorkspaceErrorKind,
    persistence: Option<PersistenceError>,
    service: Option<Box<ServiceError>>,
    shutdown: Option<PersistenceError>,
}

impl LocalWorkspaceError {
    fn new(kind: LocalWorkspaceErrorKind) -> Self {
        Self {
            kind,
            persistence: None,
            service: None,
            shutdown: None,
        }
    }
    fn persistence(error: PersistenceError) -> Self {
        Self {
            persistence: Some(error),
            ..Self::new(LocalWorkspaceErrorKind::Persistence)
        }
    }
    fn service(error: ServiceError) -> Self {
        Self {
            service: Some(Box::new(error)),
            ..Self::new(LocalWorkspaceErrorKind::Service)
        }
    }
    /// Original typed infrastructure failure, when available.
    pub fn persistence_error(&self) -> Option<&PersistenceError> {
        self.persistence.as_ref()
    }
    /// Original typed Core failure, when available.
    pub fn service_error(&self) -> Option<&ServiceError> {
        self.service.as_deref()
    }
    /// Secondary checkpoint/close failure; never substitutes for a primary error.
    pub fn shutdown_error(&self) -> Option<&PersistenceError> {
        self.shutdown.as_ref()
    }
}

impl fmt::Display for LocalWorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local workspace operation failed ({:?})", self.kind)
    }
}
impl std::error::Error for LocalWorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.persistence {
            Some(error)
        } else {
            self.service
                .as_deref()
                .map(|e| e as &(dyn std::error::Error + 'static))
        }
    }
}

/// Bounded, deliberately redacted local session projection. Project identity is
/// its persisted foundation SessionId, not a new independent identity registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSessionSummary {
    /// Stable identity; does not authenticate a caller or grant permission.
    pub session_id: SessionId,
    /// Current persisted lifecycle state.
    pub state: SessionState,
    /// Registered context generation; not a source-content digest.
    pub context_generation: u64,
    /// Session classification floor.
    pub classification_floor: SecurityClassification,
    /// Session creation time.
    pub created_at: TimestampUtc,
    /// Fixed-point budget ceiling.
    pub budget_limit: CostUsd,
    /// Reserved/known usage, including conservative uncertain holds.
    pub budget_used: CostUsd,
}

/// Result only returned after required shutdown/checkpoint succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWorkspaceReport {
    /// True only for a valid, bound persisted session.
    pub initialized: bool,
    /// True only when this invocation created the foundation session.
    pub created: bool,
    /// Absent for an uninitialized workspace/storage selection.
    pub session: Option<LocalSessionSummary>,
}

enum Operation {
    Initialize,
    Status,
    Session(SessionId),
    Recover,
}

/// Interface-neutral local lifecycle facade. Paths are explicit, storage is
/// external to the selected workspace, and only existing Core/persistence
/// abstractions can change domain records. No execution/approval API is exposed.
pub struct LocalWorkspace;

impl LocalWorkspace {
    /// Initialize a new dedicated store or return its unchanged existing identity.
    /// Existing empty/incomplete/unrelated databases and orphan sidecars deny.
    pub fn initialize(
        workspace: &Path,
        database: &Path,
    ) -> Result<LocalWorkspaceReport, LocalWorkspaceError> {
        Self::run(workspace, database, Operation::Initialize)
    }
    /// Inspect domain state without creating a database or changing domain rows.
    /// Existing SQLite recovery, PRAGMAs, lock files and checkpointing still apply.
    pub fn status(
        workspace: &Path,
        database: &Path,
    ) -> Result<LocalWorkspaceReport, LocalWorkspaceError> {
        Self::run(workspace, database, Operation::Status)
    }
    /// Inspect exactly the selected local session; no lifecycle changes.
    pub fn session(
        workspace: &Path,
        database: &Path,
        id: SessionId,
    ) -> Result<LocalWorkspaceReport, LocalWorkspaceError> {
        Self::run(workspace, database, Operation::Session(id))
    }
    /// Explicitly recovers an interrupted or incomplete foundation store.
    /// Safely completes incomplete initialization without manual file deletion.
    pub fn recover(
        workspace: &Path,
        database: &Path,
    ) -> Result<LocalWorkspaceReport, LocalWorkspaceError> {
        Self::run(workspace, database, Operation::Recover)
    }

    fn run(
        workspace: &Path,
        database: &Path,
        operation: Operation,
    ) -> Result<LocalWorkspaceReport, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        let boundary = WorkspaceBoundary::establish(
            workspace,
            SessionId::new(),
            SecurityClassification::Internal,
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;
        let parent = database
            .parent()
            .ok_or_else(|| LocalWorkspaceError::new(Kind::StorageLocation))?;
        let storage = WorkspaceBoundary::establish(
            parent,
            SessionId::new(),
            SecurityClassification::Internal,
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::StorageLocation))?;
        // Component containment of filesystem-canonical paths, never string prefixes.
        if storage
            .root()
            .canonical_path()
            .starts_with(boundary.root().canonical_path())
        {
            return Err(LocalWorkspaceError::new(Kind::StorageLocation));
        }
        let _admission = SqliteConnectionManager::local_context_admission(database)
            .map_err(LocalWorkspaceError::persistence)?;
        let present = exists(database)?;
        if !present {
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut name = database.as_os_str().to_os_string();
                name.push(suffix);
                if exists(Path::new(&name))? {
                    return Err(LocalWorkspaceError::new(Kind::Incomplete));
                }
            }
            if !matches!(operation, Operation::Initialize) {
                if matches!(operation, Operation::Session(_)) {
                    return Err(LocalWorkspaceError::new(Kind::SessionNotFound));
                }
                if matches!(operation, Operation::Recover) {
                    return Err(LocalWorkspaceError::new(Kind::Incomplete));
                }
                return Ok(LocalWorkspaceReport {
                    initialized: false,
                    created: false,
                    session: None,
                });
            }
        }
        let clock = Arc::new(SystemClock::new());
        let manager = if present {
            SqliteConnectionManager::open_existing(database, &clock)
        } else {
            SqliteConnectionManager::open(database, &clock)
        }
        .map_err(LocalWorkspaceError::persistence)?;
        let (repository, authority) = PersistenceRepository::with_authority(manager.clone());
        let service = CoreService::new(
            CoreServiceConfig::default(),
            repository,
            authority,
            PolicyEngine::new(),
            Arc::new(FailClosedBackend::new()),
            clock,
        );
        let result = (|| {
            if !present {
                let root = boundary
                    .root()
                    .canonical_path()
                    .to_str()
                    .ok_or_else(|| LocalWorkspaceError::new(Kind::Workspace))?;
                // This is a foundation record, not a Git/content snapshot or research
                // workflow. No paid operation is implicitly budget-authorized.
                service
                    .create_session(
                        root,
                        OperatingMode::ContinuousReview,
                        "local-operator",
                        SecurityClassification::Internal,
                        "local:unversioned-metadata-only",
                        CostUsd::ZERO,
                    )
                    .map_err(LocalWorkspaceError::service)?;
            }

            let session_cnt = service.session_count().unwrap_or(0);
            let record_opt = match service.local_session() {
                Ok(rec) => Some(rec),
                Err(error) => {
                    let mut result = LocalWorkspaceError::service(error);
                    if matches!(
                        result.service_error().and_then(|e| e.primary_error()),
                        Some(super::ServicePrimaryError::Persistence(p))
                            if p.kind == crate::persistence::PersistenceErrorKind::ContextMismatch
                    ) {
                        result.kind = Kind::Incomplete;
                    }
                    if matches!(operation, Operation::Recover) && session_cnt == 0 {
                        None
                    } else {
                        return Err(result);
                    }
                }
            };

            let was_missing_session = record_opt.is_none();
            let mut record = match record_opt {
                Some(rec) => rec,
                None => {
                    let root = boundary
                        .root()
                        .canonical_path()
                        .to_str()
                        .ok_or_else(|| LocalWorkspaceError::new(Kind::Workspace))?;
                    service
                        .create_session(
                            root,
                            OperatingMode::ContinuousReview,
                            "local-operator",
                            SecurityClassification::Internal,
                            "local:unversioned-metadata-only",
                            CostUsd::ZERO,
                        )
                        .map_err(LocalWorkspaceError::service)?;
                    service
                        .local_session()
                        .map_err(LocalWorkspaceError::service)?
                }
            };

            if record.state == SessionState::Created {
                if matches!(operation, Operation::Recover) {
                    service
                        .transition_session(
                            record.metadata.session_id,
                            SessionState::Scoped,
                            "operator-recovery-complete-foundation",
                        )
                        .map_err(LocalWorkspaceError::service)?;
                    record = service
                        .local_session()
                        .map_err(LocalWorkspaceError::service)?;
                } else {
                    return Err(LocalWorkspaceError::new(Kind::Incomplete));
                }
            }

            if Path::new(&record.metadata.workspace_root) != boundary.root().canonical_path() {
                return Err(LocalWorkspaceError::new(Kind::WorkspaceMismatch));
            }
            if let Operation::Session(id) = operation
                && id != record.metadata.session_id
            {
                return Err(LocalWorkspaceError::new(Kind::SessionNotFound));
            }
            let budget_used = service
                .budget_used(record.metadata.session_id)
                .map_err(LocalWorkspaceError::service)?;
            Ok(LocalWorkspaceReport {
                initialized: true,
                created: !present
                    || (matches!(operation, Operation::Recover) && was_missing_session),
                session: Some(LocalSessionSummary {
                    session_id: record.metadata.session_id,
                    state: record.state,
                    context_generation: record.context_generation,
                    classification_floor: record.classification_floor,
                    created_at: record.metadata.created_at_utc,
                    budget_limit: record.budget_limit,
                    budget_used,
                }),
            })
        })();
        match (result, manager.shutdown()) {
            (Ok(report), Ok(_)) => Ok(report),
            (Err(error), Ok(_)) => Err(error),
            (Ok(_), Err(error)) => Err(LocalWorkspaceError::persistence(error)),
            (Err(mut primary), Err(secondary)) => {
                primary.shutdown = Some(secondary);
                Err(primary)
            }
        }
    }
}

fn exists(path: &Path) -> Result<bool, LocalWorkspaceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LocalWorkspaceError::new(
            LocalWorkspaceErrorKind::StorageLocation,
        )),
    }
}
