//! Local project initialization/inspection. No terminal, target content or execution.

use std::{fmt, fs, path::Path, sync::Arc};

use crate::{
    Clock, CostUsd, EventId, FailClosedBackend, Finding, OperatingMode, PolicyEngine,
    SecurityClassification, SessionId, SessionState, SystemClock, TaskId, TimestampUtc,
    advisory::{
        AdvisoryAuditResult, AdvisoryDatabase, discover_workspace_lockfiles, parse_cargo_lock,
        parse_lockfile_content,
    },
    diff::{SnapshotDiff, compare_snapshots},
    manifest::{SnapshotLimits, capture_source_snapshot},
    persistence::{PersistenceError, PersistenceRepository, SqliteConnectionManager, TaskState},
    sast::{SastReport, SastScanner},
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

/// Result returned after running an advisory dependency audit on the workspace (Requirement F-07).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAuditReport {
    /// Associated session identifier.
    pub session_id: SessionId,
    /// Task identifier assigned to this audit.
    pub task_id: TaskId,
    /// Consolidated audit result.
    pub audit_result: AdvisoryAuditResult,
    /// Authoritative candidate findings.
    pub candidate_findings: Vec<Finding>,
}

/// Result returned after running a SAST and secret code scan on the workspace (Requirement F-05).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalScanReport {
    /// Associated session identifier.
    pub session_id: SessionId,
    /// Task identifier assigned to this scan.
    pub task_id: TaskId,
    /// SAST report details.
    pub sast_report: SastReport,
    /// Authoritative candidate findings.
    pub candidate_findings: Vec<Finding>,
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
    /// Derives differential snapshot analysis between two workspaces (REQ-F01, REQ-F02).
    /// Pure-Rust directory comparison with lexical boundary containment and zero subprocess spawning.
    pub fn diff(base: &Path, head: &Path) -> Result<SnapshotDiff, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        let base_boundary =
            WorkspaceBoundary::establish(base, SessionId::new(), SecurityClassification::Internal)
                .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        let head_boundary =
            WorkspaceBoundary::establish(head, SessionId::new(), SecurityClassification::Internal)
                .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        let clock = SystemClock::new();
        let limits = SnapshotLimits::default();
        let base_snapshot = capture_source_snapshot(&base_boundary, &limits, &clock)
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;
        let head_snapshot = capture_source_snapshot(&head_boundary, &limits, &clock)
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        Ok(compare_snapshots(&base_snapshot, &head_snapshot))
    }

    /// Explicitly recovers an interrupted or incomplete foundation store.
    /// Safely completes incomplete initialization without manual file deletion.
    pub fn recover(
        workspace: &Path,
        database: &Path,
    ) -> Result<LocalWorkspaceReport, LocalWorkspaceError> {
        Self::run(workspace, database, Operation::Recover)
    }

    /// Runs a dependency security advisory audit against the workspace's Cargo.lock (Requirement F-07).
    pub fn audit_dependencies(
        workspace: &Path,
        database: &Path,
        advisory_db: &AdvisoryDatabase,
    ) -> Result<LocalAuditReport, LocalWorkspaceError> {
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
            return Err(LocalWorkspaceError::new(Kind::Incomplete));
        }

        let clock = Arc::new(SystemClock::new());
        let manager = SqliteConnectionManager::open_existing(database, &clock)
            .map_err(LocalWorkspaceError::persistence)?;
        let (repository, authority) = PersistenceRepository::with_authority(manager.clone());
        let service = CoreService::new(
            CoreServiceConfig::default(),
            repository.clone(),
            authority,
            PolicyEngine::new(),
            Arc::new(FailClosedBackend::new()),
            clock.clone(),
        );

        let record = service
            .local_session()
            .map_err(LocalWorkspaceError::service)?;

        if record.state == SessionState::Created {
            return Err(LocalWorkspaceError::new(Kind::Incomplete));
        }
        if Path::new(&record.metadata.workspace_root) != boundary.root().canonical_path() {
            return Err(LocalWorkspaceError::new(Kind::WorkspaceMismatch));
        }

        let discovered_lockfiles = discover_workspace_lockfiles(boundary.root().canonical_path());
        let mut packages = Vec::new();
        let mut primary_lockfile = "Cargo.lock".to_string();

        if !discovered_lockfiles.is_empty() {
            primary_lockfile = discovered_lockfiles[0].1.clone();
            for (kind, filename) in &discovered_lockfiles {
                let lock_path = boundary.root().canonical_path().join(filename);
                if let Ok(content) = fs::read_to_string(&lock_path)
                    && let Ok(pkgs) = parse_lockfile_content(*kind, &content)
                {
                    packages.extend(pkgs);
                }
            }
        } else {
            let lock_path = boundary.root().canonical_path().join("Cargo.lock");
            if lock_path.is_file() {
                let content = fs::read_to_string(&lock_path)
                    .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;
                packages = parse_cargo_lock(&content)
                    .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;
            }
        }

        let now = clock.now();
        let audit_result = advisory_db
            .audit_packages(&packages, now, 30)
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        let task_id = TaskId::new();
        let existing_tasks = repository
            .list_tasks(record.metadata.session_id)
            .map_err(LocalWorkspaceError::persistence)?;
        let sequence_number = (existing_tasks.len() as u64) + 1;

        let task_title = format!("{primary_lockfile} Dependency Advisory Audit");
        repository
            .create_task(
                record.metadata.session_id,
                task_id,
                sequence_number,
                &task_title,
                &*clock,
            )
            .map_err(LocalWorkspaceError::persistence)?;

        repository
            .update_task_state(
                task_id,
                TaskState::Pending,
                TaskState::InProgress,
                EventId::new(),
                &*clock,
            )
            .map_err(LocalWorkspaceError::persistence)?;

        repository
            .update_task_state(
                task_id,
                TaskState::InProgress,
                TaskState::Completed,
                EventId::new(),
                &*clock,
            )
            .map_err(LocalWorkspaceError::persistence)?;

        let candidate_findings = audit_result.to_candidate_findings_for_lockfile(
            record.metadata.session_id,
            task_id,
            now,
            &primary_lockfile,
        );

        let report = LocalAuditReport {
            session_id: record.metadata.session_id,
            task_id,
            audit_result,
            candidate_findings,
        };

        match manager.shutdown() {
            Ok(_) => Ok(report),
            Err(error) => Err(LocalWorkspaceError::persistence(error)),
        }
    }

    /// Exports dependency security advisory audit results to an OASIS SARIF v2.1.0 document (REQ-F07, EXTENSIONS.md).
    pub fn export_audit_sarif(
        workspace: &Path,
        database: &Path,
        advisory_db: &AdvisoryDatabase,
    ) -> Result<String, LocalWorkspaceError> {
        let report = Self::audit_dependencies(workspace, database, advisory_db)?;
        crate::export::export_audit_to_sarif_json(&report, env!("CARGO_PKG_VERSION"))
            .map_err(|_| LocalWorkspaceError::new(LocalWorkspaceErrorKind::Service))
    }

    /// Scans workspace source files for secrets and code antipatterns directly without persistence.
    pub fn scan_source_direct(workspace: &Path) -> Result<SastReport, LocalWorkspaceError> {
        let boundary = WorkspaceBoundary::establish(
            workspace,
            SessionId::new(),
            SecurityClassification::Internal,
        )
        .map_err(|_| LocalWorkspaceError::new(LocalWorkspaceErrorKind::Workspace))?;

        let scanner = SastScanner::new();
        scanner
            .scan_workspace(boundary.root().canonical_path())
            .map_err(|_| LocalWorkspaceError::new(LocalWorkspaceErrorKind::Workspace))
    }

    /// Scans workspace source files for secrets and code antipatterns with authoritative session persistence.
    pub fn scan_source(
        workspace: &Path,
        database: &Path,
    ) -> Result<LocalScanReport, LocalWorkspaceError> {
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
            return Err(LocalWorkspaceError::new(Kind::Incomplete));
        }

        let clock = Arc::new(SystemClock::new());
        let manager = SqliteConnectionManager::open_existing(database, &clock)
            .map_err(LocalWorkspaceError::persistence)?;
        let (repository, authority) = PersistenceRepository::with_authority(manager.clone());
        let service = CoreService::new(
            CoreServiceConfig::default(),
            repository.clone(),
            authority,
            PolicyEngine::new(),
            Arc::new(FailClosedBackend::new()),
            clock.clone(),
        );

        let record = service
            .local_session()
            .map_err(LocalWorkspaceError::service)?;

        if record.state == SessionState::Created {
            return Err(LocalWorkspaceError::new(Kind::Incomplete));
        }
        if Path::new(&record.metadata.workspace_root) != boundary.root().canonical_path() {
            return Err(LocalWorkspaceError::new(Kind::WorkspaceMismatch));
        }

        let scanner = SastScanner::new();
        let sast_report = scanner
            .scan_workspace(boundary.root().canonical_path())
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        let task_id = TaskId::new();
        let existing_tasks = repository
            .list_tasks(record.metadata.session_id)
            .map_err(LocalWorkspaceError::persistence)?;
        let sequence_number = (existing_tasks.len() as u64) + 1;

        let task_title = "Source Code SAST & Secret Scan".to_string();
        repository
            .create_task(
                record.metadata.session_id,
                task_id,
                sequence_number,
                &task_title,
                &*clock,
            )
            .map_err(LocalWorkspaceError::persistence)?;

        repository
            .update_task_state(
                task_id,
                TaskState::Pending,
                TaskState::InProgress,
                EventId::new(),
                &*clock,
            )
            .map_err(LocalWorkspaceError::persistence)?;

        repository
            .update_task_state(
                task_id,
                TaskState::InProgress,
                TaskState::Completed,
                EventId::new(),
                &*clock,
            )
            .map_err(LocalWorkspaceError::persistence)?;

        let now = clock.now();
        let candidate_findings =
            sast_report.to_candidate_findings(record.metadata.session_id, task_id, now);

        let report = LocalScanReport {
            session_id: record.metadata.session_id,
            task_id,
            sast_report,
            candidate_findings,
        };

        match manager.shutdown() {
            Ok(_) => Ok(report),
            Err(error) => Err(LocalWorkspaceError::persistence(error)),
        }
    }

    /// Exports SAST and secret findings to an OASIS SARIF v2.1.0 document.
    pub fn export_scan_sarif(
        workspace: &Path,
        database: Option<&Path>,
    ) -> Result<String, LocalWorkspaceError> {
        let findings = if let Some(db) = database {
            let rep = Self::scan_source(workspace, db)?;
            rep.candidate_findings
        } else {
            let sast_report = Self::scan_source_direct(workspace)?;
            let now = TimestampUtc::now();
            sast_report.to_candidate_findings(SessionId::new(), TaskId::new(), now)
        };

        crate::export::generate_sarif_json(&findings, env!("CARGO_PKG_VERSION"))
            .map_err(|_| LocalWorkspaceError::new(LocalWorkspaceErrorKind::Service))
    }

    /// Generates automated remediation PR proposals for all identified vulnerabilities in the workspace.
    pub fn propose_remediations(
        workspace: &Path,
        database: &Path,
        advisory_db: &AdvisoryDatabase,
    ) -> Result<Vec<crate::remediation::RemediationPrPackage>, LocalWorkspaceError> {
        let audit = Self::audit_dependencies(workspace, database, advisory_db)?;
        let mut proposals = Vec::new();
        for m in &audit.audit_result.matches {
            proposals.push(
                crate::remediation::RemediationPrPackage::from_advisory_match(
                    m,
                    "Cargo.lock",
                    "HEAD",
                ),
            );
        }
        Ok(proposals)
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
