//! Local project initialization/inspection. No terminal, target content or execution.

use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    Clock, CostUsd, EventId, FailClosedBackend, Finding, OperatingMode, PolicyEngine,
    SecurityClassification, SessionId, SessionState, SystemClock, TaskId, TimestampUtc,
    advisory::{
        AdvisoryAuditResult, AdvisoryDatabase, InventoryLimits, MAX_INVENTORY_DEPTH,
        WorkspaceInventory, collect_lockfile_inventory, discover_workspace_lockfiles,
        parse_lockfile_content,
    },
    diff::{
        DiffError, DiffErrorKind, MAX_PATCH_BYTES, PatchFileResult, PatchPlan, PatchRollbackResult,
        RollbackPlan, SnapshotDiff, UnifiedPatch, compare_snapshots,
    },
    manifest::{SnapshotLimits, capture_source_snapshot},
    persistence::{
        OperatorEventKind, PersistenceError, PersistenceErrorKind, PersistenceRepository,
        SessionAdmission, SqliteConnectionManager, TaskState,
    },
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
    /// A request parameter is outside its documented range.
    InvalidRequest,
    /// The patch file is unreadable, too large, malformed, multi-file or binary.
    InvalidPatch,
    /// The patch is well formed but its hunks do not match the target content.
    PatchDoesNotApply,
    /// The patch/rollback target is missing, outside the workspace, reached through
    /// a link or junction, not an ordinary file, too large or not UTF-8 text.
    PatchTarget,
    /// The rollback backup is missing, unreadable, too large or not an ordinary file.
    PatchBackup,
    /// A filesystem write (backup or target) failed.
    Io,
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
    /// Authoritative candidate findings, each located at the lockfile its package was read from.
    pub candidate_findings: Vec<Finding>,
    /// Workspace-root lockfiles (file names) that were read and parsed, in discovery order.
    pub lockfiles: Vec<String>,
    /// Workspace-root lockfiles that were found but could not be read or parsed; their
    /// packages were not audited.
    pub unparsed_lockfiles: Vec<String>,
    /// For each entry of `audit_result.matches`, in order, the lockfile its package record was
    /// read from. Each lockfile is audited separately, so a package name and version listed by
    /// two lockfiles yields one match per lockfile.
    pub match_lockfiles: Vec<String>,
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

/// Read-only lockfile inventory of a validated workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalInventoryReport {
    /// Canonical workspace root that was walked.
    pub workspace_root: PathBuf,
    /// Discovered lockfiles and their parsed packages.
    pub inventory: WorkspaceInventory,
}

/// Outcome of `patch apply`, including whether a core audit event was committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPatchReport {
    /// File-level result (dry-run or applied).
    pub result: PatchFileResult,
    /// True only when a `PatchApplied` event was committed to the local store.
    pub audit_recorded: bool,
}

/// Outcome of `patch rollback`, including whether a core audit event was committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRollbackReport {
    /// File-level result.
    pub result: PatchRollbackResult,
    /// True only when a `PatchRolledBack` event was committed to the local store.
    pub audit_recorded: bool,
}

/// Persistent organization or tenant record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TenantRecord {
    /// Unique tenant identifier (1-64 chars ASCII alphanumeric, -, _).
    pub tenant_id: String,
    /// Display name of the organization.
    pub name: String,
    /// Detailed description.
    pub description: String,
    /// Default workspace directory.
    pub default_workspace: String,
    /// Isolation level (e.g. single_operator, multi_tenant_isolated).
    pub isolation_level: String,
    /// Registration ISO 8601 timestamp.
    pub created_at: String,
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

    /// Runs a dependency advisory audit of the lockfiles at the workspace root against
    /// `advisory_db` (Requirement F-07) and records it as a completed task in the store.
    ///
    /// Lockfiles are discovered at the workspace root only (see
    /// [`discover_workspace_lockfiles`]); one that cannot be read or parsed is reported in
    /// [`LocalAuditReport::unparsed_lockfiles`] instead of failing the audit.
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

        let root = boundary.root().canonical_path();
        let mut parsed_lockfiles = Vec::new();
        let mut unparsed_lockfiles = Vec::new();
        for (kind, filename) in discover_workspace_lockfiles(root) {
            let parsed = fs::read_to_string(root.join(&filename))
                .ok()
                .and_then(|content| parse_lockfile_content(kind, &content).ok());
            match parsed {
                Some(pkgs) => parsed_lockfiles.push((filename, pkgs)),
                None => unparsed_lockfiles.push(filename),
            }
        }

        // Each lockfile is audited on its own, so every match stays attributed to the lockfile
        // its package record was read from, even when several lockfiles list the same package
        // name and version. The per-lockfile results are then merged in discovery order.
        let now = clock.now();
        let mut audit_result = advisory_db
            .audit_packages(&[], now, 30)
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;
        let mut match_lockfiles = Vec::new();
        let mut vulnerable_package_names = std::collections::HashSet::new();
        for (filename, pkgs) in &parsed_lockfiles {
            let partial = advisory_db
                .audit_packages(pkgs, now, 30)
                .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;
            audit_result.packages_audited += partial.packages_audited;
            audit_result
                .unknown_version_packages
                .extend(partial.unknown_version_packages);
            for m in partial.matches {
                vulnerable_package_names.insert(m.package.clone());
                match_lockfiles.push(filename.clone());
                audit_result.matches.push(m);
            }
        }
        audit_result.vulnerable_packages = vulnerable_package_names.len();
        let lockfiles: Vec<String> = parsed_lockfiles
            .into_iter()
            .map(|(filename, _)| filename)
            .collect();

        let task_id = TaskId::new();
        let existing_tasks = repository
            .list_tasks(record.metadata.session_id)
            .map_err(LocalWorkspaceError::persistence)?;
        let sequence_number = (existing_tasks.len() as u64) + 1;

        let task_title = match lockfiles.first() {
            Some(first) => format!("{first} Dependency Advisory Audit"),
            None => "Dependency Advisory Audit (no lockfile parsed)".to_string(),
        };
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

        let candidate_findings = audit_result.to_candidate_findings_per_lockfile(
            record.metadata.session_id,
            task_id,
            now,
            &match_lockfiles,
        );

        let report = LocalAuditReport {
            session_id: record.metadata.session_id,
            task_id,
            audit_result,
            candidate_findings,
            lockfiles,
            unparsed_lockfiles,
            match_lockfiles,
        };

        match manager.shutdown() {
            Ok(_) => Ok(report),
            Err(error) => Err(LocalWorkspaceError::persistence(error)),
        }
    }

    /// Runs [`Self::audit_dependencies`] and exports its dependency advisory results (only)
    /// as an OASIS SARIF v2.1.0 document (REQ-F07, EXTENSIONS.md). SAST results are exported
    /// by [`Self::export_scan_sarif`]. Nothing is uploaded anywhere.
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

    /// Runs [`Self::audit_dependencies`] and builds one local draft pull request preview per
    /// advisory match (see [`crate::remediation::RemediationPrPackage`]).
    ///
    /// `advisory_source` describes `advisory_db` and is written into each preview body. Each
    /// preview names the lockfile the matched package was read from. No branch, commit or
    /// pull request is created, and the suggested `gh` command is not run.
    pub fn propose_remediations(
        workspace: &Path,
        database: &Path,
        advisory_db: &AdvisoryDatabase,
        advisory_source: &str,
    ) -> Result<Vec<crate::remediation::RemediationPrPackage>, LocalWorkspaceError> {
        let audit = Self::audit_dependencies(workspace, database, advisory_db)?;
        let proposals = audit
            .audit_result
            .matches
            .iter()
            .zip(&audit.match_lockfiles)
            .map(|(m, lockfile)| {
                crate::remediation::RemediationPrPackage::from_advisory_match(
                    m,
                    lockfile,
                    "HEAD",
                    advisory_source,
                )
            })
            .collect();
        Ok(proposals)
    }

    /// Probes workspace for CodeQL-compatible languages and generates invocation commands.
    pub fn probe_codeql(
        workspace: &Path,
    ) -> Result<crate::plugin::codeql::CodeQlProbeReport, LocalWorkspaceError> {
        crate::plugin::codeql::probe_codeql_workspace(workspace).map_err(|e| match e {
            crate::plugin::codeql::CodeQlError::WorkspaceReadError(_) => {
                LocalWorkspaceError::new(LocalWorkspaceErrorKind::Workspace)
            }
            _ => LocalWorkspaceError::new(LocalWorkspaceErrorKind::Service),
        })
    }

    /// Ingests a CodeQL SARIF v2.1.0 report, extracting findings and interprocedural taint traces.
    pub fn ingest_codeql_sarif(
        workspace: Option<&Path>,
        database: Option<&Path>,
        sarif_path: &Path,
    ) -> Result<crate::plugin::codeql::CodeQlSarifIngestResult, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;

        let content = std::fs::read_to_string(sarif_path)
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        if let (Some(ws), Some(db)) = (workspace, database) {
            let boundary = WorkspaceBoundary::establish(
                ws,
                SessionId::new(),
                SecurityClassification::Internal,
            )
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

            let parent = db
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

            let _admission = SqliteConnectionManager::local_context_admission(db)
                .map_err(LocalWorkspaceError::persistence)?;
            if !exists(db)? {
                return Err(LocalWorkspaceError::new(Kind::Incomplete));
            }

            let clock = Arc::new(SystemClock::new());
            let manager = SqliteConnectionManager::open_existing(db, &clock)
                .map_err(LocalWorkspaceError::persistence)?;
            let (repository, authority) = PersistenceRepository::with_authority(manager);
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

            let task_id = TaskId::new();
            let existing_tasks = repository
                .list_tasks(record.metadata.session_id)
                .map_err(LocalWorkspaceError::persistence)?;
            let sequence_number = (existing_tasks.len() as u64) + 1;

            let task_title = "GitHub CodeQL SARIF Analysis Ingestion".to_string();
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
            let result = crate::plugin::codeql::ingest_codeql_sarif_payload(
                &content,
                &record.metadata.session_id,
                task_id,
                now,
            )
            .map_err(|_| LocalWorkspaceError::new(Kind::Service))?;

            Ok(result)
        } else {
            let session_id = SessionId::new();
            let task_id = TaskId::new();
            let clock_now = TimestampUtc::now();
            crate::plugin::codeql::ingest_codeql_sarif_payload(
                &content,
                &session_id,
                task_id,
                clock_now,
            )
            .map_err(|_| LocalWorkspaceError::new(Kind::Service))
        }
    }

    /// Scans a source code snippet directly in-memory without creating files on disk.
    /// `file_name` selects the language rule families by extension and becomes the
    /// `file_path` of every match; without it the snippet is labeled `snippet.ts`.
    pub fn scan_snippet(snippet: &str, file_name: Option<&str>) -> SastReport {
        let scanner = SastScanner::new();
        let matches = scanner.scan_content(file_name.unwrap_or("snippet.ts"), snippet);
        SastReport {
            files_scanned: 1,
            directories_scanned: 0,
            matches,
        }
    }

    /// Read-only lockfile inventory: recursive discovery under the validated
    /// workspace (skip list, depth limit, no link/junction traversal) and parsing
    /// with the pure-Rust lockfile parsers. Nothing is executed or written.
    pub fn inventory(
        workspace: &Path,
        max_depth: usize,
    ) -> Result<LocalInventoryReport, LocalWorkspaceError> {
        if max_depth > MAX_INVENTORY_DEPTH {
            return Err(LocalWorkspaceError::new(
                LocalWorkspaceErrorKind::InvalidRequest,
            ));
        }
        let boundary = establish_workspace(workspace)?;
        let limits = InventoryLimits {
            max_depth,
            ..InventoryLimits::default()
        };
        let root = boundary.root().canonical_path();
        Ok(LocalInventoryReport {
            workspace_root: root.to_path_buf(),
            inventory: collect_lockfile_inventory(root, &limits),
        })
    }

    /// Applies a single-file unified diff to an ordinary file inside the workspace.
    ///
    /// Hunks are applied positionally with exact context (bounded offset search);
    /// all hunks apply or nothing is written. `dry_run` validates everything and
    /// writes nothing (no backup, no store access). With `database`, the local store
    /// must exist and belong to `workspace`; it is validated before the file is
    /// touched, and a `PatchApplied` event is committed after the write. If that
    /// event cannot be committed, the file is restored and the call fails.
    pub fn apply_patch(
        workspace: &Path,
        patch_file: &Path,
        target_rel: Option<&Path>,
        backup_dir: Option<&Path>,
        database: Option<&Path>,
        dry_run: bool,
    ) -> Result<LocalPatchReport, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        let boundary = establish_workspace(workspace)?;
        let text = read_patch_text(patch_file)?;
        let patch =
            UnifiedPatch::parse(&text).map_err(|_| LocalWorkspaceError::new(Kind::InvalidPatch))?;
        let target = match target_rel {
            Some(target) => target.to_path_buf(),
            None => PathBuf::from(
                patch
                    .target_path()
                    .ok_or_else(|| LocalWorkspaceError::new(Kind::InvalidPatch))?,
            ),
        };
        let store = match database {
            Some(database) if !dry_run => Some(LocalStore::open(&boundary, database)?),
            _ => None,
        };
        let plan = PatchPlan::prepare(&boundary, &target, &patch).map_err(patch_error)?;
        if dry_run {
            return Ok(LocalPatchReport {
                result: plan.dry_run_result(),
                audit_recorded: false,
            });
        }
        let result = plan.commit(backup_dir).map_err(patch_error)?;
        let Some(store) = store else {
            return Ok(LocalPatchReport {
                result,
                audit_recorded: false,
            });
        };
        let details = serde_json::json!({
            "target_path": result.target_path,
            "backup_path": result.backup_path,
            "already_patched": result.already_patched,
            "hunks": result.hunks,
            "patch_sha256": result.patch_sha256,
            "pre_image_sha256": result.pre_image_sha256,
            "post_image_sha256": result.post_image_sha256,
        });
        if let Err(error) = store.record(OperatorEventKind::PatchApplied, &details) {
            // No unaudited change may remain: restore the exact pre-image.
            return Err(match plan.revert() {
                Ok(()) => error,
                Err(_) => LocalWorkspaceError::new(Kind::Io),
            });
        }
        store.close();
        Ok(LocalPatchReport {
            result,
            audit_recorded: true,
        })
    }

    /// Restores an ordinary workspace file from a backup. With `database`, the
    /// local store must exist and belong to `workspace`; a `PatchRolledBack` event
    /// is committed after the write, and the pre-rollback content is restored if
    /// that event cannot be committed.
    pub fn rollback_patch(
        workspace: &Path,
        backup_file: &Path,
        target_rel: &Path,
        database: Option<&Path>,
    ) -> Result<LocalRollbackReport, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        let boundary = establish_workspace(workspace)?;
        let store = match database {
            Some(database) => Some(LocalStore::open(&boundary, database)?),
            None => None,
        };
        let plan =
            RollbackPlan::prepare(&boundary, target_rel, backup_file).map_err(patch_error)?;
        let result = plan.commit().map_err(patch_error)?;
        let Some(store) = store else {
            return Ok(LocalRollbackReport {
                result,
                audit_recorded: false,
            });
        };
        let details = serde_json::json!({
            "target_path": result.target_path,
            "restored_from": result.restored_from,
            "pre_image_sha256": result.pre_image_sha256,
            "post_image_sha256": result.post_image_sha256,
        });
        if let Err(error) = store.record(OperatorEventKind::PatchRolledBack, &details) {
            return Err(match plan.revert() {
                Ok(()) => error,
                Err(_) => LocalWorkspaceError::new(Kind::Io),
            });
        }
        store.close();
        Ok(LocalRollbackReport {
            result,
            audit_recorded: true,
        })
    }

    /// Lists tenant rows that exist in the selected SQLite file. Read-only: a
    /// missing file or a missing `tenants` table yields an empty list, and nothing
    /// (no file, table or row) is created.
    pub fn list_tenants(database: &Path) -> Result<Vec<TenantRecord>, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        if !exists(database)? {
            return Ok(Vec::new());
        }
        let conn = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;
        let has_table: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tenants')",
                [],
                |r| r.get(0),
            )
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;
        if !has_table {
            return Ok(Vec::new());
        }

        let mut stmt = conn
            .prepare("SELECT tenant_id, name, description, default_workspace, isolation_level, created_at FROM tenants ORDER BY created_at ASC, tenant_id ASC")
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(TenantRecord {
                    tenant_id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    default_workspace: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    isolation_level: row
                        .get::<_, Option<String>>(4)?
                        .unwrap_or_else(|| "multi_tenant_isolated".to_string()),
                    created_at: row.get(5)?,
                })
            })
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))
    }

    /// Registers a new tenant organization into the SQLite database.
    pub fn add_tenant(
        database: &Path,
        id: &str,
        name: &str,
        description: Option<&str>,
        default_workspace: Option<&str>,
        isolation_level: Option<&str>,
    ) -> Result<TenantRecord, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        let _valid_id = crate::dashboard::TenantId::new(id)
            .map_err(|_| LocalWorkspaceError::new(Kind::Workspace))?;

        if name.trim().is_empty() {
            return Err(LocalWorkspaceError::new(Kind::Workspace));
        }

        // A core store has an exact schema; adding a `tenants` table to it would make
        // every later core command fail its schema check. Refuse it untouched.
        if database.is_file() && is_core_store(database)? {
            return Err(LocalWorkspaceError::new(Kind::StorageLocation));
        }

        let conn = rusqlite::Connection::open(database)
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                default_workspace TEXT,
                isolation_level TEXT DEFAULT 'multi_tenant_isolated',
                created_at TEXT NOT NULL
            );",
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        let clean_id = id.trim().to_lowercase();
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tenants WHERE tenant_id = ?1",
                [&clean_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists > 0 {
            return Err(LocalWorkspaceError::new(Kind::Workspace));
        }

        let now = TimestampUtc::now().to_string();
        let clean_name = name.trim().to_string();
        let clean_desc = description.unwrap_or("").trim().to_string();
        let clean_ws = default_workspace.unwrap_or(".").trim().to_string();
        let clean_iso = if isolation_level == Some("single_operator") {
            "single_operator"
        } else {
            "multi_tenant_isolated"
        }
        .to_string();

        conn.execute(
            "INSERT INTO tenants (tenant_id, name, description, default_workspace, isolation_level, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![clean_id, clean_name, clean_desc, clean_ws, clean_iso, now],
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        Ok(TenantRecord {
            tenant_id: clean_id,
            name: clean_name,
            description: clean_desc,
            default_workspace: clean_ws,
            isolation_level: clean_iso,
            created_at: now,
        })
    }

    /// Reads system settings or configuration keys from the database.
    pub fn get_config(
        database: &Path,
        key: Option<&str>,
    ) -> Result<Vec<(String, String)>, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        let conn = rusqlite::Connection::open(database)
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        let mut results = Vec::new();
        if let Some(k) = key {
            let mut stmt = conn
                .prepare("SELECT key, value FROM system_settings WHERE key = ?1")
                .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;
            let mut rows = stmt
                .query([k])
                .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;
            while let Some(row) = rows
                .next()
                .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?
            {
                results.push((
                    row.get(0).unwrap_or_default(),
                    row.get(1).unwrap_or_default(),
                ));
            }
        } else {
            let mut stmt = conn
                .prepare("SELECT key, value FROM system_settings ORDER BY key ASC")
                .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;
            let mut rows = stmt
                .query([])
                .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;
            while let Some(row) = rows
                .next()
                .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?
            {
                results.push((
                    row.get(0).unwrap_or_default(),
                    row.get(1).unwrap_or_default(),
                ));
            }
        }
        Ok(results)
    }

    /// Sets or updates a system configuration key-value pair in the database.
    pub fn set_config(database: &Path, key: &str, value: &str) -> Result<(), LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
        if key.trim().is_empty() {
            return Err(LocalWorkspaceError::new(Kind::Workspace));
        }
        let conn = rusqlite::Connection::open(database)
            .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        let now = TimestampUtc::now().to_string();
        conn.execute(
            "INSERT INTO system_settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            rusqlite::params![key.trim(), value, now],
        )
        .map_err(|_| LocalWorkspaceError::new(Kind::Persistence))?;

        Ok(())
    }

    /// Returns the local worker fleet registry.
    ///
    /// No worker registry source (persisted table or operator fleet file) exists yet, so
    /// the registry is empty. Workers are never invented to fill it.
    pub fn fleet_manager() -> crate::fleet::WorkerFleetManager {
        crate::fleet::WorkerFleetManager::new()
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

fn establish_workspace(workspace: &Path) -> Result<WorkspaceBoundary, LocalWorkspaceError> {
    WorkspaceBoundary::establish(
        workspace,
        SessionId::new(),
        SecurityClassification::Internal,
    )
    .map_err(|_| LocalWorkspaceError::new(LocalWorkspaceErrorKind::Workspace))
}

/// Operator-supplied diff text: an ordinary readable file, bounded, UTF-8.
fn read_patch_text(patch_file: &Path) -> Result<String, LocalWorkspaceError> {
    let invalid = || LocalWorkspaceError::new(LocalWorkspaceErrorKind::InvalidPatch);
    let metadata = fs::metadata(patch_file).map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > MAX_PATCH_BYTES as u64 {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    fs::File::open(patch_file)
        .map_err(|_| invalid())?
        .take(MAX_PATCH_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > MAX_PATCH_BYTES {
        return Err(invalid());
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}

fn patch_error(error: DiffError) -> LocalWorkspaceError {
    use LocalWorkspaceErrorKind as Kind;
    LocalWorkspaceError::new(match error.kind {
        DiffErrorKind::InvalidPatch(_) => Kind::InvalidPatch,
        DiffErrorKind::PatchDoesNotApply(_) => Kind::PatchDoesNotApply,
        DiffErrorKind::InvalidBackup(_) => Kind::PatchBackup,
        DiffErrorKind::InvalidTarget(_)
        | DiffErrorKind::BinaryContent
        | DiffErrorKind::LimitsExceeded(_) => Kind::PatchTarget,
        DiffErrorKind::Io(_) => Kind::Io,
        DiffErrorKind::InvalidSnapshot(_)
        | DiffErrorKind::RevisionMismatch { .. }
        | DiffErrorKind::AntiRegressionViolation(_) => Kind::Service,
    })
}

/// Existing local store bound to the selected workspace, opened with local-context
/// admission (held until drop) for appending operator audit events.
struct LocalStore {
    manager: SqliteConnectionManager,
    repository: PersistenceRepository,
    session_id: SessionId,
    clock: SystemClock,
    _admission: SessionAdmission,
}

impl LocalStore {
    /// Same admission rules as the other local commands: storage outside the
    /// workspace, an existing initialized store, and a matching workspace root.
    fn open(boundary: &WorkspaceBoundary, database: &Path) -> Result<Self, LocalWorkspaceError> {
        use LocalWorkspaceErrorKind as Kind;
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
        let admission = SqliteConnectionManager::local_context_admission(database)
            .map_err(LocalWorkspaceError::persistence)?;
        if !exists(database)? {
            return Err(LocalWorkspaceError::new(Kind::Incomplete));
        }
        let clock = SystemClock::new();
        let manager = SqliteConnectionManager::open_existing(database, &clock)
            .map_err(LocalWorkspaceError::persistence)?;
        let (repository, _authority) = PersistenceRepository::with_authority(manager.clone());
        let record = repository.local_session().map_err(|error| {
            if error.kind == PersistenceErrorKind::ContextMismatch {
                LocalWorkspaceError::new(Kind::Incomplete)
            } else {
                LocalWorkspaceError::persistence(error)
            }
        })?;
        if record.state == SessionState::Created {
            return Err(LocalWorkspaceError::new(Kind::Incomplete));
        }
        if Path::new(&record.metadata.workspace_root) != boundary.root().canonical_path() {
            return Err(LocalWorkspaceError::new(Kind::WorkspaceMismatch));
        }
        Ok(Self {
            manager,
            repository,
            session_id: record.metadata.session_id,
            clock,
            _admission: admission,
        })
    }

    fn record(
        &self,
        kind: OperatorEventKind,
        details: &serde_json::Value,
    ) -> Result<(), LocalWorkspaceError> {
        self.repository
            .record_operator_event(self.session_id, kind, EventId::new(), details, &self.clock)
            .map(|_| ())
            .map_err(LocalWorkspaceError::persistence)
    }

    /// Close after a committed event. The event is durable once committed; a busy
    /// WAL checkpoint (for example while another process holds a read transaction)
    /// is deferred to the next writer and does not undo the commit or the file change.
    fn close(self) {
        let _deferred_checkpoint = self.manager.shutdown();
    }
}

/// Read-only probe: whether an existing SQLite file is a Sentra core store, marked
/// by the core `application_id` or a `schema_migrations` table. Nothing is written;
/// a file SQLite cannot read is a persistence failure.
fn is_core_store(database: &Path) -> Result<bool, LocalWorkspaceError> {
    // The header check needs no SQLite lock, so a store held open elsewhere is
    // still recognized; the query below also sees changes not yet checkpointed.
    if has_core_store_header(database) {
        return Ok(true);
    }
    let failure = |_| LocalWorkspaceError::new(LocalWorkspaceErrorKind::Persistence);
    let conn = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure)?;
    let application: i64 = conn
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(failure)?;
    if application == crate::persistence::CORE_STORE_APPLICATION_ID {
        return Ok(true);
    }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |r| r.get(0),
    )
    .map_err(failure)
}

/// Reads the SQLite file header and compares its `application_id` (big-endian at
/// byte offset 68) with the core store marker.
fn has_core_store_header(database: &Path) -> bool {
    let mut header = [0u8; 72];
    let read = fs::File::open(database).and_then(|mut file| file.read_exact(&mut header));
    read.is_ok()
        && header.starts_with(b"SQLite format 3\0")
        && i64::from(i32::from_be_bytes([
            header[68], header[69], header[70], header[71],
        ])) == crate::persistence::CORE_STORE_APPLICATION_ID
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
