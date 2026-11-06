# Sentra Core Engine Architecture & Interface Contracts — Phase 1, Increment 5.1

Date: 2026-11-05. **Architecture and interface design specification.** This document defines the module boundaries, domain contracts, state machines, persistence rules, security invariants, and implementation plan for Sentra Core Engine Foundation.

In accordance with Phase 1 constraints and the [Milestone 4 Closure Review](MILESTONE_4_REVIEW.md), **this document contains no production application code**. Untrusted code execution is strictly disabled and fails closed by default.

---

## 1. Module Responsibility Map

The Core Engine is the local, deterministic control plane for Sentra. It enforces security boundaries, manages session state, evaluates operational policies, persists audit trails and findings, coordinates optional AI providers, and gates execution dispatch.

```
                          +------------------------+
                          |   CLI / Client Layer   |
                          +------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                            Sentra Core Engine                                     |
|                                                                                   |
|  +--------------------+   +---------------------+   +--------------------------+  |
|  |     Session        |   |      Workspace      |   |          Policy          |  |
|  |   Management       |   |      Boundary       |   |          Engine          |  |
|  | (Lifecycle & DAG)  |   | (Path & Discovery)  |   | (Classification & Grants)|  |
|  +--------------------+   +---------------------+   +--------------------------+  |
|            |                         |                           |                |
|            +-------------------------+---------------------------+                |
|                                      |                                            |
|                                      v                                            |
|  +--------------------+   +---------------------+   +--------------------------+  |
|  |    Persistence     |   |     AI Provider     |   |        Execution         |  |
|  |    Repository      |   |       Gateway       |   |         Backend          |  |
|  | (SQLite WAL/Retry) |   | (Neutral & Optional)|   |  (FAIL-CLOSED BY DEFAULT)|  |
|  +--------------------+   +---------------------+   +--------------------------+  |
|                                                                  |                |
|                                                                  v                |
|                                                     +--------------------------+  |
|                                                     |   Evidence Verifier      |  |
|                                                     | (SHA-256 & Schema Check) |  |
|                                                     +--------------------------+  |
+-----------------------------------------------------------------------------------+
```

### Module definitions and responsibilities

| Module | Core Responsibility | Inputs | Outputs | Non-Responsibilities |
| --- | --- | --- | --- | --- |
| `sentra_core::session` | Manages session lifecycle, task dependency DAG, identity, and transitions | Operator session requests, task completion events | Validated session states, audit events, task leases | Does not execute tasks or make policy determinations |
| `sentra_core::workspace` | Enforces strict path canonicalization, symlink quarantine, and metadata-only file discovery | Raw filesystem paths, discovery options, exclusion rules | Canonical paths, file inventories, symlink quarantine notices | Does not read file contents beyond manifest bounds; never executes target scripts |
| `sentra_core::policy` | Evaluates operation authorization, security classifications, and human approval brokers | Operation intents, session context, actor ID, action digests | `PolicyDecision` (Granted, Denied, NeedsApproval) | Does not initiate execution or hold private cryptographic keys |
| `sentra_core::persistence` | Handles transactional SQLite storage, explicit rollback on errors, and WAL checkpoints | Domain entities, audit events, findings, evidence metadata | Persisted records, recovery receipts, query projections | Does not store raw large blobs inside SQLite; manages content-addressed file pointers |
| `sentra_core::provider` | Provides optional, provider-neutral model inference, cost accounting, and structured validation | Normalized prompt requests, context bounds, cost ceilings | `DecisionV1` outputs, usage receipts, stream chunks | Does not require an active provider; strictly optional; does not bypass policy |
| `sentra_core::execution` | Defines the `ExecutionBackend` trait with a mandatory fail-closed default stub | Task execution requests, resource limits, timeout policies | `Err(BackendUnavailable)` for untrusted code; execution results for synthetic fixtures | **Must not execute untrusted code**; no host fallback; no Docker/WSL2 fallback |
| `sentra_core::evidence` | Performs host-side SHA-256 verification and structured envelope schema admission | Raw worker payloads, declared digests, producer metadata | `EvidenceVerificationResult`, admitted `EvidenceArtifact` | Does not verify semantic truth of findings; verifies transit integrity and schema conformance |

---

## 2. Component Interaction Diagram

The following sequence illustrates the interaction flow for a security analysis task, demonstrating the strict enforcement of workspace boundaries, policy approval, and the **mandatory fail-closed execution boundary**:

```mermaid
sequenceDiagram
    autonumber
    actor Operator
    participant Client as CLI / Frontend
    participant Session as Session Management
    participant WS as Workspace Boundary
    participant Policy as Policy Engine
    participant Store as Persistence (SQLite)
    participant Exec as Execution Backend
    participant Verifier as Evidence Verifier

    Operator->>Client: sentra scan --root ./target-repo
    Client->>Session: CreateSession(ProjectRoot, Mode)
    Session->>WS: CanonicalizeAndValidateRoot("./target-repo")
    WS-->>Session: Validated WorkspaceRoot
    Session->>Store: PersistSession(Created, Metadata)
    Store-->>Session: SessionId
    
    Session->>WS: DiscoverFiles(WorkspaceRoot, Limits)
    Note over WS: Traverses files; quarantines symlinks;<br/>strictly zero target code execution
    WS-->>Session: ProjectDiscoveryReport (Manifests, Languages)
    Session->>Store: PersistSnapshotAndInventory()

    Session->>Policy: AuthorizeOperation(Task::BuildAndScan, Untrusted)
    alt Action is Sensitive or Untrusted
        Policy-->>Session: PolicyDecision::NeedsApproval(ApprovalRequest)
        Session->>Store: PersistApprovalRequest(ActionDigest, Expiry)
        Session-->>Client: SessionState::WaitingForApproval
        Client-->>Operator: Prompt for Approval
        Operator->>Client: sentra approve <ApprovalId>
        Client->>Policy: SubmitApproval(ApprovalGrant)
        Policy-->>Session: PolicyDecision::Granted
    end

    Session->>Exec: DispatchTask(ExecutionRequest)
    Note over Exec: Default Backend is FailClosedBackend.<br/>Dedicated Hyper-V VM is unverified.
    Exec-->>Session: Err(ExecutionBackendError::BackendUnavailable)
    
    Session->>Store: RecordAuditEvent(TaskFailed, "ExecutionBackend::NotAvailable")
    Session-->>Client: TaskAborted("Untrusted execution disabled by policy")
```

---

## 3. Rust Trait and Type Contracts

Below are the normative Rust interfaces and domain types for Sentra Core Engine. These contracts avoid unnecessary async complexity and rely on synchronous, bounded operations.

### 3.1. Session management contracts

```rust
pub type SessionId = uuid::Uuid;
pub type TaskId = uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Created,
    Scoped,
    Planned,
    Running,
    WaitingForApproval,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssessmentCompleteness {
    Complete,
    Partial,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: SessionId,
    pub created_at_utc: chrono::DateTime<chrono::Utc>,
    pub workspace_root: String,
    pub operating_mode: OperatingMode,
    pub operator_id: String,
    pub policy_digest: String,
    pub completeness: AssessmentCompleteness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: uuid::Uuid,
    pub session_id: SessionId,
    pub sequence_number: u64,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub actor: String,
    pub event_kind: AuditEventKind,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventKind {
    SessionCreated,
    SessionStateChanged { from: SessionState, to: SessionState },
    PolicyEvaluated,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalRevoked,
    TaskDispatched,
    TaskCompleted,
    TaskFailed,
    EvidenceAdmitted,
    AnomalyDetected,
}
```

### 3.2. Workspace boundary contracts

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRoot(std::path::PathBuf);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativePath(std::path::PathBuf);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    DenyAll,
    AllowInternalOnly,
}

#[derive(Debug, Clone)]
pub struct DiscoveryLimits {
    pub max_files: usize,          // Default: 10,000 files
    pub max_total_bytes: u64,      // Default: 100 MiB
    pub max_depth: usize,          // Default: 32 levels
    pub follow_symlinks: bool,     // Default: false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedPath {
    pub raw_path: String,
    pub reason: QuarantineReason,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum QuarantineReason {
    TraversalAttempt,
    ExternalSymlinkTarget,
    InvalidEncoding,
    DeviceNameReserved,
    ExceedsDepthLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDiscoveryReport {
    pub root_canonical: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub manifests_found: Vec<String>,
    pub detected_languages: Vec<String>,
    pub quarantined_paths: Vec<QuarantinedPath>,
    pub scan_duration_ms: u64,
}

pub trait WorkspaceBoundary: Send + Sync {
    fn validate_root(&self, path: &std::path::Path) -> Result<WorkspaceRoot, WorkspaceError>;
    fn resolve_safe_path(&self, root: &WorkspaceRoot, relative: &RelativePath) -> Result<std::path::PathBuf, WorkspaceError>;
    fn discover_files(&self, root: &WorkspaceRoot, limits: &DiscoveryLimits) -> Result<ProjectDiscoveryReport, WorkspaceError>;
}
```

### 3.3. Policy engine contracts

Implementation refinement (5.3.1): the [security correction](INCREMENT_5_3_1_SECURITY_REVIEW.md) documents the concrete approval API. A separately retained privileged authority registers trusted session/workspace/revision/classification context and issues receipts through the same Mutex broker. Consumption requires the current operation context and verified issuance provenance; display DTOs and canonical descriptor strings alone are not approvals. The sketches below do not authorize caller-constructed grants or conflating target revision with policy_digest. No cryptographic dependency or signature is implemented by this refinement.

Implementation refinement (5.6.2.2): the persistent service uses the SQL security snapshot as its single context authority and the pure authoritative PolicyEngine rule path; it does not refresh a second mutable memory broker. Only the privileged persistent authority mints an immutable execution context. Atomic preparation revalidates that context for approved and automatic actions and derives approval, budget ownership and audits from the same session. A safe local OS shared admission lock remains live through synchronous dispatch; trusted context/state updates require its exclusive counterpart and fail with ContextBusy during dispatch. Scoped, Planned and Running admit tasks; all other states deny. Legacy request-side context methods only compare existing owner-installed context. See the [remediation contract and limitations](INCREMENT_5_6_2_2_SECURITY_REMEDIATION.md), including protected local lock artifacts, typed error sources, unknown monetary usage and the unresolved post-commit/effect crash window. This refinement grants no untrusted execution capability and establishes no exactly-once or distributed guarantee.

Implementation refinement (5.6.2.2.2): effective PolicyEngine configuration is immutable after construction. Security snapshot JSON v2 stores an internally derived canonical effective-rule identity; the existing context generation also serves as its policy/approval epoch. The privileged policy-aware registration takes the same exclusive dispatch fence, changes rules/snapshot/epoch/audit atomically and preserves an identical effective policy/context as a no-op. A different proposed engine cannot mint under an incompatible stored identity; old contexts/approvals fail after activation, including policy ABA. Valid v1 snapshots remain readable as history but cannot authorize work until explicit owner binding; no startup/preview migration guesses their policy. Preview returns Granted/Denied/NeedsApproval separately from typed persistence evaluation failures and changes no domain rows. See the [policy lifecycle and compatibility report](INCREMENT_5_6_2_2_2_POLICY_AND_VALIDATOR_HARDENING.md). There is no global hot reload, cryptographic policy proof or external-effect recovery implementation.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationAction {
    DiscoverMetadata,
    ExecuteTool { tool_id: String, untrusted: bool },
    InvokeProvider { model_id: String, estimated_cost_usd: f64 },
    ExportReport { destination: String },
    ModifyCheckout { file_count: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Granted,
    Denied { reason: String },
    NeedsApproval { request_id: uuid::Uuid, action_digest: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: uuid::Uuid,
    pub session_id: SessionId,
    pub actor_id: String,
    pub action_digest: String,
    pub target_revision: String,
    pub explanation: String,
    pub budget_limit_usd: Option<f64>,
    pub expires_at_utc: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalGrant {
    pub request_id: uuid::Uuid,
    pub granted_by_actor: String,
    pub granted_at_utc: chrono::DateTime<chrono::Utc>,
    pub action_digest: String,
    pub signature_or_token: String,
}

pub trait PolicyEngine: Send + Sync {
    fn evaluate_action(
        &self,
        session: &SessionMetadata,
        action: &OperationAction,
        classification: SecurityClassification,
    ) -> PolicyDecision;
    
    fn verify_approval(
        &self,
        request: &ApprovalRequest,
        grant: &ApprovalGrant,
        current_time_utc: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, PolicyError>;
}
```

### 3.4. Persistence contracts

```rust
pub trait StorageTransaction {
    fn commit(self) -> Result<(), PersistenceError>;
    fn rollback(self) -> Result<(), PersistenceError>;
}

pub trait PersistenceRepository: Send + Sync {
    fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction + '_>, PersistenceError>;
    
    fn save_session(&self, session: &SessionMetadata) -> Result<(), PersistenceError>;
    fn update_session_state(&self, session_id: SessionId, state: SessionState) -> Result<(), PersistenceError>;
    fn get_session(&self, session_id: SessionId) -> Result<Option<SessionMetadata>, PersistenceError>;
    
    fn append_audit_event(&self, event: &AuditEvent) -> Result<(), PersistenceError>;
    fn get_audit_trail(&self, session_id: SessionId) -> Result<Vec<AuditEvent>, PersistenceError>;
    
    fn save_evidence_metadata(&self, artifact: &EvidenceArtifact) -> Result<(), PersistenceError>;
    fn get_evidence_metadata(&self, artifact_digest: &str) -> Result<Option<EvidenceArtifact>, PersistenceError>;
    
    fn checkpoint_wal(&self) -> Result<CheckpointStats, PersistenceError>;
}
```

### 3.5. AI provider gateway contracts

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub provider_name: String,
    pub model_id: String,
    pub max_context_tokens: usize,
    pub supports_structured_output: bool,
    pub supports_streaming: bool,
    pub cost_per_input_token_usd: f64,
    pub cost_per_output_token_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionV1 {
    pub summary: String,     // Bounded to <= 256 UTF-8 bytes
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRequest {
    pub session_id: SessionId,
    pub prompt: String,
    pub max_tokens: usize,
    pub require_structured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub raw_text: Option<String>,
    pub structured_decision: Option<DecisionV1>,
    pub usage: UsageReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReceipt {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub total_cost_usd: f64,
    pub settlement_confirmed: bool,
}

pub trait ProviderGateway: Send + Sync {
    fn initialize(&self) -> Result<(), ProviderError>;
    fn get_descriptor(&self) -> Result<ProviderDescriptor, ProviderError>;
    fn execute_structured(
        &self,
        request: &ProviderRequest,
        reservation: &CostReservation,
    ) -> Result<ProviderResponse, ProviderError>;
}
```

### 3.6. Execution backend contracts (Mandatory Fail-Closed)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,     // E.g. 512 MiB
    pub max_cpu_time_ms: u64,      // E.g. 30,000 ms
    pub max_wall_time_ms: u64,     // E.g. 60,000 ms
    pub max_pids: u32,             // E.g. 64 processes
    pub max_output_bytes: u64,     // E.g. 50 MiB
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionScope {
    SyntheticFixture,              // Maintainer-reviewed synthetic fixture ONLY
    UntrustedTargetWorkload,       // Real repository builds, tests, scanners
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub task_id: TaskId,
    pub scope: ExecutionScope,
    pub command: String,
    pub arguments: Vec<String>,
    pub input_stream_bytes: Vec<u8>,
    pub limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub task_id: TaskId,
    pub exit_code: i32,
    pub stdout_bytes: Vec<u8>,
    pub stderr_bytes: Vec<u8>,
    pub output_artifact_digest: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionBackendError {
    BackendUnavailable { reason: String },
    PolicyDenied { reason: String },
    TimeoutExpired { wall_time_ms: u64 },
    ResourceLimitExceeded { limit: String },
    AbnormalTermination { signal_or_code: i32 },
}

pub trait ExecutionBackend: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    
    /// Dispatches a task. Must fail closed for UntrustedTargetWorkload unless
    /// dedicated Hyper-V VM isolation has been proven.
    fn dispatch(
        &self,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, ExecutionBackendError>;
}

/// The normative default execution backend for Phase 1.
pub struct FailClosedBackend;

impl ExecutionBackend for FailClosedBackend {
    fn backend_name(&self) -> &'static str {
        "FailClosedBackend"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn dispatch(
        &self,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, ExecutionBackendError> {
        Err(ExecutionBackendError::BackendUnavailable {
            reason: format!(
                "Execution backend is not available for scope {:?}. Untrusted execution is disabled by policy pending Phase 2 Hyper-V validation.",
                request.scope
            ),
        })
    }
}
```

### 3.7. Evidence verification contracts (ADR-0006)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub artifact_id: uuid::Uuid,
    pub declared_sha256: String,
    pub producer_task_id: TaskId,
    pub media_type: String,
    pub raw_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceVerificationResult {
    Admitted {
        verified_sha256: String,
        payload_len: usize,
    },
    Rejected {
        reason: VerificationRejectionReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationRejectionReason {
    DigestMismatch { declared: String, computed: String },
    OversizedPayload { length: usize, max_allowed: usize },
    InvalidMediaType { media_type: String },
    MalformedEnvelope { details: String },
}

pub trait EvidenceVerifier: Send + Sync {
    fn verify_envelope(
        &self,
        envelope: &EvidenceEnvelope,
        max_bytes: usize,
    ) -> EvidenceVerificationResult;
}
```

---

## 4. Session State Machine

The session state machine governs the lifecycle of analysis operations. All transitions are deterministic, validated against allowed edges, and recorded in the audit ledger.

```
       [Created]
           |
           v
       [Scoped] --------------> [Cancelled]
           |                         ^
           v                         |
       [Planned] --------------------+
           |                         |
           v                         |
    [WaitingForApproval] ------------+
           |                         |
           v                         |
       [Running] <---------\         |
       /   |   \           |         |
      /    |    \          |         |
     v     |     v         |         |
[Paused]   |   [Failed]    |         |
   |       |               |         |
   \-------+---------------/         |
           |                         |
           v                         |
      [Completed]                    |
           |                         |
           \-------------------------/
```

### Valid state transition matrix

| Current State | Target State | Trigger / Authority | Invariants & Side Effects |
| --- | --- | --- | --- |
| `Created` | `Scoped` | Workspace boundary inspection passes | Validates canonical project root; identifies manifests; persists snapshot |
| `Scoped` | `Planned` | Task planner completes task DAG | Estimates resource bounds; checks initial provider availability |
| `Planned` | `WaitingForApproval` | Policy identifies sensitive action | Generates immutable `ApprovalRequest` with action digest and expiry |
| `Planned` | `Running` | All tasks auto-authorized by policy | Leases first batch of tasks; records dispatch audit event |
| `WaitingForApproval`| `Running` | Valid `ApprovalGrant` submitted | Verifies action digest and signature; checks grant has not expired |
| `WaitingForApproval`| `Cancelled` | Operator rejects approval | Cancels pending tasks; records rejection rationale in audit log |
| `Running` | `Paused` | Operator pauses session | Revokes active execution leases; preserves task DAG state |
| `Paused` | `Running` | Operator resumes session | Re-evaluates policy; checks revisions; re-queues unfinished tasks |
| `Running` | `Completed` | All planned tasks terminate cleanly | Sets `completeness` (Complete, Partial, Unsupported); checkpoints WAL |
| `Running` | `Failed` | Terminal unrecoverable error | Captures failure reason and error diagnostics; cleans up resources |
| Any non-terminal | `Cancelled` | Operator issues cancellation token | Enforces immediate timeout; stops workers; reconciles orphan state |

---

## 5. Policy Decision Flow

The Policy Engine follows a strict **default-deny** security architecture. Target project files, model responses, and plugin descriptors cannot grant permissions.

```
                                [Operation Request]
                                         |
                                         v
                            +--------------------------+
                            | Is Target Within Root?   |----(No)----> [PolicyDecision::Denied]
                            +--------------------------+
                                         |
                                       (Yes)
                                         v
                            +--------------------------+
                            | Involves Secret Data?    |----(Yes)---> [PolicyDecision::NeedsApproval]
                            +--------------------------+
                                         |
                                       (No)
                                         v
                            +--------------------------+
                            | Is Action Sensitive?     |
                            | (Target Execution, Mod,  |----(Yes)---> [PolicyDecision::NeedsApproval]
                            |  External Egress)        |
                            +--------------------------+
                                         |
                                       (No)
                                         v
                            +--------------------------+
                            | Within Budget Limits?    |----(No)----> [PolicyDecision::Denied]
                            +--------------------------+
                                         |
                                       (Yes)
                                         v
                            [PolicyDecision::Granted]
```

### Policy decision rules

1. **Root Confinement:** Any operation attempting to access paths outside the canonical `WorkspaceRoot` is immediately `Denied`.
2. **Action Sensitivity Matrix:**
   - *Metadata Discovery:* Auto-authorized if path is within root.
   - *Untrusted Target Execution:* Requires dedicated VM capability AND operator approval. (Under Phase 1, denied by fail-closed backend).
   - *Working Tree Modification:* Always requires human approval.
   - *External Network Egress:* Always requires human approval.
3. **Approval Binding:** Approvals are strictly cryptographic or token-bound to `(ActionDigest, TargetRevision, SessionId, Expiry)`. An approval granted for commit $A$ is automatically invalid for commit $B$.

---

## 6. Workspace Security Boundary (V-04, S-11, Q-05)

The workspace boundary isolates Sentra from hostile path structures on the host operating system.

### Path canonicalization rules
- Paths are canonicalized at session initialization using OS final path APIs (`GetFinalPathNameByHandleW` on Windows).
- All relative paths are evaluated strictly against the canonical root.
- Paths containing the following patterns are immediately **quarantined**:
  - Null bytes (`\0`)
  - Directory traversal sequences (`..`, `../`, `..\`)
  - Alternate Data Streams (Windows `::$DATA`)
  - DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`)

### Symlink and junction quarantine policy
- By default, symlinks and Windows NTFS directory junctions pointing outside the `WorkspaceRoot` are quarantined and recorded in `ProjectDiscoveryReport.quarantined_paths`.
- Target files are never opened across external symlink boundaries.
- Target build scripts (`build.rs`, `Makefile`, `configure`, lifecycle scripts) are **strictly forbidden from executing** during file discovery (F-01).

### Scale test strategy (Q-05)
- Requirement Q-05 requires completing metadata-only discovery of a 10,000-file / 100-MiB repository within **30 seconds and <= 512 MiB peak RSS**.
- Strategy:
  - Utilize non-recursive, bounded directory iterators.
  - Avoid pre-buffering all file paths into memory; stream metadata directly into SQLite or bounded buffers.
  - Benchmark using an isolated synthetic repository containing 10,000 generated files with varied directory depths and Unicode names.

---

## 7. SQLite Transaction and Recovery Rules (V-02, V-05, Q-04)

Core Engine persistence directly incorporates the empirical findings from Phase 1 Milestone 2:

```
[Write Transaction Begins: BEGIN IMMEDIATE]
                   |
                   v
         [Execute SQL Statements]
                   |
     +-------------+-------------+
     |                           |
  (Error)                     (Success)
     |                           |
     v                           v
[Statement Error?]         [Commit OK?]
     |                           |
   (Yes)                       (Yes)
     |                           |
     v                           v
[EXPLICIT ROLLBACK]       [Transaction Done]
(Do not leave live tx)
```

### Normative persistence rules
1. **Explicit Rollback on Statement Failure:** SQLite statement failures (such as constraint violations) do not roll back the transaction automatically. Core Engine repositories must issue an explicit `ROLLBACK` immediately upon receiving any statement execution error.
2. **`SQLITE_BUSY_SNAPSHOT` Recovery Protocol:** When SQLite returns error code 517 (`SQLITE_BUSY_SNAPSHOT`), retrying statements on the same WAL read transaction will repeatedly fail. The repository must:
   - Roll back the entire active transaction.
   - Wait with exponential backoff (10ms to 200ms).
   - Re-open a fresh transaction (refreshing the WAL read view).
   - Re-attempt the write operation up to a maximum of 5 attempts.
3. **Write Concurrency:** All write transactions must use `BEGIN IMMEDIATE` to obtain the write lock at the start of the transaction, preventing read-to-write upgrade deadlocks.
4. **WAL Lifecycle and Checkpoints:** The database operates in `PRAGMA journal_mode=WAL` with `PRAGMA synchronous=FULL`. Explicit checkpointing (`PRAGMA wal_checkpoint(TRUNCATE)`) is executed on session completion and clean engine shutdown.
5. **Recovery Reconciliation:** Upon startup, the engine scans the evidence table against the filesystem blob directory. Uncommitted or orphaned blob files are pruned.

---

## 8. Provider Gateway Contract (F-15, S-06)

Core Engine incorporates the mock-validated contract from Milestone 3:

1. **Provider Neutrality:** The Core Engine domain code depends solely on `ProviderGateway`. It has zero coupling to specific vendor SDKs or HTTP libraries.
2. **AI is Strictly Optional:** If no provider is configured, `sentra` operates in deterministic mode. Discovery, policy evaluation, reporting, and static evidence handling function completely without AI.
3. **Structured Validation (`DecisionV1`):** All model inference expecting structured findings must validate output against strict typed objects. Malformed responses are rejected without silent fallback to text.
4. **Conservative Accounting:** Maximum token/cost ceilings are reserved prior to dispatch. If a request times out or cancellation cannot be confirmed by the provider, the budget reservation remains held to prevent overspend.

---

## 9. Fail-Closed Execution Architecture (ADR-0004, S-07, S-14)

In compliance with the **Conditional Go** mandate from Milestone 4 closure review:

```
                       [Task Execution Dispatch]
                                  |
                                  v
                      +------------------------+
                      | Is Scope Synthetic     |----(Yes)---> [Execute Curated Fixture]
                      | Fixture in Unit Test?  |              (Maintainer Signed Only)
                      +------------------------+
                                  |
                                (No)
                                  v
                      +------------------------+
                      | Dedicated Hyper-V VM   |----(Yes)---> [Dispatch to VM Worker]
                      | Validated & Authorized?|              (PHASE 2 TARGET - UNTESTED)
                      +------------------------+
                                  |
                                (No)
                                  v
                     [FAIL-CLOSED INTERCEPTION]
             Return Err(BackendUnavailable: Untrusted execution
                     disabled pending Phase 2 validation)
```

### Non-negotiable execution constraints
- **`FailClosedBackend` is the default backend.** Any dispatch request for untrusted workloads returns `Err(ExecutionBackendError::BackendUnavailable)`.
- **No Host Execution Fallback:** The Core Engine strictly prohibits falling back to host child processes (`std::process::Command`) to run target builds, tests, or scanners.
- **No Docker/WSL2 Fallback:** The Core Engine will not dispatch untrusted workloads to local Docker or WSL2 instances.
- **Accidental Execution Prevention:** The `ExecutionBackend` trait signature requires passing `ExecutionScope`. Passing `UntrustedTargetWorkload` automatically triggers fail-closed error handling in the current foundation.

---

## 10. Evidence Verification Boundary (ADR-0006, S-09, S-13)

The Evidence Verifier establishes a verifiable trust boundary for all artifacts entering Sentra:

```
                  [Raw Artifact Payload from Worker]
                                  |
                                  v
                      +------------------------+
                      | Exceeds Size Bound?    |----(Yes)---> [Reject: OversizedPayload]
                      | (Max 50 MiB)           |
                      +------------------------+
                                  |
                                (No)
                                  v
                      +------------------------+
                      | Compute SHA-256 Digest |
                      | Digest == Declared?    |----(No)----> [Reject: DigestMismatch]
                      +------------------------+
                                  |
                                (Yes)
                                  v
                      +------------------------+
                      | Valid Schema & Syntax? |----(No)----> [Reject: MalformedEnvelope]
                      +------------------------+
                                  |
                                (Yes)
                                  v
                     [ADMISSION TO EVIDENCE REPO]
                      (Cryptographic Proof Logged)
```

### Integrity vs. semantic correctness distinction
- **Transit Integrity:** The SHA-256 check proves that the payload was not truncated, corrupted, or altered during transmission between the worker and the host.
- **Semantic Correctness:** The SHA-256 check **does not prove** that the tool output is true or that target code did not manipulate the finding before hashing. Semantic verification requires independent oracle execution or human review per ADR-0006.

---

## 11. Dependency and Technology Review

The Core Engine Foundation must build completely offline on Windows 11 with the existing MSVC toolchain, introducing only minimal, audited dependencies.

### Dependency evaluation

| Proposed Crate | Purpose | License | Maintenance & Offline Build | Decision |
| --- | --- | --- | --- | --- |
| `rusqlite` (v0.31+, `bundled`) | SQLite database binding | MIT | Compiles embedded SQLite from amalgamated C source using MSVC. Zero external DLL dependencies. | **Recommended** |
| `serde` & `serde_json` | Serialization of domain events, manifests, and envelopes | MIT / Apache-2.0 | De facto Rust standard. Zero unsafe in default configuration. Offline compatible. | **Recommended** |
| `sha2` | Pure Rust SHA-256 hashing for evidence verifier | MIT / Apache-2.0 | Pure Rust implementation of SHA-256. Zero native dependencies. | **Recommended** |
| `uuid` (`v4`, `serde`) | Type-safe session, task, and artifact identifiers | MIT / Apache-2.0 | Minimal footprint, standard cryptographic RNG support. | **Recommended** |
| `chrono` (`serde`) | Bounded UTC timestamping for audit trails | MIT / Apache-2.0 | Standard time library for deterministic UTC formatting. | **Recommended** |

### Explicitly rejected dependencies for Increment 5
- **`tokio` / `async-std`:** Rejected. Introducing an asynchronous runtime introduces complexity, thread-pool scheduling races, and cancellation pitfalls. Core Engine Foundation is synchronous and thread-safe.
- **`diesel` / `sqlx`:** Rejected. ORMs introduce compile-time complexity and query opacity. Direct parameterized SQL with `rusqlite` is predictable and matches Milestone 2 recovery rules.
- **`reqwest` / `hyper`:** Rejected. No external HTTP networking is permitted in Core Engine Foundation. AI providers in Phase 1 use the mock adapter.

---

## 12. Threat Boundaries and Unresolved Risks

| Threat / Risk | Mitigating Boundary in Design | Unresolved Risk / Phase Gate |
| --- | --- | --- |
| **Path Traversal via Malicious Symlinks** | `WorkspaceBoundary` canonicalizes paths and quarantines all external symlinks (V-04). | Complex NTFS hard links and volume mounts require thorough Windows fixture testing. |
| **Host Code Execution via Target Build Scripts** | File discovery is strictly metadata-only. Target build scripts are never executed (F-01). | Developers accidentally invoking target tooling via external scripts (mitigated by strict API separation). |
| **Tampered Finding Reports from Compromised Guest** | Evidence verifier validates envelopes; independent verifier requires clean baseline-fails/patched-passes execution (ADR-0006). | Guest worker supervisor isolation must be validated in Phase 2. |
| **SQLite WAL Lock Deadlocks under Crash** | Explicit rollback handling, `BEGIN IMMEDIATE`, and WAL checkpointing prevent poisoned locks. | Hard power-fault durability on physical disk remains untested (recorded in Milestone 2). |
| **Unchecked Model Output Injection** | `DecisionV1` typed validation rejects arbitrary model output structures. | Advanced prompt-injection evasion remains an active research topic (Phase 2 testing). |

---

## 13. Increment 5 Implementation Breakdown

To ensure incremental verification and maintain repository integrity, Increment 5 (Core Engine Foundation) is structured into five sequential, dependency-ordered sub-increments:

```
[Increment 5.1: Architecture & Contracts (CURRENT DELIVERABLE)]
                           |
                           v
[Increment 5.2: Domain Models, Session State Machine & Policy Engine]
                           |
                           v
[Increment 5.3: Workspace Boundary, Path Quarantine & Discovery (V-04)]
                           |
                           v
[Increment 5.4: SQLite Persistence Layer & WAL Recovery (V-05)]
                           |
                           v
[Increment 5.5: Fail-Closed Execution Backend & Evidence Verifier]
                           |
                           v
[Increment 5.6: Integrated Core Service & CLI-Ready Test Harness]
```

---

## 14. Acceptance Criteria for Implementation Sub-Increments

### Sub-increment 5.2 — Domain models, session state & policy engine
- All core types (`SessionId`, `SessionState`, `SessionMetadata`, `AuditEvent`, `PolicyDecision`, `ApprovalRequest`) implemented and tested.
- Session state machine enforces valid transitions and rejects invalid transitions with typed errors.
- Policy engine defaults to deny and correctly issues `NeedsApproval` for sensitive actions.
- Approvals verify action digests, revision hashes, and expiration timestamps.
- Zero external network calls; 100% offline unit tests.

### Sub-increment 5.3 — Workspace boundary & file discovery (V-04, Q-05)
- Strict canonical root validation implemented using Windows API path canonicalization.
- Path traversal sequences (`..`), null bytes, alternate data streams, and DOS device names rejected.
- External symlinks and NTFS junctions quarantined without traversing targets.
- Discovery limits (max files, max bytes, max depth) enforced deterministically.
- Synthetic 10,000-file scale test demonstrates discovery in <= 30 seconds and <= 512 MiB RSS (Q-05).

### Sub-increment 5.4 — SQLite persistence & recovery (V-05, Q-04)
- SQLite database initialized with WAL journal mode and `synchronous=FULL`.
- Session, audit event, approval, and evidence tables created with versioned schemas.
- Explicit rollback executed on all statement-level errors.
- `SQLITE_BUSY_SNAPSHOT` handled via full transaction rollback, fresh read view, and bounded backoff.
- Startup reconciliation identifies and prunes unreferenced blob files.

### Sub-increment 5.5 — Fail-closed execution backend & evidence verifier (ADR-0004, ADR-0006)
- `ExecutionBackend` trait defined with mandatory `ExecutionScope`.
- `FailClosedBackend` rejects all untrusted workload dispatch with `Err(BackendUnavailable)`.
- Host execution and Docker/WSL2 execution strictly unavailable for untrusted targets.
- Evidence verifier independently computes SHA-256 and verifies envelope length and media types.
- Corrupted or mismatched evidence envelopes rejected with typed verification errors.

### Sub-increment 5.6 — Integrated core service & harness
- Unified `CoreEngine` struct orchestrates session, workspace, policy, persistence, provider, and execution.
- Deterministic end-to-end integration test runs entirely offline with synthetic fixtures.
- CLI-ready API exposed for Phase 1 Increment 6 (CLI Foundation).
- Formatting, documentation tests, and warning-free Clippy pass on Windows MSVC x64.
