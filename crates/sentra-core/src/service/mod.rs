//! Integrated Core Service coordination foundation.
//!
//! Exposes the high-level application boundary orchestrating session state machines,
//! workspace canonical boundaries, default-deny policy enforcement, durable SQLite
//! persistence, fail-closed execution boundaries, and host-side evidence verification.

mod config;
mod core;
mod error;
pub mod harness;
mod lifecycle;
mod local_workspace;

pub use config::CoreServiceConfig;
pub use core::{
    AdmitResultRequest, CoreService, ServicePolicyDecision, TaskExecutionReport,
    TaskExecutionRequest,
};
pub use error::{ExecutionOutcomeError, ServiceError, ServiceErrorKind, ServicePrimaryError};
pub use harness::{CoreServiceHarness, HarnessDirectory};
pub use lifecycle::{
    CancellationPhase, CancellationReason, CancellationReport, ReconciledAttempt,
    SessionResumeReport,
};
pub use local_workspace::{
    LocalAuditReport, LocalScanReport, LocalSessionSummary, LocalWorkspace, LocalWorkspaceError,
    LocalWorkspaceErrorKind, LocalWorkspaceReport,
};
