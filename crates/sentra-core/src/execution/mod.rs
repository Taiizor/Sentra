//! Fail-closed execution engine and backend contracts.
//!
//! In accordance with ADR-0004 and the Milestone 4 Conditional Go decision, untrusted
//! project code execution is strictly disabled pending validated disposable Hyper-V
//! isolation. The default backend is [`FailClosedBackend`], which rejects all untrusted
//! workload dispatch requests.

mod backend;
mod engine;
mod error;
mod model;
mod scope;

pub use backend::{ExecutionBackend, FailClosedBackend, SyntheticFixtureBackend};
pub use engine::ExecutionEngine;
pub use error::{ExecutionError, ExecutionErrorKind};
pub use model::{
    BackendCapabilities, DEFAULT_EXECUTION_TIMEOUT_MILLIS, ExecutionRequest, ExecutionResult,
    ExecutionStatus, MAX_EXECUTION_TIMEOUT_MILLIS, MAX_MEMORY_LIMIT_BYTES, MAX_OUTPUT_LIMIT_BYTES,
    ResourceLimits, ResourceUsage,
};
pub use scope::ExecutionScope;
