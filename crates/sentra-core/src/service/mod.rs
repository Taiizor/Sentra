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

pub use config::CoreServiceConfig;
pub use core::{CoreService, ServicePolicyDecision, TaskExecutionReport, TaskExecutionRequest};
pub use error::{ServiceError, ServiceErrorKind};
pub use harness::{CoreServiceHarness, HarnessDirectory};
pub use lifecycle::{CancellationPhase, CancellationReason, CancellationReport};
