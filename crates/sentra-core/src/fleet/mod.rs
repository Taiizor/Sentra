//! Remote-worker fleet management, multi-user hosting security audit, and target matrix (REQ-F19, ADR-0004).

/// Multi-user hosting security assessment and independent readiness audit.
pub mod audit;
/// Fleet management and target matrix error types.
pub mod error;
/// High-level worker fleet manager coordinating leases, heartbeats, and sanitization.
pub mod manager;
/// Supported-target matrix and capability tuple declarations.
pub mod matrix;
/// Remote execution worker nodes, states, and isolation profiles.
pub mod worker;

pub use audit::{AuditStatus, MultiUserAuditReport, MultiUserSecurityAudit};
pub use error::{FleetError, FleetErrorKind};
pub use manager::WorkerFleetManager;
pub use matrix::{
    AdapterActionCapability, EvidenceMethod, HostPlatform, SupportMatrix, SupportedTargetTuple,
    TargetLanguage,
};
pub use worker::{RemoteWorkerId, RemoteWorkerNode, WorkerState};
