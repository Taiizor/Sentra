//! Local SQLite storage and durable approval/audit/budget primitives.
//!
//! A successful storage transition is not a target execution capability. The
//! trusted controller owns context registration/issuance and must establish real
//! workspace/revision identity. No provider, filesystem mutation or network side
//! effect is permitted inside retryable database operations.
//!
//! Untrusted callers cannot supply retryable side-effect closures:
//! ```compile_fail
//! use sentra_core::persistence::SqliteConnectionManager;
//! fn inject(manager: &SqliteConnectionManager) {
//!     manager.write(|_| { std::fs::write("forbidden", b"side effect").unwrap(); Ok(()) });
//! }
//! ```
//! A serialized row or copied identifier cannot create a trusted receipt:
//! ```compile_fail
//! use sentra_core::persistence::PersistentApprovalGrant;
//! let forged: PersistentApprovalGrant = serde_json::from_str("{}").unwrap();
//! ```
//! Consumers cannot construct an issuance/recovery authority:
//! ```compile_fail
//! use sentra_core::persistence::{PersistenceRepository, PersistentApprovalAuthority};
//! fn forge(repository: PersistenceRepository) -> PersistentApprovalAuthority {
//!     PersistentApprovalAuthority { repository }
//! }
//! ```
//! Nor can callers forge or mutate the authoritative execution context:
//! ```compile_fail
//! use sentra_core::{SessionId, persistence::ExecutionContext};
//! fn redirect(context: &mut ExecutionContext) {
//!     context.session.session_id = SessionId::new();
//! }
//! ```

mod connection;
mod error;
mod migration;
mod model;
mod repository;
mod transaction;

pub use connection::{
    CheckpointResult, ForeignKeyViolation, IntegrityReport, QuarantineReport,
    SqliteConnectionManager, SqliteSettings,
};
pub use error::{PersistenceError, PersistenceErrorKind};
pub use model::{
    ApprovalIntent, AuditRecord, BudgetRecord, ConsumptionRecord, PersistentApprovalGrant,
    SessionRecord, SettlementStatus, TransitionRecord,
};
pub use repository::{
    ExecutionContext, ExecutionPreview, PersistenceRepository, PersistentApprovalAuthority,
    PrepareExecutionRequest, PreparedExecution,
};
