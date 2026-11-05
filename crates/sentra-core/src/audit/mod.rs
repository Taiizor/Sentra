//! Immutable audit trail events and category payloads.

/// Audit trail event definitions and category payloads.
pub mod event;

pub use event::{AuditEvent, AuditEventKind};
