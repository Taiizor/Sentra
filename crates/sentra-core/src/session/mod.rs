//! Session lifecycle, metadata, and state machine management.

/// Deterministic session lifecycle state machine.
pub mod machine;
/// Session metadata record and boundary invariants.
pub mod metadata;
/// Canonical session states, completeness metrics, and operating modes.
pub mod state;

pub use machine::SessionStateMachine;
pub use metadata::SessionMetadata;
pub use state::{AssessmentCompleteness, OperatingMode, SessionState};
