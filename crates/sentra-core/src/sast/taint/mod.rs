//! In-Engine Pure-Rust Taint Analysis and Data-Flow Tracking Module (REQ-F05, REQ-F07).

pub mod engine;
pub mod model;

pub use engine::TaintAnalysisEngine;
pub use model::{TaintFlowStep, TaintSinkKind, TaintSourceKind, TaintStepRole, TaintVulnerability};
