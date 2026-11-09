//! Static Application Security Testing (SAST) and Secret Scanner Engine (REQ-F05, REQ-F07).

pub mod rule;
pub mod scanner;
pub mod taint;

pub use rule::{BUILTIN_RULES, RuleCategory, SastRule, find_rule_by_id};
pub use scanner::{MAX_SCANNABLE_FILE_BYTES, SastMatch, SastReport, SastScanner};
pub use taint::{
    TaintAnalysisEngine, TaintFlowStep, TaintSinkKind, TaintSourceKind, TaintStepRole,
    TaintVulnerability,
};
