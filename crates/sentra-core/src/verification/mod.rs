//! Verification bundle lifecycle, disposable worker containment, and benchmark evaluation (REQ-F12, REQ-F13, REQ-F14, Verification Specification).

pub mod bundle;
pub mod corpus;
pub mod worker;

pub use bundle::{
    AttemptDenominator, PatchVerificationOutcome, TestRunEvidence, TestStatus, VerificationBundle,
    VerificationInput,
};
pub use corpus::{
    ChangeCase, ChangeCaseCategory, ConfusionMatrix, CorpusEvaluationReport, evaluate_corpus,
    reference_20_case_corpus,
};
pub use worker::{
    ContainmentLevel, EgressPolicy, WorkerArchitecture, WorkerError, WorkerErrorKind,
    WorkerProfile, WorkerReadinessReport, WorkerResourceCaps,
};
