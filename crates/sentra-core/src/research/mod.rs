//! Deep security research campaigns, Scout/Analyst task fanout, coverage ledgers, and anti-collusion boundaries (REQ-F04, REQ-S06, REQ-S08, Roadmap Phase 3).

pub mod campaign;
pub mod coverage;
pub mod error;
pub mod hypothesis;
pub mod role;

pub use campaign::{
    Campaign, CampaignLimits, CampaignStatus, CampaignStopReason, CampaignTask, ResearchTaskStatus,
};
pub use coverage::{CoverageLedger, CoverageSummary, CoveredRegion, SkipReason, SkippedRegion};
pub use error::{ResearchError, ResearchErrorKind};
pub use hypothesis::{Hypothesis, HypothesisDeduplicator, HypothesisStatus, VulnerabilityCategory};
pub use role::{
    ResearchRole, RoleCapability, assert_patch_verifier_independent, assert_peer_approval_forbidden,
};
