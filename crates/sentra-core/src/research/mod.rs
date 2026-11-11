//! Deep security research campaigns, Scout/Analyst task fanout, coverage ledgers, and anti-collusion boundaries (REQ-F04, REQ-S06, REQ-S08, Autonomous Research Specification).

pub mod attack_tree;
pub mod campaign;
pub mod coverage;
pub mod error;
pub mod fuzzing;
pub mod hypothesis;
pub mod prompt;
pub mod role;
pub mod stride;

pub use attack_tree::{
    AttackAttributes, AttackDifficulty, AttackNode, CostTier, DetectionRisk, NodeType,
};
pub use campaign::{
    Campaign, CampaignLimits, CampaignStatus, CampaignStopReason, CampaignTask, ResearchTaskStatus,
};
pub use coverage::{CoverageLedger, CoverageSummary, CoveredRegion, SkipReason, SkippedRegion};
pub use error::{ResearchError, ResearchErrorKind};
pub use fuzzing::{
    ApproachRunMetrics, ApproachSummary, CrashArtifact, FuzzEngine, FuzzRunConfig, FuzzTarget,
    ReferenceCrashTarget, ResearchApproach, SanitizerType, TriMethodComparisonMatrix,
    generate_reference_tri_method_matrix, minimize_input, reference_root_cause_targets,
};
pub use hypothesis::{Hypothesis, HypothesisDeduplicator, HypothesisStatus, VulnerabilityCategory};
pub use prompt::{
    AgentSkillAuditPromptBuilder, ApiSecurityPromptBuilder, AppSecPersona, AppSecPrompt,
    BolaAuditResponse, PatchSynthesisPromptBuilder, ScoutPromptBuilder, SkillPromptComposer,
    SkillPromptError, SkillSafetyResponse, StructuredResponseParser, ThreatModelingPromptBuilder,
    ThreeTierPatchResponse, VerificationPromptBuilder,
};
pub use role::{
    ResearchRole, RoleCapability, assert_patch_verifier_independent, assert_peer_approval_forbidden,
};
pub use stride::{
    ControlFamily, ControlLayer, ControlType, SecurityMitigation, StrideCategory,
    ThreatMitigationMapping,
};
