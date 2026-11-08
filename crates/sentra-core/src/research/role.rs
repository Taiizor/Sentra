//! Agent research roles, capability contracts, and anti-collusion boundaries (REQ-F04, REQ-S08, Roadmap Phase 3).

use serde::{Deserialize, Serialize};

use crate::{domain::id::TaskId, research::error::ResearchError};

/// Specific capabilities that can be exercised during security research campaigns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleCapability {
    /// Read scoped source code and context within authorized workspace boundaries.
    ReadContext,
    /// Propose a ranked audit target or security-sensitive entrypoint.
    ProposeAuditTarget,
    /// Report a coverage gap or unreachable/unbuildable target region.
    ReportCoverageGap,
    /// Form a falsifiable vulnerability hypothesis.
    FormHypothesis,
    /// Request a targeted reproduction or sandbox execution task.
    RequestReproductionTask,
    /// Request a bounded tool execution task (e.g. static scanner or fuzzer).
    RequestToolTask,
    /// Propose a minimal proof-of-concept (PoC) harness.
    ProposePoCHarness,
    /// Propose a candidate patch overlay diff against an immutable source digest.
    ProposePatchOverlay,
    /// Suggest regression test cases for a proposed fix.
    SuggestRegressionCases,
    /// Execute clean verification in an isolated worker against unpatched and patched targets.
    ExecuteVerification,
    /// Evaluate verification oracle results and recommend finding disposition.
    EvaluateOracle,
}

/// Specialized research agent roles operating under deterministic orchestrator controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRole {
    /// Surface reconnaissance: reads context and proposes ranked audit targets and coverage gaps.
    Scout,
    /// In-depth investigation: analyzes targets, forms hypotheses, and requests reproduction tasks.
    Analyst,
    /// Dynamic validation: creates reproduction harnesses and requests isolated worker runs.
    Validator,
    /// Patch generation: creates overlay diffs and suggests regression cases against fixed source digests.
    PatchAuthor,
    /// Independent verification: reviews oracles, runs clean dual-state checks, and recommends disposition.
    IndependentVerifier,
}

impl ResearchRole {
    /// Returns the name of the role as a static string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Scout => "scout",
            Self::Analyst => "analyst",
            Self::Validator => "validator",
            Self::PatchAuthor => "patch_author",
            Self::IndependentVerifier => "independent_verifier",
        }
    }

    /// Returns the set of capabilities permitted for this role.
    pub fn allowed_capabilities(&self) -> &'static [RoleCapability] {
        match self {
            Self::Scout => &[
                RoleCapability::ReadContext,
                RoleCapability::ProposeAuditTarget,
                RoleCapability::ReportCoverageGap,
            ],
            Self::Analyst => &[
                RoleCapability::ReadContext,
                RoleCapability::FormHypothesis,
                RoleCapability::RequestReproductionTask,
                RoleCapability::RequestToolTask,
            ],
            Self::Validator => &[
                RoleCapability::ReadContext,
                RoleCapability::ProposePoCHarness,
                RoleCapability::RequestReproductionTask,
            ],
            Self::PatchAuthor => &[
                RoleCapability::ReadContext,
                RoleCapability::ProposePatchOverlay,
                RoleCapability::SuggestRegressionCases,
            ],
            Self::IndependentVerifier => &[
                RoleCapability::ReadContext,
                RoleCapability::ExecuteVerification,
                RoleCapability::EvaluateOracle,
            ],
        }
    }

    /// Checks whether this role is permitted to exercise the specified capability.
    pub fn can_perform(&self, capability: RoleCapability) -> bool {
        self.allowed_capabilities().contains(&capability)
    }

    /// Asserts that this role can perform the given capability, returning `ResearchError` if forbidden.
    pub fn assert_can_perform(&self, capability: RoleCapability) -> Result<(), ResearchError> {
        if self.can_perform(capability) {
            Ok(())
        } else {
            Err(ResearchError::role_capability_violation(
                self.as_str(),
                format!("{capability:?}"),
            ))
        }
    }
}

/// Enforces the strict rule that a patch author cannot verify or approve their own patch (REQ-S08).
///
/// Requires distinct task identifiers and mandates that the verifier role is `IndependentVerifier`.
pub fn assert_patch_verifier_independent(
    author_role: ResearchRole,
    verifier_role: ResearchRole,
    author_task: TaskId,
    verifier_task: TaskId,
) -> Result<(), ResearchError> {
    if author_task == verifier_task {
        return Err(ResearchError::patch_author_cannot_verify());
    }

    if author_role == ResearchRole::IndependentVerifier {
        return Err(ResearchError::new(
            crate::research::error::ResearchErrorKind::PatchAuthorCannotVerifySelf,
            "An independent verifier cannot author a patch candidate",
        ));
    }

    if verifier_role != ResearchRole::IndependentVerifier {
        return Err(ResearchError::new(
            crate::research::error::ResearchErrorKind::PatchAuthorCannotVerifySelf,
            format!(
                "Verifier must be IndependentVerifier, but got role '{}'",
                verifier_role.as_str()
            ),
        ));
    }

    Ok(())
}

/// Enforces anti-collusion rule: Model-controlled roles cannot approve peer work (Roadmap Phase 3).
///
/// Specifically:
/// - A Scout cannot approve an Analyst.
/// - An Analyst cannot approve a Scout or another Analyst.
/// - Only deterministic host policy / independent verifier / human operator can authorize actions.
pub fn assert_peer_approval_forbidden(
    proposer: ResearchRole,
    approver: ResearchRole,
) -> Result<(), ResearchError> {
    match (proposer, approver) {
        (ResearchRole::Scout, ResearchRole::Analyst)
        | (ResearchRole::Analyst, ResearchRole::Scout)
        | (ResearchRole::Analyst, ResearchRole::Analyst)
        | (ResearchRole::Scout, ResearchRole::Scout)
        | (ResearchRole::Validator, ResearchRole::Analyst)
        | (ResearchRole::PatchAuthor, ResearchRole::Analyst) => Err(
            ResearchError::peer_approval_forbidden(proposer.as_str(), approver.as_str()),
        ),
        _ => Ok(()),
    }
}
