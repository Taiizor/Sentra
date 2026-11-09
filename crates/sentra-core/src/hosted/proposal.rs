//! Draft PR proposals, immutable revision binding, stale-head defense, and publication guards
//! (REQ-F18, THREAT_MODEL T-11, S-10, Hosted Integration Specification).

use crate::{
    common::crypto::sha256_digest,
    hosted::{
        error::{WebhookError, WebhookErrorKind},
        event::validate_commit_sha,
    },
};

/// Lifecycle status of an automated remediation proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProposalStatus {
    /// Proposal created in draft status awaiting human review.
    DraftProposed,
    /// Human operator has explicitly admitted and approved this proposal.
    ApprovedByHuman,
    /// Rejected due to branch head divergence / force-push.
    RejectedStaleHead,
    /// Rejected due to missing or unverifiable merge base.
    RejectedMissingMergeBase,
    /// Rejected because the verification bundle was generated against an older revision.
    RejectedStaleVerification,
}

/// Automated remediation proposal bound to exact immutable commit revisions.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DraftPrProposal {
    /// Deterministic SHA-256 identifier derived from proposal parameters.
    pub proposal_id: String,
    /// Target repository identifier (e.g. `owner/repo`).
    pub target_repo: String,
    /// Immutable base commit SHA.
    pub base_sha: String,
    /// Exact verified commit SHA against which the remediation was verified.
    pub verified_head_sha: String,
    /// Unified diff patch content.
    pub patch_diff: String,
    /// Technical rationale and vulnerability mitigation explanation.
    pub rationale: String,
    /// Human approval ticket if explicit operator review was admitted.
    pub human_approval_ticket: Option<String>,
    /// Invariant: Always true; Sentra NEVER merges or deploys autonomously.
    pub is_draft_only: bool,
    /// Current lifecycle status.
    pub status: ProposalStatus,
}

impl DraftPrProposal {
    /// Creates a new draft PR proposal bound to exact, immutable commit revisions.
    pub fn new(
        target_repo: impl Into<String>,
        base_sha: &str,
        verified_head_sha: &str,
        patch_diff: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Result<Self, WebhookError> {
        let base_valid = validate_commit_sha(base_sha)?;
        let head_valid = validate_commit_sha(verified_head_sha)?;

        let target_repo = target_repo.into();
        let patch_diff = patch_diff.into();
        let rationale = rationale.into();

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(target_repo.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(base_valid.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(head_valid.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(patch_diff.as_bytes());

        let proposal_id = format!("prop-{}", &sha256_digest(&id_payload)[..16]);

        Ok(Self {
            proposal_id,
            target_repo,
            base_sha: base_valid,
            verified_head_sha: head_valid,
            patch_diff,
            rationale,
            human_approval_ticket: None,
            is_draft_only: true, // Strict invariant
            status: ProposalStatus::DraftProposed,
        })
    }

    /// Grants human operator approval for this proposal using an admission ticket.
    pub fn admit_human_approval(&mut self, ticket: impl Into<String>) {
        self.human_approval_ticket = Some(ticket.into());
        self.status = ProposalStatus::ApprovedByHuman;
    }

    /// Validates whether this proposal is permitted to be published as a draft PR.
    ///
    /// Enforces:
    /// 1. Must be in `ApprovedByHuman` status.
    /// 2. Must hold an admitted `human_approval_ticket`.
    /// 3. Cannot request autonomous merge (`is_draft_only` must be true).
    pub fn assert_can_publish(&self) -> Result<(), WebhookError> {
        if !self.is_draft_only {
            return Err(WebhookError::new(
                WebhookErrorKind::PolicyDenied,
                "Autonomous merge or non-draft PR creation is strictly prohibited",
            ));
        }

        if self.human_approval_ticket.is_none() || self.status != ProposalStatus::ApprovedByHuman {
            return Err(WebhookError::human_approval_required(format!(
                "Draft PR publication for proposal '{}'",
                self.proposal_id
            )));
        }

        Ok(())
    }
}

/// Defense guards verifying revision freshness, force-push absence, and merge-base integrity.
pub struct StaleHeadGuard;

impl StaleHeadGuard {
    /// Asserts that the current repository branch head matches the proposal's verified head SHA.
    ///
    /// Fails with `StaleHeadDivergence` if a force-push or new commit moved the branch head.
    pub fn verify_head_freshness(
        current_head_sha: &str,
        proposal_head_sha: &str,
    ) -> Result<(), WebhookError> {
        let cur = validate_commit_sha(current_head_sha)?;
        let prop = validate_commit_sha(proposal_head_sha)?;

        if cur != prop {
            return Err(WebhookError::stale_head(format!(
                "Branch head has diverged (current '{cur}' != proposal '{prop}'). Stale proposal rejected."
            )));
        }
        Ok(())
    }

    /// Asserts that a common merge base between base and head is present and verified.
    ///
    /// Fails with `MissingMergeBase` if the history has diverged or merge base is absent.
    pub fn verify_merge_base(merge_base_sha: Option<&str>) -> Result<String, WebhookError> {
        match merge_base_sha {
            Some(sha) if !sha.trim().is_empty() => validate_commit_sha(sha),
            _ => Err(WebhookError::missing_merge_base(
                "Missing or unverifiable common merge base between base and head revisions",
            )),
        }
    }

    /// Asserts that a patch verification bundle was computed against the exact current head revision.
    ///
    /// Under hosted integration requirements: "Stale verification blocks publication."
    pub fn verify_verification_bundle_freshness(
        bundle_target_sha: &str,
        current_head_sha: &str,
    ) -> Result<(), WebhookError> {
        let bundle_sha = validate_commit_sha(bundle_target_sha)?;
        let cur_sha = validate_commit_sha(current_head_sha)?;

        if bundle_sha != cur_sha {
            return Err(WebhookError::stale_verification_blocks_publication(
                format!(
                    "Verification bundle was evaluated on '{bundle_sha}' but current head is '{cur_sha}'. Stale verification blocks publication."
                ),
            ));
        }
        Ok(())
    }

    /// Asserts that autonomous merge is strictly disallowed.
    pub fn assert_no_autonomous_merge(requested_merge: bool) -> Result<(), WebhookError> {
        if requested_merge {
            return Err(WebhookError::new(
                WebhookErrorKind::PolicyDenied,
                "Autonomous merge or automated deployment is permanently disallowed (Governance Policy)",
            ));
        }
        Ok(())
    }
}
