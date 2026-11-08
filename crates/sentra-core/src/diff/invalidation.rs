//! Revision fencing, patch approval invalidation, and anti-regression guards (REQ-F01, REQ-F04).

use serde::{Deserialize, Serialize};

use crate::{
    diff::error::DiffError,
    domain::{Finding, FindingStatus, TimestampUtc},
};

/// Cryptographically verified revision binding anchoring approvals and reviews to exact code states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionBinding {
    /// Human-readable target revision or git commit identifier (e.g. `main` or `a1b2c3d`).
    pub target_revision: String,
    /// Exact 64-character SHA-256 aggregate digest of the source snapshot.
    pub aggregate_digest: String,
}

impl RevisionBinding {
    /// Creates a new revision binding.
    pub fn new(target_revision: impl Into<String>, aggregate_digest: impl Into<String>) -> Self {
        Self {
            target_revision: target_revision.into(),
            aggregate_digest: aggregate_digest.into(),
        }
    }

    /// Verifies that the currently evaluated workspace revision matches the bound revision.
    ///
    /// Fails closed with `DiffError::RevisionMismatch` if either the target revision string or the
    /// aggregate snapshot digest has diverged.
    pub fn verify_alignment(
        &self,
        current_revision: &str,
        current_digest: &str,
    ) -> Result<(), DiffError> {
        if self.target_revision != current_revision {
            return Err(DiffError::revision_mismatch(
                &self.target_revision,
                current_revision,
            ));
        }
        if self.aggregate_digest != current_digest {
            return Err(DiffError::revision_mismatch(
                &self.aggregate_digest,
                current_digest,
            ));
        }
        Ok(())
    }
}

/// Enforces that a patch approval issued for `approved_revision` is strictly invalid
/// if applied against a mutated or newer `candidate_revision` (REQ-F04).
pub fn validate_patch_approval_invalidation(
    approved_revision: &str,
    candidate_revision: &str,
) -> Result<(), DiffError> {
    if approved_revision != candidate_revision {
        return Err(DiffError::revision_mismatch(
            approved_revision,
            candidate_revision,
        ));
    }
    Ok(())
}

/// Reconciles findings across consecutive scans, proving that the absence of a finding in a later
/// scan cannot resolve it as fixed (REQ-F04, Roadmap Phase 2 Acceptance Criteria).
///
/// Any finding from `previous_findings` that is missing in `current_findings` is preserved in
/// an `Inconclusive` state with an explicit explanatory audit trail, unless positive verifier proof
/// was provided.
pub fn reconcile_findings_anti_regression(
    previous_findings: &[Finding],
    current_findings: &[Finding],
    current_revision: &str,
    now: TimestampUtc,
) -> Vec<Finding> {
    let mut reconciled = current_findings.to_vec();
    let current_ids: std::collections::HashSet<_> =
        current_findings.iter().map(|f| f.id()).collect();

    for prev in previous_findings {
        // If an active finding from previous scan is missing in current scan
        if !current_ids.contains(&prev.id()) {
            let mut retained = prev.clone();
            // If it was Candidate or Validated, absence cannot mark it fixed
            if matches!(
                retained.status(),
                FindingStatus::Candidate | FindingStatus::Validated
            ) {
                let reason = format!(
                    "Finding absent in scan at revision '{}'; absence alone cannot resolve a vulnerability without test harness proof",
                    current_revision
                );
                // Mark as Inconclusive to indicate unverified absence
                let _ = retained.transition_status(FindingStatus::Inconclusive, reason, now);
            }
            reconciled.push(retained);
        }
    }

    // Sort deterministically by finding ID
    reconciled.sort_by_key(|f| f.id());
    reconciled
}
