//! View models and data transfer objects representing core dashboard views (REQ-F19, ADR-0001, ADR-0003).

use serde::{Deserialize, Serialize};

use crate::{
    dashboard::tenant::TenantId,
    domain::finding::{Confidence, FindingStatus, Reachability, Severity},
};

/// High-level posture, activity, and budget summary for a tenant workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardOverview {
    /// Associated tenant identifier.
    pub tenant_id: TenantId,
    /// Human-readable workspace or organization name.
    pub workspace_name: String,
    /// Total number of sessions created.
    pub total_sessions: usize,
    /// Number of active (non-terminal) sessions.
    pub active_sessions: usize,
    /// Count of critical severity findings.
    pub critical_findings: usize,
    /// Count of high severity findings.
    pub high_findings: usize,
    /// Count of medium severity findings.
    pub medium_findings: usize,
    /// Count of low severity findings.
    pub low_findings: usize,
    /// Count of informational findings.
    pub info_findings: usize,
    /// Number of verified remediation patch bundles.
    pub verified_patches: usize,
    /// Cumulative research and inference spend in micro-USD.
    pub total_spent_micro_usd: u64,
    /// Total count of immutable audit trail records.
    pub audit_event_count: usize,
    /// RFC 3339 timestamp of the most recent activity or audit event, if any.
    pub last_activity_timestamp: Option<String>,
}

/// Summary view of an individual session lifecycle state and execution metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummaryView {
    /// Unique session identifier.
    pub session_id: String,
    /// Owning tenant identifier.
    pub tenant_id: TenantId,
    /// Canonical workspace root path.
    pub workspace_root: String,
    /// Current lifecycle state label.
    pub state: String,
    /// Current fencing generation epoch.
    pub fencing_epoch: u64,
    /// Total number of associated tasks.
    pub task_count: usize,
    /// Creation RFC 3339 timestamp.
    pub created_at: String,
    /// Last update RFC 3339 timestamp.
    pub updated_at: String,
}

/// Normalized view of a security finding with reachability and confidence lattices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingView {
    /// Unique finding identifier.
    pub finding_id: String,
    /// Owning tenant identifier.
    pub tenant_id: TenantId,
    /// Human-readable finding title or vulnerability summary.
    pub title: String,
    /// Severity classification.
    pub severity: Severity,
    /// Analytical confidence rating.
    pub confidence: Confidence,
    /// Demonstrated runtime reachability status.
    pub reachability: Reachability,
    /// Finding lifecycle status.
    pub status: FindingStatus,
    /// Target location, package name, or file path.
    pub target_location: String,
    /// Detection RFC 3339 timestamp.
    pub created_at: String,
}

/// View of an automated patch candidate and its independent verification bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchBundleView {
    /// Unique verification bundle identifier.
    pub bundle_id: String,
    /// Owning tenant identifier.
    pub tenant_id: TenantId,
    /// Associated security finding identifier.
    pub finding_id: String,
    /// Test status on unpatched code (e.g., "Failed").
    pub original_test_status: String,
    /// Test status on patched code (e.g., "Passed").
    pub patched_test_status: String,
    /// Whether all baseline regression test suites passed without failure.
    pub regressions_pass: bool,
    /// Whether the patch candidate satisfies the strict three-tier verification invariant.
    pub is_verified: bool,
    /// Number of attempts required to achieve verification.
    pub attempt_count: usize,
    /// Creation RFC 3339 timestamp.
    pub created_at: String,
}

/// Summary view of a research campaign budget ledger and progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLedgerView {
    /// Unique campaign identifier.
    pub campaign_id: String,
    /// Owning tenant identifier.
    pub tenant_id: TenantId,
    /// Research campaign title or objective description.
    pub title: String,
    /// Hard monetary budget ceiling in micro-USD.
    pub max_budget_micro_usd: u64,
    /// Confirmed cumulative spend in micro-USD.
    pub spent_budget_micro_usd: u64,
    /// Current campaign status label.
    pub status: String,
    /// Number of exploration tasks dispatched.
    pub task_count: usize,
}

/// View of an immutable audit trail entry for compliance and tamper resistance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogView {
    /// Unique audit event identifier.
    pub event_id: String,
    /// Owning tenant identifier.
    pub tenant_id: TenantId,
    /// Strictly monotonic sequence number within the tenant timeline.
    pub sequence_number: u64,
    /// Actor or component identity responsible for the action.
    pub actor: String,
    /// Action or event category label.
    pub action: String,
    /// Structured or textual details of the event.
    pub details: String,
    /// RFC 3339 timestamp when the event was recorded.
    pub timestamp: String,
}
