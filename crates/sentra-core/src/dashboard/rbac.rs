//! Role-Based Access Control (RBAC) models and authorization enforcement (REQ-F19, ADR-0001, ADR-0003).

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::dashboard::error::DashboardError;

/// Enterprise user roles governing dashboard and administrative operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UserRole {
    /// Read-only observer. Can view summaries, findings, sessions, and audit logs.
    Viewer,
    /// Active engineer or operator. Can view data, trigger scans, and propose patches.
    Operator,
    /// Security administrator. Has full control, including human approval grants and policy configuration.
    SecurityAdmin,
}

impl UserRole {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::SecurityAdmin => "security_admin",
        }
    }

    /// Evaluates whether this role is permitted to perform the specified dashboard action.
    pub fn can_perform(&self, action: DashboardAction) -> bool {
        match self {
            Self::Viewer => matches!(
                action,
                DashboardAction::ViewOverview
                    | DashboardAction::ViewSessions
                    | DashboardAction::ViewFindings
                    | DashboardAction::ViewPatchBundles
                    | DashboardAction::ViewAuditTrail
            ),
            Self::Operator => matches!(
                action,
                DashboardAction::ViewOverview
                    | DashboardAction::ViewSessions
                    | DashboardAction::ViewFindings
                    | DashboardAction::ViewPatchBundles
                    | DashboardAction::ViewAuditTrail
                    | DashboardAction::TriggerScan
                    | DashboardAction::ProposePatch
            ),
            Self::SecurityAdmin => true,
        }
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Actions subject to role-based access control within the dashboard and enterprise service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DashboardAction {
    /// Inspect overall workspace posture, statistics, and budget summaries.
    ViewOverview,
    /// List and inspect session states and progress.
    ViewSessions,
    /// Query and inspect normalized security findings.
    ViewFindings,
    /// Inspect patch verification bundles and test evidence.
    ViewPatchBundles,
    /// Query immutable audit trail timelines.
    ViewAuditTrail,
    /// Trigger an automated security scan or research campaign.
    TriggerScan,
    /// Propose a code remediation patch.
    ProposePatch,
    /// Grant human approval for a sensitive security action.
    GrantApproval,
    /// Reconfigure security policy or tenant settings.
    ConfigurePolicy,
}

impl DashboardAction {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ViewOverview => "view_overview",
            Self::ViewSessions => "view_sessions",
            Self::ViewFindings => "view_findings",
            Self::ViewPatchBundles => "view_patch_bundles",
            Self::ViewAuditTrail => "view_audit_trail",
            Self::TriggerScan => "trigger_scan",
            Self::ProposePatch => "propose_patch",
            Self::GrantApproval => "grant_approval",
            Self::ConfigurePolicy => "configure_policy",
        }
    }
}

impl fmt::Display for DashboardAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Enforces role-based access control for a given role and action.
///
/// Fails closed with `DashboardError::unauthorized_role` if the role lacks permission.
pub fn enforce_rbac(role: UserRole, action: DashboardAction) -> Result<(), DashboardError> {
    if role.can_perform(action) {
        Ok(())
    } else {
        Err(DashboardError::unauthorized_role(format!(
            "role '{}' is not authorized to perform action '{}'",
            role, action
        )))
    }
}
