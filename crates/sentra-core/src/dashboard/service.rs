//! High-level enterprise dashboard service and multi-tenant coordinator (REQ-F19, ADR-0001, ADR-0003).

use std::collections::HashMap;

use crate::{
    dashboard::{
        error::{DashboardError, DashboardErrorKind},
        rbac::{DashboardAction, UserRole, enforce_rbac},
        tenant::{TenantContext, TenantId},
        view::{
            AuditLogView, CampaignLedgerView, DashboardOverview, FindingView, PatchBundleView,
            SessionSummaryView,
        },
    },
    domain::{finding::Severity, time::TimestampUtc},
};

/// Enterprise dashboard application service and multi-tenant coordinator.
///
/// Coordinates role-based access control, strict tenant data isolation,
/// state aggregation across sessions, findings, patches, and research campaigns,
/// and emits tamper-resistant audit records for all operations.
#[derive(Clone, Debug, Default)]
pub struct DashboardService {
    tenants: HashMap<TenantId, String>,
    sessions: Vec<SessionSummaryView>,
    findings: Vec<FindingView>,
    patch_bundles: Vec<PatchBundleView>,
    campaign_ledgers: Vec<CampaignLedgerView>,
    audit_trails: HashMap<TenantId, Vec<AuditLogView>>,
    policies: HashMap<(TenantId, String), String>,
    action_counter: u64,
}

impl DashboardService {
    /// Creates a new, empty dashboard service instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an organization or tenant workspace within the platform.
    pub fn register_tenant(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        tenant_id: TenantId,
        workspace_name: impl Into<String>,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::ConfigurePolicy)?;
        context.assert_tenant_isolation(&tenant_id)?;

        let name = workspace_name.into();
        self.tenants.insert(tenant_id.clone(), name.clone());

        self.append_audit_event(
            tenant_id,
            context.user_id().to_string(),
            "tenant_registered".to_string(),
            format!("Workspace '{name}' registered"),
        );

        Ok(())
    }

    /// Records a session summary record into the tenant store.
    pub fn record_session(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        session: SessionSummaryView,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::TriggerScan)?;
        context.assert_tenant_isolation(&session.tenant_id)?;

        let tenant_id = session.tenant_id.clone();
        let session_id = session.session_id.clone();
        self.sessions.push(session);

        self.append_audit_event(
            tenant_id,
            context.user_id().to_string(),
            "session_recorded".to_string(),
            format!("Session '{session_id}' recorded"),
        );

        Ok(())
    }

    /// Records a normalized security finding into the tenant store.
    pub fn record_finding(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        finding: FindingView,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::TriggerScan)?;
        context.assert_tenant_isolation(&finding.tenant_id)?;

        let tenant_id = finding.tenant_id.clone();
        let finding_id = finding.finding_id.clone();
        let title = finding.title.clone();
        self.findings.push(finding);

        self.append_audit_event(
            tenant_id,
            context.user_id().to_string(),
            "finding_recorded".to_string(),
            format!("Finding '{finding_id}' ({title}) recorded"),
        );

        Ok(())
    }

    /// Records a patch verification bundle into the tenant store.
    pub fn record_patch_bundle(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        bundle: PatchBundleView,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::ProposePatch)?;
        context.assert_tenant_isolation(&bundle.tenant_id)?;

        let tenant_id = bundle.tenant_id.clone();
        let bundle_id = bundle.bundle_id.clone();
        let verified = bundle.is_verified;
        self.patch_bundles.push(bundle);

        self.append_audit_event(
            tenant_id,
            context.user_id().to_string(),
            "patch_bundle_recorded".to_string(),
            format!("Patch bundle '{bundle_id}' recorded (verified: {verified})"),
        );

        Ok(())
    }

    /// Records a research campaign budget ledger into the tenant store.
    pub fn record_campaign(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        campaign: CampaignLedgerView,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::TriggerScan)?;
        context.assert_tenant_isolation(&campaign.tenant_id)?;

        let tenant_id = campaign.tenant_id.clone();
        let campaign_id = campaign.campaign_id.clone();
        self.campaign_ledgers.push(campaign);

        self.append_audit_event(
            tenant_id,
            context.user_id().to_string(),
            "campaign_recorded".to_string(),
            format!("Campaign '{campaign_id}' recorded"),
        );

        Ok(())
    }

    /// Queries the high-level dashboard overview for the caller's tenant.
    pub fn get_overview(
        &self,
        context: &TenantContext,
        role: UserRole,
    ) -> Result<DashboardOverview, DashboardError> {
        enforce_rbac(role, DashboardAction::ViewOverview)?;

        let tenant_id = context.tenant_id();
        let workspace_name = self
            .tenants
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| "Default Workspace".to_string());

        let mut total_sessions = 0;
        let mut active_sessions = 0;
        for s in &self.sessions {
            if s.tenant_id == *tenant_id {
                total_sessions += 1;
                if s.state != "Completed" && s.state != "Failed" && s.state != "Cancelled" {
                    active_sessions += 1;
                }
            }
        }

        let mut critical_findings = 0;
        let mut high_findings = 0;
        let mut medium_findings = 0;
        let mut low_findings = 0;
        let mut info_findings = 0;
        for f in &self.findings {
            if f.tenant_id == *tenant_id {
                match f.severity {
                    Severity::Critical => critical_findings += 1,
                    Severity::High => high_findings += 1,
                    Severity::Medium => medium_findings += 1,
                    Severity::Low => low_findings += 1,
                    Severity::Informational => info_findings += 1,
                }
            }
        }

        let mut verified_patches = 0;
        for p in &self.patch_bundles {
            if p.tenant_id == *tenant_id && p.is_verified {
                verified_patches += 1;
            }
        }

        let mut total_spent_micro_usd: u64 = 0;
        for c in &self.campaign_ledgers {
            if c.tenant_id == *tenant_id {
                total_spent_micro_usd =
                    total_spent_micro_usd.saturating_add(c.spent_budget_micro_usd);
            }
        }

        let audit_events = self.audit_trails.get(tenant_id);
        let audit_event_count = audit_events.map_or(0, |v| v.len());
        let last_activity_timestamp = audit_events
            .and_then(|v| v.last())
            .map(|e| e.timestamp.clone());

        Ok(DashboardOverview {
            tenant_id: tenant_id.clone(),
            workspace_name,
            total_sessions,
            active_sessions,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            info_findings,
            verified_patches,
            total_spent_micro_usd,
            audit_event_count,
            last_activity_timestamp,
        })
    }

    /// Queries all sessions belonging to the caller's tenant.
    pub fn list_sessions(
        &self,
        context: &TenantContext,
        role: UserRole,
    ) -> Result<Vec<SessionSummaryView>, DashboardError> {
        enforce_rbac(role, DashboardAction::ViewSessions)?;
        let tenant_id = context.tenant_id();

        Ok(self
            .sessions
            .iter()
            .filter(|s| s.tenant_id == *tenant_id)
            .cloned()
            .collect())
    }

    /// Queries security findings belonging to the caller's tenant, with optional severity filter.
    pub fn list_findings(
        &self,
        context: &TenantContext,
        role: UserRole,
        severity_filter: Option<Severity>,
    ) -> Result<Vec<FindingView>, DashboardError> {
        enforce_rbac(role, DashboardAction::ViewFindings)?;
        let tenant_id = context.tenant_id();

        Ok(self
            .findings
            .iter()
            .filter(|f| {
                f.tenant_id == *tenant_id
                    && severity_filter.is_none_or(|target| f.severity == target)
            })
            .cloned()
            .collect())
    }

    /// Queries an individual patch bundle by its identifier, asserting tenant isolation.
    pub fn get_patch_bundle(
        &self,
        context: &TenantContext,
        role: UserRole,
        bundle_id: &str,
    ) -> Result<PatchBundleView, DashboardError> {
        enforce_rbac(role, DashboardAction::ViewPatchBundles)?;

        let bundle = self
            .patch_bundles
            .iter()
            .find(|b| b.bundle_id == bundle_id)
            .ok_or_else(|| {
                DashboardError::new(
                    DashboardErrorKind::InvalidQuery,
                    format!("patch bundle '{bundle_id}' not found"),
                )
            })?;

        context.assert_tenant_isolation(&bundle.tenant_id)?;

        Ok(bundle.clone())
    }

    /// Triggers a new security scan for the caller's tenant.
    pub fn trigger_scan(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        target_name: &str,
    ) -> Result<String, DashboardError> {
        enforce_rbac(role, DashboardAction::TriggerScan)?;

        let trimmed_target = target_name.trim();
        if trimmed_target.is_empty() {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                "target name cannot be empty",
            ));
        }

        self.action_counter = self.action_counter.saturating_add(1);
        let session_id = format!("sess-{:012x}", self.action_counter);
        let now = TimestampUtc::now().to_rfc3339();

        let session = SessionSummaryView {
            session_id: session_id.clone(),
            tenant_id: context.tenant_id().clone(),
            workspace_root: trimmed_target.to_string(),
            state: "Scoped".to_string(),
            fencing_epoch: 1,
            task_count: 0,
            created_at: now.clone(),
            updated_at: now,
        };

        self.sessions.push(session);

        self.append_audit_event(
            context.tenant_id().clone(),
            context.user_id().to_string(),
            "scan_triggered".to_string(),
            format!("Security scan triggered for target '{trimmed_target}' (session {session_id})"),
        );

        Ok(session_id)
    }

    /// Proposes an automated remediation patch candidate for an existing finding.
    pub fn propose_patch(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        finding_id: &str,
        patch_diff: &str,
    ) -> Result<String, DashboardError> {
        enforce_rbac(role, DashboardAction::ProposePatch)?;

        let trimmed_diff = patch_diff.trim();
        if trimmed_diff.is_empty() {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                "patch diff cannot be empty",
            ));
        }

        let tenant_id = context.tenant_id();
        let finding_exists = self
            .findings
            .iter()
            .any(|f| f.finding_id == finding_id && f.tenant_id == *tenant_id);

        if !finding_exists {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                format!("finding '{finding_id}' not found in current tenant"),
            ));
        }

        self.action_counter = self.action_counter.saturating_add(1);
        let bundle_id = format!("bundle-{:012x}", self.action_counter);
        let now = TimestampUtc::now().to_rfc3339();

        let bundle = PatchBundleView {
            bundle_id: bundle_id.clone(),
            tenant_id: tenant_id.clone(),
            finding_id: finding_id.to_string(),
            original_test_status: "PendingVerification".to_string(),
            patched_test_status: "PendingVerification".to_string(),
            regressions_pass: false,
            is_verified: false,
            attempt_count: 1,
            created_at: now,
        };

        self.patch_bundles.push(bundle);

        self.append_audit_event(
            tenant_id.clone(),
            context.user_id().to_string(),
            "patch_proposed".to_string(),
            format!("Patch bundle '{bundle_id}' proposed for finding '{finding_id}'"),
        );

        Ok(bundle_id)
    }

    /// Grants human approval for a sensitive security action.
    pub fn grant_approval(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        ticket_id: &str,
        justification: &str,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::GrantApproval)?;

        let trimmed_ticket = ticket_id.trim();
        if trimmed_ticket.is_empty() {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                "ticket identifier cannot be empty",
            ));
        }

        let trimmed_justification = justification.trim();
        if trimmed_justification.is_empty() {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                "approval justification cannot be empty",
            ));
        }

        self.append_audit_event(
            context.tenant_id().clone(),
            context.user_id().to_string(),
            "approval_granted".to_string(),
            format!("Ticket '{trimmed_ticket}' approved: {trimmed_justification}"),
        );

        Ok(())
    }

    /// Configures or updates a security policy setting.
    pub fn configure_policy(
        &mut self,
        context: &TenantContext,
        role: UserRole,
        key: &str,
        value: &str,
    ) -> Result<(), DashboardError> {
        enforce_rbac(role, DashboardAction::ConfigurePolicy)?;

        let trimmed_key = key.trim();
        if trimmed_key.is_empty() {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                "policy key cannot be empty",
            ));
        }

        let tenant_id = context.tenant_id().clone();
        self.policies.insert(
            (tenant_id.clone(), trimmed_key.to_string()),
            value.to_string(),
        );

        self.append_audit_event(
            tenant_id,
            context.user_id().to_string(),
            "policy_configured".to_string(),
            format!("Policy '{trimmed_key}' set to '{value}'"),
        );

        Ok(())
    }

    /// Queries the immutable audit trail for the caller's tenant.
    pub fn get_audit_trail(
        &self,
        context: &TenantContext,
        role: UserRole,
    ) -> Result<Vec<AuditLogView>, DashboardError> {
        enforce_rbac(role, DashboardAction::ViewAuditTrail)?;

        Ok(self
            .audit_trails
            .get(context.tenant_id())
            .cloned()
            .unwrap_or_default())
    }

    fn append_audit_event(
        &mut self,
        tenant_id: TenantId,
        actor: String,
        action: String,
        details: String,
    ) {
        self.action_counter = self.action_counter.saturating_add(1);
        let event_id = format!("audit-{:016x}", self.action_counter);
        let history = self.audit_trails.entry(tenant_id.clone()).or_default();
        let sequence_number = history.len() as u64 + 1;
        let timestamp = TimestampUtc::now().to_rfc3339();

        history.push(AuditLogView {
            event_id,
            tenant_id,
            sequence_number,
            actor,
            action,
            details,
            timestamp,
        });
    }
}
