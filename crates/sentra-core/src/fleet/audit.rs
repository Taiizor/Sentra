//! Multi-user hosting readiness gates over an in-process worker registry (REQ-F19, Fleet
//! Isolation Specification).
//!
//! This is a logic check of the fleet and tenant domain code against the registry it is
//! given, not an assessment of a deployment. A gate is `true` only when it was evaluated
//! and passed: a gate with nothing to evaluate (an empty registry) or no implemented check
//! is reported `false` with a "Not Assessed" finding, so the overall status cannot be
//! `Approved` without evidence for every gate.

use serde::{Deserialize, Serialize};

use crate::{
    dashboard::{IsolationLevel, TenantContext, TenantId},
    fleet::{error::FleetErrorKind, manager::WorkerFleetManager},
    verification::{EgressPolicy, WorkerArchitecture},
};

/// Status of the multi-user hosting readiness gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    /// Every gate was evaluated and passed.
    Approved,
    /// At least one gate failed or could not be assessed; multi-user hosting is blocked.
    Blocked,
}

/// Result of the multi-user hosting readiness gates. Each gate is `true` only when it was
/// evaluated and passed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiUserAuditReport {
    /// Overall status.
    pub overall_status: AuditStatus,
    /// Gate 1: the tenant context denies cross-tenant access (checked on synthetic tenants).
    pub gate_tenant_isolation: bool,
    /// Gate 2: every registered worker declares strictly denied egress (declared policy,
    /// not a network measurement). `false` for an empty registry.
    pub gate_worker_egress_containment: bool,
    /// Gate 3: a leased worker is denied to another tenant and is quarantined, not made
    /// available, on release (simulated on a copy of the registry). `false` when no worker
    /// could be leased.
    pub gate_cross_tenant_worker_reuse: bool,
    /// Gate 4: no secret inheritance into worker environments. No check is implemented, so
    /// this is always `false`.
    pub gate_zero_secret_inheritance: bool,
    /// Gate 5: tamper-evident audit trail. No check is implemented (the core audit events
    /// carry no hash chain), so this is always `false`.
    pub gate_immutable_audit_trail: bool,
    /// Failed and not-assessed gates, one entry each.
    pub findings: Vec<String>,
}

impl MultiUserAuditReport {
    /// Returns whether every gate was evaluated and passed.
    pub fn is_approved(&self) -> bool {
        self.overall_status == AuditStatus::Approved
    }
}

/// Multi-user hosting readiness gates over a [`WorkerFleetManager`].
pub struct MultiUserSecurityAudit;

impl MultiUserSecurityAudit {
    /// Evaluates the 5 multi-user hosting gates against `fleet`. Gates 4 and 5 have no
    /// implemented check, so the result is currently always [`AuditStatus::Blocked`].
    pub fn run_assessment(fleet: &WorkerFleetManager) -> MultiUserAuditReport {
        let mut findings = Vec::new();

        // Gate 1: Tenant Isolation Verification
        let tenant_a = TenantId::new("audit-tenant-a").expect("valid tenant");
        let tenant_b = TenantId::new("audit-tenant-b").expect("valid tenant");
        let ctx_a = TenantContext::new(tenant_a, "auditor", IsolationLevel::MultiTenantIsolated);

        let gate_tenant_isolation = match ctx_a.assert_tenant_isolation(&tenant_b) {
            Err(e) if e.kind() == crate::dashboard::DashboardErrorKind::CrossTenantAccessDenied => {
                true
            }
            _ => {
                findings.push("Gate 1 Failed: Cross-tenant access was not denied with CrossTenantAccessDenied".to_string());
                false
            }
        };

        // Gate 2: Worker Network Egress Containment (declared policies only)
        let mut gate_worker_egress_containment = true;
        if fleet.total_workers() == 0 {
            findings.push(
                "Gate 2 Not Assessed: the worker registry is empty, so no egress policy was checked"
                    .to_string(),
            );
            gate_worker_egress_containment = false;
        } else {
            for worker in fleet.iter_workers() {
                if worker.egress_policy != EgressPolicy::StrictlyDenied {
                    findings.push(format!(
                        "Gate 2 Failed: Worker '{}' permits egress ({:?}); expected StrictlyDenied",
                        worker.worker_id, worker.egress_policy
                    ));
                    gate_worker_egress_containment = false;
                }
            }
        }

        // Gate 3: Zero Cross-Tenant Worker Reuse Without Clean Sanitary Reset
        let mut gate_cross_tenant_worker_reuse = true;
        let mut sim_fleet = fleet.clone();
        if let Ok((worker_id, lease_id)) =
            sim_fleet.lease_worker(&ctx_a, WorkerArchitecture::LinuxX86_64)
        {
            let ctx_b =
                TenantContext::new(tenant_b, "intruder", IsolationLevel::MultiTenantIsolated);
            // Verify Tenant B cannot access Tenant A's leased worker
            match sim_fleet.verify_worker_access(&ctx_b, &worker_id, &lease_id) {
                Err(e) if e.kind() == FleetErrorKind::CrossTenantWorkerAccessDenied => {}
                _ => {
                    findings.push(
                        "Gate 3 Failed: Cross-tenant worker access was not denied".to_string(),
                    );
                    gate_cross_tenant_worker_reuse = false;
                }
            }

            // Release worker; it MUST transition into Quarantined, not Ready
            let release_ok = sim_fleet
                .release_and_quarantine_worker(&ctx_a, &worker_id, &lease_id)
                .is_ok();
            let worker_available = sim_fleet
                .get_worker(&worker_id)
                .map(|w| w.is_available())
                .unwrap_or(false);
            if release_ok && worker_available {
                findings.push(
                    "Gate 3 Failed: Released worker became available without sanitization reset"
                        .to_string(),
                );
                gate_cross_tenant_worker_reuse = false;
            }
        } else {
            findings.push(
                "Gate 3 Not Assessed: no available LinuxX86_64 worker could be leased to check cross-tenant reuse"
                    .to_string(),
            );
            gate_cross_tenant_worker_reuse = false;
        }

        // Gate 4: Zero Secret Inheritance. Nothing inspects worker environments.
        let gate_zero_secret_inheritance = false;
        findings.push(
            "Gate 4 Not Assessed: no check of secret inheritance into worker environments is implemented"
                .to_string(),
        );

        // Gate 5: Tamper-evident audit trail. Core audit events have no hash chain to verify.
        let gate_immutable_audit_trail = false;
        findings.push(
            "Gate 5 Not Assessed: no tamper-evidence check of the audit trail is implemented"
                .to_string(),
        );

        let all_passed = gate_tenant_isolation
            && gate_worker_egress_containment
            && gate_cross_tenant_worker_reuse
            && gate_zero_secret_inheritance
            && gate_immutable_audit_trail;

        let overall_status = if all_passed {
            AuditStatus::Approved
        } else {
            AuditStatus::Blocked
        };

        MultiUserAuditReport {
            overall_status,
            gate_tenant_isolation,
            gate_worker_egress_containment,
            gate_cross_tenant_worker_reuse,
            gate_zero_secret_inheritance,
            gate_immutable_audit_trail,
            findings,
        }
    }
}
