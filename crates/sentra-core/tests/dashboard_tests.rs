//! Integration tests for Dashboard Core Services API, Multi-Tenant Session Isolation & RBAC (REQ-F19, ADR-0001, ADR-0003).

use std::str::FromStr;

use sentra_core::{
    dashboard::{
        AuditLogView, CampaignLedgerView, DashboardAction, DashboardErrorKind, DashboardOverview,
        DashboardService, FindingView, IsolationLevel, PatchBundleView, SessionSummaryView,
        TenantContext, TenantId, UserRole, enforce_rbac,
    },
    domain::finding::{Confidence, FindingStatus, Reachability, Severity},
};

#[test]
fn test_tenant_id_validation_and_fencing() {
    // Valid tenant identifiers
    assert!(TenantId::new("acme-corp").is_ok());
    assert!(TenantId::new("tenant_12345").is_ok());
    assert!(TenantId::from_str("org-sec-prod-01").is_ok());
    let det = TenantId::deterministic(42);
    assert_eq!(det.as_str(), "tenant-000000000000002a");

    // Invalid identifiers fail closed with InvalidQuery
    let err_empty = TenantId::new("   ").unwrap_err();
    assert_eq!(err_empty.kind(), DashboardErrorKind::InvalidQuery);

    let err_too_long = TenantId::new("a".repeat(65)).unwrap_err();
    assert_eq!(err_too_long.kind(), DashboardErrorKind::InvalidQuery);

    let err_invalid_chars = TenantId::new("acme/corp").unwrap_err();
    assert_eq!(err_invalid_chars.kind(), DashboardErrorKind::InvalidQuery);

    let err_spaces = TenantId::new("acme corp").unwrap_err();
    assert_eq!(err_spaces.kind(), DashboardErrorKind::InvalidQuery);

    // Isolation fencing
    let tenant_a = TenantId::new("tenant-a").unwrap();
    let tenant_b = TenantId::new("tenant-b").unwrap();

    let ctx_single = TenantContext::single_operator(tenant_a.clone(), "alice");
    assert_eq!(ctx_single.isolation_level(), IsolationLevel::SingleOperator);
    // Single operator mode permits cross-tenant checks without error
    assert!(ctx_single.assert_tenant_isolation(&tenant_b).is_ok());

    let ctx_multi = TenantContext::multi_tenant(tenant_a.clone(), "alice");
    assert_eq!(
        ctx_multi.isolation_level(),
        IsolationLevel::MultiTenantIsolated
    );
    // Same tenant succeeds
    assert!(ctx_multi.assert_tenant_isolation(&tenant_a).is_ok());
    // Different tenant fails closed with CrossTenantAccessDenied
    let err = ctx_multi.assert_tenant_isolation(&tenant_b).unwrap_err();
    assert_eq!(err.kind(), DashboardErrorKind::CrossTenantAccessDenied);
}

#[test]
fn test_rbac_permission_matrix() {
    let actions = [
        DashboardAction::ViewOverview,
        DashboardAction::ViewSessions,
        DashboardAction::ViewFindings,
        DashboardAction::ViewPatchBundles,
        DashboardAction::ViewAuditTrail,
        DashboardAction::TriggerScan,
        DashboardAction::ProposePatch,
        DashboardAction::GrantApproval,
        DashboardAction::ConfigurePolicy,
    ];

    // Viewer permissions
    for &action in &actions {
        let expected = matches!(
            action,
            DashboardAction::ViewOverview
                | DashboardAction::ViewSessions
                | DashboardAction::ViewFindings
                | DashboardAction::ViewPatchBundles
                | DashboardAction::ViewAuditTrail
        );
        assert_eq!(UserRole::Viewer.can_perform(action), expected);
        if expected {
            assert!(enforce_rbac(UserRole::Viewer, action).is_ok());
        } else {
            let err = enforce_rbac(UserRole::Viewer, action).unwrap_err();
            assert_eq!(err.kind(), DashboardErrorKind::UnauthorizedRole);
        }
    }

    // Operator permissions
    for &action in &actions {
        let expected = matches!(
            action,
            DashboardAction::ViewOverview
                | DashboardAction::ViewSessions
                | DashboardAction::ViewFindings
                | DashboardAction::ViewPatchBundles
                | DashboardAction::ViewAuditTrail
                | DashboardAction::TriggerScan
                | DashboardAction::ProposePatch
        );
        assert_eq!(UserRole::Operator.can_perform(action), expected);
        if expected {
            assert!(enforce_rbac(UserRole::Operator, action).is_ok());
        } else {
            let err = enforce_rbac(UserRole::Operator, action).unwrap_err();
            assert_eq!(err.kind(), DashboardErrorKind::UnauthorizedRole);
        }
    }

    // SecurityAdmin permissions
    for &action in &actions {
        assert!(UserRole::SecurityAdmin.can_perform(action));
        assert!(enforce_rbac(UserRole::SecurityAdmin, action).is_ok());
    }
}

#[test]
fn test_dashboard_overview_parity_and_aggregations() {
    let mut service = DashboardService::new();
    let tenant_id = TenantId::new("acme-platform").unwrap();
    let ctx = TenantContext::multi_tenant(tenant_id.clone(), "admin-1");

    // Register workspace
    service
        .register_tenant(
            &ctx,
            UserRole::SecurityAdmin,
            tenant_id.clone(),
            "Acme Platform Security",
        )
        .unwrap();

    // Record sessions: 2 active, 1 completed
    service
        .record_session(
            &ctx,
            UserRole::Operator,
            SessionSummaryView {
                session_id: "sess-01".to_string(),
                tenant_id: tenant_id.clone(),
                workspace_root: "/repo".to_string(),
                state: "Scoped".to_string(),
                fencing_epoch: 1,
                task_count: 5,
                created_at: "2026-11-09T00:00:00Z".to_string(),
                updated_at: "2026-11-09T00:00:00Z".to_string(),
            },
        )
        .unwrap();

    service
        .record_session(
            &ctx,
            UserRole::Operator,
            SessionSummaryView {
                session_id: "sess-02".to_string(),
                tenant_id: tenant_id.clone(),
                workspace_root: "/repo".to_string(),
                state: "Running".to_string(),
                fencing_epoch: 2,
                task_count: 3,
                created_at: "2026-11-09T00:01:00Z".to_string(),
                updated_at: "2026-11-09T00:01:00Z".to_string(),
            },
        )
        .unwrap();

    service
        .record_session(
            &ctx,
            UserRole::Operator,
            SessionSummaryView {
                session_id: "sess-03".to_string(),
                tenant_id: tenant_id.clone(),
                workspace_root: "/repo".to_string(),
                state: "Completed".to_string(),
                fencing_epoch: 1,
                task_count: 8,
                created_at: "2026-11-09T00:02:00Z".to_string(),
                updated_at: "2026-11-09T00:02:00Z".to_string(),
            },
        )
        .unwrap();

    // Record findings across severities
    let severities = [
        (Severity::Critical, "Remote Code Execution"),
        (Severity::High, "SQL Injection"),
        (Severity::Medium, "Cross-Site Scripting"),
        (Severity::Low, "Missing Rate Limit"),
        (Severity::Informational, "Banner Disclosure"),
    ];

    for (i, (sev, title)) in severities.into_iter().enumerate() {
        service
            .record_finding(
                &ctx,
                UserRole::Operator,
                FindingView {
                    finding_id: format!("find-{:02}", i + 1),
                    tenant_id: tenant_id.clone(),
                    title: title.to_string(),
                    severity: sev,
                    confidence: Confidence::Confirmed,
                    reachability: Reachability::DemonstratedRuntime,
                    status: FindingStatus::Validated,
                    target_location: format!("src/module_{i}.rs:42"),
                    created_at: "2026-11-09T00:03:00Z".to_string(),
                },
            )
            .unwrap();
    }

    // Record patch bundles: 1 verified, 1 unverified
    service
        .record_patch_bundle(
            &ctx,
            UserRole::Operator,
            PatchBundleView {
                bundle_id: "bundle-01".to_string(),
                tenant_id: tenant_id.clone(),
                finding_id: "find-01".to_string(),
                original_test_status: "Failed".to_string(),
                patched_test_status: "Passed".to_string(),
                regressions_pass: true,
                is_verified: true,
                attempt_count: 1,
                created_at: "2026-11-09T00:04:00Z".to_string(),
            },
        )
        .unwrap();

    service
        .record_patch_bundle(
            &ctx,
            UserRole::Operator,
            PatchBundleView {
                bundle_id: "bundle-02".to_string(),
                tenant_id: tenant_id.clone(),
                finding_id: "find-02".to_string(),
                original_test_status: "Failed".to_string(),
                patched_test_status: "Failed".to_string(),
                regressions_pass: false,
                is_verified: false,
                attempt_count: 2,
                created_at: "2026-11-09T00:05:00Z".to_string(),
            },
        )
        .unwrap();

    // Record campaign ledger with budget
    service
        .record_campaign(
            &ctx,
            UserRole::Operator,
            CampaignLedgerView {
                campaign_id: "camp-01".to_string(),
                tenant_id: tenant_id.clone(),
                title: "Deep Fuzzing Scout Campaign".to_string(),
                max_budget_micro_usd: 50_000_000,
                spent_budget_micro_usd: 12_450_000,
                status: "Completed".to_string(),
                task_count: 15,
            },
        )
        .unwrap();

    // Query overview as Viewer
    let overview: DashboardOverview = service.get_overview(&ctx, UserRole::Viewer).unwrap();

    assert_eq!(overview.tenant_id, tenant_id);
    assert_eq!(overview.workspace_name, "Acme Platform Security");
    assert_eq!(overview.total_sessions, 3);
    assert_eq!(overview.active_sessions, 2);
    assert_eq!(overview.critical_findings, 1);
    assert_eq!(overview.high_findings, 1);
    assert_eq!(overview.medium_findings, 1);
    assert_eq!(overview.low_findings, 1);
    assert_eq!(overview.info_findings, 1);
    assert_eq!(overview.verified_patches, 1);
    assert_eq!(overview.total_spent_micro_usd, 12_450_000);
    assert!(overview.audit_event_count >= 8);
    assert!(overview.last_activity_timestamp.is_some());
}

#[test]
fn test_multi_tenant_isolation_boundary() {
    let mut service = DashboardService::new();

    let tenant_a = TenantId::new("org-alpha").unwrap();
    let tenant_b = TenantId::new("org-beta").unwrap();

    let ctx_a = TenantContext::multi_tenant(tenant_a.clone(), "alice");
    let ctx_b = TenantContext::multi_tenant(tenant_b.clone(), "bob");

    // Register both tenants
    service
        .register_tenant(
            &ctx_a,
            UserRole::SecurityAdmin,
            tenant_a.clone(),
            "Alpha Org",
        )
        .unwrap();
    service
        .register_tenant(
            &ctx_b,
            UserRole::SecurityAdmin,
            tenant_b.clone(),
            "Beta Org",
        )
        .unwrap();

    // Add session to Tenant A
    service
        .record_session(
            &ctx_a,
            UserRole::Operator,
            SessionSummaryView {
                session_id: "sess-alpha-1".to_string(),
                tenant_id: tenant_a.clone(),
                workspace_root: "/alpha".to_string(),
                state: "Scoped".to_string(),
                fencing_epoch: 1,
                task_count: 1,
                created_at: "2026-11-09T00:00:00Z".to_string(),
                updated_at: "2026-11-09T00:00:00Z".to_string(),
            },
        )
        .unwrap();

    // Add session to Tenant B
    service
        .record_session(
            &ctx_b,
            UserRole::Operator,
            SessionSummaryView {
                session_id: "sess-beta-1".to_string(),
                tenant_id: tenant_b.clone(),
                workspace_root: "/beta".to_string(),
                state: "Running".to_string(),
                fencing_epoch: 1,
                task_count: 2,
                created_at: "2026-11-09T00:00:00Z".to_string(),
                updated_at: "2026-11-09T00:00:00Z".to_string(),
            },
        )
        .unwrap();

    // Tenant A querying sessions sees ONLY Tenant A sessions
    let sessions_a = service.list_sessions(&ctx_a, UserRole::Viewer).unwrap();
    assert_eq!(sessions_a.len(), 1);
    assert_eq!(sessions_a[0].session_id, "sess-alpha-1");

    // Tenant B querying sessions sees ONLY Tenant B sessions
    let sessions_b = service.list_sessions(&ctx_b, UserRole::Viewer).unwrap();
    assert_eq!(sessions_b.len(), 1);
    assert_eq!(sessions_b[0].session_id, "sess-beta-1");

    // Add finding to Tenant B
    service
        .record_finding(
            &ctx_b,
            UserRole::Operator,
            FindingView {
                finding_id: "find-beta-99".to_string(),
                tenant_id: tenant_b.clone(),
                title: "Beta Secret Leak".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                reachability: Reachability::DemonstratedRuntime,
                status: FindingStatus::Validated,
                target_location: "secrets.rs:10".to_string(),
                created_at: "2026-11-09T00:00:00Z".to_string(),
            },
        )
        .unwrap();

    // Tenant A listing findings sees ZERO findings from Tenant B
    let findings_a = service
        .list_findings(&ctx_a, UserRole::Viewer, None)
        .unwrap();
    assert_eq!(findings_a.len(), 0);

    // Tenant B sees its finding
    let findings_b = service
        .list_findings(&ctx_b, UserRole::Viewer, None)
        .unwrap();
    assert_eq!(findings_b.len(), 1);
    assert_eq!(findings_b[0].finding_id, "find-beta-99");

    // Add patch bundle to Tenant B
    service
        .record_patch_bundle(
            &ctx_b,
            UserRole::Operator,
            PatchBundleView {
                bundle_id: "bundle-beta-10".to_string(),
                tenant_id: tenant_b.clone(),
                finding_id: "find-beta-99".to_string(),
                original_test_status: "Failed".to_string(),
                patched_test_status: "Passed".to_string(),
                regressions_pass: true,
                is_verified: true,
                attempt_count: 1,
                created_at: "2026-11-09T00:00:00Z".to_string(),
            },
        )
        .unwrap();

    // Tenant A querying Tenant B's patch bundle directly fails closed with CrossTenantAccessDenied
    let cross_err = service
        .get_patch_bundle(&ctx_a, UserRole::Viewer, "bundle-beta-10")
        .unwrap_err();
    assert_eq!(
        cross_err.kind(),
        DashboardErrorKind::CrossTenantAccessDenied
    );

    // Tenant A attempting to record a finding into Tenant B fails closed
    let illegal_finding = FindingView {
        finding_id: "find-forged".to_string(),
        tenant_id: tenant_b.clone(),
        title: "Forged Finding".to_string(),
        severity: Severity::High,
        confidence: Confidence::Tentative,
        reachability: Reachability::Unknown,
        status: FindingStatus::Candidate,
        target_location: "main.rs:1".to_string(),
        created_at: "2026-11-09T00:00:00Z".to_string(),
    };
    let record_err = service
        .record_finding(&ctx_a, UserRole::Operator, illegal_finding)
        .unwrap_err();
    assert_eq!(
        record_err.kind(),
        DashboardErrorKind::CrossTenantAccessDenied
    );
}

#[test]
fn test_dashboard_mutations_and_rbac_enforcement() {
    let mut service = DashboardService::new();
    let tenant_id = TenantId::new("security-corp").unwrap();
    let ctx = TenantContext::multi_tenant(tenant_id.clone(), "engineer-bob");

    // Viewer cannot trigger scan
    let viewer_scan_err = service
        .trigger_scan(&ctx, UserRole::Viewer, "/workspace")
        .unwrap_err();
    assert_eq!(viewer_scan_err.kind(), DashboardErrorKind::UnauthorizedRole);

    // Operator can trigger scan
    let session_id = service
        .trigger_scan(&ctx, UserRole::Operator, "/workspace")
        .unwrap();
    assert!(session_id.starts_with("sess-"));

    // Add a finding to current tenant
    service
        .record_finding(
            &ctx,
            UserRole::Operator,
            FindingView {
                finding_id: "find-sec-1".to_string(),
                tenant_id: tenant_id.clone(),
                title: "Path Traversal".to_string(),
                severity: Severity::High,
                confidence: Confidence::Confirmed,
                reachability: Reachability::DemonstratedRuntime,
                status: FindingStatus::Validated,
                target_location: "fs.rs:10".to_string(),
                created_at: "2026-11-09T00:00:00Z".to_string(),
            },
        )
        .unwrap();

    // Viewer cannot propose patch
    let viewer_patch_err = service
        .propose_patch(&ctx, UserRole::Viewer, "find-sec-1", "diff content")
        .unwrap_err();
    assert_eq!(
        viewer_patch_err.kind(),
        DashboardErrorKind::UnauthorizedRole
    );

    // Operator can propose patch
    let bundle_id = service
        .propose_patch(
            &ctx,
            UserRole::Operator,
            "find-sec-1",
            "--- a/fs.rs\n+++ b/fs.rs",
        )
        .unwrap();
    assert!(bundle_id.starts_with("bundle-"));

    // Operator cannot grant approval
    let op_approval_err = service
        .grant_approval(&ctx, UserRole::Operator, "ticket-101", "LGTM")
        .unwrap_err();
    assert_eq!(op_approval_err.kind(), DashboardErrorKind::UnauthorizedRole);

    // SecurityAdmin can grant approval
    assert!(
        service
            .grant_approval(
                &ctx,
                UserRole::SecurityAdmin,
                "ticket-101",
                "Verified offline by Lead Auditor"
            )
            .is_ok()
    );

    // Operator cannot configure policy
    let op_policy_err = service
        .configure_policy(&ctx, UserRole::Operator, "max_depth", "10")
        .unwrap_err();
    assert_eq!(op_policy_err.kind(), DashboardErrorKind::UnauthorizedRole);

    // SecurityAdmin can configure policy
    assert!(
        service
            .configure_policy(&ctx, UserRole::SecurityAdmin, "max_depth", "10")
            .is_ok()
    );
}

#[test]
fn test_tamper_resistant_audit_trail_parity() {
    let mut service = DashboardService::new();
    let tenant_id = TenantId::new("fintech-prod").unwrap();
    let ctx = TenantContext::multi_tenant(tenant_id.clone(), "lead-auditor");

    service
        .register_tenant(
            &ctx,
            UserRole::SecurityAdmin,
            tenant_id.clone(),
            "Fintech Production",
        )
        .unwrap();

    let sess_id = service
        .trigger_scan(&ctx, UserRole::SecurityAdmin, "/repo")
        .unwrap();

    service
        .grant_approval(
            &ctx,
            UserRole::SecurityAdmin,
            "ticket-auth-01",
            "Emergency hotfix authorized",
        )
        .unwrap();

    service
        .configure_policy(
            &ctx,
            UserRole::SecurityAdmin,
            "fuzzing_engine",
            "libfuzzer_asan",
        )
        .unwrap();

    // Query audit trail
    let audit_trail: Vec<AuditLogView> = service.get_audit_trail(&ctx, UserRole::Viewer).unwrap();

    assert_eq!(audit_trail.len(), 4);

    // Verify sequence numbers are strictly monotonic: 1, 2, 3, 4
    for (i, entry) in audit_trail.iter().enumerate() {
        assert_eq!(entry.sequence_number, (i + 1) as u64);
        assert_eq!(entry.tenant_id, tenant_id);
        assert_eq!(entry.actor, "lead-auditor");
        assert!(entry.event_id.starts_with("audit-"));
        assert!(!entry.timestamp.is_empty());
    }

    assert_eq!(audit_trail[0].action, "tenant_registered");
    assert_eq!(audit_trail[1].action, "scan_triggered");
    assert!(audit_trail[1].details.contains(&sess_id));
    assert_eq!(audit_trail[2].action, "approval_granted");
    assert!(audit_trail[2].details.contains("ticket-auth-01"));
    assert_eq!(audit_trail[3].action, "policy_configured");
    assert!(audit_trail[3].details.contains("fuzzing_engine"));
}
