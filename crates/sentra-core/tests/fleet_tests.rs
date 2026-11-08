//! Integration tests for Target Adapters, Remote-Worker Fleet Management & Multi-User Audit (REQ-F19, ADR-0004, EXTENSIONS.md).

use sentra_core::{
    dashboard::{IsolationLevel, TenantContext, TenantId},
    domain::time::TimestampUtc,
    fleet::{
        AdapterActionCapability, AuditStatus, EvidenceMethod, FleetErrorKind, HostPlatform,
        MultiUserSecurityAudit, RemoteWorkerId, RemoteWorkerNode, SupportMatrix,
        SupportedTargetTuple, TargetLanguage, WorkerFleetManager,
    },
    verification::{ContainmentLevel, EgressPolicy, WorkerArchitecture, WorkerResourceCaps},
};

#[test]
fn test_supported_target_matrix_wildcard_rejection() {
    // Valid supported target tuple
    let valid_tuple = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::Rust,
        "1.80..=1.99",
        "cargo-1.80",
        AdapterActionCapability::PatchVerification,
        EvidenceMethod::DualStateTestDiff,
    );
    assert!(valid_tuple.is_ok());

    // Wildcards in framework version range must fail closed
    let err_star_fw = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::Rust,
        "*",
        "cargo-1.80",
        AdapterActionCapability::PatchVerification,
        EvidenceMethod::DualStateTestDiff,
    )
    .unwrap_err();
    assert_eq!(err_star_fw.kind(), FleetErrorKind::WildcardProhibited);

    // Wildcards in tool version must fail closed
    let err_star_tool = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::Rust,
        "1.80..=1.99",
        "clang-*",
        AdapterActionCapability::PatchVerification,
        EvidenceMethod::DualStateTestDiff,
    )
    .unwrap_err();
    assert_eq!(err_star_tool.kind(), FleetErrorKind::WildcardProhibited);

    // 'all' / 'any' designations must fail closed
    let err_any = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::CCpp,
        "any",
        "gcc-14",
        AdapterActionCapability::ReproductionFuzzing,
        EvidenceMethod::AsanCrashArtifact,
    )
    .unwrap_err();
    assert_eq!(err_any.kind(), FleetErrorKind::WildcardProhibited);

    // Empty version strings must fail closed
    let err_empty = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::Rust,
        "   ",
        "cargo-1.80",
        AdapterActionCapability::PatchVerification,
        EvidenceMethod::DualStateTestDiff,
    )
    .unwrap_err();
    assert_eq!(err_empty.kind(), FleetErrorKind::InvalidInput);

    // DiscoveryOnly claiming dynamic execution evidence must fail closed
    let err_discovery = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::Rust,
        "1.80..=1.99",
        "cargo-1.80",
        AdapterActionCapability::DiscoveryOnly,
        EvidenceMethod::DualStateTestDiff,
    )
    .unwrap_err();
    assert_eq!(err_discovery.kind(), FleetErrorKind::InvalidInput);
}

#[test]
fn test_reference_platform_matrix_queries() {
    let matrix = SupportMatrix::reference_platform_matrix();
    assert!(matrix.total_declarations_count() >= 5);

    // Query 1: Linux C/C++ Fuzzing Engine
    let fuzz_query = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::CCpp,
        "C11..=C23",
        "clang-18",
        AdapterActionCapability::ReproductionFuzzing,
        EvidenceMethod::AsanCrashArtifact,
    )
    .unwrap();

    assert!(matrix.is_supported(&fuzz_query));
    let adapters = matrix.find_supporting_adapters(&fuzz_query);
    assert_eq!(adapters, vec!["linux_cpp_fuzz_engine".to_string()]);

    // Query 2: Binary Analysis Adapter (Ghidra 11.1)
    let ghidra_query = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::BinaryX86_64,
        "ELF-x86_64",
        "ghidra-11.1",
        AdapterActionCapability::StaticAnalysis,
        EvidenceMethod::DisassemblyArtifact,
    )
    .unwrap();

    assert!(matrix.is_supported(&ghidra_query));
    assert_eq!(
        matrix.find_supporting_adapters(&ghidra_query),
        vec!["ghidra_binary_adapter".to_string()]
    );

    // Query 3: Unsupported tool version
    let unsupported_query = SupportedTargetTuple::new(
        HostPlatform::WindowsX64,
        WorkerArchitecture::LinuxX86_64,
        TargetLanguage::CCpp,
        "C11..=C23",
        "clang-99", // Non-existent/unsupported compiler
        AdapterActionCapability::ReproductionFuzzing,
        EvidenceMethod::AsanCrashArtifact,
    )
    .unwrap();

    assert!(!matrix.is_supported(&unsupported_query));
    assert!(
        matrix
            .find_supporting_adapters(&unsupported_query)
            .is_empty()
    );
}

#[test]
fn test_remote_worker_registration_and_exclusive_leasing() {
    let mut fleet = WorkerFleetManager::new();

    let worker_1 = RemoteWorkerNode::new(
        RemoteWorkerId::new("worker-linux-01").unwrap(),
        "https://worker-01.internal:8443",
        WorkerArchitecture::LinuxX86_64,
        ContainmentLevel::DisposableVm,
        WorkerResourceCaps::default(),
        EgressPolicy::StrictlyDenied,
    );

    let worker_2 = RemoteWorkerNode::new(
        RemoteWorkerId::new("worker-linux-02").unwrap(),
        "https://worker-02.internal:8443",
        WorkerArchitecture::LinuxX86_64,
        ContainmentLevel::DisposableVm,
        WorkerResourceCaps::default(),
        EgressPolicy::StrictlyDenied,
    );

    fleet.register_worker(worker_1).unwrap();
    fleet.register_worker(worker_2).unwrap();
    assert_eq!(fleet.total_workers(), 2);
    assert_eq!(fleet.available_workers(), 2);

    let tenant_a = TenantId::new("tenant-alpha").unwrap();
    let tenant_b = TenantId::new("tenant-beta").unwrap();

    let ctx_a = TenantContext::new(tenant_a, "alice", IsolationLevel::MultiTenantIsolated);
    let ctx_b = TenantContext::new(tenant_b, "bob", IsolationLevel::MultiTenantIsolated);

    // Tenant A leases worker 1
    let (w1_id, lease_1) = fleet
        .lease_worker(&ctx_a, WorkerArchitecture::LinuxX86_64)
        .unwrap();
    assert_eq!(fleet.available_workers(), 1);
    assert_eq!(fleet.active_leases(), 1);

    // Verify Tenant A has valid exclusive access
    assert!(fleet.verify_worker_access(&ctx_a, &w1_id, &lease_1).is_ok());

    // Tenant B attempting to access Tenant A's leased worker fails with CrossTenantWorkerAccessDenied
    let cross_err = fleet
        .verify_worker_access(&ctx_b, &w1_id, &lease_1)
        .unwrap_err();
    assert_eq!(
        cross_err.kind(),
        FleetErrorKind::CrossTenantWorkerAccessDenied
    );

    // Tenant B leases worker 2
    let (w2_id, lease_2) = fleet
        .lease_worker(&ctx_b, WorkerArchitecture::LinuxX86_64)
        .unwrap();
    assert_ne!(w1_id, w2_id);
    assert_eq!(fleet.available_workers(), 0);
    assert_eq!(fleet.active_leases(), 2);

    // Next lease request fails closed with WorkerBusy since capacity is exhausted
    let busy_err = fleet
        .lease_worker(&ctx_a, WorkerArchitecture::LinuxX86_64)
        .unwrap_err();
    assert_eq!(busy_err.kind(), FleetErrorKind::WorkerBusy);

    // Verify Tenant B has access to worker 2
    assert!(fleet.verify_worker_access(&ctx_b, &w2_id, &lease_2).is_ok());
}

#[test]
fn test_cross_tenant_worker_isolation_and_sanitization() {
    let mut fleet = WorkerFleetManager::new();

    let worker = RemoteWorkerNode::new(
        RemoteWorkerId::new("worker-shared-01").unwrap(),
        "https://worker-shared.internal:8443",
        WorkerArchitecture::LinuxX86_64,
        ContainmentLevel::DisposableVm,
        WorkerResourceCaps::default(),
        EgressPolicy::StrictlyDenied,
    );

    fleet.register_worker(worker).unwrap();

    let tenant_a = TenantId::new("client-a").unwrap();
    let tenant_b = TenantId::new("client-b").unwrap();

    let ctx_a = TenantContext::new(tenant_a, "alice", IsolationLevel::MultiTenantIsolated);
    let ctx_b = TenantContext::new(tenant_b, "bob", IsolationLevel::MultiTenantIsolated);

    // Tenant A leases the single worker
    let (worker_id, lease_a) = fleet
        .lease_worker(&ctx_a, WorkerArchitecture::LinuxX86_64)
        .unwrap();

    // Tenant A finishes job and releases worker
    fleet
        .release_and_quarantine_worker(&ctx_a, &worker_id, &lease_a)
        .unwrap();

    // Worker is now in Quarantined state (NOT Ready!)
    assert_eq!(fleet.available_workers(), 0);
    assert_eq!(fleet.quarantined_workers(), 1);

    // Tenant B attempts to lease worker; fails with WorkerBusy because worker is quarantined
    let lease_b_err = fleet
        .lease_worker(&ctx_b, WorkerArchitecture::LinuxX86_64)
        .unwrap_err();
    assert_eq!(lease_b_err.kind(), FleetErrorKind::WorkerBusy);

    // Execute boundary sanitization and reset (wiping VM memory/ephemeral storage)
    fleet.sanitize_and_reset_worker(&worker_id).unwrap();

    // Worker is restored to Ready status
    assert_eq!(fleet.available_workers(), 1);
    assert_eq!(fleet.quarantined_workers(), 0);

    // Now Tenant B can safely acquire a clean lease
    let (w_id_b, lease_b) = fleet
        .lease_worker(&ctx_b, WorkerArchitecture::LinuxX86_64)
        .unwrap();
    assert_eq!(w_id_b, worker_id);
    assert_ne!(lease_a, lease_b);
    assert!(
        fleet
            .verify_worker_access(&ctx_b, &w_id_b, &lease_b)
            .is_ok()
    );
}

#[test]
fn test_worker_heartbeat_monitoring_and_stale_reaping() {
    let mut fleet = WorkerFleetManager::new();

    let worker = RemoteWorkerNode::new(
        RemoteWorkerId::new("worker-monitored-01").unwrap(),
        "https://worker-mon.internal:8443",
        WorkerArchitecture::LinuxX86_64,
        ContainmentLevel::DisposableVm,
        WorkerResourceCaps::default(),
        EgressPolicy::StrictlyDenied,
    );

    fleet.register_worker(worker).unwrap();
    let worker_id = RemoteWorkerId::new("worker-monitored-01").unwrap();

    // Set heartbeat at t = 1000s
    let t0 = TimestampUtc::from_epoch_secs(1000);
    fleet.record_heartbeat(&worker_id, t0).unwrap();

    // At t = 1010s, heartbeat is fresh within 30s window
    let t_fresh = TimestampUtc::from_epoch_secs(1010);
    let reaped_fresh = fleet.reap_stale_heartbeats(t_fresh, 30);
    assert_eq!(reaped_fresh, 0);
    assert_eq!(fleet.available_workers(), 1);

    // At t = 1040s, heartbeat is stale (> 30s)
    let t_stale = TimestampUtc::from_epoch_secs(1040);
    let reaped_stale = fleet.reap_stale_heartbeats(t_stale, 30);
    assert_eq!(reaped_stale, 1);
    assert_eq!(fleet.available_workers(), 0);
    assert_eq!(fleet.quarantined_workers(), 1);
}

#[test]
fn test_multi_user_hosting_security_audit_gates() {
    let mut fleet = WorkerFleetManager::new();

    // Register compliant workers with StrictlyDenied egress
    let worker = RemoteWorkerNode::new(
        RemoteWorkerId::new("worker-compliant-01").unwrap(),
        "https://worker-compliant.internal:8443",
        WorkerArchitecture::LinuxX86_64,
        ContainmentLevel::DisposableVm,
        WorkerResourceCaps::default(),
        EgressPolicy::StrictlyDenied,
    );

    fleet.register_worker(worker).unwrap();

    // Run independent security audit
    let report = MultiUserSecurityAudit::run_assessment(&fleet);

    assert_eq!(report.overall_status, AuditStatus::Approved);
    assert!(report.is_approved());
    assert!(report.gate_tenant_isolation);
    assert!(report.gate_worker_egress_containment);
    assert!(report.gate_cross_tenant_worker_reuse);
    assert!(report.gate_zero_secret_inheritance);
    assert!(report.gate_immutable_audit_trail);
    assert!(report.findings.is_empty());

    // Introduce a non-compliant worker permitting network egress
    let rogue_worker = RemoteWorkerNode::new(
        RemoteWorkerId::new("worker-rogue-01").unwrap(),
        "https://worker-rogue.internal:8443",
        WorkerArchitecture::LinuxX86_64,
        ContainmentLevel::DisposableVm,
        WorkerResourceCaps::default(),
        EgressPolicy::WhitelistedLocalOnly, // Non-compliant egress policy!
    );

    fleet.register_worker(rogue_worker).unwrap();

    // Re-run security audit
    let blocked_report = MultiUserSecurityAudit::run_assessment(&fleet);

    assert_eq!(blocked_report.overall_status, AuditStatus::Blocked);
    assert!(!blocked_report.is_approved());
    assert!(!blocked_report.gate_worker_egress_containment);
    assert!(!blocked_report.findings.is_empty());
    assert!(blocked_report.findings[0].contains("Gate 2 Failed"));
}
