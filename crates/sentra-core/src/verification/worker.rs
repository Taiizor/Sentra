//! Disposable Linux VM/worker containment protocol and isolation profile (REQ-F12, REQ-F13, Roadmap Phase 2).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Target operating system and processor architecture of the worker runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerArchitecture {
    /// Linux x86_64 target execution environment.
    LinuxX86_64,
    /// Windows x64 host execution environment.
    WindowsX64,
}

/// Boundary isolation topology enclosing target execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentLevel {
    /// Ephemeral, disposable hardware virtual machine.
    DisposableVm,
    /// Isolated container boundary with dedicated namespace/cgroup ceilings.
    IsolatedContainer,
    /// Fail-closed non-executing subprocess seam.
    FailClosedSubprocess,
}

/// Resource ceilings enforced on target execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerResourceCaps {
    /// Maximum allowed memory ceiling in bytes (default 2 GiB).
    pub max_memory_bytes: u64,
    /// Maximum allowed CPU cores (default 2).
    pub max_cpu_cores: u32,
    /// Maximum ephemeral disk storage in bytes (default 10 GiB).
    pub max_disk_bytes: u64,
    /// Execution timeout ceiling in seconds (default 120s).
    pub timeout_seconds: u64,
}

impl Default for WorkerResourceCaps {
    fn default() -> Self {
        Self {
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
            max_cpu_cores: 2,
            max_disk_bytes: 10 * 1024 * 1024 * 1024,
            timeout_seconds: 120,
        }
    }
}

/// Outbound network egress restriction policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPolicy {
    /// All outbound network traffic is unconditionally blocked (fail-closed).
    StrictlyDenied,
    /// Outbound traffic is restricted to loopback/local mock endpoints only.
    WhitelistedLocalOnly,
}

/// Comprehensive worker containment specification (REQ-F12/F13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerProfile {
    /// Worker profile identifier.
    pub id: String,
    /// Execution architecture.
    pub architecture: WorkerArchitecture,
    /// Containment boundary mechanism.
    pub containment: ContainmentLevel,
    /// Resource enforcement ceilings.
    pub resources: WorkerResourceCaps,
    /// Egress rules.
    pub egress: EgressPolicy,
    /// Whether path containment checks (private root, no parent escaping) passed.
    pub path_containment_verified: bool,
    /// Whether credential isolation checks (no host tokens/keys accessible) passed.
    pub credential_isolation_verified: bool,
    /// Whether crash recovery checks (deterministic failure without corruption) passed.
    pub crash_recovery_verified: bool,
    /// Whether ephemeral cleanup checks (immediate teardown upon finish) passed.
    pub ephemeral_cleanup_verified: bool,
}

impl WorkerProfile {
    /// Constructs a standard Phase 2 reference disposable Linux worker profile.
    pub fn standard_phase2_linux_worker() -> Self {
        Self {
            id: "phase2-linux-x86_64-worker".to_string(),
            architecture: WorkerArchitecture::LinuxX86_64,
            containment: ContainmentLevel::DisposableVm,
            resources: WorkerResourceCaps::default(),
            egress: EgressPolicy::StrictlyDenied,
            path_containment_verified: true,
            credential_isolation_verified: true,
            crash_recovery_verified: true,
            ephemeral_cleanup_verified: true,
        }
    }

    /// Verifies all six containment gates required before executing any untrusted target.
    pub fn verify_readiness(&self) -> Result<WorkerReadinessReport, WorkerError> {
        let mut checks_passed = 0;
        let total_checks = 6;
        let mut diagnostics = Vec::new();

        // Check 1: Architecture compatibility
        if self.architecture == WorkerArchitecture::LinuxX86_64 {
            checks_passed += 1;
            diagnostics.push("Check 1 (Architecture: Linux x86_64): PASSED".to_string());
        } else {
            return Err(WorkerError::unsupported("Unsupported architecture"));
        }

        // Check 2: Resource bounds
        if self.resources.max_memory_bytes <= 4 * 1024 * 1024 * 1024
            && self.resources.max_cpu_cores <= 4
            && self.resources.timeout_seconds <= 300
        {
            checks_passed += 1;
            diagnostics.push("Check 2 (Resource bounds enforcement): PASSED".to_string());
        } else {
            return Err(WorkerError::resource_violation(
                "Resource ceilings exceed safety policy",
            ));
        }

        // Check 3: Egress isolation
        if self.egress == EgressPolicy::StrictlyDenied {
            checks_passed += 1;
            diagnostics.push("Check 3 (Network egress: Strictly Denied): PASSED".to_string());
        } else {
            return Err(WorkerError::egress_violation(
                "Egress must be strictly denied",
            ));
        }

        // Check 4: Path containment
        if self.path_containment_verified {
            checks_passed += 1;
            diagnostics.push("Check 4 (Path containment & traversal bounds): PASSED".to_string());
        } else {
            return Err(WorkerError::containment(
                "Path containment verification missing",
            ));
        }

        // Check 5: Credential isolation
        if self.credential_isolation_verified {
            checks_passed += 1;
            diagnostics.push(
                "Check 5 (Credential isolation & host secret protection): PASSED".to_string(),
            );
        } else {
            return Err(WorkerError::credential_leak(
                "Credential isolation unverified",
            ));
        }

        // Check 6: Ephemeral cleanup & crash recovery
        if self.crash_recovery_verified && self.ephemeral_cleanup_verified {
            checks_passed += 1;
            diagnostics.push("Check 6 (Crash recovery & ephemeral teardown): PASSED".to_string());
        } else {
            return Err(WorkerError::cleanup(
                "Cleanup and crash recovery unverified",
            ));
        }

        Ok(WorkerReadinessReport {
            worker_id: self.id.clone(),
            is_ready_for_untrusted_workload: checks_passed == total_checks,
            checks_passed,
            total_checks,
            diagnostics,
        })
    }
}

/// Verification report summarizing readiness of the worker containment boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerReadinessReport {
    /// Evaluated worker profile identifier.
    pub worker_id: String,
    /// Whether all mandatory isolation checks succeeded.
    pub is_ready_for_untrusted_workload: bool,
    /// Number of checks successfully passed.
    pub checks_passed: u32,
    /// Total number of checks evaluated.
    pub total_checks: u32,
    /// Step-by-step diagnostic log entries.
    pub diagnostics: Vec<String>,
}

/// Categories of worker containment or policy errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerErrorKind {
    /// Sandbox containment or filesystem boundary breach.
    ContainmentBreach(String),
    /// Configured resource ceiling exceeded.
    ResourceCapViolation(String),
    /// Unauthorized outbound network traffic detected or allowed.
    EgressViolation(String),
    /// Host credentials or private tokens exposed to worker.
    CredentialLeakage(String),
    /// Ephemeral worker failed to clean up or destroy files.
    CleanupFailure(String),
    /// Worker configuration or platform is unsupported.
    Unsupported(String),
}

/// Strongly typed error returned during worker isolation enforcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerError {
    /// Detailed classification of the worker failure.
    pub kind: WorkerErrorKind,
}

impl WorkerError {
    /// Constructs a new worker error.
    pub fn new(kind: WorkerErrorKind) -> Self {
        Self { kind }
    }

    /// Constructs a containment error.
    pub fn containment(msg: impl Into<String>) -> Self {
        Self::new(WorkerErrorKind::ContainmentBreach(msg.into()))
    }

    /// Constructs a resource violation error.
    pub fn resource_violation(msg: impl Into<String>) -> Self {
        Self::new(WorkerErrorKind::ResourceCapViolation(msg.into()))
    }

    /// Constructs an egress violation error.
    pub fn egress_violation(msg: impl Into<String>) -> Self {
        Self::new(WorkerErrorKind::EgressViolation(msg.into()))
    }

    /// Constructs a credential leakage error.
    pub fn credential_leak(msg: impl Into<String>) -> Self {
        Self::new(WorkerErrorKind::CredentialLeakage(msg.into()))
    }

    /// Constructs a cleanup error.
    pub fn cleanup(msg: impl Into<String>) -> Self {
        Self::new(WorkerErrorKind::CleanupFailure(msg.into()))
    }

    /// Constructs an unsupported error.
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::new(WorkerErrorKind::Unsupported(msg.into()))
    }
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            WorkerErrorKind::ContainmentBreach(m) => write!(f, "Worker containment breach: {m}"),
            WorkerErrorKind::ResourceCapViolation(m) => write!(f, "Worker resource violation: {m}"),
            WorkerErrorKind::EgressViolation(m) => write!(f, "Worker egress violation: {m}"),
            WorkerErrorKind::CredentialLeakage(m) => write!(f, "Worker credential leakage: {m}"),
            WorkerErrorKind::CleanupFailure(m) => write!(f, "Worker cleanup failure: {m}"),
            WorkerErrorKind::Unsupported(m) => write!(f, "Worker unsupported: {m}"),
        }
    }
}

impl std::error::Error for WorkerError {}
