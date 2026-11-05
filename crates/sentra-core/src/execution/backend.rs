//! Execution backend abstraction and default fail-closed implementations.

use crate::{
    TimestampUtc,
    execution::{
        error::{ExecutionError, ExecutionErrorKind},
        model::{
            BackendCapabilities, ExecutionRequest, ExecutionResult, ExecutionStatus, ResourceUsage,
        },
        scope::ExecutionScope,
    },
};

/// Pluggable execution backend contract.
///
/// In compliance with ADR-0004 and ADR-0005, the Core Engine decouples task dispatch
/// from concrete worker isolation technologies. All backends must declare their
/// capabilities explicitly.
pub trait ExecutionBackend: Send + Sync {
    /// Canonical name of this backend.
    fn name(&self) -> &'static str;

    /// Declared capabilities and availability profile.
    fn capabilities(&self) -> BackendCapabilities;

    /// Dispatches a validated execution request.
    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError>;
}

/// The default, non-executing backend.
///
/// Refuses all workloads fail-closed. In compliance with the Milestone 4 Conditional Go
/// decision, untrusted execution is permanently disabled until dedicated disposable Hyper-V
/// VM isolation and an authenticated host-to-guest control channel are validated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FailClosedBackend;

impl FailClosedBackend {
    /// Constructs a new `FailClosedBackend`.
    pub const fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for FailClosedBackend {
    fn name(&self) -> &'static str {
        "fail-closed"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: false,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Default fail-closed execution boundary; untrusted target workloads are disabled pending validated Hyper-V isolation (ADR-0004)",
        }
    }

    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        request.validate()?;
        match request.scope {
            ExecutionScope::UntrustedTargetWorkload => {
                Err(ExecutionError::untrusted_workload_disabled())
            }
            ExecutionScope::SyntheticFixture => Err(ExecutionError::new(
                ExecutionErrorKind::BackendUnavailable,
                "FailClosedBackend does not execute synthetic fixtures; use SyntheticFixtureBackend for testing",
            )),
        }
    }
}

/// Controlled backend for offline test verification of execution workflows.
///
/// Strictly restricted to curated, maintainer-controlled synthetic test actions.
/// REJECTS all untrusted target workloads fail-closed. Does NOT execute host processes,
/// Docker containers, or WSL2 distributions.
#[derive(Clone, Debug, Default)]
pub struct SyntheticFixtureBackend;

impl SyntheticFixtureBackend {
    /// Constructs a new `SyntheticFixtureBackend`.
    pub const fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for SyntheticFixtureBackend {
    fn name(&self) -> &'static str {
        "synthetic-fixture"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: true,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Synthetic test fixture backend; supports curated test actions only; strictly rejects untrusted workloads",
        }
    }

    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        request.validate()?;

        // Non-negotiable security invariant: untrusted workloads are ALWAYS rejected.
        if request.scope.is_untrusted() {
            return Err(ExecutionError::untrusted_workload_disabled());
        }

        let action_name = match &request.action {
            crate::OperationAction::ExecuteTool { tool_id, .. } => tool_id.as_str(),
            other => other.action_name(),
        };
        let now = TimestampUtc::now();

        match action_name {
            "synthetic:noop" | "synthetic:success" => Ok(ExecutionResult {
                execution_id: request.execution_id,
                status: ExecutionStatus::Completed,
                exit_code: Some(0),
                resource_usage: ResourceUsage {
                    duration_millis: 1,
                    peak_memory_bytes: 1024,
                    output_bytes: 0,
                },
                evidence_descriptors: Vec::new(),
                completed_at: now,
            }),
            "synthetic:failure" => Ok(ExecutionResult {
                execution_id: request.execution_id,
                status: ExecutionStatus::Failed,
                exit_code: Some(1),
                resource_usage: ResourceUsage {
                    duration_millis: 1,
                    peak_memory_bytes: 1024,
                    output_bytes: 128,
                },
                evidence_descriptors: Vec::new(),
                completed_at: now,
            }),
            "synthetic:timeout" => Ok(ExecutionResult {
                execution_id: request.execution_id,
                status: ExecutionStatus::TimedOut,
                exit_code: None,
                resource_usage: ResourceUsage {
                    duration_millis: request.resource_limits.timeout_millis,
                    peak_memory_bytes: 1024,
                    output_bytes: 0,
                },
                evidence_descriptors: Vec::new(),
                completed_at: now,
            }),
            "synthetic:cancelled" => Ok(ExecutionResult {
                execution_id: request.execution_id,
                status: ExecutionStatus::Cancelled,
                exit_code: None,
                resource_usage: ResourceUsage::zero(),
                evidence_descriptors: Vec::new(),
                completed_at: now,
            }),
            "synthetic:evidence" => Ok(ExecutionResult {
                execution_id: request.execution_id,
                status: ExecutionStatus::Completed,
                exit_code: Some(0),
                resource_usage: ResourceUsage {
                    duration_millis: 2,
                    peak_memory_bytes: 2048,
                    output_bytes: 256,
                },
                evidence_descriptors: vec!["synthetic-evidence-artifact-001".to_string()],
                completed_at: now,
            }),
            _ => Err(ExecutionError::new(
                ExecutionErrorKind::InvalidRequest,
                format!("Unsupported synthetic fixture action: '{action_name}'"),
            )),
        }
    }
}
