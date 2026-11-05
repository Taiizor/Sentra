//! Execution engine coordinator.

use std::sync::Arc;

use crate::execution::{
    backend::{ExecutionBackend, FailClosedBackend},
    error::{ExecutionError, ExecutionErrorKind},
    model::{BackendCapabilities, ExecutionRequest, ExecutionResult},
};

/// High-level execution coordinator for the Sentra Core Engine.
///
/// Gates all task execution dispatch behind explicit validation, capability checks,
/// and security boundaries. Untrusted target workloads are rejected fail-closed
/// unless an authorized, hardware-isolated Hyper-V VM backend is configured.
pub struct ExecutionEngine {
    backend: Arc<dyn ExecutionBackend>,
}

impl Default for ExecutionEngine {
    fn default() -> Self {
        Self::new(Arc::new(FailClosedBackend::new()))
    }
}

impl ExecutionEngine {
    /// Creates a new execution engine with the specified backend.
    pub fn new(backend: Arc<dyn ExecutionBackend>) -> Self {
        Self { backend }
    }

    /// Constructs an execution engine with the default `FailClosedBackend`.
    pub fn fail_closed() -> Self {
        Self::default()
    }

    /// Returns the active backend's declared capabilities.
    pub fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    /// Dispatches a task execution request through the configured backend.
    ///
    /// # Security Invariants
    /// 1. Request parameters are exhaustively validated before invocation.
    /// 2. If `request.scope` is `UntrustedTargetWorkload`, the backend must explicitly
    ///    declare `supports_untrusted: true` and `isolated_vm_available: true`. Otherwise,
    ///    it is rejected immediately with `BackendUnavailable`.
    /// 3. Host process execution (`std::process::Command`), Docker, and WSL2 fallbacks
    ///    are strictly prohibited.
    /// 4. Cancellation and timeout are never converted into successful outcomes.
    pub fn dispatch(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        // Step 1: Strict request validation before touching the backend.
        request.validate()?;

        // Step 2: Intercept untrusted workloads if the backend lacks validated VM isolation.
        let caps = self.backend.capabilities();
        if request.scope.is_untrusted() && (!caps.supports_untrusted || !caps.isolated_vm_available)
        {
            return Err(ExecutionError::untrusted_workload_disabled());
        }

        // Step 3: Verify scope compatibility.
        if request.scope.is_synthetic() && !caps.supports_synthetic {
            return Err(ExecutionError::new(
                ExecutionErrorKind::UnsupportedScope,
                format!(
                    "Backend '{}' does not support synthetic test fixtures",
                    caps.backend_name
                ),
            ));
        }

        // Step 4: Dispatch to backend.
        let result = self.backend.execute(request)?;

        // Step 5: Exhaustive post-execution invariant and correlation checks (remediates F-551-01 and F-551-05).
        result.validate_for_request(request)?;

        Ok(result)
    }
}
