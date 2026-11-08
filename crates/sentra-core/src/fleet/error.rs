//! Remote-worker fleet management, multi-user audit, and target matrix error models (REQ-F19, ADR-0004).

use std::fmt;

/// Categories of fleet management, supported-target matrix, and multi-user security audit errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FleetErrorKind {
    /// Requested remote worker was not found in the fleet registry.
    WorkerNotFound,
    /// Remote worker is currently busy, already leased, or provisioning.
    WorkerBusy,
    /// Cross-tenant worker access or lease violation attempted.
    CrossTenantWorkerAccessDenied,
    /// Target execution tuple is unsupported by any registered adapter.
    UnsupportedTargetTuple,
    /// Wildcard character ('*' or '%') detected in target support declaration.
    WildcardProhibited,
    /// Worker heartbeat has expired or missed its keepalive window.
    HeartbeatExpired,
    /// Worker is quarantined due to suspected breach, timeout, or pending sanitization.
    WorkerQuarantined,
    /// Security audit gate failed prior to authorizing multi-user hosting.
    SecurityAuditFailed,
    /// Malformed parameter, empty identifier, or invalid configuration.
    InvalidInput,
}

impl FleetErrorKind {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WorkerNotFound => "worker_not_found",
            Self::WorkerBusy => "worker_busy",
            Self::CrossTenantWorkerAccessDenied => "cross_tenant_worker_access_denied",
            Self::UnsupportedTargetTuple => "unsupported_target_tuple",
            Self::WildcardProhibited => "wildcard_prohibited",
            Self::HeartbeatExpired => "heartbeat_expired",
            Self::WorkerQuarantined => "worker_quarantined",
            Self::SecurityAuditFailed => "security_audit_failed",
            Self::InvalidInput => "invalid_input",
        }
    }
}

impl fmt::Display for FleetErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Strongly-typed error produced by the remote-worker fleet management subsystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetError {
    kind: FleetErrorKind,
    message: String,
}

impl FleetError {
    /// Creates a new fleet error.
    pub fn new(kind: FleetErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the category of this error.
    pub fn kind(&self) -> FleetErrorKind {
        self.kind
    }

    /// Returns the descriptive error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Helper for worker not found errors.
    pub fn worker_not_found(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::WorkerNotFound, msg)
    }

    /// Helper for worker busy errors.
    pub fn worker_busy(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::WorkerBusy, msg)
    }

    /// Helper for cross-tenant access denied errors.
    pub fn cross_tenant_denied(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::CrossTenantWorkerAccessDenied, msg)
    }

    /// Helper for unsupported target tuple errors.
    pub fn unsupported_target(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::UnsupportedTargetTuple, msg)
    }

    /// Helper for wildcard prohibited errors.
    pub fn wildcard_prohibited(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::WildcardProhibited, msg)
    }

    /// Helper for worker quarantined errors.
    pub fn quarantined(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::WorkerQuarantined, msg)
    }

    /// Helper for security audit failure errors.
    pub fn security_audit_failed(msg: impl Into<String>) -> Self {
        Self::new(FleetErrorKind::SecurityAuditFailed, msg)
    }
}

impl fmt::Display for FleetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.message)
    }
}

impl std::error::Error for FleetError {}
