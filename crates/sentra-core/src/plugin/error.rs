//! Strongly-typed errors for the subprocess plugin SDK and adapter protocol (REQ-F16).

use std::fmt;

/// Specific category of plugin or adapter protocol failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginErrorKind {
    /// Plugin interface version is incompatible with the host orchestrator.
    IncompatibleInterfaceVersion {
        /// Host expected interface version.
        expected: u32,
        /// Version declared or received from plugin.
        received: u32,
    },
    /// Plugin attempted an operation requiring an undeclared capability (REQ-F16).
    UndeclaredCapability {
        /// Name of the unauthorized capability.
        capability: String,
    },
    /// Plugin emitted an output frame or cumulative buffer exceeding quota (REQ-S06).
    OutputQuotaExceeded {
        /// Measured frame or buffer bytes.
        bytes: usize,
        /// Maximum allowed limit in bytes.
        limit: usize,
    },
    /// Plugin process terminated abnormally or crashed during execution.
    ProcessCrashDetected {
        /// OS exit code if available.
        exit_code: Option<i32>,
    },
    /// Replayed or duplicate execution job rejected by idempotency fencing.
    ReplayRejected {
        /// Target task identifier.
        task_id: String,
    },
    /// Message framing or schema violation in protocol transport.
    ProtocolViolation {
        /// Descriptive failure reason.
        reason: String,
    },
    /// Plugin manifest parsing or validation failure.
    InvalidManifest {
        /// Descriptive failure reason.
        reason: String,
    },
}

/// Strongly-typed error representing an adapter, transport, or conformance failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginError {
    kind: PluginErrorKind,
    message: String,
}

impl PluginError {
    /// Creates a new plugin error.
    pub fn new(kind: PluginErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the specific error kind.
    pub fn kind(&self) -> &PluginErrorKind {
        &self.kind
    }

    /// Helper for incompatible version error.
    pub fn incompatible_version(expected: u32, received: u32) -> Self {
        Self::new(
            PluginErrorKind::IncompatibleInterfaceVersion { expected, received },
            format!("Incompatible plugin interface: expected v{expected}, received v{received}"),
        )
    }

    /// Helper for undeclared capability error.
    pub fn undeclared_capability(cap: impl Into<String>) -> Self {
        let c = cap.into();
        Self::new(
            PluginErrorKind::UndeclaredCapability {
                capability: c.clone(),
            },
            format!("Plugin attempted undeclared capability '{c}'"),
        )
    }

    /// Helper for output quota exceeded error.
    pub fn output_quota_exceeded(bytes: usize, limit: usize) -> Self {
        Self::new(
            PluginErrorKind::OutputQuotaExceeded { bytes, limit },
            format!("Plugin output size {bytes} bytes exceeded ceiling of {limit} bytes"),
        )
    }

    /// Helper for process crash error.
    pub fn process_crash(code: Option<i32>) -> Self {
        Self::new(
            PluginErrorKind::ProcessCrashDetected { exit_code: code },
            format!(
                "Plugin process crashed with exit code {}",
                code.map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        )
    }

    /// Helper for replay rejection error.
    pub fn replay_rejected(task_id: impl Into<String>) -> Self {
        let t = task_id.into();
        Self::new(
            PluginErrorKind::ReplayRejected { task_id: t.clone() },
            format!("Replay rejected for task '{t}'"),
        )
    }

    /// Helper for protocol violation error.
    pub fn protocol_violation(reason: impl Into<String>) -> Self {
        let r = reason.into();
        Self::new(
            PluginErrorKind::ProtocolViolation { reason: r.clone() },
            format!("Protocol violation: {r}"),
        )
    }

    /// Helper for invalid manifest error.
    pub fn invalid_manifest(reason: impl Into<String>) -> Self {
        let r = reason.into();
        Self::new(
            PluginErrorKind::InvalidManifest { reason: r.clone() },
            format!("Invalid plugin manifest: {r}"),
        )
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PluginError {}
