//! Strongly-typed errors for the subprocess plugin SDK and adapter protocol (REQ-F16).

use std::{fmt, path::PathBuf};

/// Longest adapter- or manifest-supplied text kept in an error message.
const MAX_REASON_BYTES: usize = 512;

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
    /// Cumulative stdout + stderr volume exceeded `max_total_output_bytes` (REQ-S06).
    OutputQuotaExceeded {
        /// Measured cumulative bytes.
        bytes: usize,
        /// `max_total_output_bytes`.
        limit: usize,
    },
    /// A single stdout frame (line) exceeded `max_frame_bytes` (REQ-S06).
    FrameTooLarge {
        /// Bytes read for the frame before it was cut off.
        bytes: usize,
        /// `max_frame_bytes`.
        limit: usize,
    },
    /// The adapter identified itself with a different plugin id than its manifest.
    IdentityMismatch {
        /// Id declared by the manifest.
        expected: String,
        /// Id the adapter sent in `initialize_ack`.
        received: String,
    },
    /// Plugin process exited or closed stdout before answering.
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
    /// The manifest's executable could not be resolved or points outside the adapter directory.
    ExecutableRejected {
        /// Descriptive failure reason.
        reason: String,
    },
    /// The operating system refused to start the adapter process.
    SpawnFailed {
        /// Descriptive failure reason.
        reason: String,
    },
    /// The adapter did not answer before the session deadline; it was killed.
    Timeout {
        /// Protocol phase that was waiting (`initialize`, `probe`, `execute`).
        phase: String,
        /// Applied deadline in seconds.
        limit_secs: u64,
    },
    /// The adapter answered the operation with an `error` frame.
    AdapterReportedError {
        /// Adapter-chosen numeric code.
        code: i32,
        /// Sanitized adapter message.
        message: String,
    },
    /// A result frame does not belong to the request (task id or evidence reference grammar).
    ResultMismatch {
        /// Descriptive failure reason.
        reason: String,
    },
    /// The workspace root handed to the adapter is not an acceptable local directory.
    InvalidWorkspace {
        /// Descriptive failure reason.
        reason: String,
    },
    /// Two or more manifests in the searched directories declare the same plugin id.
    DuplicatePluginId {
        /// Ambiguous plugin identifier.
        plugin_id: String,
        /// Every manifest that declares it.
        manifest_paths: Vec<PathBuf>,
    },
    /// No manifest in the searched directories declares the plugin id.
    PluginNotFound {
        /// Requested plugin identifier.
        plugin_id: String,
    },
}

impl PluginErrorKind {
    /// Stable machine-readable error code for CLI, API and MCP surfaces.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::IncompatibleInterfaceVersion { .. } => "plugin_incompatible_interface",
            Self::UndeclaredCapability { .. } => "plugin_undeclared_capability",
            Self::OutputQuotaExceeded { .. } => "plugin_output_quota_exceeded",
            Self::FrameTooLarge { .. } => "plugin_frame_too_large",
            Self::IdentityMismatch { .. } => "plugin_identity_mismatch",
            Self::ProcessCrashDetected { .. } => "plugin_process_exited",
            Self::ReplayRejected { .. } => "plugin_replay_rejected",
            Self::ProtocolViolation { .. } => "plugin_protocol_violation",
            Self::InvalidManifest { .. } => "invalid_manifest",
            Self::ExecutableRejected { .. } => "plugin_executable_rejected",
            Self::SpawnFailed { .. } => "plugin_spawn_failed",
            Self::Timeout { .. } => "plugin_timeout",
            Self::AdapterReportedError { .. } => "plugin_adapter_error",
            Self::ResultMismatch { .. } => "plugin_result_mismatch",
            Self::InvalidWorkspace { .. } => "plugin_invalid_workspace",
            Self::DuplicatePluginId { .. } => "plugin_duplicate_id",
            Self::PluginNotFound { .. } => "plugin_not_found",
        }
    }
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

    /// Stable machine-readable error code (see [`PluginErrorKind::code`]).
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// Single-line human-readable reason without control characters, safe to print.
    pub fn reason(&self) -> &str {
        &self.message
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
        let c = sanitize_text(&cap.into());
        Self::new(
            PluginErrorKind::UndeclaredCapability {
                capability: c.clone(),
            },
            format!("Plugin attempted undeclared capability '{c}'"),
        )
    }

    /// Helper for a cumulative output (stdout + stderr) quota breach.
    pub fn output_quota_exceeded(bytes: usize, limit: usize) -> Self {
        Self::new(
            PluginErrorKind::OutputQuotaExceeded { bytes, limit },
            format!(
                "Adapter stdout + stderr reached {bytes} bytes, exceeding max_total_output_bytes ({limit} bytes)"
            ),
        )
    }

    /// Helper for a single oversized stdout frame.
    pub fn frame_too_large(bytes: usize, limit: usize) -> Self {
        Self::new(
            PluginErrorKind::FrameTooLarge { bytes, limit },
            format!(
                "Adapter frame of at least {bytes} bytes exceeded max_frame_bytes ({limit} bytes)"
            ),
        )
    }

    /// Helper for an adapter that answers with another plugin's id.
    pub fn identity_mismatch(expected: impl Into<String>, received: impl Into<String>) -> Self {
        let expected = sanitize_text(&expected.into());
        let received = sanitize_text(&received.into());
        Self::new(
            PluginErrorKind::IdentityMismatch {
                expected: expected.clone(),
                received: received.clone(),
            },
            format!(
                "Adapter identified itself as '{received}', but its manifest declares '{expected}'"
            ),
        )
    }

    /// Helper for process crash error.
    pub fn process_crash(code: Option<i32>) -> Self {
        Self::new(
            PluginErrorKind::ProcessCrashDetected { exit_code: code },
            format!(
                "Plugin process exited before answering (exit code {})",
                code.map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        )
    }

    /// Helper for replay rejection error.
    pub fn replay_rejected(task_id: impl Into<String>) -> Self {
        let t = sanitize_text(&task_id.into());
        Self::new(
            PluginErrorKind::ReplayRejected { task_id: t.clone() },
            format!("Replay rejected for task '{t}'"),
        )
    }

    /// Helper for protocol violation error.
    pub fn protocol_violation(reason: impl Into<String>) -> Self {
        let r = sanitize_text(&reason.into());
        Self::new(
            PluginErrorKind::ProtocolViolation { reason: r.clone() },
            format!("Protocol violation: {r}"),
        )
    }

    /// Helper for invalid manifest error.
    pub fn invalid_manifest(reason: impl Into<String>) -> Self {
        let r = sanitize_text(&reason.into());
        Self::new(
            PluginErrorKind::InvalidManifest { reason: r.clone() },
            format!("Invalid plugin manifest: {r}"),
        )
    }

    /// Helper for a rejected or unresolvable adapter executable.
    pub fn executable_rejected(reason: impl Into<String>) -> Self {
        let r = sanitize_text(&reason.into());
        Self::new(
            PluginErrorKind::ExecutableRejected { reason: r.clone() },
            format!("Adapter executable rejected: {r}"),
        )
    }

    /// Helper for a process creation failure.
    pub fn spawn_failed(reason: impl Into<String>) -> Self {
        let r = sanitize_text(&reason.into());
        Self::new(
            PluginErrorKind::SpawnFailed { reason: r.clone() },
            format!("Failed to start adapter process: {r}"),
        )
    }

    /// Helper for a session deadline breach.
    pub fn timeout(phase: impl Into<String>, limit_secs: u64) -> Self {
        let phase = sanitize_text(&phase.into());
        Self::new(
            PluginErrorKind::Timeout {
                phase: phase.clone(),
                limit_secs,
            },
            format!("Adapter did not answer '{phase}' within {limit_secs} s; it was terminated"),
        )
    }

    /// Helper for an adapter `error` frame.
    pub fn adapter_reported(code: i32, message: impl Into<String>) -> Self {
        let m = sanitize_text(&message.into());
        Self::new(
            PluginErrorKind::AdapterReportedError {
                code,
                message: m.clone(),
            },
            format!("Adapter reported error {code}: {m}"),
        )
    }

    /// Helper for an uncorrelated or malformed result frame.
    pub fn result_mismatch(reason: impl Into<String>) -> Self {
        let r = sanitize_text(&reason.into());
        Self::new(
            PluginErrorKind::ResultMismatch { reason: r.clone() },
            format!("Adapter result rejected: {r}"),
        )
    }

    /// Helper for an unacceptable workspace root.
    pub fn invalid_workspace(reason: impl Into<String>) -> Self {
        let r = sanitize_text(&reason.into());
        Self::new(
            PluginErrorKind::InvalidWorkspace { reason: r.clone() },
            format!("Invalid workspace root: {r}"),
        )
    }

    /// Helper for an ambiguous plugin id.
    pub fn duplicate_plugin_id(plugin_id: impl Into<String>, manifest_paths: Vec<PathBuf>) -> Self {
        let id = sanitize_text(&plugin_id.into());
        let listed = manifest_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Self::new(
            PluginErrorKind::DuplicatePluginId {
                plugin_id: id.clone(),
                manifest_paths,
            },
            sanitize_text(&format!(
                "Plugin id '{id}' is declared by more than one manifest: {listed}"
            )),
        )
    }

    /// Helper for an unknown plugin id.
    pub fn plugin_not_found(plugin_id: impl Into<String>) -> Self {
        let id = sanitize_text(&plugin_id.into());
        Self::new(
            PluginErrorKind::PluginNotFound {
                plugin_id: id.clone(),
            },
            format!("No manifest in the plugin directories declares id '{id}'"),
        )
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PluginError {}

/// Replaces control characters with spaces and truncates to a bounded length.
///
/// Adapter- and manifest-supplied text reaches terminals and logs; this keeps it on
/// one line and free of escape sequences.
pub(crate) fn sanitize_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_REASON_BYTES));
    for ch in text.chars() {
        if out.len() + ch.len_utf8() > MAX_REASON_BYTES {
            out.push('…');
            break;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
    }
    out
}
