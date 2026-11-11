//! Subprocess plugin SDK, versioned adapter protocols, and capability fencing (REQ-F16, Plugin Architecture Specification).

pub mod codeql;
pub mod discovery;
pub mod driver;
pub mod error;
pub mod host;
pub mod manifest;
pub mod process;
pub mod protocol;
pub mod sample_adapter;

pub use codeql::{
    CodeQlAdapter, CodeQlError, CodeQlLanguage, CodeQlProbeReport, CodeQlSarifIngestResult,
    CodeQlTaintStep, CodeQlTaintTrace, TaintStepKind, ingest_codeql_sarif_payload,
    probe_codeql_workspace,
};
pub use discovery::{
    DiagnosticSeverity, DiscoveredPlugin, DiscoveryDiagnostic, MANIFEST_FILE_NAME, PLUGIN_DIR_ENV,
    PluginDiscovery, default_plugin_dir, default_plugin_dir_from, discover_plugins,
    discover_plugins_in_dir, find_plugin_by_id, plugin_dir_env_diagnostic,
    plugin_dir_env_diagnostic_from, resolve_plugin, scan_plugin_dirs,
};
pub use driver::{
    HANDSHAKE_TIMEOUT, PluginDriver, PluginExecutionOutput, PluginProbeOutput, PluginSessionReport,
    SHUTDOWN_GRACE, validate_workspace_root,
};
pub use error::{PluginError, PluginErrorKind};
pub use host::{
    HostStatus, MAX_EVIDENCE_REFS, PluginHost, is_valid_evidence_ref, is_valid_task_id,
};
pub use manifest::{
    AdapterFamily, MAX_EXECUTION_TIME_SECS, PLUGIN_INTERFACE_VERSION, PluginCapability,
    PluginManifest, PluginQuotas, split_command_line,
};
pub use process::{
    ADAPTER_ENV_ALLOWLIST, AdapterCommand, STDERR_TAIL_BYTES, adapter_environment,
    resolve_adapter_command,
};
pub use protocol::{PluginRequest, PluginResponse, decode_frame, encode_frame};
pub use sample_adapter::{SampleAdapter, SampleAdapterMode};
