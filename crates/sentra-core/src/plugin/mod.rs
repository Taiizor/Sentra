//! Subprocess plugin SDK, versioned adapter protocols, and capability fencing (REQ-F16, Plugin Architecture Specification).

pub mod codeql;
pub mod error;
pub mod host;
pub mod manifest;
pub mod protocol;
pub mod sample_adapter;

pub use codeql::{
    CodeQlAdapter, CodeQlError, CodeQlLanguage, CodeQlProbeReport, CodeQlSarifIngestResult,
    CodeQlTaintStep, CodeQlTaintTrace, TaintStepKind, ingest_codeql_sarif_payload,
    probe_codeql_workspace,
};
pub use error::{PluginError, PluginErrorKind};
pub use host::{HostStatus, PluginHost};
pub use manifest::{AdapterFamily, PluginCapability, PluginManifest, PluginQuotas};
pub use protocol::{PluginRequest, PluginResponse, decode_frame, encode_frame};
pub use sample_adapter::{SampleAdapter, SampleAdapterMode};
