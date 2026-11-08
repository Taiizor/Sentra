//! Plugin packaging manifests, adapter families, and quota boundaries (REQ-F16, EXTENSIONS.md).

use serde::{Deserialize, Serialize};

use crate::{advisory::SemverVersion, plugin::error::PluginError, verification::EgressPolicy};

/// Specific classification family for a plugin or adapter (EXTENSIONS.md § Adapter families).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterFamily {
    /// Detects project metadata, provides scoped context and harness plans.
    LanguageFramework,
    /// Executes static analysis, linters, or native scanners.
    AnalysisTool,
    /// Model provider adapter (hosted or local inference).
    AiProvider,
    /// Worker execution backend (disposable VM or container).
    ExecutionBackend,
    /// External research or autonomous cyber reasoning system (e.g. OSS-CRS).
    ResearchSystem,
    /// Importer/exporter producing versioned records (e.g. SARIF, Markdown, JSON).
    ExportImport,
}

impl AdapterFamily {
    /// Returns static string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LanguageFramework => "language_framework",
            Self::AnalysisTool => "analysis_tool",
            Self::AiProvider => "ai_provider",
            Self::ExecutionBackend => "execution_backend",
            Self::ResearchSystem => "research_system",
            Self::ExportImport => "export_import",
        }
    }
}

/// Explicit capabilities declared by a plugin adapter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Discovers source structure and component boundaries without code execution.
    SourceDiscovery,
    /// Audits project package manifests and lockfiles against vulnerability databases.
    DependencyAudit,
    /// Performs static pattern or semantic AST analysis.
    StaticAnalysis,
    /// Executes coverage-guided dynamic fuzzing.
    FuzzExecution,
    /// Generates candidate patch diffs and regression tests.
    PatchGeneration,
    /// Domain-specific custom capability tag.
    Custom(String),
}

/// Bounded resource quotas governing subprocess adapter execution (REQ-S06).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginQuotas {
    /// Maximum resident memory in MiB allocated to the subprocess.
    pub max_memory_mib: u32,
    /// Maximum execution time in seconds before forced termination.
    pub max_execution_time_secs: u32,
    /// Maximum permitted byte length for a single JSON protocol frame.
    pub max_frame_bytes: usize,
    /// Maximum cumulative stdout/stderr byte ceiling.
    pub max_total_output_bytes: usize,
}

impl Default for PluginQuotas {
    fn default() -> Self {
        Self {
            max_memory_mib: 1024,
            max_execution_time_secs: 60,
            max_frame_bytes: 1_048_576,         // 1 MiB per frame
            max_total_output_bytes: 10_485_760, // 10 MiB total output
        }
    }
}

/// Authenticated plugin manifest declaring identity, capabilities, and quotas (REQ-F16).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique identifier for this adapter (e.g. "org.sentra.adapter.rust-analyzer").
    pub id: String,
    /// Human-readable adapter name.
    pub name: String,
    /// Adapter implementation semver version.
    pub version: SemverVersion,
    /// Major protocol interface version supported (host mandates compatibility).
    pub interface_version: u32,
    /// Adapter classification family.
    pub family: AdapterFamily,
    /// Path or command used to invoke the supervised subprocess.
    pub executable_path: String,
    /// Explicitly declared capabilities (REQ-F16: undeclared capabilities rejected).
    pub declared_capabilities: Vec<PluginCapability>,
    /// Resource and output quotas.
    pub quotas: PluginQuotas,
    /// Network egress policy enforced for this adapter.
    pub egress_policy: EgressPolicy,
}

impl PluginManifest {
    /// Checks if a capability is declared in this manifest.
    pub fn supports_capability(&self, capability: &PluginCapability) -> bool {
        self.declared_capabilities.contains(capability)
    }

    /// Validates internal manifest integrity.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.id.trim().is_empty() {
            return Err(PluginError::invalid_manifest("Plugin ID cannot be empty"));
        }
        if self.executable_path.trim().is_empty() {
            return Err(PluginError::invalid_manifest(
                "Executable path cannot be empty",
            ));
        }
        if self.quotas.max_frame_bytes == 0 {
            return Err(PluginError::invalid_manifest(
                "max_frame_bytes must be greater than zero",
            ));
        }
        if self.quotas.max_total_output_bytes < self.quotas.max_frame_bytes {
            return Err(PluginError::invalid_manifest(
                "max_total_output_bytes cannot be less than max_frame_bytes",
            ));
        }
        Ok(())
    }
}
