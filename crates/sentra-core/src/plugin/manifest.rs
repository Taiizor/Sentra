//! Plugin packaging manifests, adapter families, and quota boundaries (REQ-F16, EXTENSIONS.md).

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{advisory::SemverVersion, plugin::error::PluginError, verification::EgressPolicy};

/// Adapter protocol interface version implemented by this host.
pub const PLUGIN_INTERFACE_VERSION: u32 = 1;

/// Upper bound applied to `quotas.max_execution_time_secs` (one hour).
pub const MAX_EXECUTION_TIME_SECS: u32 = 3_600;

/// Longest accepted plugin identifier.
const MAX_PLUGIN_ID_LEN: usize = 128;

/// Longest accepted custom capability name.
const MAX_CAPABILITY_NAME_LEN: usize = 64;

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
///
/// On the wire and in manifests every capability is a plain string. Names other than
/// the five built-ins become [`PluginCapability::Custom`]; the legacy
/// `{"custom": "name"}` object form is still accepted when reading.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

impl PluginCapability {
    /// Returns static string representation of the capability.
    pub fn as_str(&self) -> &str {
        match self {
            Self::SourceDiscovery => "source_discovery",
            Self::DependencyAudit => "dependency_audit",
            Self::StaticAnalysis => "static_analysis",
            Self::FuzzExecution => "fuzz_execution",
            Self::PatchGeneration => "patch_generation",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Whether a custom capability name is acceptable in a manifest:
    /// 1-64 characters of `[a-z0-9_.-]`, starting with a letter or digit.
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_CAPABILITY_NAME_LEN
            && name
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            })
    }
}

impl std::str::FromStr for PluginCapability {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "source_discovery" => Self::SourceDiscovery,
            "dependency_audit" => Self::DependencyAudit,
            "static_analysis" => Self::StaticAnalysis,
            "fuzz_execution" => Self::FuzzExecution,
            "patch_generation" => Self::PatchGeneration,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl std::fmt::Display for PluginCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for PluginCapability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PluginCapability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Name(String),
            Legacy { custom: String },
        }
        let name = match Repr::deserialize(deserializer)? {
            Repr::Name(name) | Repr::Legacy { custom: name } => name,
        };
        Ok(match name.parse() {
            Ok(capability) => capability,
            Err(never) => match never {},
        })
    }
}

/// Resource quotas declared by an adapter manifest (REQ-S06).
///
/// Enforced by the host today: `max_execution_time_secs` (session deadline, clamped to
/// [`MAX_EXECUTION_TIME_SECS`]), `max_frame_bytes` (bounded line reads) and
/// `max_total_output_bytes` (stdout frames plus drained stderr). `max_memory_mib` is
/// declared only; no memory limit is applied to the adapter process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginQuotas {
    /// Declared resident memory ceiling in MiB (declared, not enforced).
    pub max_memory_mib: u32,
    /// Session deadline in seconds; the adapter process tree is killed when it expires.
    pub max_execution_time_secs: u32,
    /// Maximum permitted byte length for a single JSON protocol frame.
    pub max_frame_bytes: usize,
    /// Maximum cumulative stdout and stderr bytes per session.
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

impl PluginQuotas {
    /// Session deadline actually applied by the host (1 s to [`MAX_EXECUTION_TIME_SECS`]).
    pub fn execution_timeout(&self) -> Duration {
        Duration::from_secs(u64::from(
            self.max_execution_time_secs
                .clamp(1, MAX_EXECUTION_TIME_SECS),
        ))
    }
}

/// Plugin manifest declaring identity, capabilities, and quotas (REQ-F16).
///
/// The manifest is written by the adapter author. It is not signed, and nothing in it
/// is trusted beyond what the host enforces itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique identifier for this adapter (e.g. "org.sentra.adapter.rust-analyzer").
    pub id: String,
    /// Human-readable adapter name.
    pub name: String,
    /// Adapter implementation semver version.
    pub version: SemverVersion,
    /// Major protocol interface version supported (must equal [`PLUGIN_INTERFACE_VERSION`]).
    pub interface_version: u32,
    /// Adapter classification family.
    pub family: AdapterFamily,
    /// Command line used to start the adapter, without a shell.
    ///
    /// Split on whitespace; `"..."` or `'...'` group an argument that contains spaces.
    /// A program containing a path separator is resolved inside the adapter directory,
    /// a bare program name through `PATH`.
    pub executable_path: String,
    /// Explicitly declared capabilities (REQ-F16: undeclared capabilities rejected).
    pub declared_capabilities: Vec<PluginCapability>,
    /// Resource and output quotas.
    #[serde(default)]
    pub quotas: PluginQuotas,
    /// Declared network egress policy (declared, not enforced by the host).
    pub egress_policy: EgressPolicy,
}

/// Top-level keys a manifest may contain.
pub(crate) const MANIFEST_KEYS: &[&str] = &[
    "id",
    "name",
    "version",
    "interface_version",
    "family",
    "executable_path",
    "declared_capabilities",
    "quotas",
    "egress_policy",
];

/// Keys a manifest `quotas` object may contain.
pub(crate) const QUOTA_KEYS: &[&str] = &[
    "max_memory_mib",
    "max_execution_time_secs",
    "max_frame_bytes",
    "max_total_output_bytes",
];

impl PluginManifest {
    /// Checks if a capability is declared in this manifest.
    pub fn supports_capability(&self, capability: &PluginCapability) -> bool {
        self.declared_capabilities.contains(capability)
    }

    /// Whether a plugin identifier is acceptable: 1-128 characters of `[A-Za-z0-9._-]`,
    /// starting with a letter or digit.
    pub fn is_valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= MAX_PLUGIN_ID_LEN
            && id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }

    /// Splits `executable_path` into program and arguments without invoking a shell.
    pub fn command_argv(&self) -> Result<Vec<String>, PluginError> {
        let argv = split_command_line(&self.executable_path).map_err(|reason| {
            PluginError::invalid_manifest(format!("executable_path: {reason}"))
        })?;
        match argv.first() {
            Some(program) if !program.is_empty() => Ok(argv),
            _ => Err(PluginError::invalid_manifest(
                "Executable path cannot be empty",
            )),
        }
    }

    /// Validates internal manifest integrity.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.id.trim().is_empty() {
            return Err(PluginError::invalid_manifest("Plugin ID cannot be empty"));
        }
        if !Self::is_valid_id(&self.id) {
            return Err(PluginError::invalid_manifest(format!(
                "Plugin ID '{}' must be 1-{MAX_PLUGIN_ID_LEN} characters of [A-Za-z0-9._-] starting with a letter or digit",
                self.id
            )));
        }
        if self.interface_version != PLUGIN_INTERFACE_VERSION {
            return Err(PluginError::invalid_manifest(format!(
                "interface_version {} is not supported; this host implements v{PLUGIN_INTERFACE_VERSION}",
                self.interface_version
            )));
        }
        if self.executable_path.trim().is_empty() {
            return Err(PluginError::invalid_manifest(
                "Executable path cannot be empty",
            ));
        }
        self.command_argv()?;
        for capability in &self.declared_capabilities {
            if let PluginCapability::Custom(name) = capability
                && !PluginCapability::is_valid_name(name)
            {
                return Err(PluginError::invalid_manifest(format!(
                    "custom capability '{name}' must be 1-{MAX_CAPABILITY_NAME_LEN} characters of [a-z0-9_.-] starting with a letter or digit"
                )));
            }
        }
        if self.quotas.max_memory_mib == 0 {
            return Err(PluginError::invalid_manifest(
                "max_memory_mib must be greater than zero",
            ));
        }
        if self.quotas.max_execution_time_secs == 0 {
            return Err(PluginError::invalid_manifest(
                "max_execution_time_secs must be greater than zero",
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

/// Splits a manifest command line into arguments without shell semantics.
///
/// Whitespace separates arguments. A double- or single-quoted run is taken literally
/// (no escapes, no expansion) and may contain whitespace.
pub fn split_command_line(line: &str) -> Result<Vec<String>, String> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                in_token = true;
            }
            None if ch.is_whitespace() => {
                if in_token {
                    argv.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            None => {
                current.push(ch);
                in_token = true;
            }
        }
    }
    if let Some(q) = quote {
        return Err(format!("unterminated {q} quote"));
    }
    if in_token {
        argv.push(current);
    }
    Ok(argv)
}
