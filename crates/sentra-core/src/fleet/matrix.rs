//! Per-adapter supported-target matrix and capability tuple declarations (REQ-F19, EXTENSIONS.md).

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

use crate::{
    fleet::error::{FleetError, FleetErrorKind},
    verification::WorkerArchitecture,
};

/// Host operating system and platform where the Sentra control plane executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    /// Windows 11 x64 host platform.
    WindowsX64,
    /// Linux x86_64 host platform.
    LinuxX86_64,
    /// macOS ARM64 host platform.
    MacOsArm64,
}

impl HostPlatform {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WindowsX64 => "windows_x64",
            Self::LinuxX86_64 => "linux_x86_64",
            Self::MacOsArm64 => "macos_arm64",
        }
    }
}

impl fmt::Display for HostPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Target language, framework, or artifact classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetLanguage {
    /// Rust source repository and cargo manifests.
    Rust,
    /// C/C++ source repository with autotools, cmake, or make.
    CCpp,
    /// Native compiled x86_64 binary artifact (ELF / PE).
    BinaryX86_64,
    /// Structured SARIF static analysis document.
    SarifReport,
    /// Dependency lockfile manifest (Cargo.lock, lockfile manifests).
    LockfileManifest,
}

impl TargetLanguage {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::CCpp => "c_cpp",
            Self::BinaryX86_64 => "binary_x86_64",
            Self::SarifReport => "sarif_report",
            Self::LockfileManifest => "lockfile_manifest",
        }
    }
}

impl fmt::Display for TargetLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Granular action capability supported by an adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterActionCapability {
    /// Scopes and discovers project structure without native code execution.
    DiscoveryOnly,
    /// Performs AST, data-flow, or pattern analysis without executing target binaries.
    StaticAnalysis,
    /// Runs dynamic fuzzing and harness reproduction in an isolated disposable worker.
    ReproductionFuzzing,
    /// Executes dual-state regression test verification on base and candidate patches.
    PatchVerification,
}

impl AdapterActionCapability {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DiscoveryOnly => "discovery_only",
            Self::StaticAnalysis => "static_analysis",
            Self::ReproductionFuzzing => "reproduction_fuzzing",
            Self::PatchVerification => "patch_verification",
        }
    }
}

impl fmt::Display for AdapterActionCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Method of evidence generation and admission backing a capability claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMethod {
    /// Tamper-resistant immutable audit trail record.
    AuditLogProof,
    /// Static AST / call-graph structural evidence.
    StaticAstProof,
    /// AddressSanitizer/UBSan crash artifact with verified signal and exit code.
    AsanCrashArtifact,
    /// Passing dual-state test execution diff (unpatched fails, patched passes).
    DualStateTestDiff,
    /// Decompiled/disassembled binary instruction trace.
    DisassemblyArtifact,
}

impl EvidenceMethod {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AuditLogProof => "audit_log_proof",
            Self::StaticAstProof => "static_ast_proof",
            Self::AsanCrashArtifact => "asan_crash_artifact",
            Self::DualStateTestDiff => "dual_state_test_diff",
            Self::DisassemblyArtifact => "disassembly_artifact",
        }
    }
}

impl fmt::Display for EvidenceMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Strict 7-tuple defining an exact supported execution target profile (EXTENSIONS.md).
///
/// Wildcards ('*', '%', 'all', 'any') are strictly prohibited to prevent overstated capability claims.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SupportedTargetTuple {
    /// Control-plane host platform.
    pub host: HostPlatform,
    /// Worker architecture enclosing execution.
    pub worker_arch: WorkerArchitecture,
    /// Target programming language or artifact format.
    pub target_language: TargetLanguage,
    /// Target language/framework version range (e.g. "1.80..=1.99").
    pub framework_version_range: String,
    /// Tool or compiler version (e.g. "cargo-1.80", "clang-18").
    pub tool_version: String,
    /// Specific action capability supported.
    pub action: AdapterActionCapability,
    /// Evidence method backing the result.
    pub evidence_method: EvidenceMethod,
}

impl SupportedTargetTuple {
    /// Creates and validates a new supported target tuple.
    ///
    /// Fails closed with `WildcardProhibited` if any version string contains wildcards ('*', '%', 'all', 'any').
    /// Fails closed with `InvalidInput` if version strings are empty or if discovery claims dynamic proof.
    pub fn new(
        host: HostPlatform,
        worker_arch: WorkerArchitecture,
        target_language: TargetLanguage,
        framework_version_range: impl Into<String>,
        tool_version: impl Into<String>,
        action: AdapterActionCapability,
        evidence_method: EvidenceMethod,
    ) -> Result<Self, FleetError> {
        let fw_range = framework_version_range.into();
        let fw_trimmed = fw_range.trim();

        let tool_ver = tool_version.into();
        let tool_trimmed = tool_ver.trim();

        if fw_trimmed.is_empty() {
            return Err(FleetError::new(
                FleetErrorKind::InvalidInput,
                "framework version range cannot be empty",
            ));
        }

        if tool_trimmed.is_empty() {
            return Err(FleetError::new(
                FleetErrorKind::InvalidInput,
                "tool version cannot be empty",
            ));
        }

        // Validate wildcard prohibition (Fleet Security Specification / EXTENSIONS.md)
        for val in &[fw_trimmed, tool_trimmed] {
            if val.contains('*')
                || val.contains('%')
                || val.eq_ignore_ascii_case("all")
                || val.eq_ignore_ascii_case("any")
            {
                return Err(FleetError::wildcard_prohibited(format!(
                    "wildcard support declaration is prohibited in '{val}'; exact versions required"
                )));
            }
        }

        // Discovery-only support cannot claim dynamic reproduction or patch verification evidence
        if action == AdapterActionCapability::DiscoveryOnly
            && matches!(
                evidence_method,
                EvidenceMethod::AsanCrashArtifact | EvidenceMethod::DualStateTestDiff
            )
        {
            return Err(FleetError::new(
                FleetErrorKind::InvalidInput,
                "discovery-only action cannot declare dynamic execution evidence methods",
            ));
        }

        Ok(Self {
            host,
            worker_arch,
            target_language,
            framework_version_range: fw_trimmed.to_string(),
            tool_version: tool_trimmed.to_string(),
            action,
            evidence_method,
        })
    }
}

/// Registry of adapter supported-target matrices enforcing strict capability checking.
#[derive(Clone, Debug, Default)]
pub struct SupportMatrix {
    declarations: HashMap<String, Vec<SupportedTargetTuple>>,
}

impl SupportMatrix {
    /// Creates a new, empty support matrix registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a validated target tuple for an adapter.
    pub fn register_adapter_support(
        &mut self,
        adapter_name: impl Into<String>,
        tuple: SupportedTargetTuple,
    ) {
        let name = adapter_name.into();
        let list = self.declarations.entry(name).or_default();
        if !list.contains(&tuple) {
            list.push(tuple);
        }
    }

    /// Checks if a requested target tuple is supported by at least one registered adapter.
    pub fn is_supported(&self, query: &SupportedTargetTuple) -> bool {
        self.declarations
            .values()
            .any(|tuples| tuples.iter().any(|t| t == query))
    }

    /// Returns the names of all adapters supporting the requested target tuple.
    pub fn find_supporting_adapters(&self, query: &SupportedTargetTuple) -> Vec<String> {
        self.declarations
            .iter()
            .filter(|(_, tuples)| tuples.iter().any(|t| t == query))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Total count of registered capability tuples across all adapters.
    pub fn total_declarations_count(&self) -> usize {
        self.declarations.values().map(|v| v.len()).sum()
    }

    /// Builds the canonical reference platform matrix for Sentra's verified adapters.
    pub fn reference_platform_matrix() -> Self {
        let mut matrix = Self::new();

        // 1. Rust Cargo.lock Advisory Auditor
        if let Ok(tuple) = SupportedTargetTuple::new(
            HostPlatform::WindowsX64,
            WorkerArchitecture::WindowsX64,
            TargetLanguage::LockfileManifest,
            "Cargo.lock-v1..=v4",
            "rustsec-v0.1.0",
            AdapterActionCapability::StaticAnalysis,
            EvidenceMethod::AuditLogProof,
        ) {
            matrix.register_adapter_support("rust_advisory_auditor", tuple);
        }

        // 2. Rust Source Differential Analyzer
        if let Ok(tuple) = SupportedTargetTuple::new(
            HostPlatform::WindowsX64,
            WorkerArchitecture::WindowsX64,
            TargetLanguage::Rust,
            "1.80..=1.99",
            "cargo-1.80",
            AdapterActionCapability::StaticAnalysis,
            EvidenceMethod::StaticAstProof,
        ) {
            matrix.register_adapter_support("rust_diff_analyzer", tuple);
        }

        // 3. Linux C/C++ Fuzzing & Crash Reproduction Engine
        if let Ok(tuple) = SupportedTargetTuple::new(
            HostPlatform::WindowsX64,
            WorkerArchitecture::LinuxX86_64,
            TargetLanguage::CCpp,
            "C11..=C23",
            "clang-18",
            AdapterActionCapability::ReproductionFuzzing,
            EvidenceMethod::AsanCrashArtifact,
        ) {
            matrix.register_adapter_support("linux_cpp_fuzz_engine", tuple);
        }

        // 4. Disposable Linux Patch Verification Engine
        if let Ok(tuple) = SupportedTargetTuple::new(
            HostPlatform::WindowsX64,
            WorkerArchitecture::LinuxX86_64,
            TargetLanguage::Rust,
            "1.80..=1.99",
            "cargo-1.80",
            AdapterActionCapability::PatchVerification,
            EvidenceMethod::DualStateTestDiff,
        ) {
            matrix.register_adapter_support("disposable_patch_verifier", tuple);
        }

        // 5. Binary Analysis Adapter Candidate (Ghidra Static Analysis)
        if let Ok(tuple) = SupportedTargetTuple::new(
            HostPlatform::WindowsX64,
            WorkerArchitecture::LinuxX86_64,
            TargetLanguage::BinaryX86_64,
            "ELF-x86_64",
            "ghidra-11.1",
            AdapterActionCapability::StaticAnalysis,
            EvidenceMethod::DisassemblyArtifact,
        ) {
            matrix.register_adapter_support("ghidra_binary_adapter", tuple);
        }

        matrix
    }
}
