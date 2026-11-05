//! Explicit execution scope models.

use std::fmt;

/// Explicit execution security scope.
///
/// This enum strictly separates repository-controlled test fixtures from untrusted
/// target project workloads. In compliance with ADR-0004 and Phase 1 constraints,
/// untrusted target code MUST NEVER execute directly on the host, via Docker, or via WSL2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionScope {
    /// Curated, repository-controlled, maintainer-signed harmless test fixture.
    /// Used strictly for protocol verification and internal engine testing.
    SyntheticFixture,
    /// Arbitrary target project workload (build scripts, test runners, linters, binaries).
    /// Requires an isolated disposable Hyper-V VM worker. Fail-closed by default.
    UntrustedTargetWorkload,
}

impl ExecutionScope {
    /// Returns true if this scope represents an untrusted target workload.
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::UntrustedTargetWorkload)
    }

    /// Returns true if this scope represents a synthetic test fixture.
    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::SyntheticFixture)
    }

    /// Canonical string identifier for auditing and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SyntheticFixture => "SYNTHETIC_FIXTURE",
            Self::UntrustedTargetWorkload => "UNTRUSTED_TARGET_WORKLOAD",
        }
    }
}

impl fmt::Display for ExecutionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
