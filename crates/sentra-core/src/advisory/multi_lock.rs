//! Multi-ecosystem lockfile detection and dispatch (Requirement F-07, polyglot expansion).
//!
//! Supports pure-Rust parsing of:
//! - Rust: `Cargo.lock`
//! - npm / Node.js: `package-lock.json`
//! - Yarn: `yarn.lock` (v1 Classic and v2+ Berry)
//! - pnpm: `pnpm-lock.yaml`
//! - Bun: `bun.lock`
//! - Deno: `deno.lock`
//! - Python: `requirements.txt`, `poetry.lock`, `Pipfile.lock`
//! - Go: `go.sum`
//! - PHP Composer: `composer.lock`
//! - .NET NuGet: `packages.lock.json`
//! - Ruby Bundler: `Gemfile.lock`

use std::path::Path;

use crate::advisory::{
    bun_lock::parse_bun_lock,
    cargo_lock::{PackageRecord, parse_cargo_lock},
    composer_lock::parse_composer_lock,
    deno_lock::parse_deno_lock,
    error::AdvisoryError,
    gemfile_lock::parse_gemfile_lock,
    go_lock::parse_go_sum,
    nuget_lock::parse_nuget_lock,
    package_lock::parse_package_lock,
    pnpm_lock::parse_pnpm_lock,
    python_lock::{parse_pipfile_lock, parse_poetry_lock, parse_requirements_txt},
    yarn_lock::parse_yarn_lock,
};

/// Supported package manager lockfile formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LockfileKind {
    /// Rust Cargo package manager (`Cargo.lock`).
    Cargo,
    /// npm and Node.js (`package-lock.json`).
    PackageLock,
    /// Yarn package manager (`yarn.lock`).
    Yarn,
    /// pnpm package manager (`pnpm-lock.yaml`).
    Pnpm,
    /// Bun runtime and package manager (`bun.lock`).
    Bun,
    /// Deno runtime (`deno.lock`).
    Deno,
    /// Python pip pinned requirements (`requirements.txt`).
    RequirementsTxt,
    /// Python Poetry package manager (`poetry.lock`).
    Poetry,
    /// Python Pipenv package manager (`Pipfile.lock`).
    Pipfile,
    /// Go module checksum manifest (`go.sum`).
    GoSum,
    /// PHP Composer package manager (`composer.lock`).
    Composer,
    /// .NET NuGet package manager (`packages.lock.json`).
    NuGet,
    /// Ruby Bundler package manager (`Gemfile.lock`).
    Gemfile,
}

impl LockfileKind {
    /// Returns the canonical default filename for this lockfile format.
    pub const fn default_filename(&self) -> &'static str {
        match self {
            Self::Cargo => "Cargo.lock",
            Self::PackageLock => "package-lock.json",
            Self::Yarn => "yarn.lock",
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Bun => "bun.lock",
            Self::Deno => "deno.lock",
            Self::RequirementsTxt => "requirements.txt",
            Self::Poetry => "poetry.lock",
            Self::Pipfile => "Pipfile.lock",
            Self::GoSum => "go.sum",
            Self::Composer => "composer.lock",
            Self::NuGet => "packages.lock.json",
            Self::Gemfile => "Gemfile.lock",
        }
    }

    /// Detects the lockfile kind from a given filename or path.
    pub fn detect_from_filename(filename: &str) -> Option<Self> {
        let name = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename);

        match name {
            "Cargo.lock" => Some(Self::Cargo),
            "package-lock.json" => Some(Self::PackageLock),
            "yarn.lock" => Some(Self::Yarn),
            "pnpm-lock.yaml" | "pnpm-lock.yml" => Some(Self::Pnpm),
            "bun.lock" | "bun.lockb.json" => Some(Self::Bun),
            "deno.lock" | "deno.lock.json" => Some(Self::Deno),
            "requirements.txt" => Some(Self::RequirementsTxt),
            "poetry.lock" => Some(Self::Poetry),
            "Pipfile.lock" => Some(Self::Pipfile),
            "go.sum" => Some(Self::GoSum),
            "composer.lock" => Some(Self::Composer),
            "packages.lock.json" => Some(Self::NuGet),
            "Gemfile.lock" => Some(Self::Gemfile),
            _ => None,
        }
    }

    /// List of all canonical lockfile filenames in order of detection preference.
    pub const ALL_FILENAMES: [&'static str; 13] = [
        "Cargo.lock",
        "package-lock.json",
        "bun.lock",
        "pnpm-lock.yaml",
        "yarn.lock",
        "deno.lock",
        "requirements.txt",
        "poetry.lock",
        "Pipfile.lock",
        "go.sum",
        "composer.lock",
        "packages.lock.json",
        "Gemfile.lock",
    ];
}

/// Splits a package specifier string like `lodash@4.17.21` or `@types/node@18.0.0`
/// into `(package_name, version)`.
pub fn split_package_specifier(spec: &str) -> Option<(&str, &str)> {
    let trimmed = spec.trim().trim_matches('"').trim_matches('\'');
    let s = trimmed.strip_prefix('/').unwrap_or(trimmed);

    // Handle peer dependency suffixes in pnpm like `package@1.0.0(dep@2.0.0)`
    let s = if let Some(idx) = s.find('(') {
        &s[..idx]
    } else {
        s
    };

    if let Some(rest) = s.strip_prefix('@') {
        // Scoped package e.g. `@scope/pkg@1.2.3`
        let (scope_and_name, version) = rest.split_once('@')?;
        let name_slice = &s[..scope_and_name.len() + 1];
        Some((name_slice, version))
    } else {
        // Unscoped package e.g. `lodash@1.2.3`
        s.split_once('@')
    }
}

/// Parses the contents of a lockfile based on its detected kind.
pub fn parse_lockfile_content(
    kind: LockfileKind,
    content: &str,
) -> Result<Vec<PackageRecord>, AdvisoryError> {
    match kind {
        LockfileKind::Cargo => parse_cargo_lock(content),
        LockfileKind::PackageLock => parse_package_lock(content),
        LockfileKind::Yarn => parse_yarn_lock(content),
        LockfileKind::Pnpm => parse_pnpm_lock(content),
        LockfileKind::Bun => parse_bun_lock(content),
        LockfileKind::Deno => parse_deno_lock(content),
        LockfileKind::RequirementsTxt => parse_requirements_txt(content),
        LockfileKind::Poetry => parse_poetry_lock(content),
        LockfileKind::Pipfile => parse_pipfile_lock(content),
        LockfileKind::GoSum => parse_go_sum(content),
        LockfileKind::Composer => parse_composer_lock(content),
        LockfileKind::NuGet => parse_nuget_lock(content),
        LockfileKind::Gemfile => parse_gemfile_lock(content),
    }
}

/// Discovers all supported lockfiles present in the specified workspace root.
pub fn discover_workspace_lockfiles(workspace_root: &Path) -> Vec<(LockfileKind, String)> {
    let mut found = Vec::new();
    for &filename in &LockfileKind::ALL_FILENAMES {
        let path = workspace_root.join(filename);
        if path.is_file()
            && let Some(kind) = LockfileKind::detect_from_filename(filename)
        {
            found.push((kind, filename.to_string()));
        }
    }
    // Also check pnpm alternate extension .yml
    if !found.iter().any(|(k, _)| *k == LockfileKind::Pnpm) {
        let pnpm_yml = workspace_root.join("pnpm-lock.yml");
        if pnpm_yml.is_file() {
            found.push((LockfileKind::Pnpm, "pnpm-lock.yml".to_string()));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_detection() {
        assert_eq!(
            LockfileKind::detect_from_filename("requirements.txt"),
            Some(LockfileKind::RequirementsTxt)
        );
        assert_eq!(
            LockfileKind::detect_from_filename("go.sum"),
            Some(LockfileKind::GoSum)
        );
        assert_eq!(
            LockfileKind::detect_from_filename("composer.lock"),
            Some(LockfileKind::Composer)
        );
        assert_eq!(
            LockfileKind::detect_from_filename("packages.lock.json"),
            Some(LockfileKind::NuGet)
        );
        assert_eq!(
            LockfileKind::detect_from_filename("Gemfile.lock"),
            Some(LockfileKind::Gemfile)
        );
    }
}
