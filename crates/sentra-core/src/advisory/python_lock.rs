//! Pure-Rust parser for Python package manifests and lockfiles (Requirement F-07).
//!
//! Supports:
//! - Pinned requirements files (`requirements.txt`)
//! - Poetry lockfiles (`poetry.lock`)
//! - Pipenv lockfiles (`Pipfile.lock`)
//!
//! Extracts declared package names and exact versions safely under `#![forbid(unsafe_code)]`.

use std::collections::BTreeSet;

use crate::advisory::{
    cargo_lock::PackageRecord,
    error::{AdvisoryError, AdvisoryErrorKind},
};

/// Parses a `requirements.txt` file content into structured package records.
///
/// Supports exact pins (`==`, `===`) and extracts version numbers cleanly.
/// Ignores comments, blank lines, and pip command flags (e.g. `-r`, `-i`, `--extra-index-url`).
pub fn parse_requirements_txt(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments, empty lines, and command options
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Split off inline comments (e.g. `requests==2.31.0 # critical`)
        let clean_line = trimmed.split('#').next().unwrap_or("").trim();
        if clean_line.is_empty() {
            continue;
        }

        // Check for exact pin `==` or `===`
        if let Some((name, version_part)) = clean_line.split_once("==") {
            let pkg_name = name.trim().to_lowercase();
            // Handle environment markers (e.g. `package==1.0.0; python_version >= '3.8'`)
            let ver = version_part.split(';').next().unwrap_or(version_part).trim();
            // Strip any leading '=' from `===`
            let clean_ver = ver.trim_start_matches('=').trim();

            if !pkg_name.is_empty() && !clean_ver.is_empty() && seen.insert((pkg_name.clone(), clean_ver.to_string())) {
                packages.push(PackageRecord::new(pkg_name, clean_ver));
            }
        }
    }

    Ok(packages)
}

/// Parses a `poetry.lock` (TOML format) content into structured package records.
pub fn parse_poetry_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                packages.push(PackageRecord::new(name, version));
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("name =") {
            current_name = Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version =") {
            current_version = Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
        }
    }

    if let (Some(name), Some(version)) = (current_name, current_version) {
        packages.push(PackageRecord::new(name, version));
    }

    Ok(packages)
}

/// Parses a `Pipfile.lock` (JSON format) content into structured package records.
pub fn parse_pipfile_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let root: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            format!("Invalid JSON in Pipfile.lock: {e}"),
        )
    })?;

    let mut packages = Vec::new();
    let sections = ["default", "develop"];

    for section in sections {
        if let Some(map) = root.get(section).and_then(|v| v.as_object()) {
            for (pkg_name, details) in map {
                if let Some(version_str) = details.get("version").and_then(|v| v.as_str()) {
                    let clean_ver = version_str.trim().trim_start_matches("==").trim_start_matches('=').trim();
                    if !clean_ver.is_empty() {
                        packages.push(PackageRecord::new(pkg_name.to_lowercase(), clean_ver));
                    }
                }
            }
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_requirements_txt() {
        let data = "
# Core API Dependencies
requests==2.31.0
urllib3==2.0.7 ; python_version >= '3.8'
flask===3.0.0 # web framework
-i https://pypi.org/simple
";
        let pkgs = parse_requirements_txt(data).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].raw_version, "2.31.0");
        assert_eq!(pkgs[1].name, "urllib3");
        assert_eq!(pkgs[1].raw_version, "2.0.7");
        assert_eq!(pkgs[2].name, "flask");
        assert_eq!(pkgs[2].raw_version, "3.0.0");
    }

    #[test]
    fn test_parse_poetry_lock() {
        let data = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "urllib3"
version = "2.0.7"
description = "HTTP library with thread-safe connection pooling."
"#;
        let pkgs = parse_poetry_lock(data).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].raw_version, "2.31.0");
        assert_eq!(pkgs[1].name, "urllib3");
        assert_eq!(pkgs[1].raw_version, "2.0.7");
    }
}
