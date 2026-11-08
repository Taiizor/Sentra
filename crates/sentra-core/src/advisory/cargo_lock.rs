//! Pure-Rust parser for Cargo.lock files (Requirement F-07).
//!
//! Extracts declared dependencies and versions safely without external dependencies
//! or unsafe code. Handles valid, unknown, and malformed version formats.

use std::str::FromStr;

use crate::advisory::{
    error::{AdvisoryError, AdvisoryErrorKind},
    semver::SemverVersion,
};

/// A package entry recorded in a `Cargo.lock` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    /// Name of the package (e.g. `serde`).
    pub name: String,
    /// Raw unparsed version string as written in the lockfile.
    pub raw_version: String,
    /// Result of parsing the raw version into semantic versioning.
    pub semver: Result<SemverVersion, String>,
    /// Package source repository or registry URL if present.
    pub source: Option<String>,
    /// Package cryptographic checksum if present.
    pub checksum: Option<String>,
}

impl PackageRecord {
    /// Creates a new package record.
    pub fn new(name: impl Into<String>, raw_version: impl Into<String>) -> Self {
        let name_str = name.into();
        let raw_ver_str = raw_version.into();
        let semver = SemverVersion::from_str(&raw_ver_str).map_err(|e| e.to_string());
        Self {
            name: name_str,
            raw_version: raw_ver_str,
            semver,
            source: None,
            checksum: None,
        }
    }
}

/// Parses the complete contents of a `Cargo.lock` file into structured package records.
pub fn parse_cargo_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_source: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut in_package_block = false;

    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[[package]]" {
            // Flush preceding package if any
            if in_package_block {
                if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                    let semver = SemverVersion::from_str(&version).map_err(|e| e.to_string());
                    packages.push(PackageRecord {
                        name,
                        raw_version: version,
                        semver,
                        source: current_source.take(),
                        checksum: current_checksum.take(),
                    });
                } else if current_name.is_some() || current_version.is_some() {
                    return Err(AdvisoryError::new(
                        AdvisoryErrorKind::MalformedLockfile,
                        format!("incomplete package block before line {}", line_no + 1),
                    ));
                }
            }
            in_package_block = true;
            continue;
        }

        if !in_package_block {
            continue;
        }

        if let Some((key, val)) = parse_key_value(line) {
            match key {
                "name" => current_name = Some(val.to_string()),
                "version" => current_version = Some(val.to_string()),
                "source" => current_source = Some(val.to_string()),
                "checksum" => current_checksum = Some(val.to_string()),
                _ => {}
            }
        }
    }

    // Flush final package block
    if in_package_block && let (Some(name), Some(version)) = (current_name, current_version) {
        let semver = SemverVersion::from_str(&version).map_err(|e| e.to_string());
        packages.push(PackageRecord {
            name,
            raw_version: version,
            semver,
            source: current_source,
            checksum: current_checksum,
        });
    }

    Ok(packages)
}

fn parse_key_value(line: &str) -> Option<(&str, &str)> {
    let (key_part, val_part) = line.split_once('=')?;
    let key = key_part.trim();
    let val = val_part.trim();
    let unquoted_val = val.strip_prefix('"')?.strip_suffix('"')?;
    Some((key, unquoted_val))
}
