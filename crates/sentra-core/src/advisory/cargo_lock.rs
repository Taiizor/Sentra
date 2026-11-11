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
    let mut has_content = false;
    let mut has_lock_marker = false;

    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Cargo writes only table headers, `key = value` pairs and the items and
        // closing bracket of multi-line arrays. Anything else means the content is
        // not a Cargo.lock, which must not be reported as a clean audit.
        let recognized = (line.starts_with('[') && line.ends_with(']'))
            || line.contains('=')
            || line.starts_with('"')
            || line.starts_with(']');
        if !recognized {
            return Err(AdvisoryError::new(
                AdvisoryErrorKind::MalformedLockfile,
                format!(
                    "line {} is not a Cargo.lock table header, key or array item",
                    line_no + 1
                ),
            ));
        }
        has_content = true;
        if line == "[[package]]" || (!in_package_block && parse_key_value_raw(line).0 == "version")
        {
            has_lock_marker = true;
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

    if has_content && !has_lock_marker {
        return Err(AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            "no [[package]] table or top-level `version` key; this is not a Cargo.lock",
        ));
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

/// Splits `key = value` without interpreting the value (`("", line)` without `=`).
fn parse_key_value_raw(line: &str) -> (&str, &str) {
    match line.split_once('=') {
        Some((key, value)) => (key.trim(), value.trim()),
        None => ("", line),
    }
}

fn parse_key_value(line: &str) -> Option<(&str, &str)> {
    let (key_part, val_part) = line.split_once('=')?;
    let key = key_part.trim();
    let val = val_part.trim();
    let unquoted_val = val.strip_prefix('"')?.strip_suffix('"')?;
    Some((key, unquoted_val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_that_is_not_a_cargo_lock_is_rejected() {
        for content in ["garbage[[[", "name = \"x\"\n", "[[package]]\ngarbage\n"] {
            let error = parse_cargo_lock(content).unwrap_err();
            assert_eq!(
                error.kind(),
                AdvisoryErrorKind::MalformedLockfile,
                "{content}"
            );
        }
    }

    #[test]
    fn comments_only_and_multi_line_arrays_are_accepted() {
        assert!(parse_cargo_lock("# Lock file\n").unwrap().is_empty());
        assert!(parse_cargo_lock("").unwrap().is_empty());
        let lock = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"2.0.0\"\n";
        let packages = parse_cargo_lock(lock).unwrap();
        assert_eq!(packages.len(), 2);
    }
}
