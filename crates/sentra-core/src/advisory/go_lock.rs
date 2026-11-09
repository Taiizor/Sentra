//! Pure-Rust parser for Go module checksum manifests (`go.sum`).
//!
//! Extracts declared Go modules and versions under `#![forbid(unsafe_code)]`.
//! Normalizes Go module version tags (e.g. `v1.2.3` -> `1.2.3`) for standard
//! semantic version advisory evaluation.

use std::collections::BTreeSet;

use crate::advisory::{cargo_lock::PackageRecord, error::AdvisoryError};

/// Parses a `go.sum` file content into structured package records.
///
/// Handles entries like:
/// `golang.org/x/net v0.17.0 h1:....`
/// `golang.org/x/net v0.17.0/go.mod h1:....`
///
/// Strips `/go.mod` suffix entries and leading `v` from semantic version tags.
pub fn parse_go_sum(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let module_name = match parts.next() {
            Some(m) => m,
            None => continue,
        };
        let raw_ver_token = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        // Skip `/go.mod` descriptor lines to prevent duplicate reporting
        let ver_cleaned = raw_ver_token.split('/').next().unwrap_or(raw_ver_token);

        // Normalize `v1.2.3` -> `1.2.3`
        let clean_ver = ver_cleaned.strip_prefix('v').unwrap_or(ver_cleaned);

        // Handle pseudo-versions like `0.0.0-20230905200255-921286631fa9`
        let key = (module_name.to_string(), clean_ver.to_string());
        if !module_name.is_empty() && !clean_ver.is_empty() && seen.insert(key) {
            packages.push(PackageRecord::new(module_name, clean_ver));
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_sum() {
        let data = "
golang.org/x/net v0.17.0 h1:pYNtqbwVNCLjmQhUwt5h/19u398gJd4Zg+9t2y61q=
golang.org/x/net v0.17.0/go.mod h1:c0w=
github.com/pkg/errors v0.9.1 h1:qZCd=
github.com/pkg/errors v0.9.1/go.mod h1:x=
";
        let pkgs = parse_go_sum(data).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "golang.org/x/net");
        assert_eq!(pkgs[0].raw_version, "0.17.0");
        assert_eq!(pkgs[1].name, "github.com/pkg/errors");
        assert_eq!(pkgs[1].raw_version, "0.9.1");
    }
}
