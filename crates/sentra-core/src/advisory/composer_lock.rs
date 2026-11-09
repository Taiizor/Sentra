//! Pure-Rust parser for PHP Composer lockfiles (`composer.lock`).
//!
//! Extracts declared Composer packages and versions under `#![forbid(unsafe_code)]`.
//! Normalizes version tags (e.g. `v7.4.5` -> `7.4.5`) for standard advisory evaluation.

use crate::advisory::{
    cargo_lock::PackageRecord,
    error::{AdvisoryError, AdvisoryErrorKind},
};

/// Parses a `composer.lock` JSON content into structured package records.
pub fn parse_composer_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let root: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            format!("Invalid JSON in composer.lock: {e}"),
        )
    })?;

    let mut packages = Vec::new();
    let sections = ["packages", "packages-dev"];

    for section in sections {
        if let Some(list) = root.get(section).and_then(|v| v.as_array()) {
            for item in list {
                if let (Some(name), Some(raw_ver)) = (
                    item.get("name").and_then(|v| v.as_str()),
                    item.get("version").and_then(|v| v.as_str()),
                ) {
                    let clean_ver = raw_ver.trim().strip_prefix('v').unwrap_or(raw_ver.trim());
                    if !name.is_empty() && !clean_ver.is_empty() {
                        packages.push(PackageRecord::new(name, clean_ver));
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
    fn test_parse_composer_lock() {
        let data = r#"{
    "_readme": ["Composer lockfile format"],
    "packages": [
        {
            "name": "guzzlehttp/guzzle",
            "version": "7.4.5"
        },
        {
            "name": "symfony/http-kernel",
            "version": "v6.2.0"
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "9.5.10"
        }
    ]
}"#;
        let pkgs = parse_composer_lock(data).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "guzzlehttp/guzzle");
        assert_eq!(pkgs[0].raw_version, "7.4.5");
        assert_eq!(pkgs[1].name, "symfony/http-kernel");
        assert_eq!(pkgs[1].raw_version, "6.2.0");
        assert_eq!(pkgs[2].name, "phpunit/phpunit");
        assert_eq!(pkgs[2].raw_version, "9.5.10");
    }
}
