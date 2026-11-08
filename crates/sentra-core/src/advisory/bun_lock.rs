//! Pure-Rust parser for Bun lockfiles (`bun.lock`).
//!
//! Handles text-based Bun 1.1 / 1.2 lockfiles and JSON-based lockfile representations
//! without invoking the `bun` runtime under `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;

use crate::advisory::{
    cargo_lock::PackageRecord, error::AdvisoryError, multi_lock::split_package_specifier,
    package_lock::parse_package_lock, yarn_lock::parse_yarn_lock,
};

/// Parses a `bun.lock` content string into structured package records.
pub fn parse_bun_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let trimmed = content.trim();

    // 1. If it starts with '{', attempt JSON parsing (modern Bun 1.2+ format)
    if trimmed.starts_with('{') {
        if let Ok(packages) = parse_bun_json_format(trimmed)
            && !packages.is_empty()
        {
            return Ok(packages);
        }
        // Fallback to npm package-lock parser if it's formatted similarly
        if let Ok(packages) = parse_package_lock(trimmed)
            && !packages.is_empty()
        {
            return Ok(packages);
        }
    }

    // 2. Otherwise, attempt Yarn-compatible line parser (earlier Bun text format)
    parse_yarn_lock(content)
}

/// Parses the standard Bun text JSON lockfile structure:
/// `{ "lockfileVersion": 1, "packages": { "lodash": ["lodash@4.17.21", "registry.npmjs.org/...", ...] } }`
fn parse_bun_json_format(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let root: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        AdvisoryError::new(
            crate::advisory::error::AdvisoryErrorKind::MalformedLockfile,
            format!("Invalid JSON in bun.lock: {e}"),
        )
    })?;

    let root_obj = match root.as_object() {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };

    let mut packages_map: BTreeMap<(String, String), PackageRecord> = BTreeMap::new();

    if let Some(serde_json::Value::Object(packages_val)) = root_obj.get("packages") {
        for (pkg_key, val) in packages_val {
            if pkg_key.is_empty() {
                continue;
            }

            match val {
                // Bun 1.2 array entry format: "lodash": ["lodash@4.17.21", "https://...", { ... }]
                serde_json::Value::Array(arr) => {
                    if let Some(first_str) = arr.first().and_then(|v| v.as_str()) {
                        if let Some((name, version)) = split_package_specifier(first_str) {
                            let mut record = PackageRecord::new(name, version);
                            if let Some(second_str) = arr.get(1).and_then(|v| v.as_str()) {
                                record.source = Some(second_str.to_string());
                            }
                            packages_map.insert((name.to_string(), version.to_string()), record);
                        } else if let Some((_, version)) =
                            split_package_specifier(&format!("{pkg_key}@{first_str}"))
                        {
                            let record = PackageRecord::new(pkg_key, version);
                            packages_map.insert((pkg_key.clone(), version.to_string()), record);
                        }
                    }
                }
                // Object entry format with explicit "version"
                serde_json::Value::Object(obj) => {
                    if let Some(version) = obj.get("version").and_then(|v| v.as_str()) {
                        let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or(pkg_key);
                        let mut record = PackageRecord::new(name, version);
                        record.source = obj
                            .get("resolved")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string());
                        record.checksum = obj
                            .get("integrity")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string());
                        packages_map.insert((name.to_string(), version.to_string()), record);
                    }
                }
                // Simple string value: "lodash": "4.17.21"
                serde_json::Value::String(ver_str) => {
                    let record = PackageRecord::new(pkg_key, ver_str.as_str());
                    packages_map.insert((pkg_key.clone(), ver_str.to_string()), record);
                }
                _ => {}
            }
        }
    }

    Ok(packages_map.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bun_v1_json_lockfile() {
        let content = r#"{
            "lockfileVersion": 1,
            "packages": {
                "lodash": [
                    "lodash@4.17.21",
                    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    {
                        "integrity": "sha512-abc"
                    }
                ],
                "@types/node": [
                    "@types/node@18.11.18",
                    "https://registry.npmjs.org/@types/node/-/node-18.11.18.tgz"
                ]
            }
        }"#;

        let pkgs = parse_bun_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.raw_version, "4.17.21");

        let types_node = pkgs.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types_node.raw_version, "18.11.18");
    }
}
