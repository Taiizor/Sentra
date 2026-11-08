//! Pure-Rust parser for npm / Node.js `package-lock.json` files (Requirement F-07).
//!
//! Extracts declared packages, versions, and integrity hashes without external dependencies
//! or node runtime invocation under `#![forbid(unsafe_code)]`. Supports v1, v2, and v3 schemas.

use std::collections::BTreeMap;

use crate::advisory::{
    cargo_lock::PackageRecord,
    error::{AdvisoryError, AdvisoryErrorKind},
};

/// Parses a `package-lock.json` string into a list of structured package records.
pub fn parse_package_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let root: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            format!("Invalid JSON in package-lock.json: {e}"),
        )
    })?;

    let root_obj = root.as_object().ok_or_else(|| {
        AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            "Root of package-lock.json must be a JSON object",
        )
    })?;

    let mut packages_map: BTreeMap<(String, String), PackageRecord> = BTreeMap::new();

    // 1. Try modern npm v2 / v3 format: "packages": { "node_modules/<pkg>": { "version": "..." } }
    if let Some(serde_json::Value::Object(packages_val)) = root_obj.get("packages") {
        for (path_key, pkg_val) in packages_val {
            // The empty key "" represents the root workspace itself; skip it
            if path_key.is_empty() {
                continue;
            }

            let pkg_obj = match pkg_val.as_object() {
                Some(obj) => obj,
                None => continue,
            };

            let version = match pkg_obj.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.trim(),
                None => continue,
            };

            if version.is_empty() {
                continue;
            }

            // Determine package name: explicit "name" field or extracted from "node_modules/<name>"
            let name = if let Some(n) = pkg_obj.get("name").and_then(|v| v.as_str()) {
                n.trim().to_string()
            } else {
                extract_package_name_from_node_modules_path(path_key)
            };

            if name.is_empty() {
                continue;
            }

            let source = pkg_obj
                .get("resolved")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let checksum = pkg_obj
                .get("integrity")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut record = PackageRecord::new(&name, version);
            record.source = source;
            record.checksum = checksum;

            packages_map.insert((name, version.to_string()), record);
        }
    }

    // 2. Also inspect / fallback to legacy npm v1 format: "dependencies": { "<pkg>": { "version": "..." } }
    if let Some(serde_json::Value::Object(deps_val)) = root_obj.get("dependencies") {
        traverse_npm_v1_dependencies(deps_val, &mut packages_map);
    }

    Ok(packages_map.into_values().collect())
}

/// Recursively traverses npm v1 "dependencies" trees.
fn traverse_npm_v1_dependencies(
    deps_obj: &serde_json::Map<String, serde_json::Value>,
    out: &mut BTreeMap<(String, String), PackageRecord>,
) {
    for (name, val) in deps_obj {
        if let Some(obj) = val.as_object() {
            if let Some(version) = obj.get("version").and_then(|v| v.as_str()) {
                let v = version.trim();
                if !v.is_empty() {
                    let source = obj
                        .get("resolved")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string());
                    let checksum = obj
                        .get("integrity")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string());

                    let mut record = PackageRecord::new(name, v);
                    record.source = source;
                    record.checksum = checksum;

                    out.insert((name.clone(), v.to_string()), record);
                }
            }

            // Nested dependencies (e.g. sub-dependencies in npm v1)
            if let Some(serde_json::Value::Object(nested)) = obj.get("dependencies") {
                traverse_npm_v1_dependencies(nested, out);
            }
        }
    }
}

/// Extracts a clean package name from a path like `node_modules/lodash` or
/// `node_modules/@types/node` or `node_modules/a/node_modules/b`.
fn extract_package_name_from_node_modules_path(path: &str) -> String {
    let clean = path.replace('\\', "/");
    let parts: Vec<&str> = clean.split("node_modules/").collect();
    let last = parts.last().unwrap_or(&path).trim_matches('/');

    last.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npm_v3_package_lock() {
        let content = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0"
                },
                "node_modules/@types/node": {
                    "version": "18.11.18",
                    "resolved": "https://registry.npmjs.org/@types/node/-/node-18.11.18.tgz",
                    "integrity": "sha512-..."
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-..."
                }
            }
        }"#;

        let pkgs = parse_package_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.raw_version, "4.17.21");
        assert!(lodash.semver.is_ok());

        let types_node = pkgs.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types_node.raw_version, "18.11.18");
    }

    #[test]
    fn test_parse_npm_v1_package_lock() {
        let content = r#"{
            "name": "legacy-app",
            "version": "0.1.0",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "accepts": {
                            "version": "1.3.8"
                        }
                    }
                }
            }
        }"#;

        let pkgs = parse_package_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.raw_version == "4.18.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "accepts" && p.raw_version == "1.3.8")
        );
    }
}
