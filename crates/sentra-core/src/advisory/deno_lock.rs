//! Pure-Rust parser for Deno lockfiles (`deno.lock`).
//!
//! Extracts npm and JSR dependencies and version specifications from Deno v2 / v3 lockfiles
//! without invoking the `deno` binary under `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;

use crate::advisory::{
    cargo_lock::PackageRecord,
    error::{AdvisoryError, AdvisoryErrorKind},
    multi_lock::split_package_specifier,
};

/// Parses a `deno.lock` string into a deduplicated list of package records.
pub fn parse_deno_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let root: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            format!("Invalid JSON in deno.lock: {e}"),
        )
    })?;

    let root_obj = match root.as_object() {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };

    let mut packages_map: BTreeMap<(String, String), PackageRecord> = BTreeMap::new();

    // 1. Deno v3 format: "packages": { "npm": { "<name>@<version>": { "integrity": "..." } } }
    if let Some(serde_json::Value::Object(packages_val)) = root_obj.get("packages") {
        if let Some(serde_json::Value::Object(npm_val)) = packages_val.get("npm") {
            parse_deno_npm_map(npm_val, &mut packages_map);
        }
        if let Some(serde_json::Value::Object(jsr_val)) = packages_val.get("jsr") {
            parse_deno_npm_map(jsr_val, &mut packages_map);
        }
    }

    // 2. Deno v2 format: top-level "npm": { "<name>@<version>": { ... } }
    if let Some(serde_json::Value::Object(npm_val)) = root_obj.get("npm") {
        if let Some(serde_json::Value::Object(packages_inner)) = npm_val.get("packages") {
            parse_deno_npm_map(packages_inner, &mut packages_map);
        } else {
            parse_deno_npm_map(npm_val, &mut packages_map);
        }
    }

    Ok(packages_map.into_values().collect())
}

/// Helper to parse key-value entries where keys are `"<name>@<version>"`.
fn parse_deno_npm_map(
    map: &serde_json::Map<String, serde_json::Value>,
    out: &mut BTreeMap<(String, String), PackageRecord>,
) {
    for (spec_key, val) in map {
        let clean_spec = spec_key.trim().strip_prefix("npm:").unwrap_or(spec_key);
        if let Some((name, version)) = split_package_specifier(clean_spec) {
            let mut record = PackageRecord::new(name, version);
            if let Some(val_obj) = val.as_object() {
                record.checksum = val_obj
                    .get("integrity")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            out.insert((name.to_string(), version.to_string()), record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_deno_v3_lockfile() {
        let content = r#"{
            "version": "3",
            "packages": {
                "specifiers": {
                    "npm:lodash@^4.17.21": "npm:lodash@4.17.21"
                },
                "npm": {
                    "lodash@4.17.21": {
                        "integrity": "sha512-abc123"
                    },
                    "@types/node@18.11.18": {
                        "integrity": "sha512-def456"
                    }
                }
            }
        }"#;

        let pkgs = parse_deno_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.raw_version, "4.17.21");
        assert_eq!(lodash.checksum.as_deref(), Some("sha512-abc123"));

        let types_node = pkgs.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types_node.raw_version, "18.11.18");
    }
}
