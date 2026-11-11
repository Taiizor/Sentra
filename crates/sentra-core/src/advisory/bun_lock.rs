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
    let sanitized = strip_json_trailing_commas(content);
    let trimmed = sanitized.trim();

    // 1. If it starts with '{', attempt JSON parsing (modern Bun 1.1/1.2 format)
    if trimmed.starts_with('{') {
        let bun = parse_bun_json_format(trimmed);
        if let Ok(packages) = &bun
            && !packages.is_empty()
        {
            return bun;
        }
        // Fallback to npm package-lock parser if it's formatted similarly
        if let Ok(packages) = parse_package_lock(trimmed)
            && !packages.is_empty()
        {
            return Ok(packages);
        }
        // A valid JSON lockfile without packages (no dependencies) is not an error;
        // the line-based fallback below only fits the earlier text format.
        if bun.is_ok() {
            return bun;
        }
    }

    // 2. Otherwise, attempt Yarn-compatible line parser (earlier Bun text format)
    parse_yarn_lock(content)
}

/// Sanitizes JSON text by stripping trailing commas before closing braces/brackets and single-line comments.
fn strip_json_trailing_commas(input: &str) -> String {
    // 1. Strip comments
    let mut no_comments = String::with_capacity(input.len());
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        no_comments.push_str(line);
        no_comments.push('\n');
    }

    // 2. Remove trailing commas before } or ]
    let bytes = no_comments.as_bytes();
    let mut clean = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b',' {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r' || bytes[j] == b'\n')
            {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'}' || bytes[j] == b']') {
                i += 1;
                continue;
            }
        }
        clean.push(bytes[i] as char);
        i += 1;
    }
    clean
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
                // Bun 1.2 array entry format: "lodash": ["lodash@4.17.21", "https://...", { ... }, "sha512-..."]
                serde_json::Value::Array(arr) => {
                    if let Some(first_str) = arr.first().and_then(|v| v.as_str()) {
                        if let Some((name, version)) = split_package_specifier(first_str) {
                            let mut record = PackageRecord::new(name, version);
                            for item in arr.iter().skip(1) {
                                if let Some(s) = item.as_str() {
                                    if s.starts_with("http://") || s.starts_with("https://") {
                                        record.source = Some(s.to_string());
                                    } else if s.starts_with("sha512-")
                                        || s.starts_with("sha1-")
                                        || s.starts_with("sha256-")
                                    {
                                        record.checksum = Some(s.to_string());
                                    }
                                }
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

    #[test]
    fn a_text_lockfile_with_a_block_without_a_version_is_rejected() {
        // Regression: the text form (read by the yarn.lock reader) dropped such blocks
        // silently, so a truncated or non-lockfile `bun.lock` was reported as audited.
        for content in [
            "x:\n  y z\n",
            "lodash@^4.17.0:\n  version \"4.17.11\"\n\nexpress@^4.0.0:\n  resol",
        ] {
            let error = parse_bun_lock(content).unwrap_err();
            assert_eq!(
                error.kind(),
                crate::advisory::error::AdvisoryErrorKind::MalformedLockfile,
                "{content}"
            );
        }
        let pkgs = parse_bun_lock("lodash@^4.17.0:\n  version \"4.17.11\"\n").unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].raw_version, "4.17.11");
    }
}
