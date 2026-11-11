//! Pure-Rust parser for Yarn lockfiles (`yarn.lock`, Classic v1 and Berry v2+).
//!
//! Parses package declarations and installed versions line-by-line without external binaries
//! under `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;

use crate::advisory::{
    cargo_lock::PackageRecord,
    error::{AdvisoryError, AdvisoryErrorKind},
    multi_lock::split_package_specifier,
};

/// Parses a `yarn.lock` content string into a deduplicated list of package records.
///
/// Every unindented line must be a comment or a `<specifiers>:` block header, and every
/// block (except Berry's `__metadata:`) must carry a `version` line; otherwise the content is
/// rejected as [`AdvisoryErrorKind::MalformedLockfile`], so a truncated block is not dropped
/// silently. Indented lines inside a block other than `version`, `resolved`/`resolution`
/// and `integrity`/`checksum` are ignored.
pub fn parse_yarn_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages_map: BTreeMap<(String, String), PackageRecord> = BTreeMap::new();

    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;
    let mut current_resolved: Option<String> = None;
    let mut current_integrity: Option<String> = None;
    let mut in_block = false;
    // 1-based line number of the header of the block being read.
    let mut block_line = 0;

    // Records the block that ends here. A block without a non-empty version is rejected, so
    // a truncated block is never dropped silently.
    let flush_block = |block_line: usize,
                       names: &mut Vec<String>,
                       ver: &mut Option<String>,
                       res: &mut Option<String>,
                       integ: &mut Option<String>,
                       map: &mut BTreeMap<(String, String), PackageRecord>|
     -> Result<(), AdvisoryError> {
        let v = ver
            .take()
            .map(|version| {
                version
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string()
            })
            .unwrap_or_default();
        if v.is_empty() {
            return Err(AdvisoryError::new(
                AdvisoryErrorKind::MalformedLockfile,
                format!("the block that starts on line {block_line} has no version"),
            ));
        }
        for name in names.drain(..) {
            let mut record = PackageRecord::new(&name, &v);
            record.source = res.clone();
            record.checksum = integ.clone();
            map.insert((name, v.clone()), record);
        }
        *res = None;
        *integ = None;
        Ok(())
    };

    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Skip yarn berry metadata
        if trimmed.starts_with("__metadata:") {
            if in_block {
                flush_block(
                    block_line,
                    &mut current_names,
                    &mut current_version,
                    &mut current_resolved,
                    &mut current_integrity,
                    &mut packages_map,
                )?;
            }
            in_block = false;
            continue;
        }

        // Block header starts at column 0 and ends with ':'
        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            // Flush previous entry if any
            if in_block {
                flush_block(
                    block_line,
                    &mut current_names,
                    &mut current_version,
                    &mut current_resolved,
                    &mut current_integrity,
                    &mut packages_map,
                )?;
            }

            in_block = true;
            block_line = line_no + 1;
            let header = line.trim_end_matches(':');

            // Header can contain multiple comma-separated specifiers:
            // e.g. "lodash@^4.17.21, lodash@~4.17.15" or "\"@scope/pkg@npm:^1.0.0\""
            for spec in header.split(',') {
                let clean_spec = spec.trim().trim_matches('"').trim_matches('\'');
                // Yarn Berry uses npm: prefix e.g. "lodash@npm:^4.17.21" or "@types/node@npm:^18.0.0"
                let normalized = clean_spec.replace("@npm:", "@");
                if let Some((pkg_name, _range)) = split_package_specifier(&normalized) {
                    let name = pkg_name.to_string();
                    if !current_names.contains(&name) {
                        current_names.push(name);
                    }
                }
            }
            continue;
        }

        // Every unindented line is a block header (`<specifiers>:`), so anything else
        // means the content is not a yarn.lock and must not yield a clean audit.
        if !line.starts_with([' ', '\t']) {
            return Err(AdvisoryError::new(
                AdvisoryErrorKind::MalformedLockfile,
                format!(
                    "line {} is neither a comment nor a `<package>@<range>:` block header",
                    line_no + 1
                ),
            ));
        }

        if !in_block {
            continue;
        }

        // Inside block: parse properties
        if let Some((k, v)) = parse_property_line(trimmed) {
            match k {
                "version" => {
                    let clean_v = v.trim().trim_matches('"').trim_matches('\'');
                    current_version = Some(clean_v.to_string());
                }
                "resolved" | "resolution" => {
                    let clean_r = v.trim().trim_matches('"').trim_matches('\'');
                    current_resolved = Some(clean_r.to_string());
                }
                "integrity" | "checksum" => {
                    let clean_i = v.trim().trim_matches('"').trim_matches('\'');
                    current_integrity = Some(clean_i.to_string());
                }
                _ => {}
            }
        }
    }

    // Flush last block
    if in_block {
        flush_block(
            block_line,
            &mut current_names,
            &mut current_version,
            &mut current_resolved,
            &mut current_integrity,
            &mut packages_map,
        )?;
    }

    Ok(packages_map.into_values().collect())
}

/// Splits a property line like `version "4.17.21"` or `version: 4.17.21` into key and value.
fn parse_property_line(line: &str) -> Option<(&str, &str)> {
    if let Some((k, v)) = line.split_once(':') {
        Some((k.trim(), v.trim()))
    } else if let Some((k, v)) = line.split_once(' ') {
        Some((k.trim(), v.trim()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yarn_v1_classic() {
        let content = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"@types/node@^18.11.18":
  version "18.11.18"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-18.11.18.tgz"
  integrity sha512-abc123

lodash@^4.17.21, lodash@~4.17.15:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-def456
"#;

        let pkgs = parse_yarn_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);

        let types_node = pkgs.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types_node.raw_version, "18.11.18");
        assert_eq!(types_node.checksum.as_deref(), Some("sha512-abc123"));

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.raw_version, "4.17.21");
    }

    #[test]
    fn content_that_is_not_a_yarn_lock_is_rejected() {
        for content in [
            "garbage[[[",
            "lodash@^4:\n  version \"4.0.0\"\nnot a header\n",
        ] {
            let error = parse_yarn_lock(content).unwrap_err();
            assert_eq!(
                error.kind(),
                AdvisoryErrorKind::MalformedLockfile,
                "{content}"
            );
        }
        // A project without dependencies has a header-only lockfile.
        assert!(
            parse_yarn_lock("# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_block_without_a_version_is_rejected() {
        // Regression: a block without a `version` line (for example a file truncated inside
        // its last block) was dropped silently, so the lockfile was reported as audited.
        for (content, line) in [
            (
                "express@^4.0.0:\n  version \"4.17.1\"\n\nlodash@^4.17.0:\n  resol",
                4,
            ),
            ("x:\n  y z\n", 1),
            ("lodash@^4.17.0:\n  version \"\"\n", 1),
            ("lodash@^4.17.0:\n  version\n", 1),
            (
                "lodash@^4.17.0:\n  resolved \"https://r/lodash.tgz\"\n\nexpress@^4.0.0:\n  version \"4.17.1\"\n",
                1,
            ),
        ] {
            let error = parse_yarn_lock(content).unwrap_err();
            assert_eq!(
                error.kind(),
                AdvisoryErrorKind::MalformedLockfile,
                "{content}"
            );
            assert!(
                error.message().contains(&format!(
                    "the block that starts on line {line} has no version"
                )),
                "{content}: {}",
                error.message()
            );
        }
        // Berry's `__metadata:` block carries no package version and is not a package block.
        assert!(
            parse_yarn_lock("__metadata:\n  version: 6\n  cacheKey: 8\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_parse_yarn_berry_v2() {
        let content = r#"__metadata:
  version: 6

"accepts@npm:^1.3.8":
  version: 1.3.8
  resolution: "accepts@npm:1.3.8"
  checksum: 10c0/xyz

"express@npm:4.18.2":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
"#;

        let pkgs = parse_yarn_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "accepts" && p.raw_version == "1.3.8")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.raw_version == "4.18.2")
        );
    }
}
