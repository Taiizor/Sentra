//! Pure-Rust parser for pnpm lockfiles (`pnpm-lock.yaml`).
//!
//! Parses package records from YAML lockfiles across pnpm v5, v6, and v9 formats
//! without requiring a heavy or unsafe C YAML parser under `#![forbid(unsafe_code)]`.

use std::collections::BTreeMap;

use crate::advisory::{
    cargo_lock::PackageRecord, error::AdvisoryError, multi_lock::split_package_specifier,
};

/// Parses a `pnpm-lock.yaml` string into a list of package records.
pub fn parse_pnpm_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages_map: BTreeMap<(String, String), PackageRecord> = BTreeMap::new();

    let mut in_packages_section = false;
    let mut current_pkg: Option<(String, String)> = None;
    let mut current_integrity: Option<String> = None;
    let mut current_source: Option<String> = None;

    let flush_current =
        |pkg_opt: &mut Option<(String, String)>,
         integ_opt: &mut Option<String>,
         src_opt: &mut Option<String>,
         map: &mut BTreeMap<(String, String), PackageRecord>| {
            if let Some((name, version)) = pkg_opt.take() {
                let mut record = PackageRecord::new(&name, &version);
                record.checksum = integ_opt.take();
                record.source = src_opt.take();
                map.insert((name, version), record);
            }
        };

    for raw_line in content.lines() {
        let trimmed = raw_line.trim_end();

        // Check top-level section headers
        if !trimmed.starts_with(' ') && !trimmed.starts_with('\t') {
            if trimmed.starts_with("packages:") {
                in_packages_section = true;
                continue;
            } else if trimmed.ends_with(':') && !trimmed.is_empty() {
                // Leaving packages section
                if in_packages_section {
                    flush_current(
                        &mut current_pkg,
                        &mut current_integrity,
                        &mut current_source,
                        &mut packages_map,
                    );
                    in_packages_section = false;
                }
                continue;
            }
        }

        if !in_packages_section {
            continue;
        }

        // Package declarations are indented by 2 spaces under packages:
        // Examples:
        // "  /@types/node@18.11.18:"
        // "  /lodash@4.17.21:"
        // "  lodash@4.17.21:"
        // "  '/lodash@4.17.21':"
        // "  /@scope/pkg@1.0.0(peer@2.0.0):"
        let is_package_header = (trimmed.starts_with("  ") && !trimmed.starts_with("    "))
            && trimmed.trim().ends_with(':');

        if is_package_header {
            flush_current(
                &mut current_pkg,
                &mut current_integrity,
                &mut current_source,
                &mut packages_map,
            );

            let header = trimmed.trim().trim_end_matches(':');
            if let Some((name, version)) = split_package_specifier(header) {
                current_pkg = Some((name.to_string(), version.to_string()));
            }
            continue;
        }

        // Inside package entry: look for resolution integrity / tarball
        if current_pkg.is_some() {
            let inner_trimmed = trimmed.trim();
            if inner_trimmed.starts_with("resolution:") {
                // e.g. "resolution: {integrity: sha512-...}"
                if let Some(idx) = inner_trimmed.find("integrity:") {
                    let after = &inner_trimmed[idx + "integrity:".len()..];
                    let integ = after
                        .trim()
                        .trim_end_matches('}')
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim();
                    current_integrity = Some(integ.to_string());
                }
                if let Some(idx) = inner_trimmed.find("tarball:") {
                    let after = &inner_trimmed[idx + "tarball:".len()..];
                    let tarball = after
                        .trim()
                        .trim_end_matches('}')
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim();
                    current_source = Some(tarball.to_string());
                }
            } else if let Some(stripped) = inner_trimmed.strip_prefix("integrity:") {
                let integ = stripped.trim().trim_matches('"').trim_matches('\'');
                current_integrity = Some(integ.to_string());
            }
        }
    }

    if in_packages_section {
        flush_current(
            &mut current_pkg,
            &mut current_integrity,
            &mut current_source,
            &mut packages_map,
        );
    }

    Ok(packages_map.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pnpm_v6_lockfile() {
        let content = r#"lockfileVersion: '6.0'

settings:
  autoInstallPeers: true

packages:

  /@types/node@18.11.18:
    resolution: {integrity: sha512-abc123}
    dev: true

  /lodash@4.17.21:
    resolution: {integrity: sha512-def456}
    dev: false

  /express@4.18.2(debug@2.6.9):
    resolution: {integrity: sha512-ghi789}

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
"#;

        let pkgs = parse_pnpm_lock(content).unwrap();
        assert_eq!(pkgs.len(), 3);

        let types_node = pkgs.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types_node.raw_version, "18.11.18");
        assert_eq!(types_node.checksum.as_deref(), Some("sha512-abc123"));

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.raw_version, "4.17.21");

        let express = pkgs.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.raw_version, "4.18.2");
    }

    #[test]
    fn test_parse_pnpm_v9_lockfile() {
        let content = r#"lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-xyz}

  minimist@1.2.8:
    resolution: {integrity: sha512-uvw}
"#;

        let pkgs = parse_pnpm_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "lodash" && p.raw_version == "4.17.21")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "minimist" && p.raw_version == "1.2.8")
        );
    }
}
