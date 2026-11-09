//! Pure-Rust parser for .NET NuGet lockfiles (`packages.lock.json`).
//!
//! Extracts resolved NuGet dependencies and versions under `#![forbid(unsafe_code)]`.

use std::collections::BTreeSet;

use crate::advisory::{
    cargo_lock::PackageRecord,
    error::{AdvisoryError, AdvisoryErrorKind},
};

/// Parses a NuGet `packages.lock.json` content into structured package records.
pub fn parse_nuget_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let root: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        AdvisoryError::new(
            AdvisoryErrorKind::MalformedLockfile,
            format!("Invalid JSON in packages.lock.json: {e}"),
        )
    })?;

    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();

    // NuGet lockfile has a "dependencies" tree keyed by target framework (e.g. `net8.0`, `.NETCoreApp,Version=v8.0`)
    if let Some(target_frameworks) = root.get("dependencies").and_then(|v| v.as_object()) {
        for (_framework, deps_map) in target_frameworks {
            if let Some(deps) = deps_map.as_object() {
                for (pkg_name, info) in deps {
                    if let Some(resolved_ver) = info.get("resolved").and_then(|v| v.as_str()) {
                        let clean_name = pkg_name.trim();
                        let clean_ver = resolved_ver.trim();
                        if !clean_name.is_empty()
                            && !clean_ver.is_empty()
                            && seen.insert((clean_name.to_string(), clean_ver.to_string()))
                        {
                            packages.push(PackageRecord::new(clean_name, clean_ver));
                        }
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
    fn test_parse_nuget_lock() {
        let data = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.1, )",
        "resolved": "13.0.1",
        "contentHash": "ppPFZZFQ37AZfr55LuGhOzHzY55wg3QUqzpETFF613nQ2CPRU3354XMQ8vLTa6VC3D2fCFF5SzVek54iP87CQ=="
      },
      "Serilog": {
        "type": "Direct",
        "requested": "[3.1.1, )",
        "resolved": "3.1.1",
        "contentHash": "50L60T82YVvGgqL053g1W1E1128p36u49sKq5r1=="
      }
    }
  }
}"#;
        let pkgs = parse_nuget_lock(data).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "Newtonsoft.Json");
        assert_eq!(pkgs[0].raw_version, "13.0.1");
        assert_eq!(pkgs[1].name, "Serilog");
        assert_eq!(pkgs[1].raw_version, "3.1.1");
    }
}
