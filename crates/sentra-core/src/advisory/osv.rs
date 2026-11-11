//! Parsing of local Open Source Vulnerability (OSV) JSON records (REQ-F07, EXTENSIONS.md).
//!
//! Converts OSV records (a single object or an array) from local files into in-memory
//! [`Advisory`] entries, one per affected package. This is a subset of the OSV schema:
//! only `introduced` and `fixed` range events are read, and they are evaluated as
//! semver-like ranges whatever the range type; `last_affected` and `limit` events, the
//! package ecosystem and `withdrawn` are not used. Nothing is downloaded, and nothing is
//! persisted: the entries live only in the [`AdvisoryDatabase`] passed in.

use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    advisory::{
        database::{Advisory, AdvisoryDatabase},
        error::{AdvisoryError, AdvisoryErrorKind},
    },
    domain::finding::Severity,
};

/// Open Source Vulnerability (OSV) package descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvPackage {
    /// Affected package name.
    pub name: String,
    /// Ecosystem (e.g. "crates.io", "npm", "PyPI", "Go").
    #[serde(default)]
    pub ecosystem: Option<String>,
    /// Package URL specification (purl).
    #[serde(default)]
    pub purl: Option<String>,
}

/// A version range event (e.g. `{"introduced": "0"}`, `{"fixed": "1.2.3"}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvRange {
    /// Range type (typically "SEMVER" or "ECOSYSTEM").
    #[serde(rename = "type", default)]
    pub range_type: String,
    /// Ordered event timeline.
    #[serde(default)]
    pub events: Vec<BTreeMap<String, String>>,
}

/// Affected entry inside an OSV advisory record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvAffected {
    /// Affected package.
    pub package: OsvPackage,
    /// Affected version ranges.
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    /// Explicit list of affected versions.
    #[serde(default)]
    pub versions: Vec<String>,
    /// Database-specific metadata bag.
    #[serde(default)]
    pub database_specific: Option<BTreeMap<String, serde_json::Value>>,
}

/// OSV severity specification (e.g. CVSS vector).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvSeverity {
    /// Severity type (e.g. "CVSS_V3", "CVSS_V4").
    #[serde(rename = "type")]
    pub severity_type: String,
    /// CVSS score vector string or rating.
    pub score: String,
}

/// Top-level OSV schema v1.6 advisory record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvRecord {
    /// Canonical advisory identifier (e.g. `GHSA-...`, `RUSTSEC-...`, `CVE-...`).
    pub id: String,
    /// Publication timestamp.
    #[serde(default)]
    pub published: Option<String>,
    /// Modification timestamp.
    #[serde(default)]
    pub modified: Option<String>,
    /// Aliases (e.g. CVE identifiers).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Concise summary title.
    #[serde(default)]
    pub summary: Option<String>,
    /// Detailed vulnerability description.
    #[serde(default)]
    pub details: Option<String>,
    /// Severity scores.
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    /// Affected components.
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

impl OsvRecord {
    /// Converts this OSV record into one or more Sentra `Advisory` structures.
    pub fn to_advisories(&self) -> Vec<Advisory> {
        let mut advisories = Vec::new();
        let fallback_title = self.id.clone();
        let title = self
            .summary
            .as_deref()
            .unwrap_or(&fallback_title)
            .to_string();
        let description = self.details.as_deref().unwrap_or(&title).to_string();
        let published_at = self.published.clone().unwrap_or_default();

        let global_severity = self.determine_severity();

        for aff in &self.affected {
            let package_name = aff.package.name.clone();
            let mut affected_reqs = Vec::new();
            let mut patched_versions = Vec::new();

            for range in &aff.ranges {
                let mut current_intro: Option<String> = None;
                for event in &range.events {
                    if let Some(intro) = event.get("introduced") {
                        current_intro = Some(intro.clone());
                    }
                    if let Some(fixed) = event.get("fixed") {
                        patched_versions.push(fixed.clone());
                        match &current_intro {
                            Some(intro) if intro == "0" || intro == "0.0.0" => {
                                affected_reqs.push(format!("< {fixed}"));
                            }
                            Some(intro) => {
                                affected_reqs.push(format!(">= {intro}, < {fixed}"));
                            }
                            None => {
                                affected_reqs.push(format!("< {fixed}"));
                            }
                        }
                        current_intro = None;
                    }
                }
                if let Some(intro) = current_intro
                    && intro != "0"
                    && intro != "0.0.0"
                {
                    affected_reqs.push(format!(">= {intro}"));
                }
            }

            // Fallback to explicit affected versions if no range parsed
            if affected_reqs.is_empty() {
                for v in &aff.versions {
                    affected_reqs.push(format!("= {v}"));
                }
            }

            // Severity override from database_specific if provided
            let severity = if let Some(db_spec) = &aff.database_specific
                && let Some(sev_val) = db_spec.get("severity")
                && let Some(sev_str) = sev_val.as_str()
            {
                match_severity_str(sev_str).unwrap_or(global_severity)
            } else {
                global_severity
            };

            advisories.push(Advisory {
                id: self.id.clone(),
                package: package_name,
                title: title.clone(),
                description: description.clone(),
                severity,
                affected_version_reqs: affected_reqs,
                patched_versions,
                published_at: published_at.clone(),
                aliases: self.aliases.clone(),
            });
        }

        advisories
    }

    fn determine_severity(&self) -> Severity {
        for s in &self.severity {
            if s.severity_type.starts_with("CVSS") {
                // If the score string contains a numeric representation or CVSS vector
                if let Some(sev) = parse_cvss_vector_or_score(&s.score) {
                    return sev;
                }
            }
        }
        Severity::High
    }
}

fn match_severity_str(s: &str) -> Option<Severity> {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MODERATE" | "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "INFORMATIONAL" | "INFO" => Some(Severity::Informational),
        _ => None,
    }
}

fn parse_cvss_vector_or_score(score_str: &str) -> Option<Severity> {
    // If it's a numeric score like "9.8" or "7.5"
    if let Ok(num) = score_str.parse::<f64>() {
        if num >= 9.0 {
            return Some(Severity::Critical);
        } else if num >= 7.0 {
            return Some(Severity::High);
        } else if num >= 4.0 {
            return Some(Severity::Medium);
        } else {
            return Some(Severity::Low);
        }
    }

    // If it's a CVSS 3.x vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    let upper = score_str.to_ascii_uppercase();
    if upper.contains("/C:H/I:H/A:H") || upper.contains("/S:C/C:H/I:H") {
        return Some(Severity::Critical);
    }
    if upper.contains("/C:H") || upper.contains("/I:H") || upper.contains("/A:H") {
        return Some(Severity::High);
    }
    if upper.contains("/C:L") || upper.contains("/I:L") || upper.contains("/A:L") {
        return Some(Severity::Medium);
    }

    None
}

/// Parses an OSV JSON string representing either a single advisory record or a bundle array of advisories.
pub fn parse_osv_payload(json_str: &str) -> Result<Vec<Advisory>, AdvisoryError> {
    let trimmed = json_str.trim();

    if trimmed.starts_with('[') {
        let records: Vec<OsvRecord> = serde_json::from_str(trimmed).map_err(|e| {
            AdvisoryError::new(
                AdvisoryErrorKind::InvalidDatabase,
                format!("Failed to parse OSV array: {e}"),
            )
        })?;
        let mut advisories = Vec::new();
        for rec in records {
            advisories.extend(rec.to_advisories());
        }
        Ok(advisories)
    } else {
        let record: OsvRecord = serde_json::from_str(trimmed).map_err(|e| {
            AdvisoryError::new(
                AdvisoryErrorKind::InvalidDatabase,
                format!("Failed to parse OSV record: {e}"),
            )
        })?;
        Ok(record.to_advisories())
    }
}

/// What [`ingest_osv_directory_report`] read from a local OSV directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OsvDirectoryIngest {
    /// Advisory entries added to the database: one per affected package of each record.
    pub advisory_entries: usize,
    /// Top-level `.json` files that were read and parsed.
    pub files_parsed: usize,
    /// Top-level `.json` files that could not be read or parsed; nothing was taken from them.
    pub files_skipped: usize,
}

/// Ingests all `.json` OSV advisories located in a directory into the given database.
///
/// Returns the number of advisory entries added. Only top-level `.json` files are read;
/// files that cannot be read or parsed are skipped. Use [`ingest_osv_directory_report`]
/// to learn how many files were skipped.
pub fn ingest_osv_directory(
    database: &mut AdvisoryDatabase,
    dir_path: &Path,
) -> Result<usize, AdvisoryError> {
    ingest_osv_directory_report(database, dir_path).map(|report| report.advisory_entries)
}

/// Ingests the top-level `.json` OSV files of a directory into the given (in-memory)
/// database and reports how many files were parsed and skipped. Subdirectories are not
/// searched and non-`.json` files are ignored.
pub fn ingest_osv_directory_report(
    database: &mut AdvisoryDatabase,
    dir_path: &Path,
) -> Result<OsvDirectoryIngest, AdvisoryError> {
    if !dir_path.is_dir() {
        return Err(AdvisoryError::new(
            AdvisoryErrorKind::InvalidDatabase,
            format!("Path '{}' is not a directory", dir_path.display()),
        ));
    }

    let entries = fs::read_dir(dir_path).map_err(|e| {
        AdvisoryError::new(
            AdvisoryErrorKind::InvalidDatabase,
            format!(
                "Cannot read advisory directory '{}': {e}",
                dir_path.display()
            ),
        )
    })?;

    let mut report = OsvDirectoryIngest::default();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if !path.is_file() || path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let parsed = fs::read_to_string(&path)
            .ok()
            .and_then(|content| parse_osv_payload(&content).ok());
        match parsed {
            Some(advisories) => {
                report.files_parsed += 1;
                for adv in advisories {
                    database.add_advisory(adv);
                    report.advisory_entries += 1;
                }
            }
            None => report.files_skipped += 1,
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::cargo_lock::PackageRecord;
    use crate::domain::time::TimestampUtc;

    #[test]
    fn test_parse_osv_single_record() {
        let json = r#"{
            "schema_version": "1.6.0",
            "id": "GHSA-test-1234-abcd",
            "summary": "Remote Code Execution in sample-pkg",
            "details": "A severe vulnerability allows arbitrary command execution.",
            "aliases": ["CVE-2023-9999"],
            "published": "2023-05-01T00:00:00Z",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "affected": [
                {
                    "package": {
                        "name": "sample-pkg",
                        "ecosystem": "npm"
                    },
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                { "introduced": "0" },
                                { "fixed": "2.4.0" }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let advisories = parse_osv_payload(json).expect("should parse OSV record");
        assert_eq!(advisories.len(), 1);
        let adv = &advisories[0];
        assert_eq!(adv.id, "GHSA-test-1234-abcd");
        assert_eq!(adv.package, "sample-pkg");
        assert_eq!(adv.title, "Remote Code Execution in sample-pkg");
        assert_eq!(adv.severity, Severity::Critical);
        assert_eq!(adv.affected_version_reqs, vec!["< 2.4.0".to_string()]);
        assert_eq!(adv.patched_versions, vec!["2.4.0".to_string()]);
        assert_eq!(adv.aliases, vec!["CVE-2023-9999".to_string()]);
    }

    #[test]
    fn test_parse_osv_bundle_array() {
        let json = r#"[
            {
                "id": "RUSTSEC-2024-0001",
                "summary": "Buffer overflow in crate-a",
                "affected": [
                    {
                        "package": { "name": "crate-a" },
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    { "introduced": "1.0.0" },
                                    { "fixed": "1.2.5" }
                                ]
                            }
                        ]
                    }
                ]
            },
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Prototype pollution in crate-b",
                "affected": [
                    {
                        "package": { "name": "crate-b" },
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    { "introduced": "0" },
                                    { "fixed": "3.0.0" }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]"#;

        let advisories = parse_osv_payload(json).expect("should parse OSV bundle");
        assert_eq!(advisories.len(), 2);
        assert_eq!(advisories[0].package, "crate-a");
        assert_eq!(
            advisories[0].affected_version_reqs,
            vec![">= 1.0.0, < 1.2.5".to_string()]
        );
        assert_eq!(advisories[1].package, "crate-b");
    }

    #[test]
    fn test_osv_database_ingest_and_audit() {
        let now = TimestampUtc::now();
        let mut db = AdvisoryDatabase::empty(now);

        let json = r#"{
            "id": "GHSA-test-vulnerable",
            "summary": "Flaw in target-dep",
            "affected": [
                {
                    "package": { "name": "target-dep" },
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                { "introduced": "0" },
                                { "fixed": "1.5.0" }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let count = db.ingest_osv_payload(json).expect("should ingest");
        assert_eq!(count, 1);

        let test_packages = vec![
            PackageRecord::new("target-dep", "1.4.2"),
            PackageRecord::new("safe-dep", "2.0.0"),
        ];

        let result = db.audit_packages(&test_packages, now, 30).unwrap();
        assert_eq!(result.packages_audited, 2);
        assert_eq!(result.vulnerable_packages, 1);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].advisory.id, "GHSA-test-vulnerable");
        assert_eq!(
            result.matches[0].recommended_patch.as_deref(),
            Some("1.5.0")
        );
    }

    #[test]
    fn test_osv_directory_report_counts_skipped_files() {
        let dir = std::env::temp_dir().join(format!(
            "sentra-osv-dir-{}-{}",
            std::process::id(),
            crate::domain::id::SessionId::new()
        ));
        fs::create_dir_all(dir.join("nested")).unwrap();
        let record = r#"{"id":"GHSA-dir-1","affected":[
            {"package":{"name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]},
            {"package":{"name":"b"},"versions":["0.1.0"]}
        ]}"#;
        fs::write(dir.join("one.json"), record).unwrap();
        fs::write(dir.join("broken.json"), "{ not json").unwrap();
        fs::write(dir.join("readme.txt"), "not an advisory").unwrap();
        // Subdirectories are not searched.
        fs::write(dir.join("nested").join("two.json"), record).unwrap();

        let mut db = AdvisoryDatabase::empty(TimestampUtc::now());
        let report = ingest_osv_directory_report(&mut db, &dir).unwrap();
        assert_eq!(
            report,
            OsvDirectoryIngest {
                advisory_entries: 2,
                files_parsed: 1,
                files_skipped: 1,
            }
        );
        assert_eq!(db.advisory_count(), 2);

        // The count-only wrapper reports the same entries.
        let mut db = AdvisoryDatabase::empty(TimestampUtc::now());
        assert_eq!(ingest_osv_directory(&mut db, &dir).unwrap(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
