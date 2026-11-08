//! OASIS SARIF v2.1.0 data models and report generator (REQ-F05, REQ-F07, EXTENSIONS.md).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    domain::{Finding, FindingSource, Severity},
    service::LocalAuditReport,
};

/// Schema URI for OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0.
pub const SARIF_SCHEMA_V2_1_0: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// Version identifier for SARIF v2.1.0.
pub const SARIF_VERSION_2_1_0: &str = "2.1.0";

/// Root container for a SARIF v2.1.0 log document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifLog {
    /// URI of the SARIF schema definition.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// SARIF version, always "2.1.0".
    pub version: String,
    /// List of tool execution runs contained in this log.
    pub runs: Vec<SarifRun>,
}

/// A single analysis run by a tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifRun {
    /// Information about the tool that performed the run.
    pub tool: SarifTool,
    /// List of static analysis or vulnerability results.
    pub results: Vec<SarifResult>,
}

/// Information about the analysis tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifTool {
    /// The primary driver executable or component.
    pub driver: SarifDriver,
}

/// Tool driver descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifDriver {
    /// Name of the tool.
    pub name: String,
    /// Semantic version of the tool.
    pub version: String,
    /// Informational URI for the tool homepage.
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    /// List of rules defined by this driver.
    pub rules: Vec<SarifRule>,
}

/// Multiformat text message container.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifMessage {
    /// Plain text message string.
    pub text: String,
}

/// Rule definition and metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifRule {
    /// Stable identifier of the rule (e.g. advisory ID or static check ID).
    pub id: String,
    /// Short rule name.
    pub name: String,
    /// Short description of the rule.
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    /// Full description of the rule, if available.
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    /// Help URI with remediation advice or advisory reference.
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// Default configuration level for results produced by this rule.
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifReportingConfiguration,
    /// Additional property bag (e.g. security-severity for GitHub Code Scanning).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, String>,
}

/// Default configuration for a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifReportingConfiguration {
    /// Severity level.
    pub level: SarifLevel,
}

/// SARIF result severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SarifLevel {
    /// Indicates an error / high severity condition.
    Error,
    /// Indicates a warning / medium severity condition.
    Warning,
    /// Indicates an informational note or low severity condition.
    Note,
    /// No severity / pass.
    None,
}

/// A single finding / result produced by analysis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifResult {
    /// Identifier of the rule that produced this result.
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    /// Severity level of the result.
    pub level: SarifLevel,
    /// Result explanation message.
    pub message: SarifMessage,
    /// Locations where the issue was observed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
    /// Property bag with Sentra-specific metadata (finding ID, reachability, status).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, String>,
}

/// Location of a result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifLocation {
    /// Physical location in an artifact on disk.
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

/// Physical file and region location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    /// Artifact file location.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    /// Text region within the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// Artifact location descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    /// Workspace-relative URI path with forward slashes.
    pub uri: String,
    /// Base identifier, typically "%SRCROOT%".
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// Region within a source or manifest file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifRegion {
    /// 1-based start line.
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    /// 1-based end line.
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
}

/// Maps Sentra severity to a compliant SARIF level.
pub fn severity_to_sarif_level(severity: Severity) -> SarifLevel {
    match severity {
        Severity::Critical | Severity::High => SarifLevel::Error,
        Severity::Medium => SarifLevel::Warning,
        Severity::Low | Severity::Informational => SarifLevel::Note,
    }
}

/// Maps Sentra severity to a CVSS-equivalent security severity score for GitHub Code Scanning.
pub fn severity_to_security_score(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
        Severity::Informational => "0.0",
    }
}

/// Generates an in-memory SARIF v2.1.0 log document from a slice of findings.
pub fn generate_sarif_report(findings: &[Finding], tool_version: &str) -> SarifLog {
    let mut rules_map = BTreeMap::new();
    let mut results = Vec::new();

    for finding in findings {
        let (rule_id, rule_name, help_uri, default_path) = match finding.source() {
            FindingSource::CargoLockAdvisory { advisory_id, .. } => {
                let help = if advisory_id.starts_with("RUSTSEC-") {
                    Some(format!("https://rustsec.org/advisories/{advisory_id}.html"))
                } else {
                    None
                };
                (
                    advisory_id.clone(),
                    "DependencyVulnerability".to_string(),
                    help,
                    "Cargo.lock".to_string(),
                )
            }
            FindingSource::DependencyLockAdvisory {
                advisory_id,
                lockfile_path,
                ..
            } => {
                let help = if advisory_id.starts_with("RUSTSEC-") {
                    Some(format!("https://rustsec.org/advisories/{advisory_id}.html"))
                } else if advisory_id.starts_with("GHSA-") {
                    Some(format!("https://github.com/advisories/{advisory_id}"))
                } else {
                    None
                };
                (
                    advisory_id.clone(),
                    "DependencyVulnerability".to_string(),
                    help,
                    lockfile_path.clone(),
                )
            }
            FindingSource::StaticAnalysis { engine, rule_id } => (
                rule_id.clone(),
                format!("{engine}Rule"),
                None,
                "src/lib.rs".to_string(),
            ),
            FindingSource::DynamicAnalysis {
                agent_role,
                oracle_id,
            } => (
                format!("{agent_role}-{oracle_id}"),
                "DynamicVerificationFailure".to_string(),
                None,
                "src/lib.rs".to_string(),
            ),
            FindingSource::Manual { author } => (
                format!("MANUAL-{}", finding.id()),
                format!("ManualFindingBy{author}"),
                None,
                ".".to_string(),
            ),
        };

        let level = severity_to_sarif_level(finding.severity());
        let score = severity_to_security_score(finding.severity());

        rules_map.entry(rule_id.clone()).or_insert_with(|| {
            let mut props = BTreeMap::new();
            props.insert("security-severity".to_string(), score.to_string());
            SarifRule {
                id: rule_id.clone(),
                name: rule_name,
                short_description: SarifMessage {
                    text: finding.title().to_string(),
                },
                full_description: Some(SarifMessage {
                    text: finding.description().to_string(),
                }),
                help_uri,
                default_configuration: SarifReportingConfiguration { level },
                properties: props,
            }
        });

        let locations = if let Some(loc) = finding.location() {
            vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: loc.path.replace('\\', "/"),
                        uri_base_id: Some("%SRCROOT%".to_string()),
                    },
                    region: Some(SarifRegion {
                        start_line: loc.start_line,
                        end_line: loc.end_line,
                    }),
                },
            }]
        } else {
            vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: default_path,
                        uri_base_id: Some("%SRCROOT%".to_string()),
                    },
                    region: Some(SarifRegion {
                        start_line: Some(1),
                        end_line: Some(1),
                    }),
                },
            }]
        };

        let mut properties = BTreeMap::new();
        properties.insert("finding_id".to_string(), finding.id().to_string());
        properties.insert(
            "reachability".to_string(),
            finding.reachability().as_str().to_string(),
        );
        properties.insert("status".to_string(), finding.status().as_str().to_string());
        properties.insert(
            "confidence".to_string(),
            finding.confidence().as_str().to_string(),
        );

        results.push(SarifResult {
            rule_id,
            level,
            message: SarifMessage {
                text: format!("{}: {}", finding.title(), finding.description()),
            },
            locations,
            properties,
        });
    }

    let rules: Vec<SarifRule> = rules_map.into_values().collect();

    SarifLog {
        schema: SARIF_SCHEMA_V2_1_0.to_string(),
        version: SARIF_VERSION_2_1_0.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Sentra".to_string(),
                    version: tool_version.to_string(),
                    information_uri: "https://github.com/sentra-security/sentra".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

/// Generates a pretty-printed JSON string representation of a SARIF v2.1.0 document.
pub fn generate_sarif_json(
    findings: &[Finding],
    tool_version: &str,
) -> Result<String, serde_json::Error> {
    let report = generate_sarif_report(findings, tool_version);
    serde_json::to_string_pretty(&report)
}

/// Converts a `LocalAuditReport` into an OASIS SARIF v2.1.0 log document.
pub fn export_audit_to_sarif(report: &LocalAuditReport, tool_version: &str) -> SarifLog {
    generate_sarif_report(&report.candidate_findings, tool_version)
}

/// Converts a `LocalAuditReport` into a pretty-printed JSON string representation of SARIF v2.1.0.
pub fn export_audit_to_sarif_json(
    report: &LocalAuditReport,
    tool_version: &str,
) -> Result<String, serde_json::Error> {
    let sarif = export_audit_to_sarif(report, tool_version);
    serde_json::to_string_pretty(&sarif)
}
