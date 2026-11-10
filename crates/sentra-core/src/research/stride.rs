//! STRIDE threat modeling taxonomy and defense-in-depth mitigation mapping (REQ-F04).
//!
//! Encodes the STRIDE methodology from `stride-analysis-patterns` and multi-layered
//! mitigation models from `threat-mitigation-mapping` to prioritize research campaigns
//! and evaluate control coverage.

use serde::{Deserialize, Serialize};

/// STRIDE threat category classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrideCategory {
    /// Pretending to be someone or something other than oneself (Authentication threat).
    Spoofing,
    /// Unauthorized modification of data in transit or at rest (Integrity threat).
    Tampering,
    /// Ability to deny having performed an action without proof (Audit/Logging threat).
    Repudiation,
    /// Exposure of protected information to unauthorized parties (Confidentiality threat).
    InformationDisclosure,
    /// Disruption or degradation of legitimate service access (Availability threat).
    DenialOfService,
    /// Gaining unearned capabilities or administrative rights (Authorization threat).
    ElevationOfPrivilege,
}

impl StrideCategory {
    /// Returns all 6 STRIDE categories in canonical order.
    pub const fn all() -> [Self; 6] {
        [
            Self::Spoofing,
            Self::Tampering,
            Self::Repudiation,
            Self::InformationDisclosure,
            Self::DenialOfService,
            Self::ElevationOfPrivilege,
        ]
    }

    /// Canonical human-readable label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Spoofing => "Spoofing",
            Self::Tampering => "Tampering",
            Self::Repudiation => "Repudiation",
            Self::InformationDisclosure => "Information Disclosure",
            Self::DenialOfService => "Denial of Service",
            Self::ElevationOfPrivilege => "Elevation of Privilege",
        }
    }

    /// Maps each STRIDE category to its primary defensive control family.
    pub const fn primary_control_family(&self) -> ControlFamily {
        match self {
            Self::Spoofing => ControlFamily::Authentication,
            Self::Tampering => ControlFamily::Integrity,
            Self::Repudiation => ControlFamily::NonRepudiation,
            Self::InformationDisclosure => ControlFamily::Confidentiality,
            Self::DenialOfService => ControlFamily::Availability,
            Self::ElevationOfPrivilege => ControlFamily::Authorization,
        }
    }

    /// Returns the uppercase standard acronym letter.
    pub const fn letter(&self) -> char {
        match self {
            Self::Spoofing => 'S',
            Self::Tampering => 'T',
            Self::Repudiation => 'R',
            Self::InformationDisclosure => 'I',
            Self::DenialOfService => 'D',
            Self::ElevationOfPrivilege => 'E',
        }
    }

    /// Descriptive question used during threat modeling sessions.
    pub const fn diagnostic_question(&self) -> &'static str {
        match self {
            Self::Spoofing => "Can an attacker pretend to be a valid user, worker, or service?",
            Self::Tampering => {
                "Can an attacker modify source code, configuration, or data in transit/rest?"
            }
            Self::Repudiation => {
                "Can an attacker or operator perform malicious actions without an immutable audit trail?"
            }
            Self::InformationDisclosure => {
                "Can an attacker leak secrets, private keys, or confidential source code?"
            }
            Self::DenialOfService => {
                "Can an attacker exhaust CPU, memory, budget, or worker concurrency ceilings?"
            }
            Self::ElevationOfPrivilege => {
                "Can an unprivileged actor or child task gain unrestricted capabilities?"
            }
        }
    }
}

/// Primary control family corresponding to security attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFamily {
    /// Identity verification and credential management.
    Authentication,
    /// Cryptographic hashing, signatures, and input validation.
    Integrity,
    /// Immutable append-only audit ledgers and non-repudiation.
    NonRepudiation,
    /// Encryption, secret isolation, and data redaction.
    Confidentiality,
    /// Rate limiting, budget controls, and worker fencing.
    Availability,
    /// Policy engine, RBAC, and approval gates.
    Authorization,
}

/// Defense-in-depth architectural layer where a security control resides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlLayer {
    /// Ingress gateway, WAF, API gateway, reverse proxy.
    Perimeter,
    /// Mutual TLS, network segmentation, VPC endpoints.
    Network,
    /// Operating system hardening, container sandboxes, process isolation.
    Host,
    /// Framework security, input validation, authentication, authorization.
    Application,
    /// Encryption at rest, database access controls, CAS blob integrity.
    Data,
}

/// Operational classification of a defensive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlType {
    /// Stops attacks before they execute (e.g. input validation, policy gate, sandbox).
    Preventive,
    /// Detects attacks in progress or anomalies (e.g. SAST scan, audit log monitor, IDS).
    Detective,
    /// Responds, isolates, and recovers (e.g. secret revocation, worker kill, rollback).
    Corrective,
}

/// Concrete security mitigation entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityMitigation {
    /// Concise mitigation identifier.
    pub id: String,
    /// Mitigation title.
    pub name: String,
    /// Description of control behavior.
    pub description: String,
    /// Layer where control operates.
    pub layer: ControlLayer,
    /// Operational control type.
    pub control_type: ControlType,
    /// Control effectiveness rating (1 to 5).
    pub effectiveness: u32,
}

/// Comprehensive STRIDE threat and mitigation mapping descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatMitigationMapping {
    /// Unique threat identifier (e.g. `THREAT-STRIDE-001`).
    pub threat_id: String,
    /// STRIDE category.
    pub category: StrideCategory,
    /// Concrete threat title.
    pub title: String,
    /// Narrative scenario of how an attacker abuses this boundary.
    pub description: String,
    /// Applicable CWE references.
    pub cwe_refs: Vec<String>,
    /// Associated defensive controls across defense-in-depth layers.
    pub mitigations: Vec<SecurityMitigation>,
}

impl ThreatMitigationMapping {
    /// Creates a new threat mitigation entry.
    pub fn new(
        threat_id: impl Into<String>,
        category: StrideCategory,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            threat_id: threat_id.into(),
            category,
            title: title.into(),
            description: description.into(),
            cwe_refs: Vec::new(),
            mitigations: Vec::new(),
        }
    }

    /// Adds a mitigation control.
    pub fn add_mitigation(&mut self, mitigation: SecurityMitigation) {
        self.mitigations.push(mitigation);
    }

    /// Calculates Defense-in-Depth score (0-100) based on coverage across layers and types.
    pub fn defense_in_depth_score(&self) -> u32 {
        if self.mitigations.is_empty() {
            return 0;
        }

        let has_preventive = self
            .mitigations
            .iter()
            .any(|m| m.control_type == ControlType::Preventive);
        let has_detective = self
            .mitigations
            .iter()
            .any(|m| m.control_type == ControlType::Detective);
        let has_corrective = self
            .mitigations
            .iter()
            .any(|m| m.control_type == ControlType::Corrective);

        let mut unique_layers = std::collections::HashSet::new();
        for m in &self.mitigations {
            unique_layers.insert(m.layer);
        }

        let mut score = 0;
        if has_preventive {
            score += 35;
        }
        if has_detective {
            score += 25;
        }
        if has_corrective {
            score += 15;
        }

        // Up to 25 bonus points for multi-layer diversity (5 points per distinct layer)
        score += (unique_layers.len() as u32).min(5) * 5;

        score.min(100)
    }
}
