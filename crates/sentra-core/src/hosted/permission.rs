//! Granular hosted integration permissions, fork isolation profiles, and credential fencing
//! (REQ-F18, THREAT_MODEL T-11, S-10, Roadmap Phase 5 Acceptance Criteria).

use std::collections::HashSet;

use crate::hosted::error::WebhookError;

/// Granular permission flags governing hosted integration workflows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HostedPermission {
    /// Read-scoped repository acquisition (clone / fetch).
    AcquireSource,
    /// Static analysis and advisory scanning in isolated container.
    RunAnalysis,
    /// Updating commit check runs or pipeline status checks.
    PublishStatusCheck,
    /// Proposing a draft pull / merge request for verified remediation.
    ProposeDraftPr,
    /// Publishing public security advisories or public vulnerability disclosures.
    PublicDisclosure,
}

impl HostedPermission {
    /// Returns the canonical permission identifier.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AcquireSource => "acquire_source",
            Self::RunAnalysis => "run_analysis",
            Self::PublishStatusCheck => "publish_status_check",
            Self::ProposeDraftPr => "propose_draft_pr",
            Self::PublicDisclosure => "public_disclosure",
        }
    }
}

/// Security containment profile enforcing fork isolation and zero-secret exposure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkSecurityProfile {
    /// Whether the workload originates from an untrusted fork.
    pub is_fork: bool,
    /// Whether access to repository or provider secrets is permitted.
    pub secrets_permitted: bool,
    /// Set of permitted operations authorized under this profile.
    pub allowed_permissions: HashSet<HostedPermission>,
}

impl ForkSecurityProfile {
    /// Constructs a strict, zero-secret security profile for untrusted fork pull requests.
    pub fn for_fork() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(HostedPermission::AcquireSource);
        allowed.insert(HostedPermission::RunAnalysis);

        Self {
            is_fork: true,
            secrets_permitted: false, // Strict zero-secret guarantee
            allowed_permissions: allowed,
        }
    }

    /// Constructs an authorized profile for internal repository branches.
    pub fn for_internal_branch() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(HostedPermission::AcquireSource);
        allowed.insert(HostedPermission::RunAnalysis);
        allowed.insert(HostedPermission::PublishStatusCheck);
        allowed.insert(HostedPermission::ProposeDraftPr);

        Self {
            is_fork: false,
            secrets_permitted: true,
            allowed_permissions: allowed,
        }
    }

    /// Validates whether an action is authorized under this profile.
    pub fn check_permission(&self, permission: HostedPermission) -> Result<(), WebhookError> {
        if !self.allowed_permissions.contains(&permission) {
            if self.is_fork {
                return Err(WebhookError::fork_secret_access_denied(format!(
                    "Untrusted fork events are strictly denied permission '{}'",
                    permission.as_str()
                )));
            }
            return Err(WebhookError::permission_downgrade(format!(
                "Operation requires permission '{}' which is not granted under this profile",
                permission.as_str()
            )));
        }
        Ok(())
    }

    /// Asserts that secrets access is permitted, failing closed on fork workloads.
    pub fn check_secrets_access(&self) -> Result<(), WebhookError> {
        if !self.secrets_permitted || self.is_fork {
            return Err(WebhookError::fork_secret_access_denied(
                "Fork workloads are strictly prohibited from accessing credentials or secrets (T-11)",
            ));
        }
        Ok(())
    }
}

/// Bounded credentials for hosted Git interactions with strict worker-side redaction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HostedCredentials {
    /// Read-scoped token for source acquisition.
    pub read_token: Option<String>,
    /// Write-scoped token for status checks and draft PR proposals.
    pub write_token: Option<String>,
}

impl HostedCredentials {
    /// Creates new credentials.
    pub fn new(read_token: Option<String>, write_token: Option<String>) -> Self {
        Self {
            read_token,
            write_token,
        }
    }

    /// Filters credentials for worker consumption, ensuring credentials cannot reach target workers.
    ///
    /// Per Roadmap Phase 5 acceptance criteria: "Credentials cannot reach target workers."
    pub fn filter_for_worker(&self, profile: &ForkSecurityProfile) -> Self {
        if profile.is_fork || !profile.secrets_permitted {
            // Zero-secret guarantee for forks
            Self {
                read_token: None,
                write_token: None,
            }
        } else {
            // Even for non-forks, write tokens are NEVER passed to worker environments
            Self {
                read_token: self.read_token.clone(),
                write_token: None,
            }
        }
    }
}
