//! Supported continuous hosted git providers (REQ-F18).

use std::fmt;

/// Continuous hosted Git provider identifying the origin platform of webhook events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HostedProvider {
    /// GitHub / GitHub Enterprise (`X-GitHub-Event`, `X-Hub-Signature-256`).
    GitHub,
    /// GitLab / GitLab Self-Managed (`X-Gitlab-Event`, `X-Gitlab-Token`).
    GitLab,
}

impl HostedProvider {
    /// Returns the canonical provider string identifier.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
        }
    }
}

impl fmt::Display for HostedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
