//! Canonical webhook event and payload models (REQ-F18, THREAT_MODEL T-11).

use crate::{
    domain::TimestampUtc,
    hosted::{
        error::{WebhookError, WebhookErrorKind},
        provider::HostedProvider,
    },
};

/// Validates that a string is a valid 40-character hexadecimal Git commit SHA.
pub fn validate_commit_sha(sha: &str) -> Result<String, WebhookError> {
    let trimmed = sha.trim();
    if trimmed.len() != 40 {
        return Err(WebhookError::new(
            WebhookErrorKind::InvalidRevision,
            format!("Commit SHA must be 40 characters; got {}", trimmed.len()),
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WebhookError::new(
            WebhookErrorKind::InvalidRevision,
            format!("Commit SHA contains non-hex characters: '{trimmed}'"),
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Normalized payload for direct branch push events.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PushPayload {
    /// Git reference name (e.g., `refs/heads/main`).
    pub ref_name: String,
    /// Commit SHA prior to the push (or zero SHA for new branch creation).
    pub before_sha: String,
    /// Commit SHA after the push.
    pub after_sha: String,
    /// Whether this push was a force-push (`forced = true`).
    pub is_forced: bool,
    /// Count of commits included in this push.
    pub commit_count: usize,
}

/// Normalized action lifecycle for pull/merge request events.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrAction {
    /// Pull request opened.
    Opened,
    /// Head branch updated / synchronized with new commits.
    Synchronize,
    /// Pull request closed (merged or rejected).
    Closed,
    /// Pull request reopened.
    Reopened,
    /// Other non-analyzed PR action (labeled, assigned, etc.).
    Other(String),
}

/// Normalized payload for pull/merge request events.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PullRequestPayload {
    /// Pull/Merge request numerical identifier.
    pub pr_number: u64,
    /// Lifecycle action of the pull request.
    pub action: PrAction,
    /// Target base branch reference (e.g., `main`).
    pub base_ref: String,
    /// Immutable base commit SHA.
    pub base_sha: String,
    /// Source head branch reference.
    pub head_ref: String,
    /// Immutable head commit SHA.
    pub head_sha: String,
    /// Whether the head repository is a fork of the base repository.
    pub is_fork: bool,
}

/// Normalized event payload variant.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EventKind {
    /// Branch push event.
    Push(PushPayload),
    /// Pull or Merge request event.
    PullRequest(PullRequestPayload),
    /// Ping or connection handshake event.
    Ping,
}

/// Canonical, provider-agnostic representation of an authenticated webhook event.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebhookEvent {
    /// Delivery / event identifier (e.g. from `X-GitHub-Delivery`).
    pub event_id: String,
    /// Host provider origin.
    pub provider: HostedProvider,
    /// Full repository identifier (e.g., `owner/repo`).
    pub repository_name: String,
    /// Clone URL of the repository.
    pub repository_url: String,
    /// Whether the event originates from a fork repository.
    pub is_fork: bool,
    /// Specific normalized payload.
    pub payload: EventKind,
    /// Timestamp when the webhook was ingested.
    pub received_at: TimestampUtc,
}
