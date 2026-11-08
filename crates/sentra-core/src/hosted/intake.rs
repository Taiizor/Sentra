//! Webhook intake coordinator validating authentication, deduplicating deliveries,
//! and parsing canonical events (REQ-F18, THREAT_MODEL T-11).

use std::collections::HashSet;

use crate::{
    domain::TimestampUtc,
    hosted::{
        error::{WebhookError, WebhookErrorKind},
        event::{
            EventKind, PrAction, PullRequestPayload, PushPayload, WebhookEvent, validate_commit_sha,
        },
        ledger::DeliveryLedger,
        provider::HostedProvider,
        verifier::{verify_github_signature, verify_gitlab_token},
    },
};

/// High-level coordinator managing authenticated webhook intake.
#[derive(Clone, Debug)]
pub struct WebhookIntake {
    /// Delivery ledger tracking recent events for replay protection.
    pub ledger: DeliveryLedger,
    /// Optional shared secret for GitHub HMAC-SHA256 signature verification.
    pub github_secret: Option<Vec<u8>>,
    /// Optional secret token for GitLab webhook verification.
    pub gitlab_secret: Option<String>,
    /// Optional allowlist of repositories authorized for processing.
    pub allowed_repositories: HashSet<String>,
}

impl Default for WebhookIntake {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookIntake {
    /// Constructs a new webhook intake coordinator.
    pub fn new() -> Self {
        Self {
            ledger: DeliveryLedger::default(),
            github_secret: None,
            gitlab_secret: None,
            allowed_repositories: HashSet::new(),
        }
    }

    /// Sets the GitHub webhook secret.
    pub fn with_github_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.github_secret = Some(secret.into());
        self
    }

    /// Sets the GitLab webhook secret token.
    pub fn with_gitlab_secret(mut self, secret: impl Into<String>) -> Self {
        self.gitlab_secret = Some(secret.into());
        self
    }

    /// Adds an authorized repository identifier to the allowlist (e.g., `owner/repo`).
    pub fn allow_repository(&mut self, repo_name: impl Into<String>) {
        self.allowed_repositories.insert(repo_name.into());
    }

    /// Processes an incoming GitHub webhook request.
    pub fn process_github_webhook(
        &mut self,
        delivery_id: Option<&str>,
        event_type: Option<&str>,
        signature: Option<&str>,
        body: &[u8],
        now: TimestampUtc,
    ) -> Result<WebhookEvent, WebhookError> {
        // 1. Signature verification
        if let Some(ref secret) = self.github_secret {
            verify_github_signature(secret, signature, body)?;
        }

        // 2. Delivery ID extraction & Replay check
        let dev_id = delivery_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                WebhookError::malformed_payload("Missing required 'X-GitHub-Delivery' header")
            })?;

        self.ledger
            .record_delivery(dev_id, HostedProvider::GitHub, None, now)?;

        // 3. Event type dispatch
        let event = event_type
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                WebhookError::malformed_payload("Missing required 'X-GitHub-Event' header")
            })?;

        // 4. Parse JSON payload
        let json: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            WebhookError::new(
                WebhookErrorKind::MalformedPayload,
                format!("Failed to parse JSON body: {e}"),
            )
        })?;

        if event == "ping" {
            let repo_name = json["repository"]["full_name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let clone_url = json["repository"]["clone_url"]
                .as_str()
                .unwrap_or("")
                .to_string();

            return Ok(WebhookEvent {
                event_id: dev_id.to_string(),
                provider: HostedProvider::GitHub,
                repository_name: repo_name,
                repository_url: clone_url,
                is_fork: false,
                payload: EventKind::Ping,
                received_at: now,
            });
        }

        let repo = json.get("repository").ok_or_else(|| {
            WebhookError::malformed_payload("Missing 'repository' object in payload")
        })?;
        let repo_name = repo["full_name"]
            .as_str()
            .ok_or_else(|| WebhookError::malformed_payload("Missing 'repository.full_name'"))?
            .to_string();
        let clone_url = repo["clone_url"].as_str().unwrap_or("").to_string();
        let repo_is_fork = repo["fork"].as_bool().unwrap_or(false);

        // Policy allowlist check
        if !self.allowed_repositories.is_empty() && !self.allowed_repositories.contains(&repo_name)
        {
            return Err(WebhookError::policy_denied(format!(
                "Repository '{repo_name}' is not in the authorized repository allowlist"
            )));
        }

        match event {
            "push" => {
                let ref_name = json["ref"]
                    .as_str()
                    .ok_or_else(|| WebhookError::malformed_payload("Missing 'ref' in push event"))?
                    .to_string();
                let before_sha = json["before"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'before' in push event")
                })?;
                let after_sha = json["after"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'after' in push event")
                })?;

                let before_valid = validate_commit_sha(before_sha)?;
                let after_valid = validate_commit_sha(after_sha)?;
                let is_forced = json["forced"].as_bool().unwrap_or(false);
                let commit_count = json["commits"].as_array().map(|a| a.len()).unwrap_or(0);

                Ok(WebhookEvent {
                    event_id: dev_id.to_string(),
                    provider: HostedProvider::GitHub,
                    repository_name: repo_name,
                    repository_url: clone_url,
                    is_fork: repo_is_fork,
                    payload: EventKind::Push(PushPayload {
                        ref_name,
                        before_sha: before_valid,
                        after_sha: after_valid,
                        is_forced,
                        commit_count,
                    }),
                    received_at: now,
                })
            }
            "pull_request" => {
                let pr_num = json["number"].as_u64().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'number' in pull_request")
                })?;
                let action_str = json["action"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'action' in pull_request")
                })?;

                let action = match action_str {
                    "opened" => PrAction::Opened,
                    "synchronize" => PrAction::Synchronize,
                    "closed" => PrAction::Closed,
                    "reopened" => PrAction::Reopened,
                    other => PrAction::Other(other.to_string()),
                };

                let pr_obj = &json["pull_request"];
                let base_ref = pr_obj["base"]["ref"].as_str().unwrap_or("main").to_string();
                let base_sha = pr_obj["base"]["sha"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'pull_request.base.sha'")
                })?;
                let head_ref = pr_obj["head"]["ref"].as_str().unwrap_or("head").to_string();
                let head_sha = pr_obj["head"]["sha"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'pull_request.head.sha'")
                })?;

                let base_valid = validate_commit_sha(base_sha)?;
                let head_valid = validate_commit_sha(head_sha)?;

                let head_repo_fork = pr_obj["head"]["repo"]["fork"].as_bool().unwrap_or(false);
                let is_fork = head_repo_fork
                    || pr_obj["head"]["repo"]["full_name"] != pr_obj["base"]["repo"]["full_name"];

                Ok(WebhookEvent {
                    event_id: dev_id.to_string(),
                    provider: HostedProvider::GitHub,
                    repository_name: repo_name,
                    repository_url: clone_url,
                    is_fork,
                    payload: EventKind::PullRequest(PullRequestPayload {
                        pr_number: pr_num,
                        action,
                        base_ref,
                        base_sha: base_valid,
                        head_ref,
                        head_sha: head_valid,
                        is_fork,
                    }),
                    received_at: now,
                })
            }
            unknown => Err(WebhookError::new(
                WebhookErrorKind::MalformedPayload,
                format!("Unsupported GitHub event: '{unknown}'"),
            )),
        }
    }

    /// Processes an incoming GitLab webhook request.
    pub fn process_gitlab_webhook(
        &mut self,
        delivery_id: Option<&str>,
        event_type: Option<&str>,
        token: Option<&str>,
        body: &[u8],
        now: TimestampUtc,
    ) -> Result<WebhookEvent, WebhookError> {
        // 1. Secret token verification
        if let Some(ref secret) = self.gitlab_secret {
            verify_gitlab_token(secret, token)?;
        }

        // 2. Delivery ID extraction & Replay check
        let dev_id = delivery_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                WebhookError::malformed_payload("Missing required 'X-Gitlab-Event-UUID' header")
            })?;

        self.ledger
            .record_delivery(dev_id, HostedProvider::GitLab, None, now)?;

        // 3. Event type dispatch
        let event = event_type
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                WebhookError::malformed_payload("Missing required 'X-Gitlab-Event' header")
            })?;

        // 4. Parse JSON payload
        let json: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            WebhookError::new(
                WebhookErrorKind::MalformedPayload,
                format!("Failed to parse JSON body: {e}"),
            )
        })?;

        let project = json.get("project").ok_or_else(|| {
            WebhookError::malformed_payload("Missing 'project' object in GitLab webhook")
        })?;
        let repo_name = project["path_with_namespace"]
            .as_str()
            .ok_or_else(|| {
                WebhookError::malformed_payload("Missing 'project.path_with_namespace'")
            })?
            .to_string();
        let clone_url = project["git_http_url"].as_str().unwrap_or("").to_string();

        // Policy allowlist check
        if !self.allowed_repositories.is_empty() && !self.allowed_repositories.contains(&repo_name)
        {
            return Err(WebhookError::policy_denied(format!(
                "Repository '{repo_name}' is not in the authorized repository allowlist"
            )));
        }

        match event {
            "Push Hook" => {
                let ref_name = json["ref"]
                    .as_str()
                    .ok_or_else(|| {
                        WebhookError::malformed_payload("Missing 'ref' in GitLab Push Hook")
                    })?
                    .to_string();
                let before_sha = json["before"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'before' in GitLab Push Hook")
                })?;
                let after_sha = json["after"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'after' in GitLab Push Hook")
                })?;

                let before_valid = validate_commit_sha(before_sha)?;
                let after_valid = validate_commit_sha(after_sha)?;
                let commit_count = json["total_commits_count"].as_u64().unwrap_or(0) as usize;

                Ok(WebhookEvent {
                    event_id: dev_id.to_string(),
                    provider: HostedProvider::GitLab,
                    repository_name: repo_name,
                    repository_url: clone_url,
                    is_fork: false,
                    payload: EventKind::Push(PushPayload {
                        ref_name,
                        before_sha: before_valid,
                        after_sha: after_valid,
                        is_forced: false,
                        commit_count,
                    }),
                    received_at: now,
                })
            }
            "Merge Request Hook" => {
                let attrs = &json["object_attributes"];
                let mr_num = attrs["iid"].as_u64().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'object_attributes.iid'")
                })?;
                let action_str = attrs["action"].as_str().unwrap_or("open");

                let action = match action_str {
                    "open" | "reopen" => PrAction::Opened,
                    "update" => PrAction::Synchronize,
                    "close" => PrAction::Closed,
                    other => PrAction::Other(other.to_string()),
                };

                let target_branch = attrs["target_branch"]
                    .as_str()
                    .unwrap_or("main")
                    .to_string();
                let source_branch = attrs["source_branch"]
                    .as_str()
                    .unwrap_or("feature")
                    .to_string();

                let head_sha = attrs["last_commit"]["id"].as_str().ok_or_else(|| {
                    WebhookError::malformed_payload("Missing 'last_commit.id' in Merge Request")
                })?;
                let head_valid = validate_commit_sha(head_sha)?;

                // For base_sha, use target commit id if present or fallback to head
                let base_sha = attrs["target"]["default_branch"]
                    .as_str()
                    .unwrap_or(&head_valid);
                let base_valid =
                    validate_commit_sha(base_sha).unwrap_or_else(|_| head_valid.clone());

                let source_project_id = attrs["source_project_id"].as_i64();
                let target_project_id = attrs["target_project_id"].as_i64();
                let is_fork = source_project_id != target_project_id;

                Ok(WebhookEvent {
                    event_id: dev_id.to_string(),
                    provider: HostedProvider::GitLab,
                    repository_name: repo_name,
                    repository_url: clone_url,
                    is_fork,
                    payload: EventKind::PullRequest(PullRequestPayload {
                        pr_number: mr_num,
                        action,
                        base_ref: target_branch,
                        base_sha: base_valid,
                        head_ref: source_branch,
                        head_sha: head_valid,
                        is_fork,
                    }),
                    received_at: now,
                })
            }
            unknown => Err(WebhookError::new(
                WebhookErrorKind::MalformedPayload,
                format!("Unsupported GitLab event: '{unknown}'"),
            )),
        }
    }
}
