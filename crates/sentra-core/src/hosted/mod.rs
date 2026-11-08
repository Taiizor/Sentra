//! Continuous hosted integrations, webhook authentication, and delivery deduplication (REQ-F18, ADR-0005, THREAT_MODEL T-11).

pub mod error;
pub mod event;
pub mod intake;
pub mod ledger;
pub mod permission;
pub mod proposal;
pub mod provider;
pub mod verifier;

pub use error::{WebhookError, WebhookErrorKind};
pub use event::{
    EventKind, PrAction, PullRequestPayload, PushPayload, WebhookEvent, validate_commit_sha,
};
pub use intake::WebhookIntake;
pub use ledger::{
    DEFAULT_MAX_DRIFT_SECS, DEFAULT_MAX_LEDGER_CAPACITY, DeliveryLedger, DeliveryRecord,
};
pub use permission::{ForkSecurityProfile, HostedCredentials, HostedPermission};
pub use proposal::{DraftPrProposal, ProposalStatus, StaleHeadGuard};
pub use provider::HostedProvider;
pub use verifier::{verify_github_signature, verify_gitlab_token};
