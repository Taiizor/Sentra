//! Webhook and hosted integration error models (REQ-F18, THREAT_MODEL T-11).

use std::fmt;

/// Categories of webhook ingestion and validation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookErrorKind {
    /// HMAC or secret token signature verification failed or was missing.
    InvalidSignature,
    /// Webhook payload JSON is malformed or missing required schema fields.
    MalformedPayload,
    /// Webhook delivery ID was previously processed (replay attack or duplicate delivery).
    ReplayDetected,
    /// Delivery timestamp deviates from host time beyond allowed freshness window.
    TimestampDriftDetected,
    /// Webhook provider is unrecognized or unsupported.
    UnsupportedProvider,
    /// Git revision (SHA-1 / SHA-256) is malformed or invalid hex format.
    InvalidRevision,
    /// Repository or event type is rejected by policy.
    PolicyDenied,
    /// Untrusted fork event attempted to access repository write credentials or provider secrets (T-11, S-10).
    ForkSecretAccessDenied,
    /// Permission downgrade or privilege escalation rejected by authorization policy.
    PermissionDowngrade,
    /// Target branch head has diverged or force-pushed since analysis began.
    StaleHeadDivergence,
    /// Common merge base between base and head cannot be determined or verified.
    MissingMergeBase,
    /// Verification bundle is stale because target commit revision changed, blocking publication.
    StaleVerificationBlocksPublication,
    /// Operation requires explicit human operator approval before execution.
    HumanApprovalRequired,
}

impl WebhookErrorKind {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::MalformedPayload => "malformed_payload",
            Self::ReplayDetected => "replay_detected",
            Self::TimestampDriftDetected => "timestamp_drift_detected",
            Self::UnsupportedProvider => "unsupported_provider",
            Self::InvalidRevision => "invalid_revision",
            Self::PolicyDenied => "policy_denied",
            Self::ForkSecretAccessDenied => "fork_secret_access_denied",
            Self::PermissionDowngrade => "permission_downgrade",
            Self::StaleHeadDivergence => "stale_head_divergence",
            Self::MissingMergeBase => "missing_merge_base",
            Self::StaleVerificationBlocksPublication => "stale_verification_blocks_publication",
            Self::HumanApprovalRequired => "human_approval_required",
        }
    }
}

impl fmt::Display for WebhookErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Strongly-typed error produced during webhook intake, authentication, or parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookError {
    kind: WebhookErrorKind,
    message: String,
}

impl WebhookError {
    /// Creates a new webhook error.
    pub fn new(kind: WebhookErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the category of this error.
    pub fn kind(&self) -> WebhookErrorKind {
        self.kind
    }

    /// Returns the descriptive error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Helper for invalid signature errors.
    pub fn invalid_signature(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::InvalidSignature, msg)
    }

    /// Helper for malformed payload errors.
    pub fn malformed_payload(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::MalformedPayload, msg)
    }

    /// Helper for replay detected errors.
    pub fn replay_detected(delivery_id: impl Into<String>) -> Self {
        let id = delivery_id.into();
        Self::new(
            WebhookErrorKind::ReplayDetected,
            format!("Delivery '{id}' has already been processed"),
        )
    }

    /// Helper for timestamp drift errors.
    pub fn timestamp_drift(diff_secs: u64, max_secs: u64) -> Self {
        Self::new(
            WebhookErrorKind::TimestampDriftDetected,
            format!("Timestamp drift of {diff_secs}s exceeds tolerance limit of {max_secs}s"),
        )
    }

    /// Helper for policy denied errors.
    pub fn policy_denied(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::PolicyDenied, msg)
    }

    /// Helper for fork secret access denied errors.
    pub fn fork_secret_access_denied(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::ForkSecretAccessDenied, msg)
    }

    /// Helper for permission downgrade errors.
    pub fn permission_downgrade(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::PermissionDowngrade, msg)
    }

    /// Helper for stale head divergence errors.
    pub fn stale_head(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::StaleHeadDivergence, msg)
    }

    /// Helper for missing merge base errors.
    pub fn missing_merge_base(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::MissingMergeBase, msg)
    }

    /// Helper for stale verification blocking publication errors.
    pub fn stale_verification_blocks_publication(msg: impl Into<String>) -> Self {
        Self::new(WebhookErrorKind::StaleVerificationBlocksPublication, msg)
    }

    /// Helper for human approval required errors.
    pub fn human_approval_required(action: impl Into<String>) -> Self {
        let a = action.into();
        Self::new(
            WebhookErrorKind::HumanApprovalRequired,
            format!("Action '{a}' requires explicit human operator review and approval"),
        )
    }
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.message)
    }
}

impl std::error::Error for WebhookError {}
