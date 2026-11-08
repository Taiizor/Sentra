//! Webhook authentication and signature verification primitives (REQ-F18, THREAT_MODEL T-11).

use crate::{
    common::crypto::{constant_time_eq, hmac_sha256_hex},
    hosted::error::WebhookError,
};

/// Verifies GitHub `X-Hub-Signature-256` HMAC-SHA256 signature using constant-time comparison.
pub fn verify_github_signature(
    secret: &[u8],
    signature_header: Option<&str>,
    body: &[u8],
) -> Result<(), WebhookError> {
    let header = signature_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WebhookError::invalid_signature("Missing required 'X-Hub-Signature-256' header")
        })?;

    let expected_hex = header.strip_prefix("sha256=").ok_or_else(|| {
        WebhookError::invalid_signature("GitHub signature header must use 'sha256=' prefix")
    })?;

    let computed_hex = hmac_sha256_hex(secret, body);

    if !constant_time_eq(computed_hex.as_bytes(), expected_hex.as_bytes()) {
        return Err(WebhookError::invalid_signature(
            "HMAC-SHA256 signature mismatch for payload",
        ));
    }

    Ok(())
}

/// Verifies GitLab `X-Gitlab-Token` webhook secret token using constant-time comparison.
pub fn verify_gitlab_token(secret: &str, token_header: Option<&str>) -> Result<(), WebhookError> {
    let header = token_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WebhookError::invalid_signature("Missing required 'X-Gitlab-Token' header")
        })?;

    if !constant_time_eq(secret.as_bytes(), header.as_bytes()) {
        return Err(WebhookError::invalid_signature(
            "GitLab webhook token mismatch",
        ));
    }

    Ok(())
}
