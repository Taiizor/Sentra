//! Typed evidence verification error models.

use std::fmt;

/// Categories of evidence verification failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceVerificationErrorKind {
    /// The evidence payload exceeds the allowable size ceiling (default 50 MiB).
    OversizedPayload,
    /// The actual payload byte count does not match the metadata-declared length.
    LengthMismatch,
    /// The computed cryptographic digest disagrees with the declared digest.
    DigestMismatch,
    /// The declared digest string is malformed (e.g. not 64 lowercase hexadecimal chars).
    MalformedDigest,
    /// The media type string is invalid, malformed, or not in the allowed set.
    InvalidMediaType,
    /// The metadata contains invalid or missing required attributes.
    InvalidMetadata,
    /// Cryptographic SHA-256 verification is unavailable in the current offline environment.
    CryptographicVerificationUnavailable,
    /// The payload is empty when a non-zero byte length was declared.
    MissingPayload,
}

/// Redacted typed evidence verification error.
///
/// Ensures raw evidence payloads or sensitive content are never leaked through
/// error diagnostics or formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceVerificationError {
    /// Specific failure category.
    pub kind: EvidenceVerificationErrorKind,
    /// Safe diagnostic summary (free of confidential artifact contents).
    pub message: String,
}

impl EvidenceVerificationError {
    /// Constructs a new verification error.
    pub fn new(kind: EvidenceVerificationErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Helper for unavailable cryptographic verification.
    pub fn crypto_unavailable() -> Self {
        Self::new(
            EvidenceVerificationErrorKind::CryptographicVerificationUnavailable,
            "SHA-256 cryptographic verification is unavailable offline; sha2 is not in local Cargo cache and manual/non-crypto substitution is prohibited (ADR-0006)",
        )
    }
}

impl fmt::Display for EvidenceVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "evidence verification error [{:?}]: {}",
            self.kind, self.message
        )
    }
}

impl fmt::Debug for EvidenceVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceVerificationError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for EvidenceVerificationError {}
