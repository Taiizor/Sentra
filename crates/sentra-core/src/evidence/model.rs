//! Domain models, envelopes, and metadata for evidence artifacts.

use std::fmt;

use crate::{
    EvidenceId, SecurityClassification, SessionId, TaskId, TimestampUtc,
    evidence::error::{EvidenceVerificationError, EvidenceVerificationErrorKind},
};

/// Maximum permissible evidence payload size: 50 MiB (52,428,800 bytes).
pub const MAX_EVIDENCE_SIZE_BYTES: u64 = 52_428_800;
/// Maximum length of media type strings.
pub const MAX_MEDIA_TYPE_LENGTH: usize = 128;
/// Maximum length of producer role identifiers.
pub const MAX_PRODUCER_ROLE_LENGTH: usize = 64;

/// Metadata describing an evidence artifact produced by an analysis or execution task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceMetadata {
    /// Unique identifier for this evidence item.
    pub evidence_id: EvidenceId,
    /// Research session correlation.
    pub session_id: SessionId,
    /// Producing execution task.
    pub task_id: TaskId,
    /// Role identifier of the producer (e.g. "security-scanner", "test-runner").
    pub producer_role: String,
    /// RFC 2046 media type (e.g. "application/json", "text/plain").
    pub media_type: String,
    /// Declared byte length of the raw payload.
    pub payload_length_bytes: u64,
    /// Declared SHA-256 digest in lowercase hexadecimal format (if available).
    pub declared_sha256: Option<String>,
    /// Classification level governing the artifact's data.
    pub classification: SecurityClassification,
    /// Emission timestamp.
    pub created_at: TimestampUtc,
}

impl EvidenceMetadata {
    /// Validates metadata integrity and bounds.
    pub fn validate(&self) -> Result<(), EvidenceVerificationError> {
        let role = self.producer_role.trim();
        if role.is_empty()
            || role.len() > MAX_PRODUCER_ROLE_LENGTH
            || role.chars().any(char::is_control)
        {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::InvalidMetadata,
                "producer_role must be non-empty, <= 64 chars, and contain no control characters",
            ));
        }

        let media = self.media_type.trim();
        if media.is_empty()
            || media.len() > MAX_MEDIA_TYPE_LENGTH
            || !media.contains('/')
            || media.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::InvalidMediaType,
                format!("invalid media_type '{media}'"),
            ));
        }

        if let Some(ref digest) = self.declared_sha256
            && (digest.len() != 64
                || !digest
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::MalformedDigest,
                "declared_sha256 must be exactly 64 lowercase hexadecimal characters",
            ));
        }

        Ok(())
    }
}

/// Raw transit envelope containing evidence metadata and its binary payload.
///
/// Implements custom `fmt::Debug` to guarantee that sensitive payload bytes are
/// never leaked into diagnostic logs or error traces.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceEnvelope {
    /// Structured metadata envelope.
    pub metadata: EvidenceMetadata,
    /// Raw unparsed payload bytes.
    pub payload: Vec<u8>,
}

impl EvidenceEnvelope {
    /// Creates a new evidence envelope.
    pub fn new(metadata: EvidenceMetadata, payload: Vec<u8>) -> Self {
        Self { metadata, payload }
    }

    /// Accessor for payload length in bytes.
    pub fn byte_len(&self) -> usize {
        self.payload.len()
    }
}

impl fmt::Debug for EvidenceEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceEnvelope")
            .field("metadata", &self.metadata)
            .field("payload_len_bytes", &self.payload.len())
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Verification status classification for an admitted artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityVerificationStatus {
    /// Transit integrity proven via cryptographic hash comparison (SHA-256).
    CryptographicallyVerified,
    /// Structural bounds, length matching, and media-type validated; crypto hash unavailable.
    StructuralBoundsVerified,
}

/// An admitted, verified evidence artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceArtifact {
    /// Admitted artifact metadata.
    pub metadata: EvidenceMetadata,
    /// Verification timestamp on host.
    pub verified_at: TimestampUtc,
    /// Concrete verification level achieved.
    pub integrity_status: IntegrityVerificationStatus,
}
