//! Host-side evidence verification boundary and admission filters.

use crate::{
    TimestampUtc,
    evidence::{
        error::{EvidenceVerificationError, EvidenceVerificationErrorKind},
        model::{
            EvidenceArtifact, EvidenceEnvelope, IntegrityVerificationStatus,
            MAX_EVIDENCE_SIZE_BYTES,
        },
    },
};

/// Host-side evidence verifier.
///
/// Implements the verification filters defined in `CORE_ENGINE_DESIGN.md` Section 10:
/// - Maximum payload ceiling enforcement (50 MiB).
/// - Exact length byte-count verification (truncation/padding detection).
/// - Media-type syntax and policy admission.
/// - Cryptographic transit integrity verification (explicitly fail-closed when crypto unavailable).
///
/// # Transit Integrity vs. Semantic Correctness (ADR-0006)
/// A successful integrity verification proves **only** that the artifact was transmitted
/// without in-flight truncation, corruption, or network-level alteration.
///
/// It **does not prove** that:
/// - The scanner/tool output is truthful or accurate.
/// - The target code did not subvert the tool inside the worker before emission.
/// - The finding is a true positive.
///
/// Semantic correctness requires independent oracle execution or human authorization.
pub struct EvidenceVerifier {
    max_payload_size: u64,
    allowed_media_types: Option<Vec<String>>,
}

impl Default for EvidenceVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceVerifier {
    /// Creates a new `EvidenceVerifier` with default 50 MiB bounds and unrestricted media types.
    pub fn new() -> Self {
        Self {
            max_payload_size: MAX_EVIDENCE_SIZE_BYTES,
            allowed_media_types: None,
        }
    }

    /// Configures a custom maximum payload size ceiling.
    pub fn with_max_size(mut self, max_bytes: u64) -> Self {
        self.max_payload_size = max_bytes;
        self
    }

    /// Restricts allowed media types to an explicit whitelist.
    pub fn with_allowed_media_types(mut self, media_types: Vec<String>) -> Self {
        self.allowed_media_types = Some(media_types);
        self
    }

    /// Reports whether cryptographic SHA-256 verification is available offline.
    ///
    /// Returns `false` because the `sha2` crate is not cached in the local offline Cargo registry,
    /// and implementing SHA-256 manually or substituting non-cryptographic hashes is prohibited.
    pub fn is_crypto_available(&self) -> bool {
        false
    }

    /// Verifies structural bounds, metadata validity, length matching, and media types.
    pub fn verify_structural_bounds(
        &self,
        envelope: &EvidenceEnvelope,
    ) -> Result<(), EvidenceVerificationError> {
        // Step 1: Validate metadata fields and format.
        envelope.metadata.validate()?;

        // Step 2: Enforce maximum payload size ceiling.
        let actual_len = envelope.payload.len() as u64;
        if actual_len > self.max_payload_size {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::OversizedPayload,
                format!(
                    "evidence payload size ({} bytes) exceeds ceiling ({} bytes)",
                    actual_len, self.max_payload_size
                ),
            ));
        }

        // Step 3: Enforce declared vs actual byte length equality.
        if actual_len != envelope.metadata.payload_length_bytes {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::LengthMismatch,
                format!(
                    "payload byte length ({actual_len}) disagrees with metadata declared length ({})",
                    envelope.metadata.payload_length_bytes
                ),
            ));
        }

        // Step 4: Missing payload check.
        if envelope.metadata.payload_length_bytes > 0 && envelope.payload.is_empty() {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::MissingPayload,
                "metadata declared positive payload length but raw payload is empty",
            ));
        }

        // Step 5: Whitelist media type enforcement (if configured).
        if let Some(ref allowed) = self.allowed_media_types
            && !allowed.iter().any(|m| m == &envelope.metadata.media_type)
        {
            return Err(EvidenceVerificationError::new(
                EvidenceVerificationErrorKind::InvalidMediaType,
                format!(
                    "media_type '{}' is not in the allowed policy whitelist",
                    envelope.metadata.media_type
                ),
            ));
        }

        Ok(())
    }

    /// Evaluates evidence envelope admission.
    ///
    /// If `declared_sha256` is specified, full cryptographic verification is mandatory;
    /// because `sha2` is unavailable offline, this fails closed with `CryptographicVerificationUnavailable`.
    /// If no digest was declared, the artifact is admitted under `StructuralBoundsVerified`.
    pub fn verify_envelope(
        &self,
        envelope: &EvidenceEnvelope,
    ) -> Result<EvidenceArtifact, EvidenceVerificationError> {
        self.verify_structural_bounds(envelope)?;

        if envelope.metadata.declared_sha256.is_some() {
            // Cryptographic verification was requested/declared, but is unavailable offline.
            return Err(EvidenceVerificationError::crypto_unavailable());
        }

        Ok(EvidenceArtifact {
            metadata: envelope.metadata.clone(),
            verified_at: TimestampUtc::now(),
            integrity_status: IntegrityVerificationStatus::StructuralBoundsVerified,
        })
    }

    /// Attempts transit integrity verification.
    ///
    /// In accordance with ADR-0006 and Phase 1 constraints, fails closed with
    /// `CryptographicVerificationUnavailable` because a verified SHA-256 crate is not available offline.
    pub fn verify_transit_integrity(
        &self,
        envelope: &EvidenceEnvelope,
    ) -> Result<EvidenceArtifact, EvidenceVerificationError> {
        self.verify_structural_bounds(envelope)?;
        Err(EvidenceVerificationError::crypto_unavailable())
    }
}
