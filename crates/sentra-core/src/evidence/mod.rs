//! Host-side evidence verification boundary and artifact admission filters.
//!
//! Validates artifact envelopes from worker processes before admitting them into the
//! repository. Enforces size ceilings, length matching, media-type policies, and
//! cryptographic transit integrity (failing closed when offline cryptographic tools are unavailable).
//!
//! In compliance with ADR-0006, transit integrity verification is strictly separated
//! from semantic finding correctness.

mod error;
mod model;
mod verifier;

pub use error::{EvidenceVerificationError, EvidenceVerificationErrorKind};
pub use model::{
    EvidenceArtifact, EvidenceEnvelope, EvidenceMetadata, IntegrityVerificationStatus,
    MAX_EVIDENCE_SIZE_BYTES, MAX_MEDIA_TYPE_LENGTH, MAX_PRODUCER_ROLE_LENGTH,
};
pub use verifier::EvidenceVerifier;
