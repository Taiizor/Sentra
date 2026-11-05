//! Host-side evidence verification and admission boundary tests.

use sentra_core::{
    EvidenceArtifact, EvidenceEnvelope, EvidenceId, EvidenceMetadata, EvidenceVerificationError,
    EvidenceVerificationErrorKind, EvidenceVerifier, IntegrityVerificationStatus,
    MAX_EVIDENCE_SIZE_BYTES, SecurityClassification, SessionId, TaskId, TimestampUtc,
};

fn sample_metadata(payload_len: u64, declared_sha: Option<&str>) -> EvidenceMetadata {
    EvidenceMetadata {
        evidence_id: EvidenceId::for_test_sequence(1),
        session_id: SessionId::for_test_sequence(10),
        task_id: TaskId::for_test_sequence(20),
        producer_role: "security-scanner".to_string(),
        media_type: "application/json".to_string(),
        payload_length_bytes: payload_len,
        declared_sha256: declared_sha.map(|s| s.to_string()),
        classification: SecurityClassification::Confidential,
        created_at: TimestampUtc::now(),
    }
}

#[test]
fn valid_evidence_structural_verification_success() {
    let verifier = EvidenceVerifier::new();
    let payload = b"{\"finding\":\"sql-injection-01\",\"severity\":\"high\"}".to_vec();
    let meta = sample_metadata(payload.len() as u64, None);
    let envelope = EvidenceEnvelope::new(meta.clone(), payload);

    assert_eq!(envelope.byte_len(), 48);
    assert!(verifier.verify_structural_bounds(&envelope).is_ok());

    let artifact: EvidenceArtifact = verifier.verify_envelope(&envelope).unwrap();
    assert_eq!(artifact.metadata, meta);
    assert_eq!(
        artifact.integrity_status,
        IntegrityVerificationStatus::StructuralBoundsVerified
    );
}

#[test]
fn oversized_evidence_rejected_immediately() {
    assert_eq!(MAX_EVIDENCE_SIZE_BYTES, 52_428_800);
    let verifier = EvidenceVerifier::new().with_max_size(1024); // 1 KiB ceiling
    let payload = vec![0x41u8; 2048]; // 2 KiB payload
    let meta = sample_metadata(2048, None);
    let envelope = EvidenceEnvelope::new(meta, payload);

    let err = verifier.verify_structural_bounds(&envelope).unwrap_err();
    assert_eq!(err.kind, EvidenceVerificationErrorKind::OversizedPayload);
    assert!(err.message.contains("exceeds ceiling"));
}

#[test]
fn length_mismatch_detected_and_rejected() {
    let verifier = EvidenceVerifier::new();
    let payload = b"exact-thirty-bytes-of-data!!12".to_vec();
    assert_eq!(payload.len(), 30);

    // Metadata declares 35 bytes instead of 30
    let meta = sample_metadata(35, None);
    let envelope = EvidenceEnvelope::new(meta, payload);

    let err = verifier.verify_structural_bounds(&envelope).unwrap_err();
    assert_eq!(err.kind, EvidenceVerificationErrorKind::LengthMismatch);
    assert!(err.message.contains("disagrees with metadata"));
}

#[test]
fn missing_payload_when_positive_length_declared() {
    let verifier = EvidenceVerifier::new();
    let payload = Vec::new();
    let meta = sample_metadata(100, None);
    let envelope = EvidenceEnvelope::new(meta, payload);

    let err = verifier.verify_structural_bounds(&envelope).unwrap_err();
    // Rejects either as LengthMismatch or MissingPayload fail-closed
    assert!(matches!(
        err.kind,
        EvidenceVerificationErrorKind::LengthMismatch
            | EvidenceVerificationErrorKind::MissingPayload
    ));
}

#[test]
fn invalid_media_type_syntax_and_whitelist_enforcement() {
    let verifier = EvidenceVerifier::new();

    // 1. Missing slash
    let mut meta = sample_metadata(4, None);
    meta.media_type = "plain".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMediaType
    );
    let envelope = EvidenceEnvelope::new(meta.clone(), b"test".to_vec());
    assert_eq!(
        verifier
            .verify_structural_bounds(&envelope)
            .unwrap_err()
            .kind,
        EvidenceVerificationErrorKind::InvalidMediaType
    );

    // 2. Whitespace in media type
    meta.media_type = "text/ plain".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMediaType
    );

    // 3. Control character in media type
    meta.media_type = "text/plain\0".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMediaType
    );

    // 4. Whitelist enforcement
    let whitelist_verifier =
        EvidenceVerifier::new().with_allowed_media_types(vec!["application/json".to_string()]);
    let payload = b"test".to_vec();
    let mut xml_meta = sample_metadata(4, None);
    xml_meta.media_type = "application/xml".to_string();
    let envelope = EvidenceEnvelope::new(xml_meta, payload);

    let err = whitelist_verifier
        .verify_structural_bounds(&envelope)
        .unwrap_err();
    assert_eq!(err.kind, EvidenceVerificationErrorKind::InvalidMediaType);
    assert!(err.message.contains("not in the allowed policy whitelist"));
}

#[test]
fn invalid_metadata_producer_role_rejected() {
    let mut meta = sample_metadata(4, None);

    // Empty role
    meta.producer_role = "".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMetadata
    );

    // Role with control char
    meta.producer_role = "scanner\nrole".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMetadata
    );

    // Role exceeding 64 chars
    meta.producer_role = "a".repeat(65);
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMetadata
    );
}

#[test]
fn malformed_declared_sha256_format_rejected() {
    let mut meta = sample_metadata(4, None);

    // Uppercase hex chars (must be lowercase)
    meta.declared_sha256 = Some("A".repeat(64));
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::MalformedDigest
    );

    // Too short (63 chars)
    meta.declared_sha256 = Some("a".repeat(63));
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::MalformedDigest
    );

    // Too long (65 chars)
    meta.declared_sha256 = Some("a".repeat(65));
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::MalformedDigest
    );

    // Non-hex chars (e.g. 'z')
    meta.declared_sha256 = Some(format!("{}z", "a".repeat(63)));
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::MalformedDigest
    );

    // Valid 64 lowercase hex chars passes
    meta.declared_sha256 =
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());
    assert!(meta.validate().is_ok());
}

#[test]
fn cryptographic_verification_explicitly_unavailable_offline() {
    let verifier = EvidenceVerifier::new();

    // Verifier explicitly reports crypto is unavailable offline
    assert!(!verifier.is_crypto_available());

    let payload = b"finding-content".to_vec();
    let digest_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let meta = sample_metadata(payload.len() as u64, Some(digest_str));
    let envelope = EvidenceEnvelope::new(meta, payload);

    // Envelope with declared SHA-256 fails closed because crypto is unavailable
    let err = verifier.verify_envelope(&envelope).unwrap_err();
    assert_eq!(
        err.kind,
        EvidenceVerificationErrorKind::CryptographicVerificationUnavailable
    );
    assert!(err.message.contains("sha2 is not in local Cargo cache"));

    // Direct call to verify_transit_integrity also fails closed
    let err_transit = verifier.verify_transit_integrity(&envelope).unwrap_err();
    assert_eq!(
        err_transit.kind,
        EvidenceVerificationErrorKind::CryptographicVerificationUnavailable
    );
}

#[test]
fn sensitive_content_redacted_in_debug_formatting() {
    let sensitive_data = "CONFIDENTIAL_SOURCE_CODE_EXPLOIT_PROOF_OF_CONCEPT";
    let payload = sensitive_data.as_bytes().to_vec();
    let meta = sample_metadata(payload.len() as u64, None);
    let envelope = EvidenceEnvelope::new(meta, payload);

    // Debug formatting of envelope must NOT contain the sensitive payload string
    let debug_repr = format!("{envelope:?}");
    assert!(
        !debug_repr.contains(sensitive_data),
        "EvidenceEnvelope leaked sensitive payload data in Debug formatting!"
    );
    assert!(debug_repr.contains("[REDACTED]"));
    assert!(debug_repr.contains("payload_len_bytes"));

    // Error formatting must also be clean
    let err = EvidenceVerificationError::new(
        EvidenceVerificationErrorKind::LengthMismatch,
        "safe diagnostic message",
    );
    let err_debug = format!("{err:?}");
    assert!(!err_debug.contains(sensitive_data));
}
