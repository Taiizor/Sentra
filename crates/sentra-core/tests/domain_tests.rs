use std::str::FromStr;

use sentra_core::domain::{
    ApprovalId, DomainError, EventId, Identifier, SecurityClassification, SessionId, TaskId,
    TimestampUtc,
};

#[test]
fn test_identifier_bytes_roundtrip() {
    let bytes: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let id = Identifier::from_bytes(bytes);
    assert_eq!(id.as_bytes(), &bytes);

    let formatted = id.to_hyphenated_string();
    assert_eq!(formatted, "01020304-0506-0708-090a-0b0c0d0e0f10");

    let parsed = Identifier::parse_hyphenated(&formatted).expect("parsing valid UUID string");
    assert_eq!(parsed, id);
    assert_eq!(parsed.as_bytes(), &bytes);
}

#[test]
fn test_identifier_invalid_strings() {
    // Too short
    assert!(matches!(
        Identifier::parse_hyphenated("01020304-0506-0708-090a-0b0c0d0e0f1"),
        Err(DomainError::InvalidIdentifier(_))
    ));
    // Too long
    assert!(matches!(
        Identifier::parse_hyphenated("01020304-0506-0708-090a-0b0c0d0e0f100"),
        Err(DomainError::InvalidIdentifier(_))
    ));
    // Missing hyphen
    assert!(matches!(
        Identifier::parse_hyphenated("0102030400506-0708-090a-0b0c0d0e0f10"),
        Err(DomainError::InvalidIdentifier(_))
    ));
    // Non-hex characters
    assert!(matches!(
        Identifier::parse_hyphenated("01020304-0506-0708-090a-0b0c0d0e0fZZ"),
        Err(DomainError::InvalidIdentifier(_))
    ));
}

#[test]
fn test_deterministic_and_sequential_identifiers() {
    let det1 = Identifier::new_deterministic(100, 1);
    let det2 = Identifier::new_deterministic(100, 1);
    let det3 = Identifier::new_deterministic(100, 2);
    assert_eq!(det1, det2);
    assert_ne!(det1, det3);

    let seq1 = Identifier::new_sequential(42);
    let seq2 = Identifier::new_sequential(42);
    assert_ne!(seq1, seq2);
}

#[test]
fn test_typed_identifiers() {
    let session_id = SessionId::new();
    let s_str = session_id.to_string();
    assert_eq!(s_str.len(), 36);
    let parsed_session = SessionId::from_str(&s_str).expect("parse SessionId");
    assert_eq!(session_id, parsed_session);

    let task_id = TaskId::new();
    let t_str = task_id.to_string();
    let parsed_task = TaskId::from_str(&t_str).expect("parse TaskId");
    assert_eq!(task_id, parsed_task);

    let app_id = ApprovalId::new();
    let parsed_app = ApprovalId::from_str(&app_id.to_string()).expect("parse ApprovalId");
    assert_eq!(app_id, parsed_app);

    let evt_id = EventId::new();
    let parsed_evt = EventId::from_str(&evt_id.to_string()).expect("parse EventId");
    assert_eq!(evt_id, parsed_evt);
}

#[test]
fn test_timestamp_utc_roundtrip_and_rfc3339() {
    let ts = TimestampUtc::from_epoch_millis(1_700_000_000_123);
    assert_eq!(ts.as_epoch_millis(), 1_700_000_000_123);
    assert_eq!(ts.as_epoch_secs(), 1_700_000_000);

    let rfc = ts.to_rfc3339();
    assert!(rfc.ends_with(".123Z"));

    let parsed = TimestampUtc::from_rfc3339(&rfc).expect("parse RFC 3339");
    assert_eq!(parsed, ts);

    // Test zero epoch
    let zero = TimestampUtc::from_epoch_millis(0);
    assert_eq!(zero.to_rfc3339(), "1970-01-01T00:00:00.000Z");
    let parsed_zero = TimestampUtc::from_rfc3339("1970-01-01T00:00:00.000Z").unwrap();
    assert_eq!(parsed_zero, zero);
}

#[test]
fn test_timestamp_expiry_and_arithmetic() {
    let t1 = TimestampUtc::from_epoch_secs(100);
    let t2 = t1.add_seconds(30);
    assert_eq!(t2.as_epoch_secs(), 130);
    assert_eq!(t2.as_epoch_millis(), 130_000);

    // t1 is expired at t1
    assert!(t1.is_expired_at(t1));
    // t1 is expired at t2 (t2 is later)
    assert!(t1.is_expired_at(t2));
    // t2 is NOT expired at t1 (t1 is earlier)
    assert!(!t2.is_expired_at(t1));
}

#[test]
fn test_timestamp_invalid_rfc3339() {
    assert!(matches!(
        TimestampUtc::from_rfc3339("not-a-timestamp"),
        Err(DomainError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        TimestampUtc::from_rfc3339("2026-13-01T00:00:00Z"), // Month 13
        Err(DomainError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        TimestampUtc::from_rfc3339("2026-02-32T00:00:00Z"), // Day 32
        Err(DomainError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        TimestampUtc::from_rfc3339("2026-02-01T25:00:00Z"), // Hour 25
        Err(DomainError::InvalidTimestamp(_))
    ));
}

#[test]
fn test_security_classification_ranking_and_pairwise_flow() {
    let levels = [
        SecurityClassification::Public,
        SecurityClassification::Internal,
        SecurityClassification::Confidential,
        SecurityClassification::Restricted,
    ];

    // Explicit rank verification
    assert_eq!(SecurityClassification::Public.rank(), 10);
    assert_eq!(SecurityClassification::Internal.rank(), 20);
    assert_eq!(SecurityClassification::Confidential.rank(), 30);
    assert_eq!(SecurityClassification::Restricted.rank(), 40);

    // Ord verification
    assert!(SecurityClassification::Public < SecurityClassification::Internal);
    assert!(SecurityClassification::Internal < SecurityClassification::Confidential);
    assert!(SecurityClassification::Confidential < SecurityClassification::Restricted);

    // Pairwise flow matrix: source can flow to target iff source.rank <= target.rank
    for src in &levels {
        for dst in &levels {
            let expected = src.rank() <= dst.rank();
            assert_eq!(
                src.can_flow_to(dst),
                expected,
                "Flow from {:?} to {:?} failed expected={}",
                src,
                dst,
                expected
            );
        }
    }
}

#[test]
fn test_security_classification_egress_and_parsing() {
    assert!(!SecurityClassification::Public.requires_approval_for_external_egress());
    assert!(SecurityClassification::Internal.requires_approval_for_external_egress());
    assert!(SecurityClassification::Confidential.requires_approval_for_external_egress());
    assert!(SecurityClassification::Restricted.requires_approval_for_external_egress());

    assert_eq!(
        SecurityClassification::from_str("PUBLIC").unwrap(),
        SecurityClassification::Public
    );
    assert_eq!(
        SecurityClassification::from_str("internal").unwrap(),
        SecurityClassification::Internal
    );
    assert_eq!(
        SecurityClassification::from_str("Confidential").unwrap(),
        SecurityClassification::Confidential
    );
    assert_eq!(
        SecurityClassification::from_str("RESTRICTED").unwrap(),
        SecurityClassification::Restricted
    );

    assert!(matches!(
        SecurityClassification::from_str("TOP_SECRET"),
        Err(DomainError::PolicyViolation(_))
    ));
}
