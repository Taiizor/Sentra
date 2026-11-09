#![forbid(unsafe_code)]

use sentra::{AdvisoryDatabase, SessionId, TimestampUtc};

#[test]
fn test_facade_reexports_core_types() {
    let session_id = SessionId::from_sequence(42);
    assert_eq!(session_id.version(), 4);
    assert_eq!(session_id.variant(), 2);

    let now = TimestampUtc::now();
    let db = AdvisoryDatabase::new(vec![], now);
    assert_eq!(db.updated_at(), now);
}

#[test]
fn test_facade_cli_module_accessible() {
    assert!(!sentra::cli::HELP.is_empty());
}
