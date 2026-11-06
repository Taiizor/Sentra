use std::fmt;

/// Payload-free failure category. No SQLite diagnostic text is logged implicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistenceErrorKind {
    /// Invalid/locality-ambiguous database path or missing/inaccessible parent.
    InvalidPath,
    /// Open/read/write/native failure, with an optional SQLite extended code.
    Database,
    /// Mandatory configuration was not effective.
    PragmaMismatch,
    /// Physical or logical integrity validation failed.
    Integrity,
    /// The schema is newer than this implementation supports.
    NewerSchema,
    /// Migration history, application ID or schema objects disagree.
    SchemaMetadata,
    /// Invalid/overflowing domain value or malformed stored record.
    InvalidValue,
    /// A database transaction has already failed and cannot commit.
    TransactionAborted,
    /// Explicit rollback itself failed; connection use must stop.
    RollbackFailed,
    /// Five complete operation attempts were exhausted.
    RetryExhausted,
    /// No managed connection remains usable.
    Closed,
    /// Integrity/rollback failure quarantined operations in place.
    Halted,
    /// Manager synchronization is unavailable.
    Poisoned,
    /// A required WAL checkpoint was blocked by another connection.
    CheckpointBusy,
    /// Close did not complete.
    CloseFailed,
    /// Unknown/mismatched/unissued private approval receipt.
    InvalidApproval,
    /// Trusted current context does not match the intended operation.
    ContextMismatch,
    /// A live execution admission prevents a concurrent lifecycle/context update.
    ContextBusy,
    /// A grant has already been consumed.
    ApprovalReused,
    /// The request has expired or is not yet valid.
    ApprovalExpired,
    /// Existing Core policy rejects this operation.
    PolicyDenied,
    /// A record is absent or an expected state changed.
    Conflict,
    /// A reservation exceeds the registered budget.
    BudgetExceeded,
    /// Relational foreign-key constraint violation detected by runtime check.
    ForeignKeyViolation,
}

/// Redacted typed persistence failure; original SQLite numbers remain inspectable.
#[derive(Clone, PartialEq, Eq)]
pub struct PersistenceError {
    /// Primary outcome category.
    pub kind: PersistenceErrorKind,
    /// Original SQLite extended result code, when applicable.
    pub sqlite_code: Option<i32>,
    /// Separate rollback result code if rollback failed.
    pub rollback_code: Option<i32>,
    /// Number of complete attempts made, if bounded retry was exhausted.
    pub attempts: Option<u8>,
}

impl PersistenceError {
    /// Constructs a persistence error from a categorical kind.
    pub fn from_kind(kind: PersistenceErrorKind) -> Self {
        Self::new(kind)
    }

    pub(super) fn new(kind: PersistenceErrorKind) -> Self {
        Self {
            kind,
            sqlite_code: None,
            rollback_code: None,
            attempts: None,
        }
    }
    pub(super) fn sql(error: rusqlite::Error) -> Self {
        let code = error.sqlite_error().map(|error| error.extended_code);
        let kind = if code.is_some_and(|code| matches!(code & 255, 11 | 26)) {
            PersistenceErrorKind::Integrity
        } else {
            PersistenceErrorKind::Database
        };
        Self {
            sqlite_code: code,
            ..Self::new(kind)
        }
    }
    pub(super) fn is_contention(&self) -> bool {
        self.sqlite_code.is_some_and(|code| code & 255 == 5)
    }
    pub(super) fn must_halt(&self) -> bool {
        matches!(
            self.kind,
            PersistenceErrorKind::Integrity
                | PersistenceErrorKind::RollbackFailed
                | PersistenceErrorKind::ForeignKeyViolation
        )
    }
}
impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "persistence {:?} (sqlite={:?}, rollback={:?}, attempts={:?})",
            self.kind, self.sqlite_code, self.rollback_code, self.attempts
        )
    }
}
impl fmt::Debug for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for PersistenceError {}
