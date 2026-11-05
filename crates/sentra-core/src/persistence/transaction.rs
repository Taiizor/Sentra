use rusqlite::{Connection, Params, Row};

use super::{PersistenceError, PersistenceErrorKind as Kind};

/// Private managed unit: every SQL error explicitly aborts the whole transaction.
/// Even an internal caller catching a statement error cannot commit earlier writes.
pub(super) struct ManagedTransaction<'a> {
    connection: &'a Connection,
    failure: Option<PersistenceError>,
    active: bool,
}

impl<'a> ManagedTransaction<'a> {
    pub fn begin(connection: &'a Connection) -> Result<Self, PersistenceError> {
        Self::begin_sql(connection, "BEGIN IMMEDIATE")
    }
    fn begin_sql(connection: &'a Connection, sql: &str) -> Result<Self, PersistenceError> {
        connection
            .execute_batch(sql)
            .map_err(PersistenceError::sql)?;
        Ok(Self {
            connection,
            failure: None,
            active: true,
        })
    }
    fn check(&self) -> Result<(), PersistenceError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if !self.active {
            return Err(PersistenceError::new(Kind::TransactionAborted));
        }
        Ok(())
    }
    fn handle<T>(&mut self, result: rusqlite::Result<T>) -> Result<T, PersistenceError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => Err(self.abort(PersistenceError::sql(error))),
        }
    }
    pub fn execute(&mut self, sql: &str, params: impl Params) -> Result<usize, PersistenceError> {
        self.check()?;
        self.handle(self.connection.execute(sql, params))
    }
    pub fn batch(&mut self, sql: &str) -> Result<(), PersistenceError> {
        self.check()?;
        self.handle(self.connection.execute_batch(sql))
    }
    pub fn query<T>(
        &mut self,
        sql: &str,
        params: impl Params,
        map: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<T, PersistenceError> {
        self.check()?;
        self.handle(self.connection.query_row(sql, params, map))
    }
    pub fn optional<T>(
        &mut self,
        sql: &str,
        params: impl Params,
        map: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>, PersistenceError> {
        use rusqlite::OptionalExtension;
        self.check()?;
        self.handle(self.connection.query_row(sql, params, map).optional())
    }
    pub fn collect<T>(
        &mut self,
        sql: &str,
        params: impl Params,
        map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>, PersistenceError> {
        self.check()?;
        let result = (|| {
            let mut statement = self.connection.prepare(sql)?;
            statement.query_map(params, map)?.collect()
        })();
        self.handle(result)
    }
    pub fn abort(&mut self, cause: PersistenceError) -> PersistenceError {
        self.abort_using(cause, |db| db.execute_batch("ROLLBACK"))
    }
    fn abort_using(
        &mut self,
        mut cause: PersistenceError,
        rollback: impl FnOnce(&Connection) -> rusqlite::Result<()>,
    ) -> PersistenceError {
        if let Some(existing) = &self.failure {
            return existing.clone();
        }
        if self.active {
            // SQLite can auto-abort after IOERR/FULL. Autocommit is positive evidence
            // that no transaction remains, not an assumption based on dropping a guard.
            if !self.connection.is_autocommit()
                && let Err(rollback) = rollback(self.connection)
            {
                cause.kind = Kind::RollbackFailed;
                cause.rollback_code = rollback.sqlite_error().map(|error| error.extended_code);
            }
            self.active = false;
        }
        self.failure = Some(cause.clone());
        cause
    }
    pub fn commit(mut self) -> Result<(), PersistenceError> {
        self.check()?;
        match self.connection.execute_batch("COMMIT") {
            Ok(()) => {
                self.active = false;
                Ok(())
            }
            Err(error) => Err(self.abort(PersistenceError::sql(error))),
        }
    }
}

impl Drop for ManagedTransaction<'_> {
    fn drop(&mut self) {
        // Only panic/early-return cleanup reaches this path. Ordinary error paths
        // call abort explicitly and report rollback failure instead of relying on Drop.
        if self.active {
            let _ = self.abort(PersistenceError::new(Kind::TransactionAborted));
        }
    }
}

pub(super) fn attempt<T>(
    connection: &Connection,
    operation: &mut impl FnMut(&mut ManagedTransaction<'_>) -> Result<T, PersistenceError>,
) -> Result<T, PersistenceError> {
    let mut transaction = ManagedTransaction::begin(connection)?;
    match operation(&mut transaction) {
        Ok(value) => {
            transaction.commit()?;
            Ok(value)
        }
        Err(error) => Err(transaction.abort(error)),
    }
}

/// Non-security jitter: bounded dephasing, never a nonce or a cryptographic source.
pub(super) fn delay_ms(attempt: u8, ticket: u64) -> u64 {
    let base = (10u64 << attempt.min(4)).min(250);
    (base
        + ticket
            .wrapping_mul(37)
            .wrapping_add(u64::from(attempt) * 17)
            % 17)
        .min(250)
}

pub(super) fn retry<T>(
    ticket: u64,
    mut operation: impl FnMut(u8) -> Result<T, PersistenceError>,
    mut sleep: impl FnMut(u64),
) -> Result<T, PersistenceError> {
    for attempt in 0..5 {
        match operation(attempt) {
            Err(mut error) if error.is_contention() && error.kind != Kind::RollbackFailed => {
                if attempt == 4 {
                    error.kind = Kind::RetryExhausted;
                    error.attempts = Some(5);
                    return Err(error);
                }
                sleep(delay_ms(attempt, ticket));
            }
            result => return result,
        }
    }
    unreachable!("fifth attempt returns")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caught_statement_failure_still_cannot_commit_partial_work() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE test(value INTEGER PRIMARY KEY)")
            .unwrap();
        let result = attempt(&db, &mut |tx| {
            tx.execute("INSERT INTO test VALUES(1)", [])?;
            assert!(tx.execute("INSERT INTO test VALUES(1)", []).is_err());
            Ok(())
        });
        assert!(result.is_err());
        assert!(db.is_autocommit());
        assert_eq!(
            db.query_row("SELECT count(*) FROM test", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn rollback_failure_is_distinct_from_the_statement_failure() {
        let db = Connection::open_in_memory().unwrap();
        let mut tx = ManagedTransaction::begin(&db).unwrap();
        let cause = PersistenceError {
            sqlite_code: Some(19),
            ..PersistenceError::new(Kind::Database)
        };
        // Explicit fault injection, not an executed storage IOERR experiment.
        let error = tx.abort_using(cause, |_| {
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(23),
                None,
            ))
        });
        assert_eq!(error.sqlite_code, Some(19));
        assert_eq!(error.kind, Kind::RollbackFailed);
        assert_eq!(error.rollback_code, Some(23));
        db.execute_batch("ROLLBACK").unwrap();
        assert!(db.is_autocommit());
    }

    #[test]
    fn backoff_stays_in_approved_range_and_varies_by_ticket() {
        for attempt in 0..5 {
            for ticket in 0..100 {
                assert!((10..=250).contains(&delay_ms(attempt, ticket)));
            }
        }
        assert_ne!(delay_ms(0, 1), delay_ms(0, 2));
    }

    #[test]
    fn real_busy_snapshot_retries_the_whole_transaction_with_fresh_reads() {
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/persistence-snapshot-unit");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("snapshot-{}.db", std::process::id()));
        assert!(!path.exists(), "owned fixture must be fresh");
        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE counter(value INTEGER); INSERT INTO counter VALUES(0)").unwrap();
        let writer = Connection::open(&path).unwrap();
        let mut observed = Vec::new();
        let mut original_code = None;
        let mut delays = Vec::new();
        let final_value = retry(
            1,
            |number| {
                // Production uses BEGIN IMMEDIATE, which avoids this promotion race.
                // DEFERRED here deliberately reproduces the real 517 failure and
                // exercises the SAME managed abort and complete-operation retry code.
                let mut tx = ManagedTransaction::begin_sql(
                    &reader,
                    if number == 0 {
                        "BEGIN"
                    } else {
                        "BEGIN IMMEDIATE"
                    },
                )?;
                let before: i64 = tx.query("SELECT value FROM counter", [], |r| r.get(0))?;
                observed.push(before);
                if number == 0 {
                    writer.execute("UPDATE counter SET value=1", []).unwrap();
                }
                if let Err(error) = tx.execute("UPDATE counter SET value=?1", [before + 1]) {
                    original_code = error.sqlite_code;
                    assert!(reader.is_autocommit());
                    return Err(error);
                }
                tx.commit()?;
                Ok(before + 1)
            },
            |delay| delays.push(delay),
        )
        .unwrap();
        assert_eq!(original_code, Some(517));
        assert_eq!(observed, [0, 1]);
        assert_eq!(delays.len(), 1);
        assert_eq!(final_value, 2);
        assert_eq!(
            reader
                .query_row("SELECT value FROM counter", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        drop(writer);
        drop(reader);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn actual_begin_contention_stops_after_five_whole_operation_attempts() {
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/persistence-busy-unit");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("busy-{}.db", std::process::id()));
        assert!(!path.exists());
        let blocker = Connection::open(&path).unwrap();
        blocker
            .execute_batch("CREATE TABLE counter(value);BEGIN IMMEDIATE")
            .unwrap();
        let contender = Connection::open(&path).unwrap();
        contender.busy_timeout(std::time::Duration::ZERO).unwrap();
        let mut attempts = 0;
        let mut business_entries = 0;
        let mut sleeps = 0;
        let result = retry(
            2,
            |_| {
                attempts += 1;
                attempt(&contender, &mut |_tx| {
                    business_entries += 1;
                    Ok(())
                })
            },
            |_| sleeps += 1,
        )
        .unwrap_err();
        assert_eq!(attempts, 5);
        assert_eq!(sleeps, 4);
        assert_eq!(business_entries, 0);
        assert_eq!(result.kind, Kind::RetryExhausted);
        assert_eq!(result.sqlite_code, Some(5));
        assert_eq!(result.attempts, Some(5));
        blocker.execute_batch("ROLLBACK").unwrap();
        drop(contender);
        drop(blocker);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn non_contention_and_failed_rollback_are_never_retried() {
        for (kind, code) in [(Kind::Database, 19), (Kind::RollbackFailed, 5)] {
            let mut attempts = 0;
            let result: Result<(), _> = retry(
                3,
                |_| {
                    attempts += 1;
                    Err(PersistenceError {
                        sqlite_code: Some(code),
                        ..PersistenceError::new(kind)
                    })
                },
                |_| panic!("must not retry"),
            );
            assert_eq!(result.unwrap_err().kind, kind);
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn sqlite_page_limit_full_aborts_without_partial_rows() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "PRAGMA page_size=4096;CREATE TABLE payload(value BLOB);PRAGMA max_page_count=8",
        )
        .unwrap();
        let error = attempt(&db, &mut |tx| {
            tx.execute("INSERT INTO payload VALUES(zeroblob(100))", [])?;
            tx.execute("INSERT INTO payload VALUES(zeroblob(100000))", [])?;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.sqlite_code, Some(13));
        assert!(db.is_autocommit());
        assert_eq!(
            db.query_row("SELECT count(*) FROM payload", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        // SQLITE_FULL from max_page_count is not physical disk exhaustion.
    }
}
