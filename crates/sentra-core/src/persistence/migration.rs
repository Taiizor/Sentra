use super::{
    PersistenceError, PersistenceErrorKind as Kind,
    transaction::{self, ManagedTransaction},
};
use rusqlite::{Connection, params};

pub(super) const VERSION: i64 = 1;
pub(super) const APPLICATION_ID: i64 = 0x5345_4e54;
pub(super) const SQL: &str = include_str!("schema_v1.sql");
const DESCRIPTION: &str = "Initial Sentra persistence schema";

/// FNV-1a-64 detects accidental drift only. This is NOT tamper authentication.
fn checksum() -> String {
    checksum_for(SQL)
}

fn canonical_sql(source: &str) -> String {
    // Git text checkouts may use CRLF on Windows. Pin the trusted embedded
    // migration representation without ignoring any other source drift.
    source.replace("\r\n", "\n")
}

fn checksum_for(source: &str) -> String {
    let hash = canonical_sql(source)
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        });
    format!("fnv1a64:{hash:016x}")
}

fn objects(
    tx: &mut ManagedTransaction<'_>,
) -> Result<Vec<(String, String, String, String)>, PersistenceError> {
    tx.collect("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, canonical_sql(&row.get::<_,String>(3)?))))
}

pub(super) fn initialize(
    connection: &Connection,
    applied_at: &str,
) -> Result<(), PersistenceError> {
    // A template is trusted embedded DDL, never SQL from a target or database record.
    let template = Connection::open_in_memory().map_err(PersistenceError::sql)?;
    let sql = canonical_sql(SQL);
    template
        .execute_batch(&sql)
        .map_err(PersistenceError::sql)?;
    let expected = transaction::attempt(&template, &mut objects)?;
    transaction::attempt(connection, &mut |tx| {
        let version: i64 = tx.query("PRAGMA user_version", [], |row| row.get(0))?;
        let application: i64 = tx.query("PRAGMA application_id", [], |row| row.get(0))?;
        if version > VERSION {
            return Err(PersistenceError::new(Kind::NewerSchema));
        }
        if version < 0 {
            return Err(PersistenceError::new(Kind::SchemaMetadata));
        }
        if version == 0 {
            if application != 0 || !objects(tx)?.is_empty() {
                return Err(PersistenceError::new(Kind::SchemaMetadata));
            }
            tx.batch(&sql)?;
            tx.execute("INSERT INTO schema_migrations(version,description,applied_at,checksum) VALUES(1,?1,?2,?3)", params![DESCRIPTION, applied_at, checksum()])?;
            tx.batch(&format!(
                "PRAGMA user_version={VERSION}; PRAGMA application_id={APPLICATION_ID}"
            ))?;
        } else if application != APPLICATION_ID {
            return Err(PersistenceError::new(Kind::SchemaMetadata));
        }
        let history = tx.collect("SELECT version,description,applied_at,checksum FROM schema_migrations ORDER BY version", [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?;
        if history.len() != 1
            || history[0].0 != VERSION
            || history[0].1 != DESCRIPTION
            || history[0].3 != checksum()
            || super::model::parse_time(&history[0].2).is_err()
            || objects(tx)? != expected
        {
            return Err(PersistenceError::new(Kind::SchemaMetadata));
        }
        let violations = tx.collect("PRAGMA foreign_key_check", [], |_| Ok(()))?;
        if !violations.is_empty() {
            return Err(PersistenceError::new(Kind::Integrity));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migration_line_endings_are_stable_and_failed_ddl_leaves_no_partial_schema() {
        let lf = canonical_sql(SQL);
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(checksum_for(&lf), checksum_for(&crlf));
        let lf_template = Connection::open_in_memory().unwrap();
        let crlf_template = Connection::open_in_memory().unwrap();
        lf_template.execute_batch(&lf).unwrap();
        crlf_template.execute_batch(&crlf).unwrap();
        assert_eq!(
            transaction::attempt(&lf_template, &mut objects).unwrap(),
            transaction::attempt(&crlf_template, &mut objects).unwrap()
        );
        assert_ne!(
            checksum_for(&lf),
            checksum_for(&(lf + "\n-- real source drift"))
        );
        let db = Connection::open_in_memory().unwrap();
        let result = transaction::attempt(&db, &mut |tx| {
            tx.batch(SQL)?;
            tx.batch("THIS IS NOT SQL")
        });
        assert!(result.is_err());
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM sqlite_master", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
