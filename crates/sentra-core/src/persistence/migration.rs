use super::{
    PersistenceError, PersistenceErrorKind as Kind,
    transaction::{self, ManagedTransaction},
};
use rusqlite::{Connection, params};

pub(super) const VERSION: i64 = 2;
pub(super) const APPLICATION_ID: i64 = 0x5345_4e54;
pub(super) const SQL_V1: &str = include_str!("schema_v1.sql");
pub(super) const SQL_V2: &str = include_str!("schema_v2.sql");
const DESCRIPTION_V1: &str = "Initial Sentra persistence schema";
const DESCRIPTION_V2: &str = "Add tasks, manifests, and durable execution attempts";

/// FNV-1a-64 detects accidental drift only. This is NOT tamper authentication.
fn checksum_for(source: &str) -> String {
    let hash = canonical_sql(source)
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        });
    format!("fnv1a64:{hash:016x}")
}

fn canonical_sql(source: &str) -> String {
    // Git text checkouts may use CRLF on Windows. Pin the trusted embedded
    // migration representation without ignoring any other source drift.
    source.replace("\r\n", "\n")
}

fn objects(
    tx: &mut ManagedTransaction<'_>,
) -> Result<Vec<(String, String, String, String)>, PersistenceError> {
    tx.collect(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                canonical_sql(&row.get::<_, String>(3)?),
            ))
        },
    )
}

pub(super) fn initialize(
    connection: &Connection,
    applied_at: &str,
) -> Result<(), PersistenceError> {
    // A template is trusted embedded DDL, never SQL from a target or database record.
    let template = Connection::open_in_memory().map_err(PersistenceError::sql)?;
    let sql_v1 = canonical_sql(SQL_V1);
    let sql_v2 = canonical_sql(SQL_V2);
    template
        .execute_batch(&sql_v1)
        .map_err(PersistenceError::sql)?;
    template
        .execute_batch(&sql_v2)
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
            // Step 1: Apply V1
            tx.batch(&sql_v1)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,description,applied_at,checksum) VALUES(1,?1,?2,?3)",
                params![DESCRIPTION_V1, applied_at, checksum_for(SQL_V1)],
            )?;
            // Step 2: Apply V2
            tx.batch(&sql_v2)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,description,applied_at,checksum) VALUES(2,?1,?2,?3)",
                params![DESCRIPTION_V2, applied_at, checksum_for(SQL_V2)],
            )?;
            tx.batch(&format!(
                "PRAGMA user_version={VERSION}; PRAGMA application_id={APPLICATION_ID}"
            ))?;
        } else if version == 1 {
            if application != APPLICATION_ID {
                return Err(PersistenceError::new(Kind::SchemaMetadata));
            }
            // Verify existing V1 migration history
            let history_v1 = tx.collect(
                "SELECT version,description,applied_at,checksum FROM schema_migrations ORDER BY version",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )?;
            if history_v1.len() != 1
                || history_v1[0].0 != 1
                || history_v1[0].1 != DESCRIPTION_V1
                || history_v1[0].3 != checksum_for(SQL_V1)
                || super::model::parse_time(&history_v1[0].2).is_err()
            {
                return Err(PersistenceError::new(Kind::SchemaMetadata));
            }
            // Transactionally migrate V1 to V2
            tx.batch(&sql_v2)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,description,applied_at,checksum) VALUES(2,?1,?2,?3)",
                params![DESCRIPTION_V2, applied_at, checksum_for(SQL_V2)],
            )?;
            tx.batch(&format!("PRAGMA user_version={VERSION}"))?;
        } else if application != APPLICATION_ID {
            return Err(PersistenceError::new(Kind::SchemaMetadata));
        }

        // Verify final V2 schema state
        let history = tx.collect(
            "SELECT version,description,applied_at,checksum FROM schema_migrations ORDER BY version",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?;
        if history.len() != 2
            || history[0].0 != 1
            || history[0].1 != DESCRIPTION_V1
            || history[0].3 != checksum_for(SQL_V1)
            || super::model::parse_time(&history[0].2).is_err()
            || history[1].0 != 2
            || history[1].1 != DESCRIPTION_V2
            || history[1].3 != checksum_for(SQL_V2)
            || super::model::parse_time(&history[1].2).is_err()
            || objects(tx)? != expected
        {
            return Err(PersistenceError::new(Kind::SchemaMetadata));
        }

        let violations = tx.collect("PRAGMA foreign_key_check", [], |_| Ok(()))?;
        if !violations.is_empty() {
            return Err(PersistenceError::new(Kind::ForeignKeyViolation));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_line_endings_are_stable_and_failed_ddl_leaves_no_partial_schema() {
        let lf_v1 = canonical_sql(SQL_V1);
        let crlf_v1 = lf_v1.replace('\n', "\r\n");
        assert_eq!(checksum_for(&lf_v1), checksum_for(&crlf_v1));

        let lf_v2 = canonical_sql(SQL_V2);
        let crlf_v2 = lf_v2.replace('\n', "\r\n");
        assert_eq!(checksum_for(&lf_v2), checksum_for(&crlf_v2));

        let lf_template = Connection::open_in_memory().unwrap();
        let crlf_template = Connection::open_in_memory().unwrap();
        lf_template.execute_batch(&lf_v1).unwrap();
        lf_template.execute_batch(&lf_v2).unwrap();
        crlf_template.execute_batch(&crlf_v1).unwrap();
        crlf_template.execute_batch(&crlf_v2).unwrap();
        assert_eq!(
            transaction::attempt(&lf_template, &mut objects).unwrap(),
            transaction::attempt(&crlf_template, &mut objects).unwrap()
        );
        assert_ne!(
            checksum_for(&lf_v1),
            checksum_for(&(lf_v1 + "\n-- real source drift"))
        );

        let db = Connection::open_in_memory().unwrap();
        let result = transaction::attempt(&db, &mut |tx| {
            tx.batch(&lf_v1)?;
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
