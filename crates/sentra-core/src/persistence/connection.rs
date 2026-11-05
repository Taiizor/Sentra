use super::{
    PersistenceError, PersistenceErrorKind as Kind, migration,
    transaction::{self, ManagedTransaction},
};
use crate::Clock;
use rusqlite::{Connection, OpenFlags, config::DbConfig};
use std::{
    fmt,
    fs::{self, File},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

static RETRY_TICKET: AtomicU64 = AtomicU64::new(1);

/// Effective, read-back connection configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteSettings {
    /// Runtime SQLite version, not inferred from crate metadata.
    pub sqlite_version: String,
    /// Foreign-key enforcement enabled for this connection.
    pub foreign_keys: bool,
    /// Persistent database journal mode.
    pub journal_mode: String,
    /// Connection synchronous mode (2 = FULL).
    pub synchronous: i64,
    /// Connection busy timeout in milliseconds.
    pub busy_timeout_ms: i64,
    /// Connection passive autocheckpoint threshold in pages.
    pub wal_autocheckpoint: i64,
    /// Schema-defined SQL cannot opt into non-innocuous functions.
    pub trusted_schema: bool,
}

/// A checkpoint result, including incomplete passive progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointResult {
    /// SQLite reported a blocker.
    pub busy: bool,
    /// Frames present before checkpoint (negative if no WAL exists).
    pub log_frames: i64,
    /// Frames checkpointed.
    pub checkpointed_frames: i64,
}

/// Conservative quarantine outcome: no source file is moved/copied/deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineReport {
    /// All managed operations have stopped.
    pub operations_halted: bool,
    /// The owned connection was closed.
    pub managed_connection_closed: bool,
    /// DB, WAL, SHM and rollback-journal presence, respectively.
    pub recovery_files_present: [bool; 4],
    /// No claim that other processes are quiescent; preserve the set in place.
    pub preserved_in_place: bool,
}

struct State {
    connection: Option<Connection>,
    halted: bool,
    last_checkpoint: Option<CheckpointResult>,
}
struct Inner {
    state: Mutex<State>,
    path: PathBuf,
    _parent_pins: Vec<File>,
}

/// One serialized connection, no pooling, raw-connection export or user callbacks.
#[derive(Clone)]
pub struct SqliteConnectionManager(Arc<Inner>);
impl fmt::Debug for SqliteConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteConnectionManager([redacted])")
    }
}

fn recovery_paths(path: &Path) -> [PathBuf; 4] {
    let base = path.as_os_str().to_os_string();
    let sidecar = |suffix| {
        let mut name = base.clone();
        name.push(suffix);
        PathBuf::from(name)
    };
    [
        path.to_path_buf(),
        sidecar("-wal"),
        sidecar("-shm"),
        sidecar("-journal"),
    ]
}

fn ordinary(path: &Path) -> Result<(), PersistenceError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PersistenceError::new(Kind::InvalidPath))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & (0x400 | 0x40 | 0x1000 | 0x40000 | 0x400000) != 0 {
            return Err(PersistenceError::new(Kind::InvalidPath));
        }
    }
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        return Err(PersistenceError::new(Kind::InvalidPath));
    }
    Ok(())
}

#[cfg(windows)]
fn drive_path(path: &Path) -> bool {
    use std::path::Prefix;
    matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
}

fn validated_path(input: &Path) -> Result<(PathBuf, Vec<File>), PersistenceError> {
    let invalid = || PersistenceError::new(Kind::InvalidPath);
    if !input.is_absolute() || input.as_os_str().as_encoded_bytes().len() > 30_000 {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        if !drive_path(input) {
            return Err(invalid());
        }
    }
    for part in input.components() {
        if matches!(part, Component::ParentDir) {
            return Err(invalid());
        }
        if let Component::Normal(name) = part {
            let text = name.to_str().ok_or_else(invalid)?;
            let base = text
                .split('.')
                .next()
                .unwrap_or("")
                .trim_end_matches(' ')
                .to_uppercase();
            if text.is_empty()
                || text.ends_with(['.', ' '])
                || text
                    .chars()
                    .any(|c| c.is_control() || ":<>\"|?*/\\".contains(c))
                || matches!(
                    base.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                )
                || ["COM", "LPT"].iter().any(|p| {
                    base.strip_prefix(p).is_some_and(|s| {
                        matches!(
                            s,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                })
            {
                return Err(invalid());
            }
        }
    }
    let parent = input.parent().ok_or_else(invalid)?;
    let leaf = input.file_name().ok_or_else(invalid)?;
    let mut walk = PathBuf::new();
    let mut pins = Vec::new();
    for component in parent.components() {
        walk.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        ordinary(&walk)?;
        #[cfg(windows)]
        {
            use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
            let handle = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(1)
                .custom_flags(0x0220_0000)
                .open(&walk)
                .map_err(|_| invalid())?;
            let metadata = handle.metadata().map_err(|_| invalid())?;
            use std::os::windows::fs::MetadataExt;
            if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
            pins.push(handle);
        }
    }
    let canonical_parent = fs::canonicalize(parent).map_err(|_| invalid())?;
    // A caller's drive spelling can resolve to a UNC provider. Recheck the
    // filesystem-produced prefix before opening SQLite, not only caller text.
    #[cfg(windows)]
    if !drive_path(&canonical_parent) {
        return Err(invalid());
    }
    let path = canonical_parent.join(leaf);
    for member in recovery_paths(&path) {
        match fs::symlink_metadata(&member) {
            Ok(metadata) => {
                ordinary(&member)?;
                if !metadata.is_file() {
                    return Err(invalid());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid()),
        }
    }
    Ok((path, pins))
}

fn integrity(connection: &Connection) -> Result<(), PersistenceError> {
    let mut query = connection
        .prepare("PRAGMA integrity_check(10)")
        .map_err(PersistenceError::sql)?;
    let rows = query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(PersistenceError::sql)?;
    let values: Vec<_> = rows
        .collect::<rusqlite::Result<_>>()
        .map_err(PersistenceError::sql)?;
    if values != ["ok"] {
        return Err(PersistenceError::new(Kind::Integrity));
    }
    Ok(())
}

fn settings(connection: &Connection) -> Result<SqliteSettings, PersistenceError> {
    let number = |sql| {
        connection
            .query_row(sql, [], |row| row.get(0))
            .map_err(PersistenceError::sql)
    };
    Ok(SqliteSettings {
        sqlite_version: rusqlite::version().into(),
        foreign_keys: number("PRAGMA foreign_keys")? == 1,
        journal_mode: connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(PersistenceError::sql)?,
        synchronous: number("PRAGMA synchronous")?,
        busy_timeout_ms: number("PRAGMA busy_timeout")?,
        wal_autocheckpoint: number("PRAGMA wal_autocheckpoint")?,
        trusted_schema: number("PRAGMA trusted_schema")? != 0,
    })
}

fn verify_settings(effective: &SqliteSettings) -> Result<(), PersistenceError> {
    if !effective.foreign_keys
        || effective.journal_mode != "wal"
        || effective.synchronous != 2
        || effective.busy_timeout_ms != 5000
        || effective.wal_autocheckpoint != 1000
        || effective.trusted_schema
    {
        return Err(PersistenceError::new(Kind::PragmaMismatch));
    }
    Ok(())
}

impl SqliteConnectionManager {
    /// Open only an explicitly selected local data file with an existing trusted parent.
    /// Parent/sidecar checks mitigate static indirection; they are not race-free VFS containment.
    pub fn open(path: &Path, clock: &impl Clock) -> Result<Self, PersistenceError> {
        let (path, pins) = validated_path(path)?;
        let exists = path
            .try_exists()
            .map_err(|_| PersistenceError::new(Kind::InvalidPath))?;
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if !exists {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection =
            Connection::open_with_flags(&path, flags).map_err(PersistenceError::sql)?;
        if !connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
            .map_err(PersistenceError::sql)?
            || !connection
                .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
                .map_err(PersistenceError::sql)?
        {
            return Err(PersistenceError::new(Kind::PragmaMismatch));
        }
        connection
            .execute_batch("PRAGMA trusted_schema=OFF")
            .map_err(PersistenceError::sql)?;
        integrity(&connection)?;
        // Reject another application's/newer database before journal-mode writes.
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(PersistenceError::sql)?;
        let application: i64 = connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(PersistenceError::sql)?;
        let objects: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .map_err(PersistenceError::sql)?;
        if version > migration::VERSION {
            return Err(PersistenceError::new(Kind::NewerSchema));
        }
        if version < 0
            || (version == 0 && (objects != 0 || application != 0))
            || (version > 0 && application != migration::APPLICATION_ID)
        {
            return Err(PersistenceError::new(Kind::SchemaMetadata));
        }
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA wal_autocheckpoint=1000;").map_err(PersistenceError::sql)?;
        let effective = settings(&connection)?;
        verify_settings(&effective)?;
        let applied = super::model::time_text(clock.now())?;
        transaction::retry(
            RETRY_TICKET.fetch_add(1, Ordering::Relaxed),
            |_| migration::initialize(&connection, &applied),
            |milliseconds| thread::sleep(Duration::from_millis(milliseconds)),
        )?;
        Ok(Self(Arc::new(Inner {
            state: Mutex::new(State {
                connection: Some(connection),
                halted: false,
                last_checkpoint: None,
            }),
            path,
            _parent_pins: pins,
        })))
    }

    pub(super) fn write<T>(
        &self,
        mut operation: impl FnMut(&mut ManagedTransaction<'_>) -> Result<T, PersistenceError>,
    ) -> Result<T, PersistenceError> {
        let ticket = RETRY_TICKET.fetch_add(1, Ordering::Relaxed);
        transaction::retry(
            ticket,
            |_| {
                let mut state = self
                    .0
                    .state
                    .lock()
                    .map_err(|_| PersistenceError::new(Kind::Poisoned))?;
                if state.halted {
                    return Err(PersistenceError::new(Kind::Halted));
                }
                let db = state
                    .connection
                    .as_ref()
                    .ok_or_else(|| PersistenceError::new(Kind::Closed))?;
                let result = transaction::attempt(db, &mut operation);
                if result.as_ref().is_err_and(PersistenceError::must_halt) {
                    state.halted = true;
                }
                result
            },
            |milliseconds| thread::sleep(Duration::from_millis(milliseconds)),
        )
    }

    /// Read effective settings without returning a Connection or a long-lived reader.
    pub fn settings(&self) -> Result<SqliteSettings, PersistenceError> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| PersistenceError::new(Kind::Poisoned))?;
        if state.halted {
            return Err(PersistenceError::new(Kind::Halted));
        }
        settings(
            state
                .connection
                .as_ref()
                .ok_or_else(|| PersistenceError::new(Kind::Closed))?,
        )
    }

    /// Explicit runtime integrity inspection; failure halts subsequent operations.
    pub fn integrity_check(&self) -> Result<(), PersistenceError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| PersistenceError::new(Kind::Poisoned))?;
        if state.halted {
            return Err(PersistenceError::new(Kind::Halted));
        }
        let result = integrity(
            state
                .connection
                .as_ref()
                .ok_or_else(|| PersistenceError::new(Kind::Closed))?,
        );
        if result.is_err() {
            state.halted = true;
        }
        result
    }

    /// Attempt a checkpoint, returning progress even for a blocked PASSIVE checkpoint.
    pub fn checkpoint(&self, truncate: bool) -> Result<CheckpointResult, PersistenceError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| PersistenceError::new(Kind::Poisoned))?;
        if state.halted {
            return Err(PersistenceError::new(Kind::Halted));
        }
        let sql = if truncate {
            "PRAGMA wal_checkpoint(TRUNCATE)"
        } else {
            "PRAGMA wal_checkpoint(PASSIVE)"
        };
        let result = state
            .connection
            .as_ref()
            .ok_or_else(|| PersistenceError::new(Kind::Closed))?
            .query_row(sql, [], |row| {
                Ok(CheckpointResult {
                    busy: row.get::<_, i64>(0)? != 0,
                    log_frames: row.get(1)?,
                    checkpointed_frames: row.get(2)?,
                })
            })
            .map_err(PersistenceError::sql)?;
        state.last_checkpoint = Some(result);
        if truncate && (result.busy || result.log_frames > 0) {
            return Err(PersistenceError::new(Kind::CheckpointBusy));
        }
        Ok(result)
    }

    /// Last observed checkpoint progress, including a failed TRUNCATE's busy result.
    pub fn last_checkpoint(&self) -> Result<Option<CheckpointResult>, PersistenceError> {
        Ok(self
            .0
            .state
            .lock()
            .map_err(|_| PersistenceError::new(Kind::Poisoned))?
            .last_checkpoint)
    }

    /// Explicit graceful shutdown: checkpoint failure leaves the connection open for retry.
    pub fn shutdown(&self) -> Result<CheckpointResult, PersistenceError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| PersistenceError::new(Kind::Poisoned))?;
        if state.halted {
            return Err(PersistenceError::new(Kind::Halted));
        }
        let checkpoint = state
            .connection
            .as_ref()
            .ok_or_else(|| PersistenceError::new(Kind::Closed))?
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok(CheckpointResult {
                    busy: row.get::<_, i64>(0)? != 0,
                    log_frames: row.get(1)?,
                    checkpointed_frames: row.get(2)?,
                })
            })
            .map_err(PersistenceError::sql)?;
        state.last_checkpoint = Some(checkpoint);
        if checkpoint.busy || checkpoint.log_frames > 0 {
            return Err(PersistenceError::new(Kind::CheckpointBusy));
        }
        let db = state
            .connection
            .take()
            .ok_or_else(|| PersistenceError::new(Kind::Closed))?;
        if let Err((db, _)) = db.close() {
            state.connection = Some(db);
            return Err(PersistenceError::new(Kind::CloseFailed));
        }
        Ok(checkpoint)
    }

    /// Halt and close all managed access, preserving DB/WAL/SHM/journal in place.
    /// No archive rename/copy is attempted: other processes cannot be proven quiescent.
    pub fn quarantine_in_place(&self) -> Result<QuarantineReport, PersistenceError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| PersistenceError::new(Kind::Poisoned))?;
        state.halted = true;
        if let Some(db) = state.connection.take()
            && let Err((db, _)) = db.close()
        {
            state.connection = Some(db);
            return Err(PersistenceError::new(Kind::CloseFailed));
        }
        let mut present = [false; 4];
        for (index, path) in recovery_paths(&self.0.path).iter().enumerate() {
            present[index] = path
                .try_exists()
                .map_err(|_| PersistenceError::new(Kind::InvalidPath))?;
        }
        Ok(QuarantineReport {
            operations_halted: true,
            managed_connection_closed: true,
            recovery_files_present: present,
            preserved_in_place: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockClock, TimestampUtc};

    #[test]
    fn managed_connection_really_enforces_foreign_keys_and_closes_all_clones() {
        #[cfg(windows)]
        for unc in [r"\\server\share\db", r"\\?\UNC\server\share\db"] {
            assert!(!drive_path(Path::new(unc)));
        }
        let parent =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/persistence-manager-unit");
        fs::create_dir_all(&parent).unwrap();
        let path = fs::canonicalize(parent)
            .unwrap()
            .join(format!("fk-{}.db", std::process::id()));
        assert!(!path.exists());
        let manager = SqliteConnectionManager::open(
            &path,
            &MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)),
        )
        .unwrap();
        let clone = manager.clone();
        {
            let state = manager.0.state.lock().unwrap();
            let db = state.connection.as_ref().unwrap();
            verify_settings(&settings(db).unwrap()).unwrap();
            // Real setting changes exercise verification, not an assumed PRAGMA result.
            for (changed, restored) in [
                ("PRAGMA foreign_keys=OFF", "PRAGMA foreign_keys=ON"),
                ("PRAGMA synchronous=NORMAL", "PRAGMA synchronous=FULL"),
                ("PRAGMA busy_timeout=1", "PRAGMA busy_timeout=5000"),
                (
                    "PRAGMA wal_autocheckpoint=1",
                    "PRAGMA wal_autocheckpoint=1000",
                ),
                ("PRAGMA trusted_schema=ON", "PRAGMA trusted_schema=OFF"),
            ] {
                db.execute_batch(changed).unwrap();
                assert_eq!(
                    verify_settings(&settings(db).unwrap()).unwrap_err().kind,
                    Kind::PragmaMismatch
                );
                db.execute_batch(restored).unwrap();
            }
            let error = db
                .query_row("SELECT load_extension('never-load-a-fixture')", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap_err();
            assert!(error.to_string().contains("not authorized"));
        }
        let error=manager.write(|tx|tx.execute("INSERT INTO budget_reservations(reservation_id,session_id,model_id,reserved_cost_micro_usd,state,reserved_at) VALUES('00000000-0000-4000-8000-000000000001','missing','mock',0,'RESERVED','2023-11-14T22:13:20.000Z')",[])).unwrap_err();
        assert_eq!(error.sqlite_code, Some(787));
        manager.shutdown().unwrap();
        assert_eq!(clone.settings().unwrap_err().kind, Kind::Closed);
        drop(clone);
        drop(manager);
        fs::remove_file(path).unwrap();
    }
}
