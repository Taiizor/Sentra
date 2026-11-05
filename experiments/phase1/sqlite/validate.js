import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { arch, platform, release } from "node:os";
import { join, resolve } from "node:path";
import { Database } from "bun:sqlite";
import {
  artifactRoot,
  bytes,
  confined,
  count,
  createItems,
  errorRecord,
  expectSQLite,
  experimentRoot,
  integrity,
  openDatabase,
} from "./common.js";

const runId = `${Date.now()}-${randomUUID().slice(0, 8)}`;
confined(experimentRoot, artifactRoot);
mkdirSync(artifactRoot, { recursive: true });
const runRoot = confined(artifactRoot, join(artifactRoot, runId));
mkdirSync(runRoot);
assert.equal(realpathSync(runRoot), resolve(runRoot));
const resultDirectory = confined(
  experimentRoot,
  join(experimentRoot, "results"),
);
mkdirSync(resultDirectory, { recursive: true });
const resultPath = confined(
  resultDirectory,
  join(resultDirectory, `${runId}.json`),
);
const activeWorkers = new Set();
const memory = new Database(":memory:");
let windowsHost = null;
if (platform() === "win32") {
  const observation = Bun.spawnSync({
    cmd: [
      "pwsh",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot((Get-Location).Path)); [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; filesystem = $drive.DriveFormat; drive_type = $drive.DriveType.ToString() } | ConvertTo-Json -Compress",
    ],
    cwd: experimentRoot,
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  assert.equal(observation.exitCode, 0, observation.stderr.toString());
  windowsHost = JSON.parse(
    observation.stdout.toString().replace(/^\uFEFF/, ""),
  );
}
const report = {
  schema_version: "1",
  milestone: "Phase 1 / Milestone 2 / SQLite engine reliability",
  started_at_utc: new Date().toISOString(),
  run_id: runId,
  environment: {
    bun: Bun.version,
    platform: platform(),
    architecture: arch(),
    os_release: release(),
    windows_host: windowsHost,
    sqlite: memory
      .query(
        "SELECT sqlite_version() AS version, sqlite_source_id() AS source_id",
      )
      .get(),
    compile_options: memory.query("PRAGMA compile_options").all(),
    working_directory: experimentRoot.replaceAll("\\", "/"),
    disposable_root: runRoot.replaceAll("\\", "/"),
    child_environment: ["SystemRoot", "WINDIR", "TEMP", "TMP"],
  },
  input_sha256: Object.fromEntries(
    ["validate.js", "worker.js", "common.js"].map((name) => [
      name,
      createHash("sha256")
        .update(readFileSync(join(experimentRoot, name)))
        .digest("hex"),
    ]),
  ),
  configuration: {
    journal_mode: "WAL",
    synchronous: "FULL",
    wal_autocheckpoint: 0,
    default_busy_timeout_ms: 500,
    repetitions_per_crash_case: 3,
  },
  dependency_policy:
    "Only the existing Bun runtime, built-in bun:sqlite and node-compatible built-ins; no downloads or package installation",
  results: [],
};
memory.close();

function save() {
  writeFileSync(resultPath, `${JSON.stringify(report, null, 2)}\n`);
}

function directory(name) {
  const path = confined(runRoot, join(runRoot, name));
  mkdirSync(path);
  return path;
}

function fixture(name, baseline = false) {
  const root = directory(name);
  const path = confined(root, join(root, "database.sqlite"));
  const db = openDatabase(path);
  createItems(db);
  if (baseline)
    db.query("INSERT INTO items(id,value) VALUES (0,'baseline')").run();
  return { root, path, db };
}

function timeout(promise, milliseconds, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function worker(mode, root, options = {}) {
  const marker = confined(
    root,
    join(root, `ready-${mode}-${options.writer ?? 0}.json`),
  );
  const env = Object.fromEntries(
    ["SystemRoot", "WINDIR", "TEMP", "TMP"]
      .filter((key) => process.env[key])
      .map((key) => [key, process.env[key]]),
  );
  const processHandle = Bun.spawn({
    cmd: [
      process.execPath,
      "--no-install",
      "--no-env-file",
      join(experimentRoot, "worker.js"),
      mode,
      root,
      JSON.stringify(options),
    ],
    cwd: experimentRoot,
    env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  const entry = {
    process: processHandle,
    stdout: new Response(processHandle.stdout).text(),
    stderr: new Response(processHandle.stderr).text(),
  };
  activeWorkers.add(entry);
  const deadline = performance.now() + 10000;
  while (!existsSync(marker)) {
    if (processHandle.exitCode !== null)
      throw new Error(`worker exited before readiness: ${await entry.stderr}`);
    assert(performance.now() < deadline, "worker readiness timed out");
    await Bun.sleep(5);
  }
  entry.ready = JSON.parse(readFileSync(marker, "utf8"));
  assert.equal(entry.ready.pid, processHandle.pid);
  assert.equal(
    processHandle.exitCode,
    null,
    "worker must be alive at readiness",
  );
  return entry;
}

async function finish(entry, terminate) {
  const pid = entry.process.pid;
  if (terminate) {
    assert.equal(
      entry.process.exitCode,
      null,
      "cannot claim termination of an already-exited worker",
    );
    entry.process.kill(); // Uses Windows process termination; no POSIX signal argument.
  }
  const exitCode = await timeout(
    entry.process.exited,
    5000,
    "worker exit timed out",
  );
  const evidence = {
    pid,
    termination_requested: terminate,
    exit_code: exitCode,
    ready: entry.ready,
    stdout: await entry.stdout,
    stderr: await entry.stderr,
  };
  activeWorkers.delete(entry);
  if (terminate)
    assert.notEqual(
      exitCode,
      0,
      "abrupt termination must not be a normal successful exit",
    );
  else assert.equal(exitCode, 0, JSON.stringify(evidence));
  return evidence;
}

async function test(id, name, action) {
  const started = performance.now();
  const result = { id, name, status: "Failed", evidence: null };
  try {
    result.evidence = await action();
    result.status = "Passed";
  } catch (error) {
    result.error = { ...errorRecord(error), stack: error.stack };
  } finally {
    for (const entry of [...activeWorkers]) {
      try {
        if (entry.process.exitCode === null) await finish(entry, true);
        else {
          await entry.process.exited;
          await entry.stdout;
          await entry.stderr;
          activeWorkers.delete(entry);
        }
      } catch (error) {
        result.status = "Failed";
        result.cleanup_error = errorRecord(error);
      }
    }
    result.elapsed_ms = Math.round(performance.now() - started);
    report.results.push(result);
    save();
    console.log(`${id} ${result.status}: ${name}`);
  }
}

await test(
  "T01",
  "Transaction commit, explicit rollback and statement failure",
  () => {
    const { path, db } = fixture("transactions");
    const observer = openDatabase(path);
    try {
      db.exec(
        "BEGIN IMMEDIATE; INSERT INTO items(id,value) VALUES(1,'committed'); COMMIT;",
      );
      db.exec(
        "BEGIN IMMEDIATE; INSERT INTO items(id,value) VALUES(2,'rolled-back'); ROLLBACK;",
      );
      db.exec(
        "BEGIN IMMEDIATE; INSERT INTO items(id,value) VALUES(3,'pending');",
      );
      const error = expectSQLite(
        () => db.exec("INSERT INTO items(id,value) VALUES(1,'duplicate')"),
        19,
      );
      assert.equal(
        db.inTransaction,
        true,
        "statement failure must not be mistaken for transaction rollback",
      );
      const ownRowsAfterError = db
        .query("SELECT id,value FROM items ORDER BY id")
        .all();
      const observerRowsAfterError = observer
        .query("SELECT id,value FROM items ORDER BY id")
        .all();
      assert.deepEqual(ownRowsAfterError, [
        { id: 1, value: "committed" },
        { id: 3, value: "pending" },
      ]);
      assert.deepEqual(observerRowsAfterError, [{ id: 1, value: "committed" }]);
      db.exec("ROLLBACK");
      assert.deepEqual(
        db.query("SELECT id,value FROM items ORDER BY id").all(),
        [{ id: 1, value: "committed" }],
      );
      return {
        error,
        in_transaction_after_statement_error: true,
        own_rows_after_error: ownRowsAfterError,
        observer_rows_after_error: observerRowsAfterError,
        rows_after_explicit_rollback: db
          .query("SELECT id,value FROM items ORDER BY id")
          .all(),
        explicit_rollback_required: true,
        integrity: integrity(db),
      };
    } finally {
      observer.close();
      db.close();
    }
  },
);

await test("T02", "WAL snapshots and blocked/successful checkpoints", () => {
  const { path, db } = fixture("wal", true);
  const reader = openDatabase(path);
  try {
    reader.exec("BEGIN");
    assert.equal(count(reader), 1);
    db.exec("INSERT INTO items(id,value) VALUES(1,'later')");
    assert.equal(count(reader), 1);
    assert.equal(count(db), 2);
    const passive = db.query("PRAGMA wal_checkpoint(PASSIVE)").get();
    assert(
      passive.log > passive.checkpointed,
      "pinned reader must retain unapplied WAL frames",
    );
    db.exec("PRAGMA busy_timeout=50");
    const blocked = db.query("PRAGMA wal_checkpoint(TRUNCATE)").get();
    assert.equal(blocked.busy, 1);
    const retainedBytes = bytes(`${path}-wal`);
    assert(retainedBytes > 32);
    reader.exec("ROLLBACK");
    const completed = db.query("PRAGMA wal_checkpoint(TRUNCATE)").get();
    assert.equal(completed.busy, 0);
    assert.equal(bytes(`${path}-wal`), 0);
    return {
      passive,
      blocked,
      completed,
      retained_wal_bytes: retainedBytes,
      integrity: integrity(db),
    };
  } finally {
    reader.close();
    db.close();
  }
});

for (const [id, mode, label] of [
  ["T03", "uncommitted", "Kill an uncommitted writer"],
  ["T04", "committed", "Kill a writer after acknowledged COMMIT"],
  ["T05", "batches", "Kill an active batch-writing process"],
]) {
  await test(id, label, async () => {
    const repetitions = [];
    for (let repetition = 0; repetition < 3; repetition++) {
      const { root, path, db } = fixture(`${mode}-${repetition}`, true);
      db.close();
      const entry = await worker(mode, root);
      if (mode === "uncommitted") {
        assert(entry.ready.in_transaction);
        assert(
          entry.ready.wal_bytes > 32,
          "uncommitted pages must have spilled to a real WAL",
        );
      }
      if (mode === "committed") {
        assert.equal(entry.ready.in_transaction, false);
        assert(entry.ready.wal_bytes > 32);
      }
      if (mode === "batches") await Bun.sleep(15);
      const termination = await finish(entry, true);
      const walBeforeReopen = bytes(`${path}-wal`);
      const reopened = openDatabase(path);
      try {
        const rows = count(reopened);
        if (mode === "uncommitted") assert.equal(rows, 1);
        if (mode === "committed") {
          assert.equal(rows, 21);
          assert.equal(
            reopened
              .query(
                "SELECT count(*) n FROM items WHERE id>0 AND value='committed-'||id",
              )
              .get().n,
            20,
          );
        }
        if (mode === "batches") {
          assert(rows > 1 && (rows - 1) % 8 === 0);
          const partial = reopened
            .query(
              "SELECT batch,count(*) n FROM items WHERE id>0 GROUP BY batch HAVING count(*)<>8",
            )
            .all();
          assert.deepEqual(partial, []);
          assert.equal(
            reopened
              .query(
                "SELECT count(*) n FROM items WHERE id>0 AND value<>'batch-'||batch||'-row-'||(id%100)",
              )
              .get().n,
            0,
          );
        }
        repetitions.push({
          repetition,
          termination,
          wal_bytes_before_reopen: walBeforeReopen,
          recovered_rows: rows,
          integrity: integrity(reopened),
        });
      } finally {
        reopened.close();
      }
    }
    return {
      repetitions,
      exact_instruction_at_termination:
        "Not observed; readiness barriers establish before/after COMMIT or active batch workload, not an fsync/power-loss cut",
    };
  });
}

await test("T06", "integrity_check after commit, reopen and checkpoint", () => {
  const { path, db } = fixture("integrity", true);
  db.exec("INSERT INTO items(id,value) VALUES(1,'valid')");
  const before = integrity(db);
  db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  db.close();
  const reopened = openDatabase(path);
  try {
    assert.equal(count(reopened), 2);
    return { before, after: integrity(reopened) };
  } finally {
    reopened.close();
  }
});

await test(
  "T07",
  "SQLite VACUUM INTO snapshot backup and restore to a new database",
  () => {
    const { root, db } = fixture("backup", true);
    const backup = confined(root, join(root, "backup.sqlite"));
    const restored = confined(root, join(root, "restored.sqlite"));
    try {
      db.exec("INSERT INTO items(id,value) VALUES(1,'at-backup')");
      const expected = db.query("SELECT * FROM items ORDER BY id").all();
      db.query("VACUUM main INTO ?").run(backup);
      db.exec("INSERT INTO items(id,value) VALUES(2,'after-backup')");
      const snapshot = openDatabase(backup);
      try {
        assert.deepEqual(
          snapshot.query("SELECT * FROM items ORDER BY id").all(),
          expected,
        );
        integrity(snapshot);
        snapshot.query("VACUUM main INTO ?").run(restored);
      } finally {
        snapshot.close();
      }
      const restoredDb = openDatabase(restored);
      try {
        assert.deepEqual(
          restoredDb.query("SELECT * FROM items ORDER BY id").all(),
          expected,
        );
        assert.equal(count(db), 3);
        return {
          method:
            "VACUUM main INTO bound destination; new restore file, not in-place file replacement",
          snapshot_rows: expected,
          source_rows_after_backup: count(db),
          integrity: integrity(restoredDb),
        };
      } finally {
        restoredDb.close();
      }
    } finally {
      db.close();
    }
  },
);

await test(
  "T08",
  "Three process writers with a concurrent reader",
  async () => {
    const { root, db } = fixture("concurrent");
    try {
      const writers = [];
      for (let writerId = 1; writerId <= 3; writerId++)
        writers.push(await worker("concurrent", root, { writer: writerId }));
      writeFileSync(confined(root, join(root, "go")), "go");
      const samples = [];
      const deadline = performance.now() + 15000;
      do {
        const rows = count(db);
        assert.equal(
          rows % 4,
          0,
          "reader must never see a partial four-row transaction",
        );
        samples.push(rows);
        assert(
          performance.now() < deadline,
          "concurrent writer deadline exceeded",
        );
        await Bun.sleep(2);
      } while (writers.some((entry) => entry.process.exitCode === null));
      const exits = [];
      for (const entry of writers) exits.push(await finish(entry, false));
      assert.equal(count(db), 240);
      assert.equal(
        db.query("SELECT count(DISTINCT id) n FROM items").get().n,
        240,
      );
      assert.equal(
        db
          .query(
            "SELECT count(*) n FROM items WHERE value NOT LIKE 'writer-%-row-%'",
          )
          .get().n,
        0,
      );
      assert(
        samples.some((rows) => rows > 0 && rows < 240),
        "must observe reads while workload is incomplete",
      );
      return {
        writers: exits,
        read_samples: samples,
        final_rows: count(db),
        integrity: integrity(db),
      };
    } finally {
      db.close();
    }
  },
);

await test("T09", "Transactional schema migration survives reopen", () => {
  const { path, db } = fixture("migration-success", true);
  db.exec(
    "PRAGMA user_version=1; BEGIN IMMEDIATE; ALTER TABLE items ADD COLUMN tag TEXT NOT NULL DEFAULT 'migrated'; CREATE INDEX items_tag ON items(tag); PRAGMA user_version=2; COMMIT;",
  );
  db.close();
  const reopened = openDatabase(path);
  try {
    assert.equal(reopened.query("PRAGMA user_version").get().user_version, 2);
    assert.equal(
      reopened.query("SELECT tag FROM items WHERE id=0").get().tag,
      "migrated",
    );
    assert.equal(
      reopened
        .query(
          "SELECT count(*) n FROM sqlite_schema WHERE type='index' AND name='items_tag'",
        )
        .get().n,
      1,
    );
    return { version: 2, integrity: integrity(reopened) };
  } finally {
    reopened.close();
  }
});

await test(
  "T10",
  "Failed schema migration rolls back DDL and user_version",
  () => {
    const { db } = fixture("migration-failure", true);
    try {
      db.exec(
        "PRAGMA user_version=1; BEGIN IMMEDIATE; ALTER TABLE items ADD COLUMN proposed TEXT; PRAGMA user_version=2;",
      );
      const error = expectSQLite(
        () => db.exec("CREATE TABLE items(duplicate INTEGER)"),
        1,
      );
      assert(db.inTransaction);
      db.exec("ROLLBACK");
      assert.equal(db.query("PRAGMA user_version").get().user_version, 1);
      assert(
        !db
          .query("PRAGMA table_info(items)")
          .all()
          .some((row) => row.name === "proposed"),
      );
      assert.equal(count(db), 1);
      return {
        error,
        explicit_rollback_required: true,
        integrity: integrity(db),
      };
    } finally {
      db.close();
    }
  },
);

await test(
  "T11",
  "Process termination during a pending schema migration",
  async () => {
    const { root, path, db } = fixture("migration-crash", true);
    db.exec("PRAGMA user_version=1");
    db.close();
    const entry = await worker("migration", root);
    assert(entry.ready.in_transaction);
    const termination = await finish(entry, true);
    const reopened = openDatabase(path);
    try {
      assert.equal(reopened.query("PRAGMA user_version").get().user_version, 1);
      assert(
        !reopened
          .query("PRAGMA table_info(items)")
          .all()
          .some((row) => row.name === "proposed"),
      );
      assert.equal(count(reopened), 1);
      return { termination, integrity: integrity(reopened) };
    } finally {
      reopened.close();
    }
  },
);

await test("T12", "Writer lock and finite busy timeout", () => {
  const { path, db } = fixture("busy");
  const contender = openDatabase(path);
  try {
    db.exec("BEGIN IMMEDIATE");
    contender.exec("PRAGMA busy_timeout=175");
    const start = performance.now();
    const error = expectSQLite(
      () => contender.exec("INSERT INTO items(id,value) VALUES(1,'contender')"),
      5,
    );
    const elapsed = performance.now() - start;
    assert(
      elapsed >= 100 && elapsed < 5000,
      `unexpected timeout duration ${elapsed}`,
    );
    db.exec("ROLLBACK");
    contender.exec("INSERT INTO items(id,value) VALUES(1,'after-release')");
    assert.equal(count(db), 1);
    return {
      error,
      busy_timeout_ms: 175,
      observed_ms: Math.round(elapsed),
      integrity: integrity(db),
    };
  } finally {
    contender.close();
    db.close();
  }
});

await test(
  "T13",
  "Stale WAL read transaction cannot silently upgrade to a writer",
  () => {
    const { path, db } = fixture("busy-snapshot", true);
    const stale = openDatabase(path);
    try {
      stale.exec("BEGIN");
      assert.equal(count(stale), 1);
      db.exec("INSERT INTO items(id,value) VALUES(1,'new-snapshot')");
      assert.equal(count(db), 2);
      const attempts = [];
      for (let attempt = 1; attempt <= 2; attempt++) {
        const error = expectSQLite(
          () =>
            stale.exec("INSERT INTO items(id,value) VALUES(2,'stale-upgrade')"),
          5,
        );
        assert.equal(
          error.errno,
          517,
          "must reproduce SQLITE_BUSY_SNAPSHOT specifically",
        );
        assert.equal(stale.inTransaction, true);
        assert.equal(
          count(stale),
          1,
          "statement-only retry retains the old read snapshot",
        );
        attempts.push({
          attempt,
          error,
          in_transaction: stale.inTransaction,
          visible_rows: count(stale),
        });
      }
      stale.exec("ROLLBACK; BEGIN IMMEDIATE");
      const freshRows = count(stale);
      assert.equal(freshRows, 2);
      stale.exec("INSERT INTO items(id,value) VALUES(2,'fresh-retry'); COMMIT");
      assert.equal(count(db), 3);
      return {
        interleaving:
          "reader BEGIN and SELECT; separate connection COMMIT; two statement-only retries; reader ROLLBACK and BEGIN IMMEDIATE",
        statement_only_attempts: attempts,
        rows_after_transaction_restart: freshRows,
        rows_after_successful_commit: count(db),
        busy_timeout_ms: stale.query("PRAGMA busy_timeout").get().timeout,
        recovery: "rollback stale snapshot and retry in a fresh transaction",
        integrity: integrity(db),
      };
    } finally {
      stale.close();
      db.close();
    }
  },
);

await test("T14", "SQLITE_FULL via a bounded database page limit", () => {
  const { db } = fixture("capacity", true);
  try {
    const initial = db.query("PRAGMA page_count").get().page_count;
    const limit = initial + 4;
    assert.equal(
      db.query(`PRAGMA max_page_count=${limit}`).get().max_page_count,
      limit,
    );
    db.exec(
      "BEGIN IMMEDIATE; INSERT INTO items(id,value) VALUES(1,'must-roll-back')",
    );
    const error = expectSQLite(
      () => db.exec("INSERT INTO items(id,value) VALUES(2,zeroblob(1048576))"),
      13,
    );
    const autoRollback = !db.inTransaction;
    if (db.inTransaction) db.exec("ROLLBACK");
    assert.equal(count(db), 1);
    return {
      error,
      initial_pages: initial,
      maximum_pages: limit,
      engine_auto_rollback: autoRollback,
      physical_disk_filled: false,
      integrity: integrity(db),
    };
  } finally {
    db.close();
  }
});

await test(
  "T15",
  "Read-only connection rejects writes without changing the database",
  () => {
    const { path, db } = fixture("readonly", true);
    db.close();
    const readonly = openDatabase(path, true);
    try {
      const error = expectSQLite(
        () =>
          readonly.exec("INSERT INTO items(id,value) VALUES(1,'forbidden')"),
        8,
      );
      assert.equal(count(readonly), 1);
      return { error, integrity: integrity(readonly) };
    } finally {
      readonly.close();
    }
  },
);

await test(
  "T16",
  "Filesystem open failure is reported as SQLITE_CANTOPEN",
  () => {
    const root = directory("cannot-open");
    const directoryPath = confined(
      root,
      join(root, "directory-not-a-database"),
    );
    mkdirSync(directoryPath);
    return {
      error: expectSQLite(() => {
        const db = new Database(directoryPath, { create: true });
        try {
          db.exec("CREATE TABLE impossible(id)");
        } finally {
          db.close();
        }
      }, 14),
    };
  },
);

await test(
  "T17",
  "Corruption detection on a disposable copy preserves the original",
  () => {
    const { root, path, db } = fixture("corruption", true);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    const pageSize = db.query("PRAGMA page_size").get().page_size;
    const rootPage = db
      .query("SELECT rootpage FROM sqlite_schema WHERE name='items'")
      .get().rootpage;
    db.close();
    const damaged = confined(root, join(root, "damaged.sqlite"));
    copyFileSync(path, damaged);
    const data = readFileSync(damaged);
    data.fill(0, 0, 16);
    writeFileSync(damaged, data);
    const error = expectSQLite(() => {
      const corrupt = new Database(damaged);
      try {
        corrupt.query("PRAGMA integrity_check").all();
      } finally {
        corrupt.close();
      }
    }, 26);
    const structuralPath = confined(
      root,
      join(root, "structural-damage.sqlite"),
    );
    copyFileSync(path, structuralPath);
    const structuralData = readFileSync(structuralPath);
    const offset = (rootPage - 1) * pageSize;
    // Inflate the b-tree cell count only in this disposable copy.
    structuralData[offset + 3] = 255;
    structuralData[offset + 4] = 255;
    writeFileSync(structuralPath, structuralData);
    const structural = new Database(structuralPath);
    let structuralObservation;
    try {
      const rows = structural.query("PRAGMA integrity_check").all();
      assert.notDeepEqual(rows, [{ integrity_check: "ok" }]);
      structuralObservation = { diagnostics: rows };
    } catch (failure) {
      structuralObservation = { error: errorRecord(failure) };
      assert.equal(structuralObservation.error.errno & 255, 11);
    } finally {
      structural.close();
    }
    const original = openDatabase(path);
    try {
      assert.equal(count(original), 1);
      return {
        error,
        damage:
          "header and b-tree cell count in two closed disposable copies only",
        structural_observation: structuralObservation,
        original_integrity: integrity(original),
      };
    } finally {
      original.close();
    }
  },
);

await test("T18", "Unicode, spaces, CRLF text and Windows file paths", () => {
  const { path, db } = fixture("Unicode space \u00fc \u4e2d\u6587", true);
  const value = "Unicode: \u00fc \u4e2d\u6587 \ud83d\udd12\r\nsecond line\r\n";
  db.query("INSERT INTO items(id,value) VALUES(1,?)").run(value);
  db.close();
  const reopened = openDatabase(path);
  try {
    assert.equal(
      reopened.query("SELECT value FROM items WHERE id=1").get().value,
      value,
    );
    return {
      path: path.replaceAll("\\", "/"),
      utf8_sha256: createHash("sha256").update(value).digest("hex"),
      integrity: integrity(reopened),
    };
  } finally {
    reopened.close();
  }
});

for (const [id, name, status, reason] of [
  [
    "T19",
    "Physical volume exhaustion",
    "Blocked",
    "Filling the host volume would affect unrelated files; the safe SQLITE_FULL page-limit test is T14, not a physical-disk simulation.",
  ],
  [
    "T20",
    "Injected SQLITE_IOERR at write/fsync boundaries",
    "Not Tested",
    "No fault-injecting SQLite VFS or isolated failing device is provisioned; CANTOPEN and READONLY are tested separately and are not relabeled as IOERR.",
  ],
  [
    "T21",
    "Power loss or kernel/VM failure during storage writes",
    "Not Tested",
    "Only owned writer processes were terminated; no host/VM interruption or power-loss test is authorized or provisioned.",
  ],
  [
    "T22",
    "Production Rust SQLite binding and database/blob atomicity",
    "Not Tested",
    "No Rust binding or production persistence layer is selected; SQLite transactions do not make external blob promotion atomic.",
  ],
])
  report.results.push({ id, name, status, reason });

report.finished_at_utc = new Date().toISOString();
report.summary = Object.fromEntries(
  ["Passed", "Failed", "Blocked", "Not Tested"].map((status) => [
    status,
    report.results.filter((result) => result.status === status).length,
  ]),
);
report.assessment_recorded = true;
report.tested_subset_passed = report.summary.Failed === 0;
report.all_scenarios_passed =
  report.summary.Failed +
    report.summary.Blocked +
    report.summary["Not Tested"] ===
  0;
save();
console.log(
  JSON.stringify(
    { raw_results: resultPath.replaceAll("\\", "/"), summary: report.summary },
    null,
    2,
  ),
);
process.exitCode = report.summary.Failed > 0 ? 1 : 0;
