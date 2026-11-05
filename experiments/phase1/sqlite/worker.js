import assert from "node:assert/strict";
import { existsSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  artifactRoot,
  bytes,
  confined,
  count,
  openDatabase,
} from "./common.js";

const [mode, directory, serialized = "{}"] = process.argv.slice(2);
const root = confined(artifactRoot, directory);
const databasePath = confined(root, resolve(root, "database.sqlite"));
const marker = confined(
  root,
  resolve(root, `ready-${mode}-${JSON.parse(serialized).writer ?? 0}.json`),
);
const options = JSON.parse(serialized);
const db = openDatabase(databasePath);

function ready(extra = {}) {
  const message = {
    event: "ready",
    pid: process.pid,
    mode,
    in_transaction: db.inTransaction,
    wal_bytes: bytes(`${databasePath}-wal`),
    ...extra,
  };
  writeFileSync(`${marker}.tmp`, JSON.stringify(message));
  renameSync(`${marker}.tmp`, marker);
  console.log(JSON.stringify(message));
}

async function hold() {
  // The parent must actually terminate this process. There is no normal close.
  while (true) await Bun.sleep(1000);
}

if (mode === "uncommitted") {
  db.exec("PRAGMA cache_size=4; BEGIN IMMEDIATE;");
  const insert = db.query(
    "INSERT INTO items(id,value) VALUES (?,zeroblob(8192))",
  );
  for (let id = 1; id <= 50; id++) insert.run(id);
  assert(db.inTransaction);
  ready({ pending_rows: 50 });
  await hold();
} else if (mode === "committed") {
  db.exec("BEGIN IMMEDIATE");
  const insert = db.query("INSERT INTO items(id,value) VALUES (?,?)");
  for (let id = 1; id <= 20; id++) insert.run(id, `committed-${id}`);
  db.exec("COMMIT");
  assert.equal(count(db), 21);
  ready({ committed_rows: 20 });
  await hold();
} else if (mode === "batches") {
  const insert = db.query("INSERT INTO items(id,batch,value) VALUES (?,?,?)");
  for (let batch = 1; ; batch++) {
    db.exec("BEGIN IMMEDIATE");
    for (let row = 0; row < 8; row++)
      insert.run(batch * 100 + row, batch, `batch-${batch}-row-${row}`);
    db.exec("COMMIT");
    if (batch === 1) ready({ first_committed_batch: batch });
    await Bun.sleep(1);
  }
} else if (mode === "migration") {
  db.exec(
    "BEGIN IMMEDIATE; ALTER TABLE items ADD COLUMN proposed TEXT; PRAGMA user_version=2;",
  );
  ready({
    pending_version: db.query("PRAGMA user_version").get().user_version,
  });
  await hold();
} else if (mode === "concurrent") {
  db.exec("PRAGMA busy_timeout=3000");
  ready({ writer: options.writer });
  const gate = confined(root, resolve(root, "go"));
  const deadline = performance.now() + 10000;
  while (!existsSync(gate)) {
    assert(performance.now() < deadline, "start barrier timed out");
    await Bun.sleep(5);
  }
  const insert = db.query("INSERT INTO items(id,batch,value) VALUES (?,?,?)");
  for (let batch = 0; batch < 20; batch++) {
    db.exec("BEGIN IMMEDIATE");
    for (let row = 0; row < 4; row++) {
      const id = options.writer * 10000 + batch * 4 + row;
      insert.run(id, batch, `writer-${options.writer}-row-${batch * 4 + row}`);
    }
    db.exec("COMMIT");
    await Bun.sleep(2);
  }
  db.close();
  console.log(
    JSON.stringify({ event: "done", writer: options.writer, rows: 80 }),
  );
} else {
  throw new Error(`unsupported worker mode: ${mode}`);
}
