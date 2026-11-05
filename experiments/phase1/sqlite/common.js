import assert from "node:assert/strict";
import { existsSync, lstatSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { Database } from "bun:sqlite";

export const experimentRoot = realpathSync(import.meta.dir);
export const artifactRoot = resolve(experimentRoot, "artifacts");

// Reject escapes and reparse-point redirects before touching experiment data.
export function confined(root, candidate) {
  const path = resolve(candidate);
  const offset = relative(resolve(root), path);
  assert(
    offset &&
      !isAbsolute(offset) &&
      offset !== ".." &&
      !offset.startsWith("../") &&
      !offset.startsWith("..\\"),
    "path must be a child of the experiment root",
  );
  for (
    let parent = path;
    parent !== dirname(parent);
    parent = dirname(parent)
  ) {
    if (existsSync(parent))
      assert(
        !lstatSync(parent).isSymbolicLink(),
        "symlinks/junctions are not permitted",
      );
  }
  return path;
}

export function openDatabase(path, readonly = false) {
  confined(artifactRoot, path);
  const db = new Database(
    path,
    readonly ? { readonly: true } : { create: true },
  );
  db.exec("PRAGMA busy_timeout=500; PRAGMA foreign_keys=ON;");
  if (!readonly) {
    assert.equal(db.query("PRAGMA journal_mode=WAL").get().journal_mode, "wal");
    db.exec("PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0;");
    assert.equal(db.query("PRAGMA synchronous").get().synchronous, 2);
    assert.equal(
      db.query("PRAGMA wal_autocheckpoint").get().wal_autocheckpoint,
      0,
    );
  }
  return db;
}

export function createItems(db) {
  db.exec(
    "CREATE TABLE items(id INTEGER PRIMARY KEY, batch INTEGER NOT NULL DEFAULT 0, value TEXT NOT NULL)",
  );
}

export function count(db) {
  return db.query("SELECT count(*) AS n FROM items").get().n;
}

export function integrity(db) {
  const rows = db.query("PRAGMA integrity_check").all();
  assert.deepEqual(rows, [{ integrity_check: "ok" }]);
  return rows;
}

export function errorRecord(error) {
  return {
    name: error.name,
    message: error.message,
    code: error.code ?? null,
    errno: error.errno ?? null,
  };
}

export function expectSQLite(action, primaryCode) {
  let observed;
  try {
    action();
  } catch (error) {
    observed = errorRecord(error);
  }
  assert(observed, "expected an actual SQLite error");
  assert.equal(observed.errno & 255, primaryCode, JSON.stringify(observed));
  return observed;
}

export function bytes(path) {
  return existsSync(path) ? statSync(path).size : 0;
}
