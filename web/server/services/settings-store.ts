import type { Database } from "bun:sqlite";
import { nowIso, parseJsonColumn } from "../db.ts";

/** Small typed key/value store over the bridge `settings` table. */
export class SettingsStore {
  private readonly db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  get<T>(key: string, fallback: T): T {
    const row = this.db.query("SELECT value_json FROM settings WHERE key = ?").get(key) as { value_json: string } | null;
    return parseJsonColumn<T>(row?.value_json, fallback);
  }

  meta(key: string): { updatedAt: string; updatedBy: string } | null {
    const row = this.db.query("SELECT updated_at, updated_by FROM settings WHERE key = ?").get(key) as {
      updated_at: string;
      updated_by: string;
    } | null;
    return row ? { updatedAt: row.updated_at, updatedBy: row.updated_by } : null;
  }

  set(key: string, value: unknown, actor: string): void {
    this.db
      .query(
        `INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      )
      .run(key, JSON.stringify(value), nowIso(), actor);
  }

  delete(key: string): void {
    this.db.query("DELETE FROM settings WHERE key = ?").run(key);
  }
}
