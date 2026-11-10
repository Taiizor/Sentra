import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import { nowIso } from "./db.ts";

/**
 * Encrypted secret storage (AES-256-GCM). Ciphertext layout: base64(iv[12] | tag[16] | data).
 * The secret name is bound as additional authenticated data so ciphertexts cannot be swapped
 * between entries.
 */
export class SecretStore {
  private readonly key: Buffer;
  private readonly db: Database;

  constructor(db: Database, masterKey: Buffer) {
    this.db = db;
    this.key = Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), "sentra-web-secrets-v1", 32));
  }

  set(name: string, value: string, actor: string): void {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(name, "utf8"));
    const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    const payload = Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64");
    this.db
      .query(
        `INSERT INTO secrets (name, ciphertext, updated_at, updated_by) VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      )
      .run(name, payload, nowIso(), actor);
  }

  get(name: string): string | null {
    const row = this.db.query("SELECT ciphertext FROM secrets WHERE name = ?").get(name) as { ciphertext: string } | null;
    if (!row) return null;
    const raw = Buffer.from(row.ciphertext, "base64");
    if (raw.length < 29) throw new Error(`Secret '${name}' is corrupt`);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(name, "utf8"));
    decipher.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
  }

  has(name: string): boolean {
    return this.db.query("SELECT 1 AS present FROM secrets WHERE name = ?").get(name) !== null;
  }

  delete(name: string): void {
    this.db.query("DELETE FROM secrets WHERE name = ?").run(name);
  }

  meta(name: string): { updatedAt: string; updatedBy: string } | null {
    const row = this.db.query("SELECT updated_at, updated_by FROM secrets WHERE name = ?").get(name) as {
      updated_at: string;
      updated_by: string;
    } | null;
    return row ? { updatedAt: row.updated_at, updatedBy: row.updated_by } : null;
  }
}

/** Shows only the last four characters of a credential. */
export function maskSecret(value: string): string {
  if (value.length <= 8) return "••••";
  return `••••••••${value.slice(-4)}`;
}
