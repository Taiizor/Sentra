import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import { nowIso, parseJsonColumn } from "./db.ts";
import type { Principal } from "./http.ts";

/**
 * Append-only operator audit chain owned by the web bridge.
 *
 * Each entry stores HMAC-SHA256(chainKey, prev_hash || canonical(entry)). Every append also
 * advances a head checkpoint {seq, hash, mac} in the `settings` table, MACed with a second key;
 * both keys are derived from the bridge secret. SQLite triggers reject UPDATE/DELETE on
 * `audit_log` through normal connections, but anyone with write access to the database file can
 * drop them, which is what verification is for.
 *
 * verify() recomputes the chain from genesis and reports it invalid when:
 * - an entry was edited, reordered, or removed anywhere before the newest stored entry
 *   (sequence gap, prev_hash mismatch or MAC mismatch);
 * - the chain ends before the checkpoint's seq, i.e. the newest entries (or all of them) were
 *   removed while the checkpoint row stayed in place. A later append does not hide this: a
 *   checkpoint that no longer matches the chain is never advanced;
 * - the checkpoint is malformed, fails its MAC, records a seq the chain has passed, or does not
 *   match the newest entry's hash.
 *
 * verify() cannot detect:
 * - removal of the newest entries (or of the whole log) when the checkpoint row is deleted as
 *   well. Without a checkpoint only the chain itself is checked (`checkpointSeq` is null), and
 *   the next append starts a new checkpoint from the shortened head;
 * - removal of the newest entries when an earlier genuine checkpoint value is restored, or a
 *   rollback of the whole database file to an earlier copy;
 * - any rewrite by someone who holds the bridge secret, since both MACs derive from it.
 * Recording `headHash` and `checkedEntries` outside this host is the only anchor against these.
 */

export const GENESIS_HASH = "0".repeat(64);
const CHECKPOINT_KEY = "audit.head_checkpoint";

/** Returned with every verification result; must match what verifyChain() actually checks. */
export const AUDIT_LIMITATION =
  "Edits, reordering and removal of entries before the newest one break the HMAC chain. Removal of the newest entries (or of all entries) is detected through a MAC-protected head checkpoint kept in the same database. It is not detected when that checkpoint is also deleted or replaced with an earlier copy, when the whole database is rolled back, or when the bridge secret is compromised. Record headHash and the entry count outside this host for a stronger anchor.";

/**
 * Errors whose audit entry was already written (or that must not be recorded), so the request
 * dispatcher does not add a generic `request_rejected` entry for them.
 */
const AUDIT_HANDLED = new WeakSet<object>();

export function markAuditHandled<T>(error: T): T {
  if (error !== null && typeof error === "object") AUDIT_HANDLED.add(error);
  return error;
}

export function isAuditHandled(error: unknown): boolean {
  return error !== null && typeof error === "object" && AUDIT_HANDLED.has(error);
}

export type AuditOutcome = "success" | "failure" | "denied";

export interface AuditEntryInput {
  action: string;
  outcome: AuditOutcome;
  tenantId?: string | null;
  target?: string | null;
  details?: Record<string, unknown>;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  role: string;
  action: string;
  tenantId: string | null;
  target: string | null;
  outcome: AuditOutcome;
  details: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export interface ChainVerification {
  valid: boolean;
  checkedEntries: number;
  firstInvalidSeq: number | null;
  reason: string | null;
  headHash: string;
  /** Sequence number recorded by the head checkpoint, or null when none exists yet. */
  checkpointSeq: number | null;
  limitation: string;
  verifiedAt: string;
}

interface Checkpoint {
  seq: number;
  hash: string;
  mac: string;
}

/** Deterministic JSON: object keys sorted recursively. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

interface AuditRow {
  seq: number;
  ts: string;
  actor: string;
  role: string;
  action: string;
  tenant_id: string | null;
  target: string | null;
  outcome: AuditOutcome;
  details_json: string;
  prev_hash: string;
  hash: string;
}

export class AuditLog {
  private readonly key: Buffer;
  private readonly checkpointKey: Buffer;
  private readonly db: Database;

  constructor(db: Database, masterKey: Buffer) {
    this.db = db;
    this.key = Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), "sentra-web-audit-chain-v1", 32));
    this.checkpointKey = Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), "sentra-web-audit-checkpoint-v1", 32));
  }

  private checkpointMac(seq: number, hash: string): string {
    return crypto.createHmac("sha256", this.checkpointKey).update(`${seq}\n${hash}`).digest("hex");
  }

  /** The stored head checkpoint: null when absent, "invalid" when it is malformed or its MAC fails. */
  private readCheckpoint(): Checkpoint | null | "invalid" {
    const row = this.db.query("SELECT value_json FROM settings WHERE key = ?").get(CHECKPOINT_KEY) as { value_json: string } | null;
    if (!row) return null;
    const value = parseJsonColumn<Partial<Checkpoint> | null>(row.value_json, null);
    if (!value || typeof value.seq !== "number" || typeof value.hash !== "string" || typeof value.mac !== "string") return "invalid";
    const expected = Buffer.from(this.checkpointMac(value.seq, value.hash), "hex");
    const presented = Buffer.from(value.mac, "hex");
    if (presented.length !== expected.length || !crypto.timingSafeEqual(presented, expected)) return "invalid";
    return { seq: value.seq, hash: value.hash, mac: value.mac };
  }

  private writeCheckpoint(seq: number, hash: string, ts: string): void {
    const value: Checkpoint = { seq, hash, mac: this.checkpointMac(seq, hash) };
    this.db
      .query(
        `INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, 'audit-log')
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      )
      .run(CHECKPOINT_KEY, JSON.stringify(value), ts);
  }

  private digest(prevHash: string, body: Omit<AuditEntry, "hash" | "prevHash">): string {
    return crypto
      .createHmac("sha256", this.key)
      .update(prevHash)
      .update("\n")
      .update(
        canonicalJson({
          seq: body.seq,
          ts: body.ts,
          actor: body.actor,
          role: body.role,
          action: body.action,
          tenantId: body.tenantId,
          target: body.target,
          outcome: body.outcome,
          details: body.details,
        }),
      )
      .digest("hex");
  }

  /** Appends an entry for an authenticated principal or a named system actor. */
  append(principal: Principal | { label: string; role: string }, input: AuditEntryInput): AuditEntry {
    const write = this.db.transaction((): AuditEntry => {
      const head = this.db.query("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").get() as {
        seq: number;
        hash: string;
      } | null;
      const body = {
        seq: (head?.seq ?? 0) + 1,
        ts: nowIso(),
        actor: principal.label,
        role: principal.role,
        action: input.action,
        tenantId: input.tenantId ?? null,
        target: input.target ?? null,
        outcome: input.outcome,
        details: input.details ?? {},
      };
      const prevHash = head?.hash ?? GENESIS_HASH;
      const hash = this.digest(prevHash, body);
      this.db
        .query(
          `INSERT INTO audit_log (seq, ts, actor, role, action, tenant_id, target, outcome, details_json, prev_hash, hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          body.seq,
          body.ts,
          body.actor,
          body.role,
          body.action,
          body.tenantId,
          body.target,
          body.outcome,
          canonicalJson(body.details),
          prevHash,
          hash,
        );
      // Advance the head checkpoint only from the head it describes. A checkpoint that no
      // longer matches the chain (entries were removed) is left in place as evidence, and
      // verification keeps reporting the mismatch.
      const checkpoint = this.readCheckpoint();
      const continues =
        checkpoint === null || (checkpoint !== "invalid" && checkpoint.seq === (head?.seq ?? 0) && checkpoint.hash === prevHash);
      if (continues) this.writeCheckpoint(body.seq, hash, body.ts);
      return { ...body, prevHash, hash };
    });
    return write.immediate();
  }

  list(options: { tenantId?: string | null; limit: number; beforeSeq?: number }): AuditEntry[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (options.tenantId) {
      clauses.push("(tenant_id = ? OR tenant_id IS NULL)");
      params.push(options.tenantId);
    }
    if (options.beforeSeq) {
      clauses.push("seq < ?");
      params.push(options.beforeSeq);
    }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    params.push(options.limit);
    const rows = this.db
      .query(`SELECT * FROM audit_log ${where} ORDER BY seq DESC LIMIT ?`)
      .all(...params) as AuditRow[];
    return rows.map((row) => this.fromRow(row));
  }

  /**
   * Number of entries. With a tenant id, `includeGlobal` (the default, matching `list`) also
   * counts entries without a tenant, such as logins and authorization denials; pass false to
   * count only the entries recorded for that tenant.
   */
  count(tenantId?: string | null, options: { includeGlobal?: boolean } = {}): number {
    const includeGlobal = options.includeGlobal ?? true;
    const row = tenantId
      ? (this.db
          .query(`SELECT COUNT(*) AS c FROM audit_log WHERE tenant_id = ?${includeGlobal ? " OR tenant_id IS NULL" : ""}`)
          .get(tenantId) as { c: number })
      : (this.db.query("SELECT COUNT(*) AS c FROM audit_log").get() as { c: number });
    return row.c;
  }

  /** Recomputes the whole chain from genesis, then compares its end with the head checkpoint. */
  verify(): ChainVerification {
    // One read transaction, so an append cannot land between the chain and checkpoint reads.
    return this.db.transaction(() => this.verifyChain()).deferred();
  }

  private verifyChain(): ChainVerification {
    let prevHash = GENESIS_HASH;
    let expectedSeq = 1;
    let checked = 0;
    const checkpoint = this.readCheckpoint();
    const rows = this.db.query("SELECT * FROM audit_log ORDER BY seq ASC").iterate() as IterableIterator<AuditRow>;
    const checkpointSeq = checkpoint && checkpoint !== "invalid" ? checkpoint.seq : null;
    const result = (valid: boolean, firstInvalidSeq: number | null, reason: string | null): ChainVerification => ({
      valid,
      checkedEntries: checked,
      firstInvalidSeq,
      reason,
      headHash: prevHash,
      checkpointSeq,
      limitation: AUDIT_LIMITATION,
      verifiedAt: nowIso(),
    });
    for (const row of rows) {
      const entry = this.fromRow(row);
      if (entry.seq !== expectedSeq) return result(false, entry.seq, `sequence gap: expected ${expectedSeq}, found ${entry.seq}`);
      if (entry.prevHash !== prevHash) return result(false, entry.seq, "prev_hash does not match the preceding entry");
      const recomputed = this.digest(prevHash, entry);
      const a = Buffer.from(recomputed, "hex");
      const b = Buffer.from(entry.hash, "hex");
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return result(false, entry.seq, "entry content does not match its MAC");
      prevHash = entry.hash;
      expectedSeq += 1;
      checked += 1;
    }
    if (checkpoint === "invalid") return result(false, null, "the head checkpoint is malformed or does not match its MAC");
    if (checkpoint) {
      if (checkpoint.seq > checked) {
        return result(
          false,
          checked + 1,
          `the chain ends at seq ${checked} but the head checkpoint records seq ${checkpoint.seq}: the newest entries were removed`,
        );
      }
      if (checkpoint.seq < checked) {
        return result(false, checkpoint.seq + 1, `the head checkpoint records seq ${checkpoint.seq} but the chain continues to seq ${checked}`);
      }
      if (checkpoint.hash !== prevHash) return result(false, checkpoint.seq, "the newest entry does not match the head checkpoint");
    }
    return result(true, null, null);
  }

  private fromRow(row: AuditRow): AuditEntry {
    return {
      seq: row.seq,
      ts: row.ts,
      actor: row.actor,
      role: row.role,
      action: row.action,
      tenantId: row.tenant_id,
      target: row.target,
      outcome: row.outcome,
      details: parseJsonColumn<Record<string, unknown>>(row.details_json, {}),
      prevHash: row.prev_hash,
      hash: row.hash,
    };
  }
}
