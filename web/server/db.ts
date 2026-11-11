import { Database } from "bun:sqlite";
import { log } from "./logger.ts";

/**
 * Web-bridge-owned SQLite store. It never shares tables with the Rust core: core databases
 * are only read here, and core state changes go through the `sentra` CLI.
 */

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "initial web bridge schema",
    sql: `
      CREATE TABLE web_sessions (
        id_hash TEXT PRIMARY KEY NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
        label TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      );
      CREATE INDEX idx_web_sessions_expires ON web_sessions(expires_at);

      CREATE TABLE tenants (
        tenant_id TEXT PRIMARY KEY NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 64),
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        workspace TEXT NOT NULL,
        isolation_level TEXT NOT NULL CHECK(isolation_level IN ('single_operator','multi_tenant_isolated')),
        github_owner TEXT,
        github_repo TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        imported_from TEXT
      );

      CREATE TABLE settings (
        key TEXT PRIMARY KEY NOT NULL,
        value_json TEXT NOT NULL CHECK(json_valid(value_json)),
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
      );

      CREATE TABLE secrets (
        name TEXT PRIMARY KEY NOT NULL,
        ciphertext TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
      );

      CREATE TABLE audit_log (
        seq INTEGER PRIMARY KEY NOT NULL CHECK(seq > 0),
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        tenant_id TEXT,
        target TEXT,
        outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','denied')),
        details_json TEXT NOT NULL CHECK(json_valid(details_json)),
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE
      );
      CREATE INDEX idx_audit_log_tenant ON audit_log(tenant_id, seq);
      CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
      CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

      CREATE TABLE scan_runs (
        run_id TEXT PRIMARY KEY NOT NULL,
        tenant_id TEXT NOT NULL,
        workspace TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('sast','dependency','codeql','all','webhook','pr')),
        trigger TEXT NOT NULL CHECK(trigger IN ('operator','webhook','pull_request')),
        status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
        started_at TEXT NOT NULL,
        finished_at TEXT,
        actor TEXT NOT NULL,
        files_scanned INTEGER,
        signals_found INTEGER,
        packages_audited INTEGER,
        vulnerable_packages INTEGER,
        advisory_db_stale INTEGER,
        core_session_id TEXT,
        git_head TEXT,
        error TEXT,
        summary_json TEXT CHECK(summary_json IS NULL OR json_valid(summary_json))
      );
      CREATE INDEX idx_scan_runs_tenant ON scan_runs(tenant_id, started_at);

      CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY NOT NULL,
        tenant_id TEXT NOT NULL,
        workspace TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        source TEXT NOT NULL CHECK(source IN ('sast','dependency')),
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        cwe TEXT,
        severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low','Informational','Unknown')),
        category TEXT,
        file_path TEXT,
        line INTEGER,
        snippet TEXT,
        rationale TEXT,
        package_name TEXT,
        package_version TEXT,
        advisory_id TEXT,
        details_json TEXT CHECK(details_json IS NULL OR json_valid(details_json)),
        first_seen_run TEXT NOT NULL,
        last_seen_run TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','resolved')),
        resolved_run TEXT,
        resolved_at TEXT,
        triage_verdict TEXT CHECK(triage_verdict IS NULL OR triage_verdict IN ('confirmed','needs_validation','rejected')),
        triage_reason TEXT,
        triaged_by TEXT,
        triaged_at TEXT,
        UNIQUE(tenant_id, workspace, fingerprint)
      );
      CREATE INDEX idx_findings_tenant_state ON findings(tenant_id, state);

      CREATE TABLE patch_bundles (
        bundle_id TEXT PRIMARY KEY NOT NULL,
        tenant_id TEXT NOT NULL,
        workspace TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        title TEXT NOT NULL,
        target_path TEXT NOT NULL,
        diff TEXT NOT NULL,
        root_cause TEXT,
        rationale TEXT,
        original_snippet TEXT,
        patched_snippet TEXT,
        test_code TEXT,
        branch_name TEXT,
        commit_message TEXT,
        applies_cleanly INTEGER NOT NULL CHECK(applies_cleanly IN (0,1)),
        apply_check_detail TEXT,
        verification_status TEXT NOT NULL CHECK(verification_status IN ('not_run')),
        state TEXT NOT NULL CHECK(state IN ('proposed','applied','rolled_back')),
        applied_at TEXT,
        applied_by TEXT,
        backup_path TEXT,
        rolled_back_at TEXT,
        rolled_back_by TEXT,
        pr_number INTEGER,
        pr_url TEXT
      );
      CREATE INDEX idx_patch_bundles_tenant ON patch_bundles(tenant_id, created_at);

      CREATE TABLE webhook_deliveries (
        provider TEXT NOT NULL CHECK(provider IN ('github','gitlab')),
        delivery_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        received_at TEXT NOT NULL,
        repository TEXT,
        ref TEXT,
        after_sha TEXT,
        sender TEXT,
        signature_valid INTEGER NOT NULL CHECK(signature_valid IN (0,1)),
        status TEXT NOT NULL CHECK(status IN ('rejected','duplicate','ignored','accepted','scanned','failed')),
        detail TEXT,
        tenant_id TEXT,
        run_id TEXT,
        payload_sha256 TEXT,
        PRIMARY KEY(provider, delivery_id)
      );
      CREATE INDEX idx_webhook_received ON webhook_deliveries(received_at);

      CREATE TABLE pr_scans (
        repository TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        head_sha TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        scanned_by TEXT NOT NULL,
        files_considered INTEGER NOT NULL,
        files_scanned INTEGER NOT NULL,
        signals_found INTEGER NOT NULL,
        critical_count INTEGER NOT NULL,
        high_count INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('clean','warnings','critical','failed')),
        matches_json TEXT NOT NULL CHECK(json_valid(matches_json)),
        skipped_json TEXT NOT NULL CHECK(json_valid(skipped_json)),
        error TEXT,
        PRIMARY KEY(repository, pr_number, head_sha)
      );

      CREATE TABLE coverage_units (
        tenant_id TEXT NOT NULL,
        coverage_id TEXT NOT NULL,
        surface TEXT NOT NULL,
        boundary TEXT NOT NULL,
        subsystem TEXT NOT NULL,
        attack_class TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('planned','candidate','covered','needs_validation','deferred','blocked','out_of_scope')),
        wave INTEGER NOT NULL DEFAULT 0 CHECK(wave >= 0),
        owner TEXT,
        reviewed_paths_json TEXT NOT NULL CHECK(json_valid(reviewed_paths_json)),
        local_checks_json TEXT NOT NULL CHECK(json_valid(local_checks_json)),
        result_fingerprints_json TEXT NOT NULL CHECK(json_valid(result_fingerprints_json)),
        unresolved TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        PRIMARY KEY(tenant_id, coverage_id)
      );

      CREATE TABLE recon_reports (
        report_id TEXT PRIMARY KEY NOT NULL,
        tenant_id TEXT NOT NULL,
        workspace TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('topology','model')),
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        provider TEXT,
        model TEXT,
        content_json TEXT NOT NULL CHECK(json_valid(content_json))
      );
      CREATE INDEX idx_recon_reports_tenant ON recon_reports(tenant_id, created_at);

      CREATE TABLE osv_cache (
        vuln_id TEXT PRIMARY KEY NOT NULL,
        modified TEXT,
        fetched_at TEXT NOT NULL,
        record_json TEXT NOT NULL CHECK(json_valid(record_json))
      );
    `,
  },
  {
    version: 2,
    name: "bind console sessions to the token grant that created them",
    // Sessions created before this migration cannot be tied to a grant, so they end here and
    // their holders sign in again. A session now stays valid only while its exact grant is
    // configured: rotating or removing a token ends the sessions it created.
    sql: `
      DELETE FROM web_sessions;
      ALTER TABLE web_sessions ADD COLUMN grant_fingerprint TEXT NOT NULL DEFAULT '';
    `,
  },
  {
    version: 3,
    name: "codeql findings with an origin",
    // SQLite cannot change a CHECK constraint, so the table is rebuilt. Existing rows keep every
    // value and get origin NULL (only CodeQL findings carry an origin; the last CHECK holds both ways).
    sql: `
      CREATE TABLE findings_v3 (
        finding_id TEXT PRIMARY KEY NOT NULL,
        tenant_id TEXT NOT NULL,
        workspace TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        source TEXT NOT NULL CHECK(source IN ('sast','dependency','codeql')),
        origin TEXT CHECK(origin IS NULL OR origin IN ('host_analysis','sarif_import','github_code_scanning')),
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        cwe TEXT,
        severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low','Informational','Unknown')),
        category TEXT,
        file_path TEXT,
        line INTEGER,
        snippet TEXT,
        rationale TEXT,
        package_name TEXT,
        package_version TEXT,
        advisory_id TEXT,
        details_json TEXT CHECK(details_json IS NULL OR json_valid(details_json)),
        first_seen_run TEXT NOT NULL,
        last_seen_run TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','resolved')),
        resolved_run TEXT,
        resolved_at TEXT,
        triage_verdict TEXT CHECK(triage_verdict IS NULL OR triage_verdict IN ('confirmed','needs_validation','rejected')),
        triage_reason TEXT,
        triaged_by TEXT,
        triaged_at TEXT,
        UNIQUE(tenant_id, workspace, fingerprint),
        CHECK((source = 'codeql') = (origin IS NOT NULL))
      );
      INSERT INTO findings_v3 (finding_id, tenant_id, workspace, fingerprint, source, origin, rule_id, rule_name, cwe, severity,
        category, file_path, line, snippet, rationale, package_name, package_version, advisory_id, details_json, first_seen_run,
        last_seen_run, first_seen_at, last_seen_at, state, resolved_run, resolved_at, triage_verdict, triage_reason, triaged_by, triaged_at)
      SELECT finding_id, tenant_id, workspace, fingerprint, source, NULL, rule_id, rule_name, cwe, severity,
        category, file_path, line, snippet, rationale, package_name, package_version, advisory_id, details_json, first_seen_run,
        last_seen_run, first_seen_at, last_seen_at, state, resolved_run, resolved_at, triage_verdict, triage_reason, triaged_by, triaged_at
      FROM findings;
      DROP TABLE findings;
      ALTER TABLE findings_v3 RENAME TO findings;
      CREATE INDEX idx_findings_tenant_state ON findings(tenant_id, state);
      CREATE INDEX idx_findings_scope ON findings(tenant_id, workspace, source, origin, state);
    `,
  },
];

export const WEB_DB_SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1].version;

export function nowIso(): string {
  return new Date().toISOString();
}

export function openWebDb(dbPath: string): Database {
  const db = new Database(dbPath, { create: true, strict: true });
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA busy_timeout = 5000;");
  db.exec("PRAGMA synchronous = NORMAL;");
  db.exec(
    "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at TEXT NOT NULL);",
  );
  const applied = new Set(
    (db.query("SELECT version FROM schema_migrations").all() as { version: number }[]).map((row) => row.version),
  );
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    const apply = db.transaction(() => {
      db.exec(migration.sql);
      db.query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)").run(
        migration.version,
        migration.name,
        nowIso(),
      );
    });
    apply();
    log.info("web database migration applied", { version: migration.version, name: migration.name });
  }
  return db;
}

export function parseJsonColumn<T>(value: unknown, fallback: T): T {
  if (typeof value !== "string" || value.length === 0) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
