import { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { CodeqlIngestView, CodeqlSettingsView, FindingView, ScanStreamEvent } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { AuditLog } from "../audit-log.ts";
import { checkCodeqlLauncher, resolveCodeqlBinary, type CodeqlLauncherProbes } from "../codeql-launcher.ts";
import { parseTokenGrants, type ServerConfig } from "../config.ts";
import { MIGRATIONS, openWebDb } from "../db.ts";
import { ExecutableLocator } from "../executables.ts";
import { GitHubService, type GitHubFetcher } from "../github.ts";
import { HostPlatform } from "../host-platform.ts";
import { HttpError } from "../http-error.ts";
import type { Router } from "../http.ts";
import { createApp, handleRequest } from "../main.ts";
import { cliFailure, MAX_CORE_MESSAGE_CHARS, sanitizeCoreMessage, SentraCli, type CliResult, type CliRunOptions } from "../sentra-cli.ts";
import { sseResponse } from "../http.ts";
import { codeqlAnalysisOutcome, codeqlOriginBreakdown, codeqlOutcomeLabel } from "../../src/components/dashboard/findings-format.ts";
import {
  analysisPrecondition,
  CODEQL_IMPORT_MAX_BYTES,
  codeqlCandidates,
  createCodeqlService,
  cweFromTags,
  defaultCodeqlSettings,
  GITHUB_ALERTS_CAP,
  interpretAnalysis,
  languageScope,
  ranRules,
  SARIF_PRECHECK_MAX_BYTES,
  mapGithubAlert,
  parseCodeqlCliOutput,
  parseCodeqlSettings,
  parseCodeqlSettingsUpdate,
  safeRelativePath,
} from "../services/codeql.ts";
import { findingCounts, listFindings, reconcileFindings, type CandidateFinding } from "../services/findings.ts";
import { createOsvServiceFrom, OsvClient } from "../services/osv.ts";
import { createScanService, lastResultRunAt } from "../services/scans.ts";
import { SettingsStore } from "../services/settings-store.ts";
import type { TenantRecord } from "../services/workspaces.ts";
import { ToolPathStore } from "../tool-paths.ts";
import { elfHeader, ELF_X64, hostExecutableName, hostNativeHeader, peHeader, PE_X64 } from "./native-header.ts";

const cleanup: { dirs: string[]; dbs: Database[] } = { dirs: [], dbs: [] };

afterAll(() => {
  for (const db of cleanup.dbs) {
    try {
      db.close();
    } catch {
      // already closed
    }
  }
  for (const dir of cleanup.dirs) fs.rmSync(dir, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  cleanup.dirs.push(dir);
  return dir;
}

function tempDb(): Database {
  const db = openWebDb(path.join(tempDir("sentra-codeql-db-"), "web.db"));
  cleanup.dbs.push(db);
  return db;
}

/** A CodeQL distribution layout on disk (launcher, tools/, .codeqlmanifest.json, LICENSE.md); nothing in it can run. */
function fakeDistribution(): string {
  const dir = tempDir("sentra-codeql-dist-");
  const launcher = path.join(dir, hostExecutableName("codeql"));
  fs.writeFileSync(launcher, process.platform === "win32" ? hostNativeHeader() : "#!/bin/sh\nexit 3\n", { mode: 0o755 });
  fs.mkdirSync(path.join(dir, "tools"));
  fs.writeFileSync(path.join(dir, ".codeqlmanifest.json"), "{}");
  fs.writeFileSync(path.join(dir, "LICENSE.md"), "GitHub CodeQL Terms and Conditions\n");
  return launcher;
}

function cliResult(json: unknown, code = 0, stderr = ""): CliResult {
  const stdout = json === undefined ? "" : JSON.stringify(json);
  return { code, stdout, stderr, json, timedOut: false, durationMs: 3 };
}

function coreError(code: string, message: string, exit = 5): CliResult {
  return cliResult(undefined, exit, JSON.stringify({ schema_version: 1, error: code, message }));
}

function cliFinding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rule_id: "js/sql-injection",
    rule_name: "Database query built from user-controlled sources",
    message: "This query depends on a user-provided value.",
    severity: "high",
    security_severity: 8.8,
    problem_severity: "error",
    precision: "high",
    cwe: ["CWE-89"],
    tags: ["security", "external/cwe/cwe-089"],
    path: "src/db.js",
    start_line: 12,
    end_line: 12,
    start_column: 5,
    end_column: 30,
    fingerprint: "9a8b7c6d5e4f3a2b:1",
    help_uri: "https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/",
    language: "javascript",
    ...overrides,
  };
}

function cliDocument(command: "codeql analyze" | "codeql import", overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: 1,
    command,
    workspace: "/ws",
    codeql_version: "2.27.4",
    suite: command === "codeql analyze" ? "code-scanning" : null,
    pack_download_allowed: false,
    target_code_executed: false,
    languages: [
      { language: "javascript", status: "analyzed", reason: null, results: 1, duration_ms: 4000 },
      { language: "go", status: "skipped", reason: "requires building the project, which Sentra does not do on the host", results: 0, duration_ms: null },
    ],
    findings: [cliFinding()],
    results_total: 1,
    results_outside_workspace: 0,
    truncated: false,
    warnings: [],
    source_tool: { name: "CodeQL", version: "2.27.4" },
    ...overrides,
  };
}

function sarif(driver = "CodeQL"): string {
  return JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: driver, version: "2.27.4" } }, results: [] }] });
}

// ───────────────────────────── launcher rules (SENTRA_CODEQL_BIN) ─────────────────────────────

function launcherProbes(files: Record<string, { kind: "file" | "directory"; bytes?: Uint8Array; exec?: boolean; real?: string }>, listings: Record<string, string[]> = {}): CodeqlLauncherProbes {
  return {
    kind: (target) => files[target]?.kind ?? "missing",
    isExecutable: (target) => files[target]?.exec !== false,
    readHeader: (target) => files[target]?.bytes ?? new Uint8Array(),
    realpath: (target) => files[target]?.real ?? target,
    listDirectory: (dir) => listings[dir] ?? [],
  };
}

const POSIX_LAUNCHER = new TextEncoder().encode("#!/bin/sh\nset -e\n");

describe("CodeQL launcher rules (SENTRA_CODEQL_BIN)", () => {
  test("Windows: only a codeql.exe with a PE header inside a CodeQL distribution", () => {
    const files = {
      "D:\\CodeQL\\codeql.exe": { kind: "file" as const, bytes: peHeader(PE_X64) },
      "D:\\CodeQL\\codeql.cmd": { kind: "file" as const, bytes: new TextEncoder().encode("@echo off\r\n") },
      "D:\\CodeQL\\tools": { kind: "directory" as const },
      "D:\\CodeQL\\.codeqlmanifest.json": { kind: "file" as const },
      "D:\\Other\\codeql.exe": { kind: "file" as const, bytes: peHeader(PE_X64) },
      "D:\\Linux\\codeql.exe": { kind: "file" as const, bytes: elfHeader(ELF_X64) },
      "D:\\CodeQL\\scanner.exe": { kind: "file" as const, bytes: peHeader(PE_X64) },
    };
    const probes = launcherProbes(files);
    expect(resolveCodeqlBinary("D:\\CodeQL\\codeql.exe", "win32", probes)).toEqual({ file: "D:\\CodeQL\\codeql.exe" });
    expect(resolveCodeqlBinary('"D:\\CodeQL\\codeql.exe"', "win32", probes)).toEqual({ file: "D:\\CodeQL\\codeql.exe" });
    expect(resolveCodeqlBinary(null, "win32", probes)).toEqual({ file: null });
    const problem = (input: string) => {
      const result = resolveCodeqlBinary(input, "win32", probes);
      return "problem" in result ? result.problem : null;
    };
    expect(problem("D:\\CodeQL\\codeql.cmd")).toContain("never codeql.cmd or a batch file");
    expect(problem("D:\\Other\\codeql.exe")).toContain("has no tools directory");
    expect(problem("D:\\Linux\\codeql.exe")).toContain("is not a Windows (PE) executable");
    expect(problem("\\\\server\\share\\codeql.exe")).toContain("UNC");
    expect(problem("codeql.exe")).toContain("absolute path");
    expect(problem("D:\\missing\\codeql.exe")).toContain("Nothing exists");
    expect(problem("D:\\CodeQL\\scanner.exe")).toContain("is not named codeql.exe");
  });

  test("macOS/Linux: the launcher script is accepted inside a distribution (followed through a symlink), refused elsewhere", () => {
    const files = {
      "/usr/local/bin/codeql": { kind: "file" as const, real: "/opt/codeql/codeql" },
      "/opt/codeql/codeql": { kind: "file" as const, bytes: POSIX_LAUNCHER },
      "/opt/codeql/tools": { kind: "directory" as const },
      "/opt/codeql/javascript/codeql-extractor.yml": { kind: "file" as const },
      "/home/u/codeql": { kind: "file" as const, bytes: POSIX_LAUNCHER },
      "/home/u/noexec/codeql": { kind: "file" as const, bytes: POSIX_LAUNCHER, exec: false },
    };
    const probes = launcherProbes(files, { "/opt/codeql": ["codeql", "tools", "javascript"] });
    // The real file in the distribution is what is run.
    expect(resolveCodeqlBinary("/usr/local/bin/codeql", "linux", probes)).toEqual({ file: "/opt/codeql/codeql" });
    expect(checkCodeqlLauncher("/opt/codeql/codeql", "darwin", probes)).toEqual({ ok: true, file: "/opt/codeql/codeql" });
    const home = resolveCodeqlBinary("/home/u/codeql", "linux", probes);
    expect("problem" in home && home.problem).toContain("is not a CodeQL distribution");
    const noexec = resolveCodeqlBinary("/home/u/noexec/codeql", "linux", probes);
    expect("problem" in noexec && noexec.problem).toContain("not executable");
    const renamed = resolveCodeqlBinary("/opt/codeql/codeql-wrapper", "linux", launcherProbes({ ...files, "/opt/codeql/codeql-wrapper": { kind: "file", bytes: POSIX_LAUNCHER } }, { "/opt/codeql": ["javascript"] }));
    expect("problem" in renamed && renamed.problem).toContain("is not named codeql");
    const relative = resolveCodeqlBinary("bin/codeql", "linux", probes);
    expect("problem" in relative && relative.problem).toContain("absolute path");
  });
});

// ───────────────────────────── settings ─────────────────────────────

const LIMITS = { cpus: 8, memoryMb: 16_384 };

describe("CodeQL settings", () => {
  test("defaults are off, with no accepted terms, code-scanning, 30 minutes and min(4, cpus) threads", () => {
    expect(defaultCodeqlSettings(LIMITS)).toEqual({
      enabled: false,
      termsAcceptedBy: null,
      termsAcceptedAt: null,
      allowPackDownload: false,
      suite: "code-scanning",
      timeoutMinutes: 30,
      threads: 4,
      ramMb: null,
    });
    expect(defaultCodeqlSettings({ cpus: 2, memoryMb: 4096 }).threads).toBe(2);
    // A stored "enabled" without a recorded acceptance is read as disabled; out-of-range values fall back.
    expect(parseCodeqlSettings({ enabled: true, timeoutMinutes: 999, threads: 0, suite: "everything", ramMb: 10 }, LIMITS)).toMatchObject({
      enabled: false,
      timeoutMinutes: 30,
      threads: 4,
      suite: "code-scanning",
      ramMb: null,
    });
  });

  test("enabling requires acceptTerms: true in the same request; bounds are enforced", () => {
    const expectCode = (body: Record<string, unknown>, code: string) => {
      try {
        parseCodeqlSettingsUpdate(body, LIMITS);
        throw new Error("accepted");
      } catch (error) {
        expect(error).toBeInstanceOf(HttpError);
        expect((error as HttpError).code).toBe(code);
      }
    };
    expectCode({ enabled: true }, "codeql_terms_required");
    expectCode({ enabled: true, acceptTerms: false }, "codeql_terms_required");
    expectCode({ timeoutMinutes: 4 }, "invalid_request");
    expectCode({ timeoutMinutes: 181 }, "invalid_request");
    expectCode({ threads: 9 }, "invalid_request");
    expectCode({ ramMb: 512 }, "invalid_request");
    expectCode({ suite: "all" }, "invalid_request");
    expectCode({ shell: "rm -rf /" }, "invalid_request");
    expect(parseCodeqlSettingsUpdate({ enabled: true, acceptTerms: true, ramMb: null, threads: 8 }, LIMITS)).toEqual({ enabled: true, acceptTerms: true, ramMb: null, threads: 8 });

    const service = createCodeqlService(new SettingsStore(tempDb()), { dataDir: tempDir("sentra-codeql-data-") }, LIMITS);
    expect(service.analysisEnabled()).toBe(false);
    const enabled = service.update({ enabled: true, acceptTerms: true }, "admin");
    expect(enabled).toMatchObject({ enabled: true, termsAcceptedBy: "admin" });
    expect(service.analysisEnabled()).toBe(true);
    expect(service.update({ enabled: false }, "admin")).toMatchObject({ enabled: false, termsAcceptedBy: "admin" });
    expect(service.packCache.endsWith("codeql-packages")).toBe(true);
  });

  test("skip reasons before the lock: disabled, terms, core and launcher", () => {
    const settings = defaultCodeqlSettings(LIMITS);
    const launcher = { path: "/opt/codeql/codeql", source: "process_path" as const, problem: null };
    expect(analysisPrecondition(settings, launcher, true)?.reason).toBe("disabled");
    expect(analysisPrecondition({ ...settings, enabled: true }, launcher, true)?.reason).toBe("terms_not_accepted");
    const accepted = { ...settings, enabled: true, termsAcceptedAt: "2026-11-11T00:00:00.000Z", termsAcceptedBy: "admin" };
    expect(analysisPrecondition(accepted, launcher, false)?.reason).toBe("core_unavailable");
    expect(analysisPrecondition(accepted, { path: null, source: null, problem: "none found" }, true)).toEqual({
      reason: "launcher_unavailable",
      message: "No codeql launcher can be run: none found",
    });
    expect(analysisPrecondition(accepted, launcher, true)).toBeNull();
  });
});

// ───────────────────────────── CLI output mapping ─────────────────────────────

describe("sentra codeql analyze/import JSON", () => {
  test("maps findings, drops escaping paths (counted) and invalid entries, and checks the contract", () => {
    const doc = parseCodeqlCliOutput(
      cliDocument("codeql import", {
        findings: [
          cliFinding(),
          cliFinding({ path: "../outside.js", fingerprint: "x:1" }),
          cliFinding({ path: "C:\\Windows\\x.js", fingerprint: "y:1" }),
          cliFinding({ path: "/etc/passwd", fingerprint: "z:1" }),
          cliFinding({ severity: "catastrophic" }),
          cliFinding({ rule_id: "py/xss", path: "app\\views.py", severity: "medium", security_severity: null, language: "python", fingerprint: "f".repeat(64), help_uri: "javascript:alert(1)" }),
        ],
        results_outside_workspace: 2,
      }),
      "codeql import",
    );
    expect(doc.findings.map((finding) => finding.path)).toEqual(["src/db.js", "app/views.py"]);
    expect(doc.resultsOutsideWorkspace).toBe(5);
    expect(doc.findings[1].helpUri).toBeNull();
    const candidates = codeqlCandidates(doc, "sarif_import");
    expect(candidates[0]).toMatchObject({ source: "codeql", origin: "sarif_import", severity: "High", cwe: "CWE-89", filePath: "src/db.js", line: 12, category: "CODEQL" });
    expect(candidates[0].codeql).toMatchObject({ origin: "sarif_import", language: "javascript", securitySeverity: 8.8, fingerprintSource: "sarif_partial_fingerprint", toolVersion: "2.27.4" });
    expect(candidates[1].codeql?.fingerprintSource).toBe("cli_digest");
    expect(candidates[1].severity).toBe("Medium");
    // The same result under another origin is another finding.
    expect(codeqlCandidates(doc, "host_analysis")[0].fingerprint).not.toBe(candidates[0].fingerprint);

    expect(() => parseCodeqlCliOutput({ ...cliDocument("codeql import"), schema_version: 2 }, "codeql import")).toThrow("schema_version");
    expect(() => parseCodeqlCliOutput(cliDocument("codeql analyze"), "codeql import")).toThrow("command");
    expect(parseCodeqlCliOutput({ ...cliDocument("codeql analyze"), target_code_executed: undefined }, "codeql analyze").targetCodeExecuted).toBe(true);
  });

  test("relative path rules", () => {
    expect(safeRelativePath("src/./a.js")).toBe("src/a.js");
    expect(safeRelativePath("src\\a.js")).toBe("src/a.js");
    for (const bad of ["", "/abs", "C:/x", "c:x", "a/../../b", "..", "file:///etc/passwd", "a\u0000b", 5]) expect(safeRelativePath(bad)).toBeNull();
  });
});

// ───────────────────────────── reconciliation scoping ─────────────────────────────

function codeqlCandidate(origin: "host_analysis" | "sarif_import", id: string, language: string | null, ruleId = "js/sql-injection"): CandidateFinding {
  const doc = parseCodeqlCliOutput(cliDocument("codeql import", { findings: [cliFinding({ fingerprint: id, language, rule_id: ruleId })] }), "codeql import");
  return codeqlCandidates(doc, origin)[0];
}

/** Rules that ran, per language bucket. */
function ran(entries: Record<string, string[]>): Map<string, Set<string>> {
  return new Map(Object.entries(entries).map(([language, rules]) => [language, new Set(rules)]));
}

describe("reconciliation per (tenant, source, origin)", () => {
  const scope = { tenantId: "t1", workspace: "C:/ws" };

  test("one origin never resolves another's findings, and only covered languages are resolved", () => {
    const db = tempDb();
    reconcileFindings(db, {
      ...scope,
      runId: "run_1",
      at: "2026-11-11T00:00:00.000Z",
      candidates: [codeqlCandidate("host_analysis", "h-js:1", "javascript"), codeqlCandidate("host_analysis", "h-py:1", "python")],
      scopes: [languageScope("host_analysis", ran({ javascript: ["js/sql-injection"], python: ["js/sql-injection"] }), true)],
    });
    reconcileFindings(db, {
      ...scope,
      runId: "cqimport_1",
      at: "2026-11-11T00:01:00.000Z",
      candidates: [codeqlCandidate("sarif_import", "i-js:1", "javascript")],
      scopes: [languageScope("sarif_import", ran({ javascript: ["js/sql-injection"] }), true)],
    });
    reconcileFindings(db, { ...scope, runId: "run_s", at: "2026-11-11T00:01:30.000Z", candidates: [], completedSources: ["sast"] });
    expect(listFindings(db, "t1", "C:/ws", { state: "open", source: "codeql" })).toHaveLength(3);

    // An import of an empty javascript SARIF resolves only the imported javascript finding.
    const imported = reconcileFindings(db, {
      ...scope,
      runId: "cqimport_2",
      at: "2026-11-11T00:02:00.000Z",
      candidates: [],
      scopes: [languageScope("sarif_import", ran({ javascript: ["js/sql-injection"] }), true)],
    });
    expect(imported.resolved).toBe(1);
    expect(listFindings(db, "t1", "C:/ws", { state: "open", origin: "host_analysis" })).toHaveLength(2);

    // Host analysis that analyzed only python leaves the javascript host finding open.
    const python = reconcileFindings(db, {
      ...scope,
      runId: "run_2",
      at: "2026-11-11T00:03:00.000Z",
      candidates: [],
      scopes: [languageScope("host_analysis", ran({ python: ["js/sql-injection"] }), true)],
    });
    expect(python.resolved).toBe(1);
    const open = listFindings(db, "t1", "C:/ws", { state: "open" });
    expect(open.map((finding) => [finding.origin, finding.codeql?.language])).toEqual([["host_analysis", "javascript"]]);

    // A truncated run resolves nothing.
    const truncated = reconcileFindings(db, { ...scope, runId: "run_3", at: "2026-11-11T00:04:00.000Z", candidates: [], scopes: [languageScope("host_analysis", ran({ javascript: ["js/sql-injection"] }), false)] });
    expect(truncated.resolved).toBe(0);
    // SAST reconciliation never touches CodeQL findings.
    expect(listFindings(db, "t1", "C:/ws", { state: "open", source: "codeql" })).toHaveLength(1);
  });

  test("only findings of rules that ran are resolved: switching the query suite fixes nothing", () => {
    // Regression: reconciliation covered whole languages, so a code-scanning run after a
    // security-extended run resolved the findings of queries that no longer ran.
    const db = tempDb();
    const extended = parseCodeqlCliOutput(
      cliDocument("codeql analyze", {
        suite: "security-extended",
        languages: [{ language: "javascript", status: "analyzed", reason: null, results: 2, duration_ms: 1, rules: ["js/sql-injection", "js/extended-only", "js/xss"] }],
        findings: [cliFinding(), cliFinding({ rule_id: "js/extended-only", fingerprint: "e:1", path: "src/b.js" })],
        results_total: 2,
      }),
      "codeql analyze",
    );
    expect(extended.rulesByLanguage.get("javascript")).toEqual(["js/sql-injection", "js/extended-only", "js/xss"]);
    const first = reconcileFindings(db, { ...scope, runId: "run_1", at: "2026-11-11T00:00:00.000Z", candidates: codeqlCandidates(extended, "host_analysis"), scopes: [languageScope("host_analysis", ranRules(extended), true)] });
    expect(first.created).toBe(2);

    // code-scanning on unchanged code: js/extended-only did not run, js/sql-injection still reports.
    const narrow = parseCodeqlCliOutput(
      cliDocument("codeql analyze", {
        languages: [{ language: "javascript", status: "analyzed", reason: null, results: 1, duration_ms: 1, rules: ["js/sql-injection", "js/xss"] }],
      }),
      "codeql analyze",
    );
    const second = reconcileFindings(db, { ...scope, runId: "run_2", at: "2026-11-11T00:01:00.000Z", candidates: codeqlCandidates(narrow, "host_analysis"), scopes: [languageScope("host_analysis", ranRules(narrow), true)] });
    expect(second).toMatchObject({ resolved: 0, stillOpen: 1 });
    expect(listFindings(db, "t1", "C:/ws", { state: "open", source: "codeql" })).toHaveLength(2);

    // The fix: js/sql-injection ran and no longer reports, so only that finding is resolved.
    const fixed = parseCodeqlCliOutput(
      cliDocument("codeql analyze", { languages: [{ language: "javascript", status: "analyzed", reason: null, results: 0, duration_ms: 1, rules: ["js/sql-injection", "js/xss"] }], findings: [], results_total: 0 }),
      "codeql analyze",
    );
    const third = reconcileFindings(db, { ...scope, runId: "run_3", at: "2026-11-11T00:02:00.000Z", candidates: [], scopes: [languageScope("host_analysis", ranRules(fixed), true)] });
    expect(third.resolved).toBe(1);
    expect(listFindings(db, "t1", "C:/ws", { state: "open" }).map((finding) => finding.ruleId)).toEqual(["js/extended-only"]);

    // An older core without rule lists covers only the rules that produced findings.
    const legacy = parseCodeqlCliOutput(cliDocument("codeql analyze", { findings: [], results_total: 0 }), "codeql analyze");
    expect(ranRules(legacy).get("javascript")?.size).toBe(0);

    // Overview counts per origin add up to the CodeQL total.
    const counts = findingCounts(db, "t1", "C:/ws");
    expect(counts.bySource.codeql).toBe(1);
    expect(counts.codeqlByOrigin).toEqual({ host_analysis: 1, sarif_import: 0, github_code_scanning: 0 });
    expect(codeqlOriginBreakdown(counts.codeqlByOrigin)).toBe("host analysis 1");
  });

  test("the database refuses a CodeQL finding without an origin and an origin on a SAST finding", () => {
    const db = tempDb();
    const insert = (source: string, origin: string | null) =>
      db
        .query(
          `INSERT INTO findings (finding_id, tenant_id, workspace, fingerprint, source, origin, rule_id, rule_name, severity, first_seen_run, last_seen_run, first_seen_at, last_seen_at, state)
           VALUES (?, 't1', 'w', ?, ?, ?, 'r', 'r', 'High', 'x', 'x', 'x', 'x', 'open')`,
        )
        .run(crypto.randomUUID(), crypto.randomUUID(), source, origin);
    expect(() => insert("codeql", null)).toThrow();
    expect(() => insert("sast", "sarif_import")).toThrow();
    expect(() => insert("codeql", "elsewhere")).toThrow();
    insert("codeql", "github_code_scanning");
    insert("sast", null);
  });

  test("migration 3 keeps every existing finding and gives it no origin", () => {
    const dir = tempDir("sentra-codeql-migrate-");
    const file = path.join(dir, "web.db");
    const legacy = new Database(file, { create: true, strict: true });
    legacy.exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, applied_at TEXT NOT NULL);");
    for (const migration of MIGRATIONS.filter((entry) => entry.version <= 2)) {
      legacy.exec(migration.sql);
      legacy.query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, 'x')").run(migration.version, migration.name);
    }
    legacy
      .query(
        `INSERT INTO findings (finding_id, tenant_id, workspace, fingerprint, source, rule_id, rule_name, severity, first_seen_run, last_seen_run, first_seen_at, last_seen_at, state, triage_verdict, triage_reason, triaged_by, triaged_at)
         VALUES ('fnd_old', 't1', 'w', 'fp', 'sast', 'SENTRA-SEC-001', 'Key', 'Critical', 'run_1', 'run_1', 'a', 'b', 'open', 'confirmed', 'checked', 'alice', 'c')`,
      )
      .run();
    legacy.close();
    const db = openWebDb(file);
    cleanup.dbs.push(db);
    const [finding] = listFindings(db, "t1", "w", { state: "all" });
    expect(finding).toMatchObject({ findingId: "fnd_old", source: "sast", origin: null, codeql: null, triage: { verdict: "confirmed", reason: "checked", by: "alice", at: "c" } });
  });
});

// ───────────────────────────── GitHub code scanning mapping ─────────────────────────────

function alert(number: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    number,
    state: "open",
    html_url: `https://github.com/o/r/security/code-scanning/${number}`,
    rule: {
      id: "js/xss",
      name: "js/xss",
      severity: "error",
      security_severity_level: "high",
      description: "Client-side cross-site scripting",
      tags: ["security", "external/cwe/cwe-079", "external/cwe/cwe-116"],
    },
    tool: { name: "CodeQL", version: "2.27.4" },
    most_recent_instance: {
      ref: "refs/heads/main",
      category: "/language:javascript-typescript",
      message: { text: "Cross-site scripting vulnerability due to user-provided value." },
      location: { path: "web/src/app.ts", start_line: 7, end_line: 9, start_column: 3, end_column: 20 },
    },
    ...overrides,
  };
}

describe("GitHub code scanning alert mapping", () => {
  test("severity, CWE tags, location, message, URL, number and tool version", () => {
    const mapped = mapGithubAlert(alert(42), "o/r");
    if (!mapped || mapped === "outside") throw new Error("not mapped");
    expect(mapped).toMatchObject({
      source: "codeql",
      origin: "github_code_scanning",
      ruleId: "js/xss",
      ruleName: "Client-side cross-site scripting",
      severity: "High",
      cwe: "CWE-79, CWE-116",
      filePath: "web/src/app.ts",
      line: 7,
      rationale: "Cross-site scripting vulnerability due to user-provided value.",
    });
    expect(mapped.codeql).toMatchObject({
      repository: "o/r",
      alertNumber: 42,
      alertUrl: "https://github.com/o/r/security/code-scanning/42",
      toolVersion: "2.27.4",
      language: "javascript-typescript",
      endLine: 9,
      fingerprintSource: "github_alert_number",
    });
    const noLevel = mapGithubAlert(alert(1, { rule: { id: "py/x", severity: "warning", tags: [] } }), "o/r");
    expect(noLevel !== "outside" && noLevel?.severity).toBe("Low");
    const note = mapGithubAlert(alert(2, { rule: { id: "py/y", severity: "note" } }), "o/r");
    expect(note !== "outside" && note?.severity).toBe("Informational");
    expect(mapGithubAlert(alert(3, { most_recent_instance: { location: { path: "../etc/passwd", start_line: 1 } } }), "o/r")).toBe("outside");
    expect(mapGithubAlert({ rule: { id: "x" } }, "o/r")).toBeNull();
    expect(cweFromTags(["external/cwe/cwe-022", "external/cwe/cwe-22", "security"])).toEqual(["CWE-22"]);
  });
});

// ───────────────────────────── scan stage (fake core CLI) ─────────────────────────────

type CliHandler = (args: string[], options: CliRunOptions) => Promise<CliResult> | CliResult;

function tenantRecord(tenantId: string, workspace: string): TenantRecord {
  return {
    tenantId,
    name: tenantId,
    description: "",
    workspace,
    isolationLevel: "single_operator",
    githubOwner: null,
    githubRepo: null,
    createdAt: "2026-11-01T00:00:00.000Z",
    createdBy: "alice",
    importedFrom: null,
  };
}

function stageHarness(handler: CliHandler, options: { codeqlBin?: string | null; tenants?: string[] } = {}) {
  const db = tempDb();
  const settings = new SettingsStore(db);
  const dataDir = tempDir("sentra-codeql-data-");
  const tmpDir = path.join(dataDir, "tmp");
  const codeql = createCodeqlService(settings, { dataDir }, LIMITS);
  const tenants = new Map((options.tenants ?? ["t1"]).map((id) => [id, tenantRecord(id, tempDir(`sentra-codeql-ws-${id}-`))]));
  const calls: string[][] = [];
  const cli = {
    available: () => true,
    run: async (args: string[], runOptions: CliRunOptions = {}) => {
      calls.push(args);
      return handler(args, runOptions);
    },
  };
  const empty = tempDir("sentra-codeql-path-");
  const executables = new ExecutableLocator({ env: { PATH: empty, PATHEXT: ".EXE" }, homedir: empty, isDirectory: () => false });
  const app = {
    db,
    settings,
    audit: new AuditLog(db, crypto.randomBytes(32)),
    cli,
    osv: createOsvServiceFrom({ settings, client: new OsvClient(db, settings, async () => ({ status: 500, text: "" })), runInventory: async () => ({}) }),
    config: { cliLongTimeoutMs: 5_000, cliTimeoutMs: 5_000, ghBin: null, codeqlBin: options.codeqlBin ?? null, tmpDir, dataDir },
    codeql,
    executables,
    hostPlatform: new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null }),
    toolPaths: new ToolPathStore(settings),
    workspaces: {
      get: (tenantId: string) => {
        const tenant = tenants.get(tenantId);
        if (!tenant) throw new HttpError(404, "tenant_not_found", "not registered");
        return tenant;
      },
      workspaceRoot: (tenant: TenantRecord) => tenant.workspace,
    },
  } as unknown as Omit<AppContext, "scans">;
  return { db, codeql, calls, tmpDir, dataDir, tenants, service: createScanService(app) };
}

const actor = { label: "alice", role: "operator" };
const PROBE = { primary_language: "javascript", detected_languages: [{ language: "javascript", files_count: 3 }], database_create_command: null, database_analyze_command: null };

function codeqlStage(events: ScanStreamEvent[]): { status: string; message: string } {
  const event = events.find((entry) => entry.type === "stage" && entry.stage === "codeql" && entry.status !== "started");
  return event && event.type === "stage" ? { status: event.status, message: event.message } : { status: "missing", message: "" };
}

describe("scan CodeQL stage", () => {
  test("disabled by default: only the language probe runs and the stage says why", async () => {
    const h = stageHarness((args) => (args[1] === "analyze" ? Promise.reject(new Error("must not run")) : cliResult(PROBE)), { codeqlBin: fakeDistribution() });
    const events: ScanStreamEvent[] = [];
    const run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("completed");
    expect(run.summary?.codeqlAnalysis).toMatchObject({ attempted: false, skipReason: "disabled" });
    expect(codeqlStage(events).message).toContain("CodeQL host analysis did not run: CodeQL host analysis is disabled (the default)");
    expect(h.calls.map((args) => args.slice(0, 2).join(" "))).toEqual(["codeql --workspace"]);
  });

  test("enabled: runs `sentra codeql analyze` with the decided flags, stores host-analysis findings and removes the work directory", async () => {
    const launcher = fakeDistribution();
    let workDir = "";
    let workDirExisted = false;
    let timeoutMs = 0;
    let cancelViaStdinEof: boolean | undefined;
    const h = stageHarness(
      (args, options) => {
        if (args[1] !== "analyze") return cliResult(PROBE);
        workDir = args[args.indexOf("--work-dir") + 1];
        workDirExisted = fs.existsSync(workDir);
        timeoutMs = options.timeoutMs ?? 0;
        cancelViaStdinEof = options.cancelViaStdinEof;
        return cliResult(cliDocument("codeql analyze"));
      },
      { codeqlBin: launcher },
    );
    h.codeql.update({ enabled: true, acceptTerms: true, allowPackDownload: true, suite: "security-extended", timeoutMinutes: 10, threads: 2, ramMb: 2048 }, "admin");
    const events: ScanStreamEvent[] = [];
    const run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("completed");
    const analyze = h.calls.find((args) => args[1] === "analyze")!;
    const flag = (name: string) => analyze[analyze.indexOf(name) + 1];
    expect(flag("--workspace")).toBe(h.tenants.get("t1")!.workspace);
    expect(flag("--codeql")).toBe(launcher);
    expect(flag("--pack-cache")).toBe(path.join(h.dataDir, "codeql-packages"));
    expect(flag("--suite")).toBe("security-extended");
    expect(flag("--threads")).toBe("2");
    expect(flag("--ram")).toBe("2048");
    expect(flag("--timeout-secs")).toBe("600");
    expect(analyze).toContain("--accept-codeql-terms");
    expect(analyze).toContain("--allow-pack-download");
    expect(analyze).toContain("--json");
    // Cancelling the scan closes the core's stdin, so the core stops CodeQL before the lock is released.
    expect(analyze).toContain("--cancel-on-stdin-eof");
    expect(cancelViaStdinEof).toBe(true);
    expect(analyze.some((arg) => /build-mode|autobuild|--command/.test(arg))).toBe(false);
    expect(path.dirname(workDir)).toBe(h.tmpDir);
    expect(workDirExisted).toBe(true);
    expect(fs.existsSync(workDir)).toBe(false);
    // The bridge gives the core its own timeout plus a margin before stopping it.
    expect(timeoutMs).toBe(600_000 + 120_000);
    expect(run.summary?.codeqlAnalysis).toMatchObject({ outcome: "analyzed", attempted: true, skipReason: null, codeqlVersion: "2.27.4", resultsTotal: 1 });
    expect(codeqlStage(events)).toMatchObject({ status: "completed" });
    expect(codeqlStage(events).message).toContain("target code was not executed");
    expect(codeqlStage(events).message).toContain("go skipped: requires building the project");
    const [finding] = listFindings(h.db, "t1", h.tenants.get("t1")!.workspace, { state: "open" });
    expect(finding).toMatchObject({ source: "codeql", origin: "host_analysis", ruleId: "js/sql-injection", severity: "High" });

    // Without download permission and RAM limit the flags are left out.
    h.codeql.update({ allowPackDownload: false, ramMb: null }, "admin");
    await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor });
    const second = h.calls.filter((args) => args[1] === "analyze")[1];
    expect(second).not.toContain("--allow-pack-download");
    expect(second).not.toContain("--ram");
  });

  test("missing query packs, languages that need a build and a missing launcher are skips, not failures", async () => {
    // The core attaches its partial per-language report to the error.
    let analyzeResult: CliResult = cliResult(
      undefined,
      6,
      JSON.stringify({
        schema_version: 1,
        error: "codeql_query_pack_missing",
        message: "codeql/javascript-queries is not in the pack cache",
        command: "codeql analyze",
        codeql_version: "2.27.4",
        target_code_executed: false,
        languages: [{ language: "javascript", status: "skipped", reason: "query pack codeql/javascript-queries is missing", results: 0, duration_ms: null }],
        warnings: [],
      }),
    );
    const h = stageHarness((args) => (args[1] === "analyze" ? analyzeResult : cliResult(PROBE)), { codeqlBin: fakeDistribution() });
    h.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    let events: ScanStreamEvent[] = [];
    let run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("completed");
    expect(run.summary?.codeqlAnalysis).toMatchObject({
      attempted: true,
      skipReason: "packs_missing",
      codeqlVersion: "2.27.4",
      languages: [{ language: "javascript", status: "skipped", reason: "query pack codeql/javascript-queries is missing" }],
    });
    expect(codeqlStage(events).message).toContain("pack download is off");

    analyzeResult = cliResult(
      cliDocument("codeql analyze", {
        languages: [{ language: "go", status: "skipped", reason: "requires building the project, which Sentra does not do on the host", results: 0, duration_ms: null }],
        findings: [],
        results_total: 0,
      }),
    );
    events = [];
    run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.summary?.codeqlAnalysis).toMatchObject({ skipReason: "languages_need_build" });
    expect(codeqlStage(events)).toMatchObject({ status: "completed" });
    expect(codeqlStage(events).message).toContain("Sentra does not build projects or run their code on the host");

    const noLauncher = stageHarness((args) => (args[1] === "analyze" ? Promise.reject(new Error("must not run")) : cliResult(PROBE)));
    noLauncher.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    events = [];
    run = await noLauncher.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.summary?.codeqlAnalysis).toMatchObject({ attempted: false, skipReason: "launcher_unavailable" });
    expect(codeqlStage(events).message).toContain("SENTRA_CODEQL_BIN");
  });

  test("a failed analysis or a report of executed target code fails the stage and stores nothing", async () => {
    let analyzeResult: CliResult = cliResult(cliDocument("codeql analyze", { target_code_executed: true }));
    const h = stageHarness((args) => (args[1] === "analyze" ? analyzeResult : cliResult(PROBE)), { codeqlBin: fakeDistribution() });
    h.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    let events: ScanStreamEvent[] = [];
    let run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("failed");
    expect(codeqlStage(events)).toMatchObject({ status: "failed" });
    expect(codeqlStage(events).message).toContain("target_code_executed: false");
    expect(listFindings(h.db, "t1", h.tenants.get("t1")!.workspace, { state: "all" })).toEqual([]);

    analyzeResult = coreError("codeql_timeout", "the analysis exceeded 1800 s");
    events = [];
    run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("failed");
    expect(codeqlStage(events).message).toContain("codeql_timeout");
    expect(run.summary?.codeqlAnalysis?.message).toContain("process tree");

    analyzeResult = { ...cliResult(undefined, 1), timedOut: true };
    run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor });
    expect(run.error).toContain("the bridge stopped `sentra codeql analyze`");

    // codeql_failed names each language's reason, and a Java VM memory failure points at the RAM setting
    // (shape of a real failure on a host short of commit memory, 2026-11-11).
    analyzeResult = cliResult(
      undefined,
      5,
      JSON.stringify({
        schema_version: 1,
        error: "codeql_failed",
        message: "CodeQL failed for every language it was run for (see languages[].reason)",
        command: "codeql analyze",
        codeql_version: "2.27.4",
        target_code_executed: false,
        languages: [
          {
            language: "javascript",
            status: "failed",
            reason: "CodeQL's Java VM could not get the memory it asked for (the host is short of free memory or page file); pass a --ram value that fits the free memory, or free memory on the host. codeql database analyze exited with code 1: OpenJDK 64-Bit Server VM warning: INFO: os::commit_memory(0x0, 658505728, 0) failed (DOS error/errno=1455)",
            results: 0,
            duration_ms: 14558,
          },
        ],
        warnings: [],
      }),
    );
    events = [];
    run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("failed");
    expect(run.summary?.codeqlAnalysis?.languages).toMatchObject([{ language: "javascript", status: "failed" }]);
    expect(run.summary?.codeqlAnalysis?.message).toContain("javascript failed: CodeQL's Java VM could not get the memory");
    expect(run.summary?.codeqlAnalysis?.message).toContain("set a RAM limit in Settings > CodeQL");
    // Regression: a failed analysis was summarised as "analysis ran" with "Results 0".
    expect(run.summary?.codeqlAnalysis).toMatchObject({ outcome: "failed", attempted: true, skipReason: null });
    expect(codeqlOutcomeLabel(run.summary!.codeqlAnalysis!, run.summary!.stageErrors)).toBe("failed");
  });

  test("a mixed run names the RAM setting when one language ran out of memory", () => {
    const memory =
      "CodeQL's Java VM could not get the memory it asked for (the host is short of free memory or page file); pass a --ram value that fits the free memory, or free memory on the host. codeql database analyze exited with code 1";
    const outcome = interpretAnalysis(
      cliResult(
        cliDocument("codeql analyze", {
          languages: [
            { language: "javascript", status: "analyzed", reason: null, results: 1, duration_ms: 1, rules: ["js/sql-injection"] },
            { language: "python", status: "failed", reason: memory, results: 0, duration_ms: 1 },
          ],
        }),
      ),
      defaultCodeqlSettings(LIMITS),
      1800,
      10,
    );
    expect(outcome.status).toBe("completed");
    expect(outcome.view.outcome).toBe("analyzed");
    expect(outcome.view.message).toContain("python failed");
    expect(outcome.view.message).toContain("set a RAM limit in Settings > CodeQL");
  });

  test("the run outcome of runs stored before the outcome field is derived from the stage errors", () => {
    const legacyFailed = { attempted: true, skipReason: null, languages: [] };
    expect(codeqlAnalysisOutcome(legacyFailed, [{ stage: "codeql" }])).toBe("failed");
    expect(codeqlAnalysisOutcome(legacyFailed, [])).toBe("failed");
    expect(codeqlAnalysisOutcome({ ...legacyFailed, languages: [{ language: "javascript", status: "analyzed", reason: null, results: 0, durationMs: 1 }] }, [])).toBe("analyzed");
    expect(codeqlOutcomeLabel({ attempted: true, skipReason: "packs_missing", languages: [] }, [])).toBe("not run (packs missing)");
    expect(codeqlOutcomeLabel({ attempted: false, skipReason: "disabled", languages: [] }, [])).toBe("not run (disabled)");
  });

  test("a run whose host analysis failed is not a run with results", () => {
    const h = stageHarness(() => cliResult(PROBE));
    const workspace = h.tenants.get("t1")!.workspace;
    const insert = (runId: string, finishedAt: string, summary: unknown) =>
      h.db
        .query(
          `INSERT INTO scan_runs (run_id, tenant_id, workspace, kind, trigger, status, started_at, finished_at, actor, summary_json)
           VALUES (?, 't1', ?, 'all', 'operator', 'completed', ?, ?, 'alice', ?)`,
        )
        .run(runId, workspace, finishedAt, finishedAt, JSON.stringify(summary));
    const failedAnalysis = { codeqlAnalysis: { outcome: "failed", attempted: true, skipReason: null, languages: [{ language: "javascript", status: "failed" }] }, stageErrors: [{ stage: "codeql", message: "x" }, { stage: "sast", message: "y" }] };
    insert("run_failed", "2026-11-11T00:05:00.000Z", failedAnalysis);
    expect(lastResultRunAt({ db: h.db }, "t1", workspace)).toBeNull();
    insert("run_ok", "2026-11-11T00:01:00.000Z", { codeqlAnalysis: { outcome: "analyzed", attempted: true, skipReason: null, languages: [{ language: "javascript", status: "analyzed" }] }, stageErrors: [] });
    expect(lastResultRunAt({ db: h.db }, "t1", workspace)).toBe("2026-11-11T00:01:00.000Z");
  });

  test("at most one CodeQL analysis runs on the bridge; a second one is reported as skipped", async () => {
    let releaseFirst: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let analyses = 0;
    const h = stageHarness(
      async (args) => {
        if (args[1] !== "analyze") return cliResult(PROBE);
        analyses += 1;
        await gate;
        return cliResult(cliDocument("codeql analyze"));
      },
      { codeqlBin: fakeDistribution(), tenants: ["t1", "t2"] },
    );
    h.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    const first = h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor });
    while (analyses === 0) await Bun.sleep(5);
    expect(h.codeql.lock.current?.tenantId).toBe("t1");
    const events: ScanStreamEvent[] = [];
    const second = await h.service.run({ tenantId: "t2", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(second.status).toBe("completed");
    expect(second.summary?.codeqlAnalysis).toMatchObject({ attempted: false, skipReason: "analysis_busy" });
    expect(codeqlStage(events).message).toContain("Another CodeQL analysis is running on this bridge (workspace 't1'");
    expect(analyses).toBe(1);
    releaseFirst();
    expect((await first).summary?.codeqlAnalysis?.skipReason).toBeNull();
    expect(h.codeql.lock.current).toBeNull();
  });
});

// ───────────────────────────── routes ─────────────────────────────

const ADMIN_TOKEN = "a".repeat(40);
const OPERATOR_TOKEN = "o".repeat(40);
const VIEWER_TOKEN = "v".repeat(40);
const PORT = 3996;

function bridgeConfig(): ServerConfig {
  const dataDir = tempDir("sentra-codeql-bridge-");
  const tmp = path.join(dataDir, "tmp");
  fs.mkdirSync(tmp);
  return {
    repoRoot: tempDir("sentra-codeql-repo-"),
    webRoot: path.join(import.meta.dir, "..", ".."),
    host: "127.0.0.1",
    port: PORT,
    isLoopbackBind: true,
    production: false,
    staticDir: null,
    sentraBin: path.join(dataDir, "missing-sentra-binary"),
    ghBin: null,
    codeqlBin: null,
    dataDir,
    registryDbPath: path.join(dataDir, "sentra.db"),
    webDbPath: path.join(dataDir, "sentra-web.db"),
    backupDir: path.join(dataDir, "backups"),
    allowedOrigins: new Set([`http://127.0.0.1:${PORT}`]),
    allowedHosts: new Set([`127.0.0.1:${PORT}`]),
    tokenGrants: parseTokenGrants(`admin:${ADMIN_TOKEN},operator:${OPERATOR_TOKEN},viewer:${VIEWER_TOKEN}`),
    generatedAdminToken: null,
    sessionTtlMs: 60_000,
    cookieSecure: false,
    githubWebhookSecret: null,
    gitlabWebhookToken: null,
    githubTokenFromEnv: null,
    secretKey: crypto.randomBytes(32),
    maxBodyBytes: 1024 * 1024,
    cliTimeoutMs: 5_000,
    cliLongTimeoutMs: 5_000,
    cliMaxConcurrency: 1,
    trustProxy: false,
    workspaceRoots: [],
    pluginDir: null,
    tmpDir: tmp,
  };
}

interface FetchCall {
  url: string;
  method: string;
}

function bridge(options: { cli?: CliHandler; fetcher?: GitHubFetcher; repository?: boolean } = {}) {
  const executables = new ExecutableLocator({ env: { PATH: tempDir("sentra-codeql-nopath-") }, homedir: tempDir("sentra-codeql-home-"), isDirectory: () => false });
  const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null });
  const config = bridgeConfig();
  const { app, router } = createApp(config, { executables, hostPlatform });
  cleanup.dbs.push(app.db);
  const workspace = tempDir("sentra-codeql-tenant-");
  app.db
    .query(
      `INSERT INTO tenants (tenant_id, name, description, workspace, isolation_level, github_owner, github_repo, created_at, created_by)
       VALUES ('t1', 'T1', '', ?, 'single_operator', ?, ?, '2026-11-11T00:00:00.000Z', 'admin')`,
    )
    .run(workspace, options.repository === false ? null : "o", options.repository === false ? null : "r");
  const calls: string[][] = [];
  const handler = options.cli;
  (app as { cli: unknown }).cli = {
    available: () => true,
    queued: 0,
    run: async (args: string[], runOptions: CliRunOptions = {}) => {
      calls.push(args);
      if (!handler) throw new Error(`unexpected core call ${args.join(" ")}`);
      return handler(args, runOptions);
    },
    runShared: async () => cliResult({ version: "0.0.0" }),
  };
  const fetches: FetchCall[] = [];
  if (options.fetcher) {
    const fetcher = options.fetcher;
    app.github = new GitHubService(app.secrets, "ghp_testtokentesttokentest0000", config.dataDir, {
      fetcher: async (url, init) => {
        fetches.push({ url, method: String(init.method) });
        return fetcher(url, init);
      },
      ghTokenReader: () => null,
    });
  }
  const server = { requestIP: () => ({ address: "127.0.0.1", family: "IPv4" as const, port: 1 }), timeout: () => undefined };
  const send = async (method: string, pathname: string, token: string, body?: unknown, extra: { contentType?: string; raw?: BodyInit } = {}) => {
    const headers: Record<string, string> = { host: `127.0.0.1:${PORT}`, authorization: `Bearer ${token}` };
    if (body !== undefined || extra.raw !== undefined) headers["content-type"] = extra.contentType ?? "application/json";
    const response = await handleRequest(
      new Request(`http://127.0.0.1:${PORT}${pathname}`, {
        method,
        headers,
        body: extra.raw ?? (body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined),
        // The fetch spec requires duplex for streamed request bodies.
        ...(extra.raw instanceof ReadableStream ? { duplex: "half" } : {}),
      } as RequestInit),
      server,
      app as AppContext,
      router as Router,
    );
    const text = await response.text();
    return { status: response.status, body: text ? (JSON.parse(text) as Record<string, any>) : {} };
  };
  const audits = () => app.audit.list({ limit: 50 }).reverse();
  return { app, router, send, calls, fetches, audits, workspace, config };
}

describe("CodeQL routes", () => {
  test("declare their permissions", () => {
    const { router } = bridge();
    const routes = Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]));
    expect(routes["GET /api/settings/codeql"]).toBe("read");
    expect(routes["PUT /api/settings/codeql"]).toBe("settings:write");
    expect(routes["POST /api/tenants/:tenantId/codeql/import"]).toBe("scan:run");
    expect(routes["POST /api/tenants/:tenantId/codeql/github-sync"]).toBe("scan:run");
    const importRoute = router.list().find((route) => route.path === "/api/tenants/:tenantId/codeql/import");
    expect(importRoute?.options.maxBodyBytes).toBe(CODEQL_IMPORT_MAX_BYTES);
  });

  test("settings: every role reads, only SecurityAdmin writes; enabling needs acceptTerms in the same request; all audited", async () => {
    const h = bridge();
    const read = await h.send("GET", "/api/settings/codeql", VIEWER_TOKEN);
    expect(read.status).toBe(200);
    const view = read.body as CodeqlSettingsView;
    expect(view.settings.enabled).toBe(false);
    expect(view.skipReason).toBe("disabled");
    expect(view.launcher).toMatchObject({ available: false, path: null });
    expect(view.packCache).toBe(path.join(h.config.dataDir, "codeql-packages"));
    expect(view.terms.summary.some((line) => line.includes("Open Source Codebase"))).toBe(true);

    expect((await h.send("PUT", "/api/settings/codeql", VIEWER_TOKEN, { suite: "security-extended" })).status).toBe(403);
    expect((await h.send("PUT", "/api/settings/codeql", OPERATOR_TOKEN, { enabled: true, acceptTerms: true })).status).toBe(403);

    const noTerms = await h.send("PUT", "/api/settings/codeql", ADMIN_TOKEN, { enabled: true });
    expect(noTerms.status).toBe(400);
    expect(noTerms.body.error.code).toBe("codeql_terms_required");
    expect(h.app.codeql.analysisEnabled()).toBe(false);

    const enabled = await h.send("PUT", "/api/settings/codeql", ADMIN_TOKEN, { enabled: true, acceptTerms: true, timeoutMinutes: 45 });
    expect(enabled.status).toBe(200);
    expect((enabled.body as CodeqlSettingsView).settings).toMatchObject({ enabled: true, termsAcceptedBy: "admin", timeoutMinutes: 45 });
    // No launcher on this test host: a scan would not start host analysis, and says why.
    expect((enabled.body as CodeqlSettingsView).skipReason).toBe("launcher_unavailable");

    const entries = h.audits();
    expect(entries.map((entry) => `${entry.action}:${entry.outcome}`)).toEqual([
      "authorization_denied:denied",
      "authorization_denied:denied",
      "codeql_settings_updated:failure",
      "codeql_settings_updated:success",
    ]);
    expect(entries[2].details).toMatchObject({ error: expect.stringContaining("codeql_terms_required") });
    expect(entries[3]).toMatchObject({ actor: "admin", target: "codeql_analysis" });
    expect(entries[3].details).toMatchObject({ enabled: true, termsAccepted: true, termsAcceptedBy: "admin", changes: { enabled: true, acceptTerms: true, timeoutMinutes: 45 } });
    expect(h.app.audit.verify().valid).toBe(true);

    // The tools table now reports codeql as executed.
    const system = await h.send("GET", "/api/system", VIEWER_TOKEN);
    expect(system.body.tools.find((tool: { name: string }) => tool.name === "codeql")).toMatchObject({ usage: "executed", pathConfigurable: false });
  });

  test("import: operator only, validated, bounded, parsed by the core from a private temporary file, stored as sarif_import", async () => {
    let seenFile = "";
    let seenContent = "";
    const h = bridge({
      cli: (args) => {
        expect(args.slice(0, 2)).toEqual(["codeql", "import"]);
        seenFile = args[args.indexOf("--sarif") + 1];
        seenContent = fs.readFileSync(seenFile, "utf8");
        return cliResult(cliDocument("codeql import", { findings: [cliFinding(), cliFinding({ path: "lib/a.js", fingerprint: "b:1" })], results_total: 3, results_outside_workspace: 1 }));
      },
    });
    const body = sarif();
    expect((await h.send("POST", "/api/tenants/t1/codeql/import", VIEWER_TOKEN, body)).status).toBe(403);

    const imported = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, body);
    expect(imported.status).toBe(200);
    const view = imported.body as CodeqlIngestView;
    expect(view).toMatchObject({ origin: "sarif_import", resultsTotal: 3, resultsOutsideWorkspace: 1, findings: { created: 2, resolved: 0 } });
    expect(seenContent).toBe(body);
    expect(path.dirname(path.dirname(seenFile))).toBe(h.config.tmpDir);
    expect(fs.existsSync(seenFile)).toBe(false);
    const findings = (await h.send("GET", "/api/tenants/t1/findings?source=codeql&origin=sarif_import", VIEWER_TOKEN)).body.findings as FindingView[];
    expect(findings.map((finding) => finding.filePath).sort()).toEqual(["lib/a.js", "src/db.js"]);
    expect(findings[0].origin).toBe("sarif_import");
    const counts = (await h.send("GET", "/api/tenants/t1/findings?origin=host_analysis", VIEWER_TOKEN)).body.findings;
    expect(counts).toEqual([]);

    const entries = h.audits().filter((entry) => entry.action === "codeql_sarif_imported" || entry.action === "authorization_denied");
    expect(entries.map((entry) => `${entry.action}:${entry.outcome}`)).toEqual(["authorization_denied:denied", "codeql_sarif_imported:success"]);
    expect(entries[1]).toMatchObject({ actor: "operator", tenantId: "t1", details: { resultsTotal: 3, created: 2 } });
  });

  test("import refuses non-JSON, non-SARIF, non-CodeQL and oversized bodies without starting the core", async () => {
    const h = bridge();
    const notJson = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, "{not json");
    expect(notJson.body.error.code).toBe("sarif_invalid");
    const notSarif = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, { hello: "world" });
    expect(notSarif.body.error.code).toBe("sarif_invalid");
    const semgrep = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, sarif("Semgrep OSS"));
    expect(semgrep.status).toBe(400);
    expect(semgrep.body.error.code).toBe("sarif_not_codeql");
    const wrongType = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, undefined, { raw: sarif(), contentType: "text/plain" });
    expect(wrongType.status).toBe(415);

    const chunk = new Uint8Array(1024 * 1024).fill(0x20);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent > CODEQL_IMPORT_MAX_BYTES + chunk.byteLength) controller.close();
        else {
          sent += chunk.byteLength;
          controller.enqueue(chunk);
        }
      },
    });
    const tooLarge = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, undefined, { raw: stream });
    expect(tooLarge.status).toBe(413);
    expect(tooLarge.body.error.code).toBe("sarif_too_large");
    expect(h.calls).toEqual([]);
    expect(h.audits().filter((entry) => entry.action === "codeql_sarif_imported").every((entry) => entry.outcome === "failure")).toBe(true);
  });

  test("large uploads are streamed to disk and checked by the core, one import at a time", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered = 0;
    let seenSize = 0;
    const h = bridge({
      cli: async (args) => {
        entered += 1;
        seenSize = fs.statSync(args[args.indexOf("--sarif") + 1]).size;
        await gate;
        return cliResult(cliDocument("codeql import", { findings: [] }));
      },
    });
    // Larger than the bridge-side parse limit: only the first bytes are checked here.
    const big = JSON.stringify({ runs: [{ tool: { driver: { name: "CodeQL" } }, results: [] }], padding: "x".repeat(SARIF_PRECHECK_MAX_BYTES) });
    const first = h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, big);
    while (entered === 0) await Bun.sleep(5);
    const second = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, sarif());
    expect(second.status).toBe(429);
    expect(second.body.error.code).toBe("codeql_import_busy");
    release();
    expect((await first).status).toBe(200);
    expect(seenSize).toBe(Buffer.byteLength(big));
    expect(entered).toBe(1);

    // A large body that is not a JSON object is refused from its first bytes, without the core.
    const notObject = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, `[${" ".repeat(SARIF_PRECHECK_MAX_BYTES)}]`);
    expect(notObject.status).toBe(400);
    expect(notObject.body.error.code).toBe("sarif_invalid");
    expect(entered).toBe(1);
  });

  test("an import whose results are all gone resolves the earlier findings of the rules it ran", async () => {
    let doc = cliDocument("codeql import", { findings: [cliFinding()], languages: [{ language: "javascript", status: "analyzed", reason: null, results: 1, duration_ms: null, rules: ["js/sql-injection"] }] });
    const h = bridge({ cli: () => cliResult(doc) });
    expect(((await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, sarif())).body as CodeqlIngestView).findings.created).toBe(1);
    // Regression: a SARIF with zero results named no language, so nothing was resolved.
    doc = cliDocument("codeql import", { findings: [], results_total: 0, languages: [{ language: "javascript", status: "analyzed", reason: null, results: 0, duration_ms: null, rules: ["js/sql-injection", "js/xss"] }] });
    const fixed = (await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, sarif())).body as CodeqlIngestView;
    expect(fixed.findings.resolved).toBe(1);
    expect(fixed.note).toContain("javascript (2 rules)");
  });

  test("import maps the core's SARIF errors to client errors", async () => {
    const h = bridge({ cli: () => coreError("sarif_not_codeql", "tool.driver.name is 'ESLint'", 4) });
    const refused = await h.send("POST", "/api/tenants/t1/codeql/import", OPERATOR_TOKEN, sarif());
    expect(refused.status).toBe(400);
    expect(refused.body.error.code).toBe("sarif_not_codeql");
    expect(refused.body.error.message).toContain("ESLint");
  });

  test("GitHub sync: paginated read-only alert listing, mapped and reconciled as github_code_scanning", async () => {
    let pages: unknown[][] = [Array.from({ length: 100 }, (_, index) => alert(index + 1)), [alert(101), alert(102, { most_recent_instance: { location: { path: "/abs/x.js", start_line: 1 } } })]];
    const h = bridge({
      fetcher: async (url) => {
        const page = Number(new URL(url).searchParams.get("page"));
        return { status: 200, ok: true, headers: new Headers(), text: JSON.stringify(pages[page - 1] ?? []) };
      },
    });
    expect((await h.send("POST", "/api/tenants/t1/codeql/github-sync", VIEWER_TOKEN, {})).status).toBe(403);
    const synced = await h.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {});
    expect(synced.status).toBe(200);
    expect(synced.body as CodeqlIngestView).toMatchObject({ origin: "github_code_scanning", repository: "o/r", resultsTotal: 102, resultsOutsideWorkspace: 1, truncated: false, findings: { created: 101 } });
    expect(h.fetches.map((call) => call.method)).toEqual(["GET", "GET"]);
    const first = new URL(h.fetches[0].url);
    expect(first.pathname).toBe("/repos/o/r/code-scanning/alerts");
    expect(Object.fromEntries(first.searchParams)).toEqual({ tool_name: "CodeQL", state: "open", per_page: "100", page: "1" });

    // Alert 1 was closed on GitHub: the next sync resolves it, nothing else.
    pages = [Array.from({ length: 99 }, (_, index) => alert(index + 2))];
    const again = await h.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {});
    expect((again.body as CodeqlIngestView).findings).toMatchObject({ created: 0, resolved: 2, stillOpen: 99 });
    const entries = h.audits().filter((entry) => entry.action === "codeql_github_synced");
    expect(entries.map((entry) => entry.outcome)).toEqual(["success", "success"]);
    expect(entries[0].details).toMatchObject({ repository: "o/r", alerts: 102, created: 101 });
  });

  test("GitHub sync: stops at 1000 alerts and then resolves nothing", async () => {
    let counter = 0;
    const h = bridge({
      fetcher: async () => ({ status: 200, ok: true, headers: new Headers(), text: JSON.stringify(Array.from({ length: 100 }, () => alert(++counter))) }),
    });
    const synced = await h.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {});
    expect(synced.body).toMatchObject({ truncated: true, resultsTotal: GITHUB_ALERTS_CAP });
    // Ten pages of alerts plus one page that only shows that more exist.
    expect(h.fetches).toHaveLength(GITHUB_ALERTS_CAP / 100 + 1);
    expect((synced.body as CodeqlIngestView).note).toContain("no earlier synced alert was resolved");
  });

  test("GitHub sync: exactly 1000 open alerts are complete, and closed ones are resolved", async () => {
    // Regression: ten full pages were reported as truncated without checking for an eleventh.
    let total = 1000;
    const h = bridge({
      fetcher: async (url) => {
        const page = Number(new URL(url).searchParams.get("page"));
        const from = (page - 1) * 100;
        const count = Math.max(0, Math.min(100, total - from));
        return { status: 200, ok: true, headers: new Headers(), text: JSON.stringify(Array.from({ length: count }, (_, index) => alert(from + index + 1))) };
      },
    });
    const synced = (await h.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {})).body as CodeqlIngestView;
    expect(synced).toMatchObject({ truncated: false, resultsTotal: 1000, findings: { created: 1000 } });
    expect(h.fetches).toHaveLength(11);
    expect(synced.note).not.toContain("More than");
    total = 999;
    const again = (await h.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {})).body as CodeqlIngestView;
    expect(again).toMatchObject({ truncated: false, findings: { resolved: 1, stillOpen: 999 } });
  });

  test("GitHub sync: explicit errors for 403, 404, no credential and no repository", async () => {
    const forbidden = bridge({
      fetcher: async () => ({ status: 403, ok: false, headers: new Headers(), text: JSON.stringify({ message: "Advanced Security must be enabled for this repository to use code scanning." }) }),
    });
    const refused = await forbidden.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {});
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe("github_code_scanning_forbidden");
    expect(refused.body.error.message).toContain("security_events");
    expect(refused.body.error.message).toContain("Advanced Security must be enabled");

    const missing = bridge({ fetcher: async () => ({ status: 404, ok: false, headers: new Headers(), text: JSON.stringify({ message: "no analysis found" }) }) });
    const notFound = await missing.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {});
    expect(notFound.status).toBe(404);
    expect(notFound.body.error.code).toBe("github_code_scanning_not_found");

    const noCredential = bridge();
    (noCredential.app as { github: unknown }).github = { resolveAuth: () => null };
    expect((await noCredential.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {})).body.error.code).toBe("github_not_configured");

    const noRepository = bridge({ repository: false, fetcher: async () => ({ status: 200, ok: true, headers: new Headers(), text: "[]" }) });
    const unresolved = await noRepository.send("POST", "/api/tenants/t1/codeql/github-sync", OPERATOR_TOKEN, {});
    expect(unresolved.body.error.code).toBe("repository_not_resolved");
    expect(noRepository.fetches).toEqual([]);
  });
});

// ───────────────────────────── long CodeQL runs: stream keep-alive and cancellation ─────────────────────────────

describe("long CodeQL runs", () => {
  test("a silent scan stream still sends a keep-alive comment, which the console ignores", async () => {
    // Regression: nothing was written while `sentra codeql analyze` ran, so a reverse proxy's read
    // timeout (nginx: 60 s) closed the stream and cancelled the scan.
    const response = sseResponse(
      new Request("http://127.0.0.1/stream"),
      async (channel) => {
        await Bun.sleep(120);
        channel.send("complete", { type: "complete" });
      },
      { keepAliveMs: 20 },
    );
    const text = await response.text();
    expect(text).toContain(": keep-alive\n\n");
    expect(text.trimEnd().endsWith('data: {"type":"complete"}')).toBe(true);
  });

  test("cancelling closes stdin and waits for the core to stop its own tree; a core that ignores it is killed later", async () => {
    const dir = tempDir("sentra-codeql-cancel-");
    const marker = path.join(dir, "stopped.txt");
    // The Bun executable stands in for the core: it waits for stdin to close, then cleans up and exits.
    const cli = new SentraCli(process.execPath, dir, 30_000, 2);
    const graceful = [
      "-e",
      // The marker path is an argument (process.argv[1]), not part of the evaluated source.
      `process.stdin.on("data", () => {}); process.stdin.on("end", () => { require("fs").writeFileSync(process.argv[1], "stopped"); console.log("{}"); process.exit(0); });`,
      marker,
    ];
    const controller = new AbortController();
    const running = cli.run(graceful, { signal: controller.signal, cancelViaStdinEof: true });
    await Bun.sleep(300);
    controller.abort();
    const result = await running;
    // The run settled only after the core had cleaned up and exited by itself.
    expect(fs.readFileSync(marker, "utf8")).toBe("stopped");
    expect(result.code).toBe(0);

    const stubborn = ["-e", "setInterval(() => {}, 1000);"];
    const second = new AbortController();
    const started = performance.now();
    const pending = cli.run(stubborn, { signal: second.signal, cancelViaStdinEof: true, gracefulStopMs: 200 });
    await Bun.sleep(200);
    second.abort();
    const killed = await pending;
    expect(killed.code).not.toBe(0);
    expect(performance.now() - started).toBeLessThan(10_000);
  }, 30_000);
});

// ───────────────────────────── core error passthrough (plugins) ─────────────────────────────

describe("core error messages are passed on, bounded and sanitised", () => {
  test("a plugin adapter's reported reason reaches the client", () => {
    const error = cliFailure("plugin probe", {
      code: 5,
      stdout: "",
      stderr: JSON.stringify({ schema_version: 1, error: "plugin_adapter_error", message: "semgrep not found on PATH\u001b[31m\nInstall it", reason: "semgrep not found on PATH" }),
      json: undefined,
      timedOut: false,
      durationMs: 1,
    });
    expect(error.status).toBe(422);
    expect(error.code).toBe("core_command_failed");
    expect(error.message).toBe("sentra plugin probe failed: plugin_adapter_error: semgrep not found on PATH [31m Install it");
    expect(error.details).toMatchObject({ coreError: "plugin_adapter_error", coreMessage: "semgrep not found on PATH [31m Install it" });
    expect(sanitizeCoreMessage("x".repeat(MAX_CORE_MESSAGE_CHARS + 50))?.length).toBe(MAX_CORE_MESSAGE_CHARS + 1);
    expect(sanitizeCoreMessage(" \u0000 ")).toBeNull();
    // Without a message the code alone is reported, as before.
    expect(cliFailure("scan", cliResult(undefined, 5, '{"schema_version":1,"error":"storage_or_service_failure"}')).message).toBe("sentra scan failed: storage_or_service_failure");
  });
});
