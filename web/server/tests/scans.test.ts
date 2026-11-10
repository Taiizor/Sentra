import type { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ScanStreamEvent } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { AuditLog } from "../audit-log.ts";
import { openWebDb } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { cliFailure, type CliResult, type CliRunOptions } from "../sentra-cli.ts";
import {
  computeTrends,
  findingCounts,
  findingIdFor,
  listFindings,
  normalizeSeverity,
  parseScanOutput,
  parseTaintTrace,
  reconcileFindings,
  riskScoreValue,
  sastCandidates,
  toSastMatchView,
  triageFinding,
  type CandidateFinding,
} from "../services/findings.ts";
import { createOsvServiceFrom, OsvClient, type OsvFetcher } from "../services/osv.ts";
import { buildSarif, readRepositoryUrl, SARIF_FINGERPRINT_KEY, sarifLevel } from "../services/sarif.ts";
import { createScanService, mapCodeqlProbe } from "../services/scans.ts";
import { SettingsStore } from "../services/settings-store.ts";
import type { TenantRecord } from "../services/workspaces.ts";

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
  const db = openWebDb(path.join(tempDir("sentra-scans-db-"), "web.db"));
  cleanup.dbs.push(db);
  return db;
}

/** Markdown exactly as emitted by TaintVulnerability::to_markdown_trace in sentra-core. */
const TAINT_RATIONALE = [
  "",
  "#### In-Engine Taint Data-Flow Path (Pure-Rust Semantic Trace)",
  "",
  "| Step | Role | Line | Variable | Code Context | Explanation |",
  "| :---: | :--- | :---: | :--- | :--- | :--- |",
  "| 1 | `🔴 SOURCE` | `3` | `name` | `const name = req.query.name` | Untrusted input enters |",
  "| 2 | `🟡 PROPAGATE` | `4` | `sql` | `const sql = 'SELECT ' + (name || 'x')` | Concatenated into a query |",
  "| 3 | `💥 SINK` | `9` | `sql` | `db.query(sql)` | Executed |",
  "",
].join("\n");

function scanJson(matches: Record<string, unknown>[], filesScanned = 4): Record<string, unknown> {
  return { schema_version: 1, command: "scan", files_scanned: filesScanned, signals_found: matches.length, matches, untrusted_execution: false };
}

const SECRET_MATCH = {
  category: "SECRET_LEAK",
  cwe: "CWE-798",
  file_path: "src/config.ts",
  line_number: 2,
  rationale: "Matched AWS Access Key format (AKIA...)",
  rule_id: "SENTRA-SEC-001",
  rule_name: "AwsAccessKeyId",
  severity: "CRITICAL",
  snippet: "AKIAAB...[REDACTED]",
};

const TAINT_MATCH = {
  category: "SQL_INJECTION",
  cwe: "CWE-89",
  file_path: "src/db.ts",
  line_number: 9,
  rationale: TAINT_RATIONALE,
  rule_id: "SENTRA-TAINT-001",
  rule_name: "TaintedSqlQuery",
  severity: "HIGH",
  snippet: "db.query(sql)",
};

describe("core scan output mapping", () => {
  test("severity mapping covers the core enum and unknown values", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("Critical");
    expect(normalizeSeverity("high")).toBe("High");
    expect(normalizeSeverity("MEDIUM")).toBe("Medium");
    expect(normalizeSeverity("LOW")).toBe("Low");
    expect(normalizeSeverity("INFO")).toBe("Informational");
    expect(normalizeSeverity("INFORMATIONAL")).toBe("Informational");
    expect(normalizeSeverity("SEVERE")).toBe("Unknown");
    expect(normalizeSeverity(undefined)).toBe("Unknown");
  });

  test("taint table lines are parsed per step (backticks stripped), not collapsed to the sink line", () => {
    const { trace, text } = parseTaintTrace(TAINT_RATIONALE);
    expect(text).toBeNull();
    expect(trace).toEqual([
      { step: 1, role: "SOURCE", line: 3, variable: "name", code: "const name = req.query.name" },
      { step: 2, role: "PROPAGATION", line: 4, variable: "sql", code: "const sql = 'SELECT ' + (name || 'x')" },
      { step: 3, role: "SINK", line: 9, variable: "sql", code: "db.query(sql)" },
    ]);
    expect(parseTaintTrace("Matched AWS Access Key format (AKIA...)")).toEqual({ trace: null, text: "Matched AWS Access Key format (AKIA...)" });
  });

  test("scan JSON maps to matches; the snippet view renders the trace as text", () => {
    const parsed = parseScanOutput(scanJson([SECRET_MATCH, TAINT_MATCH]));
    expect(parsed.filesScanned).toBe(4);
    expect(parsed.signalsFound).toBe(2);
    expect(parsed.matches[0]).toMatchObject({ ruleId: "SENTRA-SEC-001", severity: "Critical", filePath: "src/config.ts", line: 2, taintTrace: null });
    expect(parsed.matches[1].taintTrace).toHaveLength(3);
    expect(toSastMatchView(parsed.matches[1]).rationale).toBe(
      "Pattern-based taint trace reported by the core: SOURCE line 3 (name) -> PROPAGATION line 4 (sql) -> SINK line 9 (sql)",
    );
    expect(() => parseScanOutput({ error: "invalid_workspace" })).toThrow(HttpError);
  });

  test("CodeQL probe maps suggested commands and never claims CodeQL ran", () => {
    const probe = mapCodeqlProbe(
      {
        primary_language: "javascript",
        detected_languages: [{ language: "javascript", files_count: 3 }],
        database_create_command: "codeql database create ...",
        database_analyze_command: null,
      },
      false,
    );
    expect(probe).toEqual({
      primaryLanguage: "javascript",
      detectedLanguages: [{ language: "javascript", filesCount: 3 }],
      suggestedCreateCommand: "codeql database create ...",
      suggestedAnalyzeCommand: null,
      codeqlInstalled: false,
    });
  });
});

describe("fingerprints", () => {
  test("moving a match to another line keeps its identity; duplicates stay distinct", () => {
    const base = { ruleId: "R1", ruleName: "R1", cwe: null, severity: "High" as const, category: "X", rationale: null, taintTrace: null };
    const before = sastCandidates([
      { ...base, filePath: "a.ts", line: 10, snippet: "eval(x)" },
      { ...base, filePath: "a.ts", line: 20, snippet: "eval(x)" },
    ]);
    const after = sastCandidates([
      { ...base, filePath: "a.ts", line: 12, snippet: "eval( x )".replace("( x )", "(x)") },
      { ...base, filePath: "a.ts", line: 25, snippet: "eval(x)" },
    ]);
    expect(before[0].fingerprint).not.toBe(before[1].fingerprint);
    expect(after.map((candidate) => candidate.fingerprint)).toEqual(before.map((candidate) => candidate.fingerprint));
    const noSnippet = sastCandidates([{ ...base, filePath: "a.ts", line: 7, snippet: null }]);
    const movedNoSnippet = sastCandidates([{ ...base, filePath: "a.ts", line: 8, snippet: null }]);
    expect(noSnippet[0].fingerprint).not.toBe(movedNoSnippet[0].fingerprint);
  });

  test("finding ids are tenant- and workspace-scoped", () => {
    const id = findingIdFor("t1", "C:/ws", "abc");
    expect(id).toMatch(/^fnd_[0-9a-f]{24}$/);
    expect(findingIdFor("t2", "C:/ws", "abc")).not.toBe(id);
    expect(findingIdFor("t1", "C:/other", "abc")).not.toBe(id);
  });
});

function candidate(overrides: Partial<CandidateFinding> & { fingerprint: string }): CandidateFinding {
  return {
    source: "sast",
    ruleId: "R1",
    ruleName: "Rule one",
    cwe: null,
    severity: "High",
    category: "X",
    filePath: "a.ts",
    line: 1,
    snippet: null,
    rationale: null,
    taintTrace: null,
    dependency: null,
    ...overrides,
  };
}

describe("reconciliation", () => {
  const scope = { tenantId: "t1", workspace: "C:/ws" };

  test("inserts, keeps, resolves and reopens findings per completed source", () => {
    const db = tempDb();
    const first = reconcileFindings(db, {
      ...scope,
      runId: "run_1",
      at: "2026-11-01T10:00:00.000Z",
      candidates: [candidate({ fingerprint: "f1" }), candidate({ fingerprint: "f2" }), candidate({ fingerprint: "f2" }), candidate({ fingerprint: "d1", source: "dependency" })],
      completedSources: ["sast", "dependency"],
    });
    expect(first).toEqual({ created: 3, reopened: 0, stillOpen: 0, resolved: 0 });

    const second = reconcileFindings(db, {
      ...scope,
      runId: "run_2",
      at: "2026-11-02T10:00:00.000Z",
      candidates: [candidate({ fingerprint: "f1", severity: "Critical" })],
      completedSources: ["sast"],
    });
    expect(second).toEqual({ created: 0, reopened: 0, stillOpen: 1, resolved: 1 });
    const open = listFindings(db, scope.tenantId, scope.workspace, { state: "open" });
    expect(open.map((finding) => finding.fingerprint).sort()).toEqual(["d1", "f1"]);
    expect(open.find((finding) => finding.fingerprint === "f1")).toMatchObject({ severity: "Critical", firstSeenRun: "run_1", lastSeenRun: "run_2" });

    const third = reconcileFindings(db, {
      ...scope,
      runId: "run_3",
      at: "2026-11-03T10:00:00.000Z",
      candidates: [candidate({ fingerprint: "f1" }), candidate({ fingerprint: "f2" })],
      completedSources: ["sast"],
    });
    expect(third).toEqual({ created: 0, reopened: 1, stillOpen: 1, resolved: 0 });
    const reopened = listFindings(db, scope.tenantId, scope.workspace, { state: "all" }).find((finding) => finding.fingerprint === "f2");
    expect(reopened).toMatchObject({ state: "open", resolvedAt: null });
  });

  test("a failed or skipped source never resolves its findings, and tenants are isolated", () => {
    const db = tempDb();
    reconcileFindings(db, { ...scope, runId: "run_1", at: "2026-11-01T00:00:00.000Z", candidates: [candidate({ fingerprint: "d1", source: "dependency" })], completedSources: ["dependency"] });
    reconcileFindings(db, { tenantId: "t2", workspace: "C:/ws", runId: "run_x", at: "2026-11-01T00:00:00.000Z", candidates: [candidate({ fingerprint: "f9" })], completedSources: ["sast"] });
    const result = reconcileFindings(db, { ...scope, runId: "run_2", at: "2026-11-02T00:00:00.000Z", candidates: [], completedSources: ["sast"] });
    expect(result.resolved).toBe(0);
    expect(listFindings(db, "t1", "C:/ws", { state: "open" })).toHaveLength(1);
    expect(listFindings(db, "t2", "C:/ws", { state: "open" })).toHaveLength(1);
    // Candidates of a source that did not complete are ignored rather than inserted.
    const ignored = reconcileFindings(db, { ...scope, runId: "run_3", at: "2026-11-03T00:00:00.000Z", candidates: [candidate({ fingerprint: "late", source: "dependency" })], completedSources: [] });
    expect(ignored.created).toBe(0);
  });

  test("triage survives later runs; rejected findings leave the open totals and the risk score", () => {
    const db = tempDb();
    reconcileFindings(db, {
      ...scope,
      runId: "run_1",
      at: "2026-11-01T00:00:00.000Z",
      candidates: [candidate({ fingerprint: "c1", severity: "Critical" }), candidate({ fingerprint: "h1", severity: "High" }), candidate({ fingerprint: "m1", severity: "Medium", source: "dependency" })],
      completedSources: ["sast", "dependency"],
    });
    const critical = listFindings(db, "t1", "C:/ws", { state: "open", severity: "Critical" })[0];
    triageFinding(db, "t1", critical.findingId, { verdict: "rejected", reason: "test fixture", by: "alice", at: "2026-11-01T01:00:00.000Z" });
    reconcileFindings(db, {
      ...scope,
      runId: "run_2",
      at: "2026-11-02T00:00:00.000Z",
      candidates: [candidate({ fingerprint: "c1", severity: "Critical" }), candidate({ fingerprint: "h1", severity: "High" })],
      completedSources: ["sast"],
    });
    const counts = findingCounts(db, "t1", "C:/ws");
    expect(counts.openTotal).toBe(2);
    expect(counts.bySeverity).toMatchObject({ Critical: 0, High: 1, Medium: 1 });
    expect(counts.bySource).toEqual({ sast: 1, dependency: 1 });
    expect(counts.byTriage).toEqual({ untriaged: 2, confirmed: 0, needs_validation: 0, rejected: 1 });
    expect(riskScoreValue(counts.bySeverity)).toBe(100 - 7 - 3);
    expect(listFindings(db, "t1", "C:/ws", { state: "all" }).find((finding) => finding.fingerprint === "c1")?.triage).toEqual({
      verdict: "rejected",
      reason: "test fixture",
      by: "alice",
      at: "2026-11-01T01:00:00.000Z",
    });
  });

  test("risk score never goes below zero", () => {
    expect(riskScoreValue({ Critical: 10, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0 })).toBe(0);
  });
});

describe("trends", () => {
  test("daily series are computed from stored rows only", () => {
    const db = tempDb();
    const scope = { tenantId: "t1", workspace: "C:/ws" };
    db.query(
      "INSERT INTO scan_runs (run_id, tenant_id, workspace, kind, trigger, status, started_at, actor) VALUES ('run_1', 't1', 'C:/ws', 'sast', 'operator', 'completed', '2026-11-08T09:00:00.000Z', 'alice')",
    ).run();
    db.query(
      "INSERT INTO scan_runs (run_id, tenant_id, workspace, kind, trigger, status, started_at, actor) VALUES ('run_2', 't1', 'C:/ws', 'sast', 'operator', 'completed', '2026-11-09T09:00:00.000Z', 'alice')",
    ).run();
    reconcileFindings(db, {
      ...scope,
      runId: "run_1",
      at: "2026-11-08T09:00:01.000Z",
      candidates: [candidate({ fingerprint: "a", severity: "Critical" }), candidate({ fingerprint: "b" })],
      completedSources: ["sast"],
    });
    reconcileFindings(db, { ...scope, runId: "run_2", at: "2026-11-09T09:00:01.000Z", candidates: [candidate({ fingerprint: "b" })], completedSources: ["sast"] });
    const points = computeTrends(db, "t1", "C:/ws", 3, Date.parse("2026-11-10T12:00:00.000Z"));
    expect(points).toEqual([
      { date: "2026-11-08", scans: 1, newFindings: 2, resolvedFindings: 0, openAtEndOfDay: 2, openCriticalAtEndOfDay: 1 },
      { date: "2026-11-09", scans: 1, newFindings: 0, resolvedFindings: 1, openAtEndOfDay: 1, openCriticalAtEndOfDay: 0 },
      { date: "2026-11-10", scans: 0, newFindings: 0, resolvedFindings: 0, openAtEndOfDay: 1, openCriticalAtEndOfDay: 0 },
    ]);
  });
});

describe("SARIF export", () => {
  test("repository URL is read from the workspace Cargo.toml, not hardcoded", () => {
    expect(readRepositoryUrl(path.resolve(import.meta.dir, "../../../Cargo.toml"))).toBe("https://github.com/Taiizor/Sentra");
    expect(readRepositoryUrl(path.join(tempDir("sentra-sarif-"), "missing.toml"))).toBeNull();
  });

  test("produces a SARIF 2.1.0 log with honest locations, levels and fingerprints", () => {
    const db = tempDb();
    const parsed = parseScanOutput(scanJson([SECRET_MATCH, TAINT_MATCH]));
    reconcileFindings(db, {
      tenantId: "t1",
      workspace: "C:/ws",
      runId: "run_1",
      at: "2026-11-01T00:00:00.000Z",
      candidates: [
        ...sastCandidates(parsed.matches),
        candidate({
          fingerprint: "dep-fp",
          source: "dependency",
          ruleId: "GHSA-vh95-rmgr-6w4m",
          ruleName: "Prototype Pollution in minimist",
          severity: "Medium",
          category: "DEPENDENCY_VULNERABILITY",
          filePath: "web/package-lock.json",
          line: null,
          snippet: "minimist@1.2.0",
          cwe: "CWE-1321",
          dependency: {
            packageName: "minimist",
            packageVersion: "1.2.0",
            ecosystem: "npm",
            lockfile: "web/package-lock.json",
            advisoryId: "GHSA-vh95-rmgr-6w4m",
            aliases: [],
            summary: "Prototype Pollution in minimist",
            details: null,
            fixedVersions: ["1.2.3"],
            fixedVersionsNote: null,
            references: [],
            published: null,
            modified: null,
            severitySource: "database_specific",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvssScore: 9.8,
          },
        }),
      ],
      completedSources: ["sast", "dependency"],
    });
    const findings = listFindings(db, "t1", "C:/ws", { state: "open" });
    const sarif = buildSarif(findings, { version: "0.1.0", informationUri: "https://github.com/Taiizor/Sentra" }, "t1", "2026-11-10T00:00:00.000Z");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json");
    expect(sarif.runs).toHaveLength(1);
    const run = sarif.runs[0];
    expect(run.tool.driver).toMatchObject({ name: "Sentra", version: "0.1.0", informationUri: "https://github.com/Taiizor/Sentra" });
    expect(new Set(run.tool.driver.rules.map((rule) => rule.id)).size).toBe(run.tool.driver.rules.length);
    expect(run.results).toHaveLength(3);
    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex].id).toBe(result.ruleId);
      expect(result.partialFingerprints[SARIF_FINGERPRINT_KEY]).toMatch(/^[0-9a-f]{64}$|^dep-fp$/);
      expect(result.message.text.length).toBeGreaterThan(0);
      expect(result.properties.status).toBe("candidate");
    }
    const secret = run.results.find((result) => result.ruleId === "SENTRA-SEC-001");
    expect(secret).toMatchObject({ level: "error", locations: [{ physicalLocation: { artifactLocation: { uri: "src/config.ts", uriBaseId: "%SRCROOT%" }, region: { startLine: 2 } } }] });
    const taint = run.results.find((result) => result.ruleId === "SENTRA-TAINT-001");
    expect(taint?.codeFlows?.[0].threadFlows[0].locations.map((step) => step.location.physicalLocation.region?.startLine)).toEqual([3, 4, 9]);
    const dep = run.results.find((result) => result.ruleId === "GHSA-vh95-rmgr-6w4m");
    expect(dep?.level).toBe("warning");
    expect(dep?.locations[0].physicalLocation).toEqual({ artifactLocation: { uri: "web/package-lock.json", uriBaseId: "%SRCROOT%" } });
    expect(dep?.locations[0].physicalLocation.region).toBeUndefined();
    expect(dep?.partialFingerprints[SARIF_FINGERPRINT_KEY]).toBe("dep-fp");
    expect(run.tool.driver.rules.find((rule) => rule.id === "GHSA-vh95-rmgr-6w4m")?.properties["security-severity"]).toBe("9.8");
    // Round-trips as plain JSON.
    expect(JSON.parse(JSON.stringify(sarif))).toEqual(sarif);
  });

  test("severity levels map Critical/High to error, Medium to warning, the rest to note", () => {
    expect(sarifLevel("Critical")).toBe("error");
    expect(sarifLevel("High")).toBe("error");
    expect(sarifLevel("Medium")).toBe("warning");
    expect(sarifLevel("Low")).toBe("note");
    expect(sarifLevel("Informational")).toBe("note");
    expect(sarifLevel("Unknown")).toBe("note");
  });
});

// ───────────────────────────── pipeline with a fake core CLI ─────────────────────────────

function cliResult(json: unknown, code = 0): CliResult {
  const stdout = json === undefined ? "" : JSON.stringify(json);
  return { code, stdout, stderr: code === 0 ? "" : '{"schema_version":1,"error":"storage_or_service_failure"}', json, timedOut: false, durationMs: 3 };
}

type CliHandler = (args: string[], options: CliRunOptions) => Promise<CliResult> | CliResult;

function pipelineHarness(handler: CliHandler, fetcher?: OsvFetcher) {
  const db = tempDb();
  const settings = new SettingsStore(db);
  const audit = new AuditLog(db, crypto.randomBytes(32));
  const workspace = tempDir("sentra-scans-ws-");
  const tenant: TenantRecord = {
    tenantId: "t1",
    name: "Test",
    description: "",
    workspace,
    isolationLevel: "single_operator",
    githubOwner: null,
    githubRepo: null,
    createdAt: "2026-11-01T00:00:00.000Z",
    createdBy: "alice",
    importedFrom: null,
  };
  const calls: string[][] = [];
  const cli = {
    run: async (args: string[], options: CliRunOptions = {}) => {
      calls.push(args);
      return handler(args, options);
    },
    runJson: async (args: string[], options: CliRunOptions = {}) => {
      const result = await cli.run(args, options);
      if (result.code !== 0 || result.json === undefined) throw cliFailure(args[0], result);
      return result.json;
    },
  };
  const client = new OsvClient(db, settings, fetcher ?? (async () => ({ status: 500, text: "" })));
  const osv = createOsvServiceFrom({ settings, client, runInventory: (dir) => cli.runJson(["inventory", "--workspace", dir, "--json"]) });
  const app = {
    db,
    settings,
    audit,
    cli,
    osv,
    config: { cliLongTimeoutMs: 5_000, cliTimeoutMs: 5_000 },
    workspaces: {
      get: (tenantId: string) => {
        if (tenantId !== "t1") throw new HttpError(404, "tenant_not_found", "not registered");
        return tenant;
      },
      workspaceRoot: () => workspace,
      coreStoreState: async () => ({ initialized: true, error: null }),
      coreStorePath: () => path.join(workspace, "..", "core.db"),
    },
  } as unknown as Omit<AppContext, "scans">;
  const service = createScanService(app, { osvFetcher: fetcher });
  return { db, audit, settings, service, calls, workspace, osv };
}

const actor = { label: "alice", role: "operator" };

function codeqlJson() {
  return { primary_language: "typescript", detected_languages: [{ language: "typescript", files_count: 2 }], database_create_command: null, database_analyze_command: null };
}

describe("scan pipeline", () => {
  test("runs all stages, skips OSV when disabled, persists findings and audits the run", async () => {
    let sastMatches: Record<string, unknown>[] = [SECRET_MATCH, TAINT_MATCH];
    const harness = pipelineHarness((args) => {
      if (args[0] === "scan") return cliResult(scanJson(sastMatches));
      if (args[0] === "codeql") return cliResult(codeqlJson());
      throw new Error(`unexpected command ${args[0]}`);
    });
    const events: ScanStreamEvent[] = [];
    const run = await harness.service.run({ tenantId: "t1", kind: "all", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("completed");
    expect(run.filesScanned).toBe(4);
    expect(run.signalsFound).toBe(2);
    expect(run.packagesAudited).toBeNull();
    expect(run.summary?.dependencySkippedReason).toContain("disabled by policy");
    expect(run.summary?.dependency).toBeNull();
    expect(run.summary?.codeql?.codeqlInstalled).toBe(!!Bun.which("codeql"));
    expect(run.summary).toMatchObject({ newFindings: 2, resolvedFindings: 0, stillOpen: 0, stageErrors: [] });
    expect(harness.calls.map((args) => args[0])).toEqual(["scan", "codeql"]);
    expect(harness.calls[0]).toContain("--database");
    expect(events[0].type).toBe("run");
    expect(events.at(-1)).toMatchObject({ type: "complete", run: { runId: run.runId, status: "completed" } });
    expect(events.some((event) => event.type === "stage" && event.stage === "dependency" && event.status === "skipped")).toBe(true);
    expect(harness.audit.list({ limit: 10 })[0]).toMatchObject({ action: "scan_completed", outcome: "success", tenantId: "t1" });

    sastMatches = [SECRET_MATCH];
    const second = await harness.service.run({ tenantId: "t1", kind: "sast", trigger: "operator", actor });
    expect(second.summary).toMatchObject({ newFindings: 0, resolvedFindings: 1, stillOpen: 1 });
  });

  test("a failed stage marks the run failed and resolves nothing", async () => {
    let fail = false;
    const harness = pipelineHarness((args) => (fail ? cliResult(undefined, 5) : cliResult(scanJson(args[0] === "scan" ? [SECRET_MATCH] : []))));
    await harness.service.run({ tenantId: "t1", kind: "sast", trigger: "operator", actor });
    fail = true;
    const failed = await harness.service.run({ tenantId: "t1", kind: "sast", trigger: "operator", actor });
    expect(failed.status).toBe("failed");
    expect(failed.error).toContain("storage_or_service_failure");
    expect(failed.summary?.stageErrors).toHaveLength(1);
    expect(listFindings(harness.db, "t1", harness.workspace, { state: "open" })).toHaveLength(1);
    expect(harness.audit.list({ limit: 1 })[0]).toMatchObject({ action: "scan_failed", outcome: "failure" });
  });

  test("only one scan per tenant runs at a time", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const harness = pipelineHarness(async () => {
      await gate;
      return cliResult(scanJson([]));
    });
    const first = harness.service.run({ tenantId: "t1", kind: "sast", trigger: "operator", actor });
    expect(harness.service.isRunning("t1")).toBe(true);
    await expect(harness.service.run({ tenantId: "t1", kind: "sast", trigger: "webhook", actor })).rejects.toMatchObject({ status: 409, code: "scan_in_progress" });
    release();
    expect((await first).status).toBe("completed");
    expect(harness.service.isRunning("t1")).toBe(false);
  });

  test("client cancellation stops the stage and marks the run failed without reconciling", async () => {
    const harness = pipelineHarness(
      (_args, options) =>
        new Promise<CliResult>((resolve) => {
          options.signal?.addEventListener("abort", () => resolve(cliResult(undefined, 1)), { once: true });
        }),
    );
    const controller = new AbortController();
    const pending = harness.service.run({ tenantId: "t1", kind: "sast", trigger: "operator", actor, signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    const run = await pending;
    expect(run.status).toBe("failed");
    expect(run.error).toBe("cancelled by client");
    expect(run.summary?.newFindings).toBe(0);
  });

  test("dependency stage queries OSV over the core inventory; an OSV outage keeps earlier findings open", async () => {
    let osvUp = true;
    const fetcher: OsvFetcher = async (url) => {
      if (!osvUp) return { status: 503, text: "" };
      if (url.endsWith("/v1/querybatch")) return { status: 200, text: JSON.stringify({ results: [{ vulns: [{ id: "GHSA-1", modified: "2024-01-01T00:00:00Z" }] }] }) };
      return {
        status: 200,
        text: JSON.stringify({
          id: "GHSA-1",
          summary: "Example advisory",
          modified: "2024-01-01T00:00:00Z",
          database_specific: { severity: "HIGH" },
          affected: [{ package: { name: "left-pad", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.0" }] }] }],
        }),
      };
    };
    const harness = pipelineHarness((args) => {
      if (args[0] === "inventory") {
        return cliResult({
          lockfiles: [{ path: "package-lock.json", kind: "Npm", ecosystem: "npm", packages: 1, parse_error: null }],
          packages: [{ name: "left-pad", version: "1.0.0", ecosystem: "npm", lockfile: "package-lock.json" }],
          total_packages: 1,
          truncated: false,
        });
      }
      throw new Error(`unexpected command ${args[0]}`);
    }, fetcher);
    harness.osv.setEnabled(true, { label: "admin", role: "admin" });
    const run = await harness.service.run({ tenantId: "t1", kind: "dependency", trigger: "operator", actor });
    expect(run.status).toBe("completed");
    expect(run.summary?.dependency).toMatchObject({ packagesAudited: 1, vulnerablePackages: 1, vulnerabilities: 1, advisorySource: "osv.dev" });
    const [finding] = listFindings(harness.db, "t1", harness.workspace, { state: "open", source: "dependency" });
    expect(finding).toMatchObject({ ruleId: "GHSA-1", severity: "High", filePath: "package-lock.json", line: null, snippet: "left-pad@1.0.0" });
    expect(finding.dependency?.fixedVersions).toEqual(["1.3.0"]);

    osvUp = false;
    const outage = await harness.service.run({ tenantId: "t1", kind: "dependency", trigger: "operator", actor });
    expect(outage.status).toBe("failed");
    expect(outage.summary?.stageErrors[0].stage).toBe("dependency");
    // Cached advisory records are reused, but the batch query itself failed: nothing resolved.
    expect(listFindings(harness.db, "t1", harness.workspace, { state: "open", source: "dependency" })).toHaveLength(1);
  });

  test("runs left 'running' by a previous process are marked failed at startup", () => {
    const db = tempDb();
    db.query(
      "INSERT INTO scan_runs (run_id, tenant_id, workspace, kind, trigger, status, started_at, actor) VALUES ('run_old', 't1', 'C:/ws', 'sast', 'operator', 'running', '2026-11-01T00:00:00.000Z', 'alice')",
    ).run();
    const settings = new SettingsStore(db);
    createScanService({ db, settings } as unknown as Omit<AppContext, "scans">);
    const row = db.query("SELECT status, error FROM scan_runs WHERE run_id = 'run_old'").get() as { status: string; error: string };
    expect(row.status).toBe("failed");
    expect(row.error).toContain("interrupted");
  });
});
