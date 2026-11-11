import { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  API_CONTRACT_VERSION,
  type CodeqlPacksDownloadView,
  type CodeqlPacksStreamEvent,
  type CodeqlPacksView,
  type CodeqlSettingsView,
  type ScanStreamEvent,
} from "../../src/types/api.ts";
import {
  CODEQL_FIRST_RUN_HINT,
  CODEQL_PREFETCH_DONE_HINT,
  CODEQL_PREFETCH_HINT,
  codeqlStageHint,
  downloadOutcomeTitle,
  packStatusText,
  PACKS_DOWNLOAD_STOP_TEXT,
  runningText,
  STOP_SCAN_PARAGRAPHS,
  waitForPackDownloadToEnd,
} from "../../src/components/dashboard/codeql-text.ts";
import type { AppContext } from "../app-context.ts";
import { AuditLog } from "../audit-log.ts";
import { parseTokenGrants, type ServerConfig } from "../config.ts";
import { ExecutableLocator } from "../executables.ts";
import { HostPlatform } from "../host-platform.ts";
import { HttpError } from "../http-error.ts";
import type { Router } from "../http.ts";
import { createApp, handleRequest } from "../main.ts";
import { coreErrorDocument, LineSplitter, MAX_STREAM_LINE_CHARS, SentraCli, type CliResult, type CliRunOptions } from "../sentra-cli.ts";
import {
  busySkip,
  chooseRamMb,
  codeqlIsolationNote,
  createCodeqlService,
  hostMemoryReading,
  parseCodeqlSettings,
  parseCodeqlSettingsUpdate,
  RAM_AUTO_FALLBACK_MB,
  runHostAnalysis,
  runtimeForWorkspace,
} from "../services/codeql.ts";
import { describeProgress, formatElapsed, parseProgressLine, progressFromLine } from "../services/codeql-progress.ts";
import { interpretDownload, parsePackEntries, parsePackLanguages, PACKS_CACHE_TTL_MS } from "../services/codeql-packs.ts";
import { openWebDb } from "../db.ts";
import { createOsvServiceFrom, OsvClient } from "../services/osv.ts";
import { createScanService } from "../services/scans.ts";
import { SettingsStore } from "../services/settings-store.ts";
import type { TenantRecord } from "../services/workspaces.ts";
import { ToolPathStore } from "../tool-paths.ts";
import { hostExecutableName, hostNativeHeader } from "./native-header.ts";

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

/** A CodeQL distribution layout on disk (launcher, tools/, .codeqlmanifest.json); nothing in it can run. */
function fakeDistribution(): string {
  const dir = tempDir("sentra-cqp-dist-");
  const launcher = path.join(dir, hostExecutableName("codeql"));
  fs.writeFileSync(launcher, process.platform === "win32" ? hostNativeHeader() : "#!/bin/sh\nexit 3\n", { mode: 0o755 });
  fs.mkdirSync(path.join(dir, "tools"));
  fs.writeFileSync(path.join(dir, ".codeqlmanifest.json"), "{}");
  return launcher;
}

function cliResult(json: unknown, code = 0, stderr = ""): CliResult {
  const stdout = json === undefined ? "" : JSON.stringify(json);
  return { code, stdout, stderr, json, timedOut: false, durationMs: 3 };
}

function progressLine(fields: Record<string, unknown>): string {
  return JSON.stringify({ progress: true, step: null, language: null, pack: null, elapsed_ms: null, duration_ms: null, message: null, ...fields });
}

const LIMITS = { cpus: 8, memoryMb: 16_384 };
const GIB = 1024 * 1024 * 1024;

// ───────────────────────────── stderr line streaming ─────────────────────────────

describe("stderr line streaming", () => {
  test("lines are split across chunks and CRLF, a last partial line is flushed at the end", () => {
    const lines: string[] = [];
    const splitter = new LineSplitter((line) => lines.push(line));
    splitter.push('{"progress":true,"ev');
    splitter.push('ent":"heartbeat"}\r\nsecond');
    splitter.push(" line\n\nthird without break");
    expect(lines).toEqual(['{"progress":true,"event":"heartbeat"}', "second line", ""]);
    splitter.end();
    expect(lines.at(-1)).toBe("third without break");
    expect(splitter.delivered).toBe(4);
  });

  test("an overlong line is cut and the rest of it dropped; after the line limit lines are only counted", () => {
    const lines: string[] = [];
    const splitter = new LineSplitter((line) => lines.push(line), { maxLineChars: 10, maxLines: 3 });
    splitter.push("0123456789ABCDEF");
    splitter.push("GHIJ\nshort\n");
    expect(lines).toEqual(["0123456789…", "short"]);
    splitter.push("a\nb\nc\n");
    splitter.end();
    expect(lines).toEqual(["0123456789…", "short", "a"]);
    expect(splitter.dropped).toBe(2);
    // The default cut is MAX_STREAM_LINE_CHARS.
    const long: string[] = [];
    const defaults = new LineSplitter((line) => long.push(line));
    defaults.push(`${"x".repeat(MAX_STREAM_LINE_CHARS + 500)}\n`);
    expect(long[0].length).toBe(MAX_STREAM_LINE_CHARS + 1);
  });

  test("a listener that throws does not stop the stream", () => {
    const seen: string[] = [];
    const splitter = new LineSplitter((line) => {
      seen.push(line);
      throw new Error("listener failed");
    });
    splitter.push("a\nb\n");
    expect(seen).toEqual(["a", "b"]);
  });

  test("a running core's stderr reaches onStderrLine line by line, and the error document is still found", async () => {
    const dir = tempDir("sentra-cqp-stream-");
    // The Bun executable stands in for the core: progress lines written in pieces, a plain line,
    // then the error document as the last stderr object.
    const script = `
      const w = (text) => process.stderr.write(text);
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      (async () => {
        w('{"progress":true,"event":"step_started","step":"pack_download","language":"javascript","pack":"codeql/javascript-queries"}\\n{"progress":true,"event":"heart');
        await sleep(50);
        w('beat","step":"pack_download","language":"javascript","elapsed_ms":15000}\\r\\nplain warning line\\n');
        await sleep(50);
        w('{"schema_version":1,"error":"codeql_pack_download_failed","message":"denied: unauthorized","languages":[]}\\n');
        process.exit(5);
      })();`;
    const cli = new SentraCli(process.execPath, dir, 30_000, 2);
    const lines: string[] = [];
    const chunks: string[] = [];
    const result = await cli.run(["-e", script], { onStderrLine: (line) => lines.push(line), onOutput: (stream, text) => stream === "stderr" && chunks.push(text) });
    expect(result.code).toBe(5);
    expect(lines).toHaveLength(4);
    expect(parseProgressLine(lines[0])).toMatchObject({ event: "step_started", step: "pack_download", language: "javascript" });
    expect(parseProgressLine(lines[1])).toMatchObject({ event: "heartbeat", elapsedMs: 15000 });
    expect(lines[2]).toBe("plain warning line");
    expect(chunks.join("")).toBe(result.stderr);
    expect(coreErrorDocument(result)).toMatchObject({ code: "codeql_pack_download_failed", message: "denied: unauthorized" });
  }, 30_000);

  test("the error document is the last JSON line without progress: true, also after interleaved progress lines", () => {
    const stderr = [
      progressLine({ event: "step_started", step: "version" }),
      "a plain diagnostic",
      progressLine({ event: "step_failed", step: "database_analyze", language: "python", message: "x", error: "not the error document" }),
      JSON.stringify({ schema_version: 1, error: "codeql_failed", message: "every language failed", languages: [{ language: "python", status: "failed", reason: "x", results: 0, duration_ms: 1 }] }),
      "",
    ].join("\n");
    const document = coreErrorDocument({ stdout: "", stderr });
    expect(document).toMatchObject({ code: "codeql_failed", message: "every language failed" });
    expect(Array.isArray(document?.details.languages)).toBe(true);
    // Only progress lines: no error document.
    expect(coreErrorDocument({ stdout: "", stderr: `${progressLine({ event: "heartbeat", step: "version", error: "x" })}\n` })).toBeNull();
  });
});

// ───────────────────────────── progress events ─────────────────────────────

describe("CodeQL progress events", () => {
  test("lines are parsed defensively", () => {
    expect(parseProgressLine("not json")).toBeNull();
    expect(parseProgressLine('{"progress":true,')).toBeNull();
    expect(parseProgressLine(JSON.stringify({ progress: false, event: "heartbeat", step: "version" }))).toBeNull();
    expect(parseProgressLine(JSON.stringify({ progress: "true", event: "heartbeat", step: "version" }))).toBeNull();
    expect(parseProgressLine(progressLine({ event: "exploded", step: "version" }))).toBeNull();
    expect(parseProgressLine(progressLine({ event: "heartbeat", step: "autobuild" }))).toBeNull();
    expect(parseProgressLine(progressLine({ event: "heartbeat", step: "version", padding: "x".repeat(9000) }))).toBeNull();
    expect(parseProgressLine("[1,2]")).toBeNull();
    const parsed = parseProgressLine(
      progressLine({ event: "step_failed", step: "pack_download", language: "Java Script", pack: "../../etc", elapsed_ms: -5, duration_ms: 12.6, message: "denied\u001b[31m\n  retry" }),
    );
    expect(parsed).toEqual({ event: "step_failed", step: "pack_download", language: null, pack: null, elapsedMs: null, durationMs: 13, message: "denied [31m retry" });
    // A skip may name no step.
    expect(parseProgressLine(progressLine({ event: "language_skipped", language: "rust", message: "runs build scripts" }))).toMatchObject({ event: "language_skipped", step: null, language: "rust" });
  });

  test("durations read like people write them", () => {
    expect(formatElapsed(0)).toBe("0 s");
    expect(formatElapsed(45_400)).toBe("45 s");
    expect(formatElapsed(60_000)).toBe("1 min");
    expect(formatElapsed(135_000)).toBe("2 min 15 s");
    expect(formatElapsed(3_900_000)).toBe("1 h 5 min");
    expect(formatElapsed(7_200_000)).toBe("2 h");
    expect(formatElapsed(null)).toBe("unknown time");
  });

  test("every step becomes a readable line", () => {
    const text = (fields: Record<string, unknown>, suite?: "code-scanning") => progressFromLine(progressLine(fields), { suite })?.text;
    // "first run only" applies to a scan, whose download happens because the pack is not cached yet;
    // an explicit download in Settings > CodeQL > Query packs is not a first run of anything.
    const started = { event: "step_started", step: "pack_download", language: "javascript", pack: "codeql/javascript-queries" };
    expect(progressFromLine(progressLine(started), { scan: true })?.text).toBe(
      "Downloading query pack codeql/javascript-queries — first run only; can take several minutes on a slow connection",
    );
    expect(text(started)).toBe("Downloading query pack codeql/javascript-queries; can take several minutes on a slow connection");
    // The core's retry is shown as a retry, in both contexts.
    const retry = { ...started, message: "Retrying the download of codeql/javascript-queries (attempt 2 of 2)" };
    expect(progressFromLine(progressLine(retry), { scan: true })?.text).toBe("Retrying the download of codeql/javascript-queries (attempt 2 of 2)");
    expect(text(retry)).toBe("Retrying the download of codeql/javascript-queries (attempt 2 of 2)");
    // Another start message does not replace the readable line.
    expect(text({ ...started, message: "Downloading query pack codeql/javascript-queries into the pack cache (needed once)" })).toBe(
      "Downloading query pack codeql/javascript-queries; can take several minutes on a slow connection",
    );
    expect(text({ event: "heartbeat", step: "pack_download", language: "javascript", elapsed_ms: 135_000 })).toBe("Still downloading codeql/javascript-queries (2 min 15 s)");
    expect(text({ event: "step_finished", step: "pack_download", pack: "codeql/python-queries", duration_ms: 290_000 })).toBe(
      "Downloaded codeql/python-queries in 4 min 50 s; it stays in the pack cache",
    );
    expect(text({ event: "step_failed", step: "pack_download", pack: "codeql/actions-queries", duration_ms: 3000, message: "registry unreachable" })).toBe(
      "Downloading codeql/actions-queries failed after 3 s: registry unreachable",
    );
    expect(text({ event: "step_started", step: "database_create", language: "javascript" })).toBe("Creating the javascript database (build mode none)");
    // With --typescript-runtime the javascript line says what parses TypeScript; other languages do not.
    const withBun = (fields: Record<string, unknown>) => progressFromLine(progressLine(fields), { typescriptRuntime: "Bun" })?.text;
    expect(withBun({ event: "step_started", step: "database_create", language: "javascript" })).toBe(
      "Creating the javascript database (build mode none; TypeScript is parsed with Bun)",
    );
    expect(withBun({ event: "step_started", step: "database_create", language: "python" })).toBe("Creating the python database (build mode none)");
    expect(text({ event: "heartbeat", step: "database_create", language: "javascript", elapsed_ms: 30_000 })).toBe("Still creating the javascript database (30 s)");
    expect(text({ event: "step_started", step: "database_analyze", language: "javascript" }, "code-scanning")).toBe("Analyzing javascript (code-scanning suite)");
    expect(text({ event: "heartbeat", step: "database_analyze", language: "python", elapsed_ms: 180_000 })).toBe("Still analyzing python (3 min)");
    expect(text({ event: "step_finished", step: "database_analyze", language: "javascript", duration_ms: 34_000, message: "3 results" })).toBe("javascript finished: 3 results in 34 s");
    // The core's own wording of a finished analysis.
    expect(text({ event: "step_finished", step: "database_analyze", language: "python", duration_ms: 61_000, message: "python analyzed: 1 result (code-scanning suite)" })).toBe(
      "python finished: 1 result in 1 min 1 s",
    );
    expect(text({ event: "step_finished", step: "database_analyze", language: "ruby", duration_ms: 5_000, message: "done" })).toBe("ruby finished in 5 s (done)");
    expect(text({ event: "step_finished", step: "version", duration_ms: 900, message: "CodeQL CLI 2.27.4" })).toBe("CodeQL version checked in 1 s: CodeQL CLI 2.27.4");
    expect(text({ event: "step_started", step: "version" })).toBe("Checking the CodeQL version");
    expect(text({ event: "language_skipped", language: "rust", message: "CodeQL's Rust extractor runs the project's Cargo build scripts" })).toBe(
      "Skipping rust: CodeQL's Rust extractor runs the project's Cargo build scripts",
    );
    expect(describeProgress({ event: "step_failed", step: "database_analyze", language: "python", pack: null, elapsedMs: null, durationMs: null, message: null })).toBe("Analyzing python failed");
  });
});

// ───────────────────────────── RAM default ─────────────────────────────

describe("CodeQL RAM default", () => {
  test("half of the available memory within 1024..8192 MiB; an explicit setting wins", () => {
    expect(chooseRamMb({ ramMb: null }, 8 * GIB)).toMatchObject({ ramMb: 4096, source: "automatic", availableMb: 8192 });
    expect(chooseRamMb({ ramMb: null }, 8 * GIB).note).toContain("half of the 8192 MiB available on the host now");
    expect(chooseRamMb({ ramMb: null }, 64 * GIB)).toMatchObject({ ramMb: 8192 });
    expect(chooseRamMb({ ramMb: null }, 64 * GIB).note).toContain("capped at 8192 MiB");
    const tight = chooseRamMb({ ramMb: null }, 1500 * 1024 * 1024);
    expect(tight.ramMb).toBe(1024);
    expect(tight.note).toContain("below the minimum");
    expect(chooseRamMb({ ramMb: null }, 5001 * 1024 * 1024).ramMb).toBe(2500);
    expect(chooseRamMb({ ramMb: null }, null)).toMatchObject({ ramMb: RAM_AUTO_FALLBACK_MB, source: "automatic", availableMb: null });
    expect(chooseRamMb({ ramMb: 6000 }, 2 * GIB)).toMatchObject({ ramMb: 6000, source: "setting" });
    expect(chooseRamMb({ ramMb: 6000 }, 2 * GIB).note).toContain("the RAM setting in Settings > CodeQL");
  });

  test("a reading that is only os.freemem() on Linux or macOS is named; 2048 MiB only when nothing can be read", async () => {
    // Regression: the docs promised 2048 MiB for an unreadable reading, but HostPlatform falls back
    // to os.freemem(), which on macOS counts only free pages; the stage message did not say so.
    const host = (platform: NodeJS.Platform, freemem: () => number) =>
      new HostPlatform({ platform, run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null, freemem });
    const mac = await hostMemoryReading(host("darwin", () => 3 * GIB));
    expect(mac.availableBytes).toBe(3 * GIB);
    expect(mac.fallbackNote).toContain("os.freemem()");
    expect(mac.fallbackNote).toContain("vm_stat");
    expect(mac.fallbackNote).toContain("only free pages");
    const macRam = chooseRamMb({ ramMb: null }, mac.availableBytes, mac.fallbackNote);
    expect(macRam.ramMb).toBe(1536);
    expect(macRam.note).toContain("half of the 3072 MiB available on the host now (read with os.freemem() because vm_stat was not available");
    const linux = await hostMemoryReading(host("linux", () => 3 * GIB));
    expect(linux.fallbackNote).toContain("/proc/meminfo");
    // On Windows os.freemem() is the platform reading (available physical memory): nothing to add.
    const windows = await hostMemoryReading(host("win32", () => 3 * GIB));
    expect(windows).toEqual({ availableBytes: 3 * GIB, fallbackNote: null });
    // Only a reading that throws leaves the fixed fallback.
    const broken = await hostMemoryReading(
      host("win32", () => {
        throw new Error("no memory reading");
      }),
    );
    expect(broken).toEqual({ availableBytes: null, fallbackNote: null });
    expect(chooseRamMb({ ramMb: null }, broken.availableBytes).note).toContain(`--ram ${RAM_AUTO_FALLBACK_MB} MiB`);
  });
});

// ───────────────────────────── settings ─────────────────────────────

describe("downloadTimeoutMinutes setting", () => {
  test("is validated like the analysis timeout (5..180, integer) and falls back to 30 when stored out of range", () => {
    const refused = (body: Record<string, unknown>) => {
      try {
        parseCodeqlSettingsUpdate(body, LIMITS);
        return null;
      } catch (error) {
        return error instanceof HttpError ? error.code : String(error);
      }
    };
    for (const value of [4, 181, 30.5, "30", null, true]) expect(refused({ downloadTimeoutMinutes: value })).toBe("invalid_request");
    expect(parseCodeqlSettingsUpdate({ downloadTimeoutMinutes: 5 }, LIMITS)).toEqual({ downloadTimeoutMinutes: 5 });
    expect(parseCodeqlSettingsUpdate({ downloadTimeoutMinutes: 180 }, LIMITS)).toEqual({ downloadTimeoutMinutes: 180 });
    expect(parseCodeqlSettings({ downloadTimeoutMinutes: 999 }, LIMITS).downloadTimeoutMinutes).toBe(30);
    // Settings stored before the field existed read the default.
    expect(parseCodeqlSettings({ timeoutMinutes: 45 }, LIMITS)).toMatchObject({ timeoutMinutes: 45, downloadTimeoutMinutes: 30 });
    const db = openWebDb(path.join(tempDir("sentra-cqp-db-"), "web.db"));
    cleanup.dbs.push(db);
    const service = createCodeqlService(new SettingsStore(db), { dataDir: tempDir("sentra-cqp-data-") }, LIMITS);
    expect(service.update({ downloadTimeoutMinutes: 90 }, "admin").downloadTimeoutMinutes).toBe(90);
  });
});

// ───────────────────────────── scan stage ─────────────────────────────

type CliHandler = (args: string[], options: CliRunOptions) => CliResult | Promise<CliResult>;

function stageHarness(handler: CliHandler, options: { availableBytes?: number } = {}) {
  const db = openWebDb(path.join(tempDir("sentra-cqp-stage-db-"), "web.db"));
  cleanup.dbs.push(db);
  const settings = new SettingsStore(db);
  const dataDir = tempDir("sentra-cqp-stage-data-");
  const codeql = createCodeqlService(settings, { dataDir }, LIMITS);
  const workspace = tempDir("sentra-cqp-ws-");
  const tenant: TenantRecord = {
    tenantId: "t1",
    name: "t1",
    description: "",
    workspace,
    isolationLevel: "single_operator",
    githubOwner: null,
    githubRepo: null,
    createdAt: "2026-11-11T00:00:00.000Z",
    createdBy: "admin",
    importedFrom: null,
  };
  const calls: { args: string[]; options: CliRunOptions }[] = [];
  const empty = tempDir("sentra-cqp-path-");
  const app = {
    db,
    settings,
    audit: new AuditLog(db, crypto.randomBytes(32)),
    cli: {
      available: () => true,
      run: async (args: string[], runOptions: CliRunOptions = {}) => {
        calls.push({ args, options: runOptions });
        return handler(args, runOptions);
      },
    },
    osv: createOsvServiceFrom({ settings, client: new OsvClient(db, settings, async () => ({ status: 500, text: "" })), runInventory: async () => ({}) }),
    config: { cliLongTimeoutMs: 5_000, cliTimeoutMs: 5_000, ghBin: null, codeqlBin: fakeDistribution(), tmpDir: path.join(dataDir, "tmp"), dataDir },
    codeql,
    executables: new ExecutableLocator({ env: { PATH: empty, PATHEXT: ".EXE" }, homedir: empty, isDirectory: () => false }),
    hostPlatform: new HostPlatform({
      run: async () => ({ code: 1, stdout: "", timedOut: false }),
      readTextFile: async () => null,
      freemem: () => options.availableBytes ?? 10 * GIB,
    }),
    toolPaths: new ToolPathStore(settings),
    workspaces: {
      get: (tenantId: string) => {
        if (tenantId !== "t1") throw new HttpError(404, "tenant_not_found", "not registered");
        return tenant;
      },
      workspaceRoot: (record: TenantRecord) => record.workspace,
    },
  } as unknown as Omit<AppContext, "scans">;
  return { codeql, calls, service: createScanService(app) };
}

const PROBE = { primary_language: "javascript", detected_languages: [{ language: "javascript", files_count: 3 }], database_create_command: null, database_analyze_command: null };

function analyzeDocument(): Record<string, unknown> {
  return {
    schema_version: 1,
    command: "codeql analyze",
    codeql_version: "2.27.4",
    suite: "code-scanning",
    pack_download_allowed: true,
    target_code_executed: false,
    languages: [{ language: "javascript", status: "analyzed", reason: null, results: 0, duration_ms: 34_000, rules: [] }],
    findings: [],
    results_total: 0,
    results_outside_workspace: 0,
    truncated: false,
    warnings: [],
  };
}

const actor = { label: "alice", role: "operator" };

describe("scan CodeQL stage progress", () => {
  test("progress lines become progress events with readable text; other stderr lines stay log lines", async () => {
    const h = stageHarness((args, options) => {
      if (args[1] !== "analyze") return cliResult(PROBE);
      for (const line of [
        progressLine({ event: "step_started", step: "pack_download", language: "javascript", pack: "codeql/javascript-queries" }),
        progressLine({ event: "heartbeat", step: "pack_download", language: "javascript", pack: "codeql/javascript-queries", elapsed_ms: 135_000 }),
        "a CodeQL warning the core passed on",
        progressLine({ event: "step_started", step: "database_analyze", language: "javascript" }),
        progressLine({ event: "step_finished", step: "database_analyze", language: "javascript", duration_ms: 34_000, message: "3 results" }),
      ]) {
        options.onStderrLine?.(line);
      }
      return cliResult(analyzeDocument());
    });
    h.codeql.update({ enabled: true, acceptTerms: true, allowPackDownload: true }, "admin");
    const events: ScanStreamEvent[] = [];
    const run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(run.status).toBe("completed");
    const progress = events.filter((event) => event.type === "progress").map((event) => (event.type === "progress" ? event.progress.text : ""));
    expect(progress).toEqual([
      "Downloading query pack codeql/javascript-queries — first run only; can take several minutes on a slow connection",
      "Still downloading codeql/javascript-queries (2 min 15 s)",
      "Analyzing javascript (code-scanning suite)",
      "javascript finished: 3 results in 34 s",
    ]);
    expect(events.every((event) => event.type !== "progress" || event.stage === "codeql")).toBe(true);
    const stderr = events.filter((event) => event.type === "log" && event.stream === "stderr");
    expect(stderr).toEqual([expect.objectContaining({ text: "a CodeQL warning the core passed on" })]);
    // The analyze call streams stderr by line and asks for progress.
    const analyze = h.calls.find((call) => call.args[1] === "analyze")!;
    expect(analyze.args).toContain("--progress");
    expect(typeof analyze.options.onStderrLine).toBe("function");
  });

  test("the stage says which RAM limit was chosen and why; an explicit RAM setting wins", async () => {
    const h = stageHarness((args) => (args[1] === "analyze" ? cliResult(analyzeDocument()) : cliResult(PROBE)), { availableBytes: 7 * GIB });
    h.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    let events: ScanStreamEvent[] = [];
    await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    const analyze = () => h.calls.filter((call) => call.args[1] === "analyze").at(-1)!.args;
    expect(analyze()[analyze().indexOf("--ram") + 1]).toBe("3584");
    const starting = events.find((event) => event.type === "stage" && event.stage === "codeql" && event.status === "started" && event.message.includes("host analysis is starting"));
    expect(starting && starting.type === "stage" ? starting.message : "").toContain("--ram 3584 MiB, chosen automatically: half of the 7168 MiB available on the host now");
    expect(starting && starting.type === "stage" ? starting.message : "").toContain("Pack download is off");

    h.codeql.update({ ramMb: 2048, allowPackDownload: true, downloadTimeoutMinutes: 45 }, "admin");
    events = [];
    await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    expect(analyze()[analyze().indexOf("--ram") + 1]).toBe("2048");
    expect(analyze()[analyze().indexOf("--download-timeout-secs") + 1]).toBe("2700");
    const bridgeLines = events.filter((event) => event.type === "log" && event.stream === "bridge").map((event) => (event.type === "log" ? event.text : ""));
    expect(bridgeLines.some((line) => line.includes("--ram 2048 MiB, the RAM setting in Settings > CodeQL"))).toBe(true);
    expect(bridgeLines.some((line) => line.includes("query pack downloads: 45 min of their own (--download-timeout-secs 2700), not counted against the analysis"))).toBe(true);
  });

  test("a memory failure names the --ram the analysis ran with", async () => {
    const failure = cliResult(
      undefined,
      5,
      [
        progressLine({ event: "step_failed", step: "database_analyze", language: "javascript", message: "out of memory" }),
        JSON.stringify({
          schema_version: 1,
          error: "codeql_failed",
          message: "CodeQL failed for every language it was run for",
          languages: [{ language: "javascript", status: "failed", reason: "CodeQL's Java VM could not get the memory it asked for", results: 0, duration_ms: 1 }],
        }),
      ].join("\n"),
    );
    const h = stageHarness((args) => (args[1] === "analyze" ? failure : cliResult(PROBE)), { availableBytes: 4 * GIB });
    h.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    const run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor });
    expect(run.status).toBe("failed");
    // The error document after a progress line is still found, and the hint names the automatic limit.
    expect(run.summary?.codeqlAnalysis?.message).toContain("codeql_failed");
    expect(run.summary?.codeqlAnalysis?.message).toContain("This analysis ran with --ram 2048 MiB (chosen automatically).");
  });

  test("the bridge's Bun inside the scanned workspace is not passed as --typescript-runtime, and the stage says why", async () => {
    // Regression: the core refuses a --typescript-runtime inside the workspace (invalid_typescript_runtime)
    // and fails the whole analysis, e.g. for a home-directory workspace holding ~/.bun/bin/bun.
    const workspace = tempDir("sentra-cqp-tsws-");
    const inside = path.join(workspace, ".bun", "bin", hostExecutableName("bun"));
    fs.mkdirSync(path.dirname(inside), { recursive: true });
    fs.writeFileSync(inside, hostNativeHeader());
    const outside = path.join(tempDir("sentra-cqp-bun-"), hostExecutableName("bun"));
    fs.writeFileSync(outside, hostNativeHeader());
    const note = "TypeScript is parsed with Bun, the runtime the bridge runs on; no Node.js is needed.";
    expect(runtimeForWorkspace({ path: outside, note }, workspace)).toEqual({ path: outside, note });
    expect(runtimeForWorkspace(undefined, workspace)).toBeUndefined();
    const refused = runtimeForWorkspace({ path: inside, note }, workspace);
    expect(refused?.path).toBeNull();
    expect(refused?.note).toContain("lies inside the workspace being scanned");

    const db = openWebDb(path.join(tempDir("sentra-cqp-ts-db-"), "web.db"));
    cleanup.dbs.push(db);
    const dataDir = tempDir("sentra-cqp-ts-data-");
    const calls: string[][] = [];
    const app = {
      cli: {
        run: async (args: string[]) => {
          calls.push(args);
          return cliResult(analyzeDocument());
        },
      },
      config: { tmpDir: path.join(dataDir, "tmp"), dataDir },
      codeql: createCodeqlService(new SettingsStore(db), { dataDir }, LIMITS),
      hostPlatform: new HostPlatform({ platform: "win32", run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null, freemem: () => 8 * GIB }),
    } as unknown as Parameters<typeof runHostAnalysis>[0];
    const run = async (runtimePath: string) => {
      let limits = "";
      const outcome = await runHostAnalysis(app, { workspace, launcher: fakeDistribution(), typescriptRuntime: { path: runtimePath, note }, onLimits: (text) => (limits = text) });
      return { outcome, limits, args: calls.at(-1)! };
    };
    const insideRun = await run(inside);
    expect(insideRun.outcome.status).toBe("completed");
    expect(insideRun.args).not.toContain("--typescript-runtime");
    expect(insideRun.limits).toContain("lies inside the workspace being scanned");
    const outsideRun = await run(outside);
    expect(outsideRun.args[outsideRun.args.indexOf("--typescript-runtime") + 1]).toBe(outside);
    expect(outsideRun.limits).toContain("no Node.js is needed");
  });

  test("the isolation note says no Node.js is needed only when the bridge can pass its Bun", () => {
    // Regression: it always said so, also when typescriptRuntimeChoice passes no path.
    expect(codeqlIsolationNote({ path: "C:/Users/me/.bun/bin/bun.exe" })).toContain("TypeScript is parsed with Bun");
    expect(codeqlIsolationNote({ path: "C:/Users/me/.bun/bin/bun.exe" })).toContain("no Node.js is needed");
    const without = codeqlIsolationNote({ path: null });
    expect(without).not.toContain("no Node.js is needed");
    expect(without).toContain("CodeQL needs Node.js to extract TypeScript files");
  });

  test("a running pack download makes a scan skip host analysis and say so", async () => {
    const h = stageHarness((args) => (args[1] === "analyze" ? Promise.reject(new Error("must not run")) : cliResult(PROBE)));
    h.codeql.update({ enabled: true, acceptTerms: true }, "admin");
    const release = h.codeql.lock.tryAcquire(null, "pack_download", "admin")!;
    const events: ScanStreamEvent[] = [];
    const run = await h.service.run({ tenantId: "t1", kind: "codeql", trigger: "operator", actor, onEvent: (event) => events.push(event) });
    release();
    expect(run.summary?.codeqlAnalysis).toMatchObject({ attempted: false, skipReason: "analysis_busy" });
    const completed = events.find((event) => event.type === "stage" && event.stage === "codeql" && event.status === "completed");
    expect(completed && completed.type === "stage" ? completed.message : "").toContain("A CodeQL query pack download is running on this bridge");
    expect(busySkip({ operation: "pack_download", tenantId: null, startedAt: "2026-11-11T00:00:00.000Z", actor: "admin" }).message).toContain("by admin");
  });
});

// ───────────────────────────── pack documents ─────────────────────────────

describe("sentra codeql packs documents", () => {
  test("entries are parsed defensively", () => {
    const entries = parsePackEntries([
      { language: "javascript", pack: "codeql/javascript-queries", analysable: true, status: "present", source: "pack_cache", version: "2.5.0", location: "C:/cache/packages/codeql/javascript-queries/2.5.0", size_bytes: 53_477_376 },
      { language: "python", status: "missing" },
      { language: "rust", analysable: false, status: "not_analysable", reason: "runs Cargo build scripts" },
      { language: "ruby", available: true },
      { language: "JAVASCRIPT", status: "present" },
      { language: "bad id!", status: "present" },
      { language: "cpp", status: "present", version: "1.0.0; rm -rf", location: "C:/x\u0000y", size_bytes: -1, source: "elsewhere" },
      "not an object",
    ]);
    expect(entries.map((entry) => [entry.language, entry.status, entry.analysable])).toEqual([
      ["javascript", "present", true],
      ["python", "missing", true],
      ["rust", "not_analysable", false],
      ["ruby", "present", true],
      ["cpp", "present", true],
    ]);
    expect(entries[0]).toMatchObject({ source: "pack_cache", version: "2.5.0", sizeBytes: 53_477_376 });
    expect(entries[1].pack).toBe("codeql/python-queries");
    expect(entries[2]).toMatchObject({ pack: null, reason: "runs Cargo build scripts" });
    expect(entries[4]).toMatchObject({ version: null, location: null, sizeBytes: null, source: null });
  });

  test("download languages: only analysable ids, no repeats, at most 10", () => {
    expect(parsePackLanguages({})).toBeUndefined();
    expect(parsePackLanguages({ languages: ["javascript", "python", "javascript"] })).toEqual(["javascript", "python"]);
    for (const body of [{ languages: [] }, { languages: ["rust"] }, { languages: "javascript" }, { languages: [1] }, { other: true }, { languages: Array(11).fill("python") }]) {
      expect(() => parsePackLanguages(body)).toThrow(HttpError);
    }
  });

  test("download outcomes: completed, partial, cancelled, nothing to do, timeout", () => {
    const packs = { available: false } as CodeqlPacksView;
    const context = { requested: undefined, durationMs: 300_000, packs, settingsMinutes: 30 };
    const doc = (languages: unknown[]) => cliResult({ schema_version: 1, command: "codeql packs", suite: "code-scanning", languages });
    expect(interpretDownload(doc([{ language: "javascript", status: "downloaded" }, { language: "python", status: "present" }]), context)).toMatchObject({
      outcome: "completed",
      requested: ["javascript"],
      downloaded: ["javascript"],
      failed: [],
    });
    expect(interpretDownload(doc([{ language: "python", status: "present" }]), context).outcome).toBe("nothing_to_do");
    const failedDoc = cliResult(
      undefined,
      5,
      [
        progressLine({ event: "step_failed", step: "pack_download", language: "python", message: "denied" }),
        JSON.stringify({
          schema_version: 1,
          error: "codeql_pack_download_failed",
          message: "codeql pack download failed for codeql/python-queries: denied",
          languages: [
            { language: "javascript", status: "downloaded" },
            { language: "python", status: "failed", reason: "denied" },
          ],
        }),
      ].join("\n"),
    );
    const partial = interpretDownload(failedDoc, { ...context, requested: ["javascript", "python"] });
    expect(partial).toMatchObject({ outcome: "partial", downloaded: ["javascript"], failed: [{ language: "python", message: "denied" }] });
    expect(partial.message).toContain("codeql_pack_download_failed");
    expect(partial.message).toContain("stay in the pack cache");
    const cancelled = interpretDownload(cliResult(undefined, 5, JSON.stringify({ schema_version: 1, error: "codeql_cancelled", message: "cancelled" })), context);
    expect(cancelled.outcome).toBe("cancelled");
    expect(cancelled.message).toContain("Packs that finished downloading stay in the pack cache");
    // Nothing partial is kept, and a later download is not promised (it depends on allowPackDownload).
    expect(cancelled.message).toContain("Sentra keeps no partial pack");
    expect(cancelled.message).not.toContain("downloaded again next time");
    expect(cancelled.message).toContain("if pack download is allowed");
    expect(interpretDownload({ ...cliResult(undefined, 1), timedOut: true }, context).message).toContain("download budget is 30 minutes");
  });

  test("a failed download's message names each reason once and claims no interruption", () => {
    // Regression: the deduplication check was inverted, so the reason and the cache sentence were
    // repeated, and "a pack that was still downloading was discarded" was added to a network failure.
    const reason = "codeql pack download exited with code 2: Connection timed out (failed twice)";
    const failure = cliResult(
      undefined,
      5,
      JSON.stringify({
        schema_version: 1,
        error: "codeql_pack_download_failed",
        message: `1 of 1 query pack downloads failed (codeql/ruby-queries: ${reason}); packs downloaded successfully stay in the pack cache`,
        languages: [{ language: "ruby", status: "failed", reason }],
      }),
    );
    const context = { requested: ["ruby"], durationMs: 60_000, packs: { available: false } as CodeqlPacksView, settingsMinutes: 30 };
    const view = interpretDownload(failure, context);
    expect(view.outcome).toBe("failed");
    const count = (needle: string) => view.message.split(needle).length - 1;
    expect(count("Connection timed out")).toBe(1);
    expect(count("stay in the pack cache")).toBe(1);
    expect(view.message).not.toContain("still downloading");
    // A core message that does not name the reason gets it appended, with the cache sentence once.
    const terse = interpretDownload(
      cliResult(undefined, 5, JSON.stringify({ schema_version: 1, error: "codeql_pack_download_failed", message: "a download failed", languages: [{ language: "ruby", status: "failed", reason }] })),
      context,
    );
    expect(terse.message).toBe(`codeql_pack_download_failed: a download failed (ruby: ${reason}). Packs that finished downloading stay in the pack cache.`);
  });
});

// ───────────────────────────── routes ─────────────────────────────

const ADMIN_TOKEN = "a".repeat(40);
const OPERATOR_TOKEN = "o".repeat(40);
const VIEWER_TOKEN = "v".repeat(40);
const PORT = 3994;

function bridgeConfig(): ServerConfig {
  const dataDir = tempDir("sentra-cqp-bridge-");
  const tmp = path.join(dataDir, "tmp");
  fs.mkdirSync(tmp);
  return {
    repoRoot: tempDir("sentra-cqp-repo-"),
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
    cliMaxConcurrency: 2,
    trustProxy: false,
    workspaceRoots: [],
    pluginDir: null,
    tmpDir: tmp,
  };
}

interface SharedCall {
  args: string[];
  ttlMs: number;
  fresh: boolean | undefined;
  /** Whether the CodeQL lock was held when the listing was read. */
  lockHeld: boolean;
}

const PACK_LISTING = {
  schema_version: 1,
  command: "codeql packs",
  suite: "code-scanning",
  languages: [
    { language: "actions", status: "missing" },
    { language: "javascript", status: "present", source: "pack_cache", version: "2.5.0", location: "/cache/packages/codeql/javascript-queries/2.5.0", size_bytes: 53_477_376 },
    { language: "python", status: "missing" },
    { language: "rust", analysable: false, status: "not_analysable", reason: "CodeQL's Rust extractor runs the project's Cargo build scripts" },
  ],
};

function bridge(options: { cli?: CliHandler; launcher?: boolean; enabled?: boolean } = {}) {
  const executables = new ExecutableLocator({ env: { PATH: tempDir("sentra-cqp-nopath-") }, homedir: tempDir("sentra-cqp-home-"), isDirectory: () => false });
  const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null, freemem: () => 12 * GIB });
  const config = bridgeConfig();
  const { app, router } = createApp(config, { executables, hostPlatform });
  cleanup.dbs.push(app.db);
  if (options.launcher !== false) (app.config as { codeqlBin: string | null }).codeqlBin = fakeDistribution();
  // Downloads run only while host analysis is enabled with accepted terms.
  if (options.enabled !== false) app.codeql.update({ enabled: true, acceptTerms: true }, "admin");
  const calls: { args: string[]; options: CliRunOptions }[] = [];
  const shared: SharedCall[] = [];
  (app as { cli: unknown }).cli = {
    available: () => true,
    queued: 0,
    run: async (args: string[], runOptions: CliRunOptions = {}) => {
      calls.push({ args, options: runOptions });
      if (!options.cli) throw new Error(`unexpected core call ${args.join(" ")}`);
      return options.cli(args, runOptions);
    },
    runShared: async (args: string[], sharedOptions: { ttlMs: number; fresh?: boolean }) => {
      if (args[0] === "codeql" && args[1] === "packs") {
        shared.push({ args, ttlMs: sharedOptions.ttlMs, fresh: sharedOptions.fresh, lockHeld: app.codeql.lock.current !== null });
        return cliResult(PACK_LISTING);
      }
      return cliResult({ version: "0.0.0" });
    },
  };
  const server = { requestIP: () => ({ address: "127.0.0.1", family: "IPv4" as const, port: 1 }), timeout: () => undefined };
  const request = (method: string, pathname: string, token: string, body?: unknown, extra: { accept?: string; signal?: AbortSignal } = {}) => {
    const headers: Record<string, string> = { host: `127.0.0.1:${PORT}`, authorization: `Bearer ${token}` };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (extra.accept) headers.accept = extra.accept;
    return handleRequest(
      new Request(`http://127.0.0.1:${PORT}${pathname}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, signal: extra.signal }),
      server,
      app as AppContext,
      router as Router,
    );
  };
  const send = async (method: string, pathname: string, token: string, body?: unknown) => {
    const response = await request(method, pathname, token, body);
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  };
  const audits = () => app.audit.list({ limit: 50 }).reverse();
  return { app, router, calls, shared, send, request, audits };
}

/** Parses the data lines of an SSE body into events. */
function sseEvents(text: string): CodeqlPacksStreamEvent[] {
  return text
    .split("\n\n")
    .map((frame) => frame.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trim()).join("\n"))
    .filter(Boolean)
    .map((data) => JSON.parse(data) as CodeqlPacksStreamEvent);
}

function downloadResult(languages: unknown[]): CliResult {
  return cliResult({ schema_version: 1, command: "codeql packs", suite: "code-scanning", languages });
}

describe("query pack routes", () => {
  test("declare their permissions", () => {
    const { router } = bridge();
    const routes = Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]));
    expect(routes["GET /api/settings/codeql/packs"]).toBe("read");
    expect(routes["POST /api/settings/codeql/packs/download"]).toBe("settings:write");
  });

  test("listing: every role reads it, it is shared and reused briefly, ?refresh=1 reads it again", async () => {
    const h = bridge();
    const listed = await h.send("GET", "/api/settings/codeql/packs", VIEWER_TOKEN);
    expect(listed.status).toBe(200);
    const view = listed.body as CodeqlPacksView;
    expect(view).toMatchObject({ available: true, problem: null, suite: "code-scanning", missing: ["actions", "python"], running: null, downloadBlockedReason: null });
    expect(view.languages.find((entry) => entry.language === "javascript")).toMatchObject({ status: "present", version: "2.5.0", sizeBytes: 53_477_376, source: "pack_cache" });
    expect(view.languages.find((entry) => entry.language === "rust")).toMatchObject({ analysable: false, status: "not_analysable" });
    expect(view.packCache).toBe(path.join(h.app.config.dataDir, "codeql-packages"));
    const args = h.shared[0].args;
    expect(args.slice(0, 2)).toEqual(["codeql", "packs"]);
    expect(args[args.indexOf("--codeql") + 1]).toBe(h.app.config.codeqlBin as string);
    expect(args[args.indexOf("--pack-cache") + 1]).toBe(view.packCache);
    expect(args).toContain("--json");
    expect(args).not.toContain("--download");
    expect(h.shared[0]).toMatchObject({ ttlMs: PACKS_CACHE_TTL_MS, fresh: false });
    await h.send("GET", "/api/settings/codeql/packs?refresh=1", OPERATOR_TOKEN);
    expect(h.shared[1].fresh).toBe(true);
    expect(h.calls).toEqual([]);
  });

  test("while host analysis is disabled the listing works but a download is refused (audited), since it runs CodeQL", async () => {
    const h = bridge({ enabled: false, cli: () => downloadResult([]) });
    const view = (await h.send("GET", "/api/settings/codeql/packs", VIEWER_TOKEN)).body as CodeqlPacksView;
    expect(view.available).toBe(true);
    expect(view.downloadBlockedReason).toContain("only while CodeQL host analysis is enabled");
    const refused = await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["python"] });
    expect(refused.status).toBe(409);
    expect(refused.body.error.code).toBe("codeql_disabled");
    expect(h.calls).toEqual([]);
    expect(h.app.codeql.lock.current).toBeNull();
    const entry = h.audits().find((row) => row.action === "codeql_packs_downloaded")!;
    expect(entry.outcome).toBe("failure");
    expect(entry.details).toMatchObject({ languages: ["python"], error: expect.stringContaining("codeql_disabled") });
  });

  test("without a launcher the listing says why and a download is refused (audited)", async () => {
    const h = bridge({ launcher: false });
    const view = (await h.send("GET", "/api/settings/codeql/packs", VIEWER_TOKEN)).body as CodeqlPacksView;
    expect(view.available).toBe(false);
    expect(view.problem).toContain("No codeql launcher can be run");
    expect(view.downloadBlockedReason).toContain("No codeql launcher can be run");
    const refused = await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, {});
    expect(refused.status).toBe(409);
    expect(refused.body.error.code).toBe("codeql_launcher_unavailable");
    expect(h.calls).toEqual([]);
    expect(h.app.codeql.lock.current).toBeNull();
    const entries = h.audits().filter((entry) => entry.action === "codeql_packs_downloaded");
    expect(entries.map((entry) => entry.outcome)).toEqual(["failure"]);
    expect(String(entries[0].details.error)).toContain("codeql_launcher_unavailable");
  });

  test("download: SecurityAdmin only, runs one core command with the decided flags, audited", async () => {
    const h = bridge({
      cli: (args) => {
        expect(args.slice(0, 2)).toEqual(["codeql", "packs"]);
        return downloadResult([
          { language: "actions", status: "downloaded", source: "pack_cache", version: "0.6.39", size_bytes: 16_000_000 },
          { language: "python", status: "downloaded", source: "pack_cache", version: "1.9.0", size_bytes: 36_000_000 },
        ]);
      },
    });
    h.app.codeql.update({ downloadTimeoutMinutes: 45 }, "admin");
    expect((await h.send("POST", "/api/settings/codeql/packs/download", VIEWER_TOKEN, {})).status).toBe(403);
    expect((await h.send("POST", "/api/settings/codeql/packs/download", OPERATOR_TOKEN, {})).status).toBe(403);
    const invalid = await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["go"] });
    expect(invalid.status).toBe(400);
    expect(h.calls).toEqual([]);

    const done = await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["actions", "python"] });
    expect(done.status).toBe(200);
    const result = done.body as CodeqlPacksDownloadView;
    expect(result).toMatchObject({ outcome: "completed", requested: ["actions", "python"], downloaded: ["actions", "python"], failed: [] });
    expect(result.packs.available).toBe(true);
    // Regression: the listing was read while the download still held the lock, so it reported the
    // finished download as running and the download button as blocked.
    expect(result.packs.running).toBeNull();
    expect(result.packs.downloadBlockedReason).toBeNull();
    const [call] = h.calls;
    const flag = (name: string) => call.args[call.args.indexOf(name) + 1];
    expect(call.args.filter((_, index) => call.args[index - 1] === "--language")).toEqual(["actions", "python"]);
    expect(flag("--suite")).toBe("code-scanning");
    expect(flag("--timeout-secs")).toBe("2700");
    for (const required of ["--download", "--cancel-on-stdin-eof", "--progress", "--json"]) expect(call.args).toContain(required);
    expect(call.args).not.toContain("--accept-codeql-terms");
    expect(call.options).toMatchObject({ cancelViaStdinEof: true, timeoutMs: 2_700_000 + 120_000 });
    // The listing after a download is read fresh.
    expect(h.shared.at(-1)?.fresh).toBe(true);
    expect(h.app.codeql.lock.current).toBeNull();

    const entries = h.audits().filter((entry) => entry.action === "codeql_packs_downloaded" || entry.action === "authorization_denied");
    expect(entries.map((entry) => `${entry.action}:${entry.outcome}`)).toEqual([
      "authorization_denied:denied",
      "authorization_denied:denied",
      "codeql_packs_downloaded:success",
    ]);
    expect(entries[2]).toMatchObject({ actor: "admin", target: "codeql_packs" });
    expect(entries[2].details).toMatchObject({ languages: ["actions", "python"], outcome: "completed", downloaded: ["actions", "python"] });
    expect(h.app.audit.verify().valid).toBe(true);
  });

  test("a failed pack keeps the completed ones and is audited as a failure with CodeQL's message", async () => {
    const h = bridge({
      cli: () =>
        cliResult(
          undefined,
          5,
          JSON.stringify({
            schema_version: 1,
            error: "codeql_pack_download_failed",
            message: "codeql pack download codeql/python-queries failed twice: Error: connect ETIMEDOUT ghcr.io",
            languages: [
              { language: "actions", status: "downloaded" },
              { language: "python", status: "failed", reason: "connect ETIMEDOUT ghcr.io" },
            ],
          }),
        ),
    });
    const result = (await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, {})).body as CodeqlPacksDownloadView;
    expect(result).toMatchObject({ outcome: "partial", downloaded: ["actions"], failed: [{ language: "python", message: "connect ETIMEDOUT ghcr.io" }] });
    expect(result.message).toContain("ETIMEDOUT");
    expect(h.calls[0].args).not.toContain("--language");
    const entry = h.audits().find((row) => row.action === "codeql_packs_downloaded")!;
    expect(entry.outcome).toBe("failure");
    expect(entry.details).toMatchObject({ languages: "all missing", outcome: "partial", failed: [{ language: "python" }] });
  });

  test("download and host analysis share one lock in both directions", async () => {
    let releaseCore: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseCore = resolve;
    });
    let entered = 0;
    const h = bridge({
      cli: async () => {
        entered += 1;
        await gate;
        return downloadResult([{ language: "python", status: "downloaded" }]);
      },
    });
    // An analysis holds the lock: the download is refused at once.
    const analysis = h.app.codeql.lock.tryAcquire("t1")!;
    const busy = await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["python"] });
    expect(busy.status).toBe(409);
    expect(busy.body.error.code).toBe("codeql_busy");
    expect(busy.body.error.message).toContain("Another CodeQL analysis is running on this bridge (workspace 't1'");
    analysis();

    // A download holds the lock: the settings and the listing say so, and an analysis cannot start.
    const pending = h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["python"] });
    while (entered === 0) await Bun.sleep(5);
    expect(h.app.codeql.lock.current).toMatchObject({ operation: "pack_download", tenantId: null, actor: "admin" });
    expect(h.app.codeql.lock.tryAcquire("t1")).toBeNull();
    const settings = (await h.send("GET", "/api/settings/codeql", VIEWER_TOKEN)).body as CodeqlSettingsView;
    expect(settings.running).toMatchObject({ operation: "pack_download", tenantId: null, actor: "admin" });
    const listing = (await h.send("GET", "/api/settings/codeql/packs", VIEWER_TOKEN)).body as CodeqlPacksView;
    expect(listing.running).toMatchObject({ operation: "pack_download" });
    expect(listing.downloadBlockedReason).toContain("A CodeQL query pack download is running on this bridge");
    const second = await h.send("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["python"] });
    expect(second.status).toBe(409);
    releaseCore();
    expect((await pending).status).toBe(200);
    expect(h.app.codeql.lock.current).toBeNull();
    expect(entered).toBe(1);
  });

  test("SSE: progress, log and complete events reach the stream", async () => {
    const h = bridge({
      cli: (_args, options) => {
        options.onStderrLine?.(progressLine({ event: "step_started", step: "pack_download", language: "python", pack: "codeql/python-queries" }));
        options.onStderrLine?.(progressLine({ event: "heartbeat", step: "pack_download", language: "python", pack: "codeql/python-queries", elapsed_ms: 135_000 }));
        options.onStderrLine?.("retrying after a registry error");
        options.onStderrLine?.(progressLine({ event: "step_finished", step: "pack_download", language: "python", pack: "codeql/python-queries", duration_ms: 290_000 }));
        return downloadResult([{ language: "python", status: "downloaded" }]);
      },
    });
    const response = await h.request("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["python"] }, { accept: "text/event-stream" });
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const events = sseEvents(await response.text());
    const progress = events.flatMap((event) => (event.type === "progress" ? [event.progress.text] : []));
    expect(progress).toEqual([
      "Downloading query pack codeql/python-queries; can take several minutes on a slow connection",
      "Still downloading codeql/python-queries (2 min 15 s)",
      "Downloaded codeql/python-queries in 4 min 50 s; it stays in the pack cache",
    ]);
    expect(events.some((event) => event.type === "log" && event.stream === "stderr" && event.text === "retrying after a registry error")).toBe(true);
    expect(events.some((event) => event.type === "log" && event.stream === "bridge" && event.text.startsWith("Running: sentra codeql packs"))).toBe(true);
    const complete = events.at(-1);
    expect(complete?.type).toBe("complete");
    expect(complete && complete.type === "complete" ? complete.result.outcome : null).toBe("completed");
    expect(complete && complete.type === "complete" ? complete.result.packs.running : "missing").toBeNull();
    expect(h.shared.at(-1)?.lockHeld).toBe(false);
  });

  test("SSE: a refusal is an error event; closing the stream cancels the download and releases the lock", async () => {
    const busy = bridge({ cli: () => downloadResult([]) });
    const holder = busy.app.codeql.lock.tryAcquire("t1")!;
    const refused = sseEvents(await (await busy.request("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, {}, { accept: "text/event-stream" })).text());
    expect(refused).toEqual([expect.objectContaining({ type: "error", status: 409, code: "codeql_busy" })]);
    holder();

    let sawSignal: AbortSignal | undefined;
    const h = bridge({
      cli: (_args, options) =>
        new Promise<CliResult>((resolve) => {
          sawSignal = options.signal;
          options.onStderrLine?.(progressLine({ event: "step_started", step: "pack_download", language: "python", pack: "codeql/python-queries" }));
          // The core answers stdin EOF by killing CodeQL and reporting codeql_cancelled.
          options.signal?.addEventListener("abort", () =>
            resolve(cliResult(undefined, 5, JSON.stringify({ schema_version: 1, error: "codeql_cancelled", message: "cancelled during codeql pack download", languages: [] }))),
          );
        }),
    });
    const response = await h.request("POST", "/api/settings/codeql/packs/download", ADMIN_TOKEN, { languages: ["python"] }, { accept: "text/event-stream" });
    const reader = response.body!.getReader();
    const first = new TextDecoder().decode((await reader.read()).value);
    expect(first).toContain("Running: sentra codeql packs");
    await reader.cancel();
    const started = performance.now();
    while (h.app.codeql.lock.current !== null && performance.now() - started < 5_000) await Bun.sleep(20);
    expect(sawSignal?.aborted).toBe(true);
    expect(h.app.codeql.lock.current).toBeNull();
    // The listing after the stopped download is read once CodeQL stopped, with the lock released.
    while (h.shared.length === 0 && performance.now() - started < 5_000) await Bun.sleep(20);
    expect(h.shared.at(-1)).toMatchObject({ fresh: true, lockHeld: false });
    let entry = h.audits().find((row) => row.action === "codeql_packs_downloaded");
    while (!entry && performance.now() - started < 5_000) {
      await Bun.sleep(20);
      entry = h.audits().find((row) => row.action === "codeql_packs_downloaded");
    }
    expect(entry?.outcome).toBe("failure");
    expect(entry?.details).toMatchObject({ outcome: "cancelled" });
  }, 15_000);

  test("settings route accepts downloadTimeoutMinutes and reports the automatic RAM limit", async () => {
    const h = bridge();
    const updated = await h.send("PUT", "/api/settings/codeql", ADMIN_TOKEN, { downloadTimeoutMinutes: 60 });
    expect(updated.status).toBe(200);
    const view = updated.body as CodeqlSettingsView;
    expect(view.settings.downloadTimeoutMinutes).toBe(60);
    expect(view.bounds.downloadTimeoutMinutes).toEqual({ min: 5, max: 180 });
    // 12 GiB available on the injected host: half of it.
    expect(view.ramAuto).toMatchObject({ mb: 6144, availableMb: 12_288 });
    expect(view.ramAuto.rule).toContain("half of the memory available on the host");
    expect((await h.send("PUT", "/api/settings/codeql", ADMIN_TOKEN, { downloadTimeoutMinutes: 2 })).status).toBe(400);
    const entry = h.audits().find((row) => row.action === "codeql_settings_updated" && row.outcome === "success")!;
    expect(entry.details).toMatchObject({ changes: { downloadTimeoutMinutes: 60 } });
  });
});

// ───────────────────────────── contract and console wording ─────────────────────────────

describe("contract and console wording", () => {
  test("the API contract version is 6", () => {
    expect(API_CONTRACT_VERSION).toBe(6);
  });

  test("stopping a scan explains that CodeQL and a pack download stop and completed packs stay", () => {
    const text = STOP_SCAN_PARAGRAPHS.join(" ");
    expect(text).toContain("CodeQL stops as well, including a query pack download in progress");
    expect(text).toContain("Query packs that finished downloading stay in the pack cache");
    expect(PACKS_DOWNLOAD_STOP_TEXT).toContain("stay in the pack cache");
    // Regression: both promised that an interrupted pack "is downloaded again next time", which no
    // scan does while pack download is off. The core keeps no partial pack (staging directory).
    for (const wording of [text, PACKS_DOWNLOAD_STOP_TEXT]) {
      expect(wording).not.toContain("downloaded again next time");
      expect(wording).toContain("Sentra keeps no partial pack");
      expect(wording).toContain("if pack download is allowed");
      expect(wording).toContain("Settings → CodeQL → Query packs → Download missing packs");
    }
  });

  test("the CodeQL stage hints at the first-run download and the prefetch action", () => {
    expect(codeqlStageHint({ stageRunning: false, packDownloadSeen: false })).toBeNull();
    expect(codeqlStageHint({ stageRunning: true, packDownloadSeen: false })).toBe(CODEQL_FIRST_RUN_HINT);
    expect(codeqlStageHint({ stageRunning: true, packDownloadSeen: true })).toBe(CODEQL_PREFETCH_HINT);
    // Regression: the finished stage kept saying "This scan is downloading query packs".
    expect(codeqlStageHint({ stageRunning: false, packDownloadSeen: true })).toBe(CODEQL_PREFETCH_DONE_HINT);
    expect(CODEQL_PREFETCH_DONE_HINT).not.toContain("is downloading");
    expect(CODEQL_PREFETCH_HINT).toContain("Settings → CodeQL → Query packs → Download missing packs");
    expect(CODEQL_PREFETCH_DONE_HINT).toContain("Settings → CodeQL → Query packs → Download missing packs");
    expect(CODEQL_FIRST_RUN_HINT).toContain("several minutes on a slow connection");
  });

  test("after Stop the panel waits until the bridge no longer reports the download as running", async () => {
    // Regression: the panel re-read the listing at once, while the bridge still held the lock, and
    // then showed "A query pack download is running" with the download button disabled.
    const running = { running: { operation: "pack_download" as const } };
    const idle = { running: null };
    const reads = [running, running, idle];
    let calls = 0;
    const slept: number[] = [];
    const sleep = async (ms: number) => {
      slept.push(ms);
    };
    expect(await waitForPackDownloadToEnd(async () => reads[calls++], { delayMs: 250, sleep })).toBe(idle);
    expect(calls).toBe(3);
    expect(slept).toEqual([250, 250]);
    // An analysis holding the lock is not this download: no waiting.
    calls = 0;
    const analysis = { running: { operation: "analysis" as const } };
    expect(await waitForPackDownloadToEnd(async () => (calls++, analysis), { sleep })).toBe(analysis);
    expect(calls).toBe(1);
    // Bounded: gives up after `attempts`, returning the last listing; failed reads are retried.
    calls = 0;
    const flaky = async () => {
      calls += 1;
      if (calls === 1) throw new Error("bridge busy");
      return running;
    };
    expect(await waitForPackDownloadToEnd(flaky, { attempts: 4, sleep })).toBe(running);
    expect(calls).toBe(4);
    // Stops when the panel goes away.
    const gone = new AbortController();
    gone.abort();
    expect(await waitForPackDownloadToEnd(async () => running, { signal: gone.signal, sleep })).toBeNull();
  });

  test("pack rows, the lock holder and download outcomes are named", () => {
    expect(packStatusText({ status: "present", source: "distribution" })).toBe("present (CodeQL distribution)");
    expect(packStatusText({ status: "downloaded", source: "pack_cache" })).toBe("downloaded (pack cache)");
    expect(packStatusText({ status: "not_analysable", source: null })).toBe("not analysed on the host");
    expect(runningText({ operation: "pack_download", tenantId: null, startedAt: "", actor: "admin" })).toBe("A query pack download is running (started by admin).");
    expect(runningText({ operation: "analysis", tenantId: "t1", startedAt: "", actor: null })).toBe("An analysis is running for workspace t1.");
    expect(downloadOutcomeTitle({ outcome: "completed", downloaded: ["python"] })).toBe("Downloaded 1 query pack");
    expect(downloadOutcomeTitle({ outcome: "cancelled", downloaded: [] })).toBe("Download stopped");
  });
});
