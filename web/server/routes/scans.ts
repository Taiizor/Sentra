import fs from "node:fs";
import path from "node:path";
import type {
  ConsoleCommand,
  ConsoleRunView,
  DiffDeltaView,
  DiffView,
  FileContentView,
  FindingSource,
  FindingState,
  OverviewView,
  ScanKind,
  ScanStreamEvent,
  SnippetScanView,
  TriageVerdict,
} from "../../src/types/api.ts";
import { SEVERITIES } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { nowIso } from "../db.ts";
import { HttpError, json, sseResponse, type AuthedContext, type Router } from "../http.ts";
import { markAuditHandled } from "../audit-log.ts";
import { isWithin, lexicalAbsolute, realDirectory, resolveInside } from "../paths.ts";
import { cliFailure, cliValue } from "../sentra-cli.ts";
import {
  findingCounts,
  getFinding,
  listFindings,
  openSecretLines,
  parseScanOutput,
  RISK_SCORE_FORMULA,
  riskScoreValue,
  toFindingView,
  toSastMatchView,
  triageFinding,
  computeTrends,
} from "../services/findings.ts";
import { buildSarif, readRepositoryUrl } from "../services/sarif.ts";
import { findRun, lastCompletedRunAt, lastResultRunAt, listRuns } from "../services/scans.ts";
import { asObject, oneOf, requiredString } from "../validate.ts";
import { actorOf, audited, intParam, tenantParam } from "./helpers.ts";

const SCAN_KINDS: readonly ScanKind[] = ["sast", "dependency", "codeql", "all"];
const FINDING_STATES: readonly (FindingState | "all")[] = ["open", "resolved", "all"];
const FINDING_SOURCES: readonly FindingSource[] = ["sast", "dependency"];
const TRIAGE_VERDICTS: readonly TriageVerdict[] = ["confirmed", "needs_validation", "rejected"];
const CONSOLE_COMMANDS: readonly ConsoleCommand[] = ["version", "status", "scan", "codeql", "inventory", "skills", "plugins"];

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SNIPPET_BYTES = 256 * 1024;
const MAX_CONSOLE_OUTPUT_BYTES = 256 * 1024;
const SNIPPET_FILE_NAME = /^[A-Za-z0-9._-]{1,100}$/;

const CASE_INSENSITIVE_FS = process.platform === "win32" || process.platform === "darwin";

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".rs": "rust",
  ".go": "go",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".hpp": "cpp",
  ".swift": "swift",
  ".scala": "scala",
  ".sh": "shell",
  ".bash": "shell",
  ".ps1": "powershell",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".json": "json",
  ".toml": "toml",
  ".md": "markdown",
  ".html": "html",
  ".css": "css",
  ".scss": "scss",
  ".sql": "sql",
  ".xml": "xml",
  ".vue": "vue",
  ".svelte": "svelte",
  ".tf": "hcl",
  ".lock": "text",
};

function languageOf(relative: string): string | null {
  const base = path.posix.basename(relative);
  if (/^dockerfile/i.test(base)) return "dockerfile";
  if (/^makefile$/i.test(base)) return "makefile";
  return LANGUAGE_BY_EXTENSION[path.posix.extname(base).toLowerCase()] ?? null;
}

function samePath(a: string, b: string): boolean {
  return CASE_INSENSITIVE_FS ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/** File names the bridge writes into its data directory (credentials, keys, its own database). */
const BRIDGE_DATA_FILE = /^(web-admin\.token|web-secret\.key|sentra-web\.db(-wal|-shm|-journal)?)$/;

/**
 * Workspace files the console never serves, whatever role asks. The bridge's own data files are
 * denied by name as well, in addition to the data-directory containment check, so they stay
 * unreadable even if the data directory is reachable through a path the check does not see.
 */
export function deniedReason(relative: string): string | null {
  const segments = relative.split("/");
  if (segments.some((segment) => segment.toLowerCase() === ".git")) return "git metadata is not served";
  const base = (segments[segments.length - 1] ?? "").toLowerCase();
  if (BRIDGE_DATA_FILE.test(base) || segments.some((segment) => segment.toLowerCase() === "core-stores")) {
    return "Sentra bridge data files are not served";
  }
  if (base.startsWith(".env")) return "environment files are not served";
  if (/\.(pem|key|p12|pfx)$/.test(base)) return "key and certificate files are not served";
  if (/^id_(rsa|dsa|ecdsa|ed25519)/.test(base)) return "SSH keys are not served";
  return null;
}

function readPrefix(file: string, size: number): Buffer {
  const length = Math.min(size, MAX_FILE_BYTES);
  const buffer = Buffer.alloc(length);
  const fd = fs.openSync(file, "r");
  let offset = 0;
  try {
    while (offset < length) {
      const read = fs.readSync(fd, buffer, offset, length - offset, offset);
      if (read === 0) break;
      offset += read;
    }
  } finally {
    fs.closeSync(fd);
  }
  return buffer.subarray(0, offset);
}

function capOutput(text: string): string {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.byteLength <= MAX_CONSOLE_OUTPUT_BYTES) return text;
  return `${new TextDecoder().decode(bytes.subarray(0, MAX_CONSOLE_OUTPUT_BYTES))}\n[output truncated by the Sentra bridge: ${bytes.byteLength} bytes total, first ${MAX_CONSOLE_OUTPUT_BYTES} shown]`;
}

let cachedCoreVersion: { value: string | null; at: number } | null = null;

async function coreVersion(app: AppContext): Promise<string | null> {
  if (cachedCoreVersion && Date.now() - cachedCoreVersion.at < 60_000) return cachedCoreVersion.value;
  let value: string | null = null;
  try {
    const result = await app.cli.runShared(["--version", "--json"], { ttlMs: 60_000, timeoutMs: 10_000 });
    const parsed = result.json as { version?: unknown } | undefined;
    if (result.code === 0 && typeof parsed?.version === "string") value = parsed.version;
  } catch {
    value = null;
  }
  cachedCoreVersion = { value, at: Date.now() };
  return value;
}

function patchCounts(app: AppContext, tenantId: string): OverviewView["patches"] {
  const rows = app.db.query("SELECT state, COUNT(*) AS c FROM patch_bundles WHERE tenant_id = ? GROUP BY state").all(tenantId) as {
    state: string;
    c: number;
  }[];
  const count = (state: string) => rows.find((row) => row.state === state)?.c ?? 0;
  const pullRequests = (
    app.db.query("SELECT COUNT(*) AS c FROM patch_bundles WHERE tenant_id = ? AND pr_number IS NOT NULL").get(tenantId) as { c: number }
  ).c;
  return { proposed: count("proposed"), applied: count("applied"), rolledBack: count("rolled_back"), pullRequests };
}

function mapDiff(raw: unknown): DiffView {
  const doc = asObject(raw, "diff output");
  const summary = (doc.summary && typeof doc.summary === "object" ? doc.summary : {}) as Record<string, unknown>;
  const num = (value: unknown) => (typeof value === "number" ? value : 0);
  const optionalNumber = (value: unknown) => (typeof value === "number" ? value : null);
  const optionalString = (value: unknown) => (typeof value === "string" ? value : null);
  const deltas: DiffDeltaView[] = (Array.isArray(doc.deltas) ? doc.deltas : [])
    .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object" && typeof (entry as Record<string, unknown>).path === "string")
    .map((entry) => {
      const kindRaw = entry.kind;
      const kind =
        typeof kindRaw === "string"
          ? kindRaw
          : kindRaw && typeof kindRaw === "object" && typeof (kindRaw as Record<string, unknown>).type === "string"
            ? ((kindRaw as Record<string, unknown>).type as string)
            : "unknown";
      return {
        path: entry.path as string,
        fromPath: optionalString(entry.from_path),
        kind,
        role: optionalString(entry.role),
        baseDigest: optionalString(entry.base_digest),
        headDigest: optionalString(entry.head_digest),
        baseSize: optionalNumber(entry.base_size),
        headSize: optionalNumber(entry.head_size),
      };
    });
  return {
    baseAggregateDigest: optionalString(doc.base_aggregate_digest) ?? "",
    headAggregateDigest: optionalString(doc.head_aggregate_digest) ?? "",
    summary: {
      totalFilesBase: num(summary.total_files_base),
      totalFilesHead: num(summary.total_files_head),
      addedFiles: num(summary.added_files),
      modifiedFiles: num(summary.modified_files),
      deletedFiles: num(summary.deleted_files),
      renamedFiles: num(summary.renamed_files),
      unchangedFiles: num(summary.unchanged_files),
      rustFilesChanged: num(summary.rust_files_changed),
      netBytesDelta: num(summary.net_bytes_delta),
    },
    deltas,
  };
}

function scanInProgress(app: AppContext, ctx: AuthedContext, tenantId: string, kind: ScanKind): HttpError {
  const error = new HttpError(409, "scan_in_progress", `A scan is already running for '${tenantId}'`);
  app.audit.append(ctx.principal, {
    action: "scan_failed",
    outcome: "failure",
    tenantId,
    details: { kind, trigger: "operator", error: `${error.code}: ${error.message}` },
  });
  return markAuditHandled(error);
}

/**
 * Resolves a diff directory. The lexical path must already lie inside a registered workspace
 * (and outside the data directory) before the disk is touched, so arbitrary host or network
 * paths are never opened; the canonical path is then checked again after following links.
 */
export function resolveDiffDirectory(app: Pick<AppContext, "config" | "workspaces">, body: Record<string, unknown>, field: "base" | "head"): string {
  const registered = app.workspaces.list().map((entry) => entry.workspace);
  const check = (candidate: string) => {
    if (isWithin(app.config.dataDir, candidate)) throw new HttpError(403, "path_denied", `'${field}' is inside the Sentra data directory`);
    if (!registered.some((workspace) => isWithin(workspace, candidate))) {
      throw new HttpError(403, "path_not_in_workspace", `'${field}' must be inside a registered tenant workspace`);
    }
  };
  const lexical = lexicalAbsolute(requiredString(body, field, { max: 1024 }), field);
  check(lexical);
  const dir = realDirectory(lexical, field);
  check(dir);
  return dir;
}

export function registerScanRoutes(router: Router, app: AppContext): void {
  // ── scan runs ───────────────────────────────────────────────────────────
  router.post("/api/tenants/:tenantId/scans", { auth: "session", permission: "scan:run" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = await ctx.readJson();
    const kind = oneOf(body.kind, "kind", SCAN_KINDS);
    if (app.scans.isRunning(tenant.tenantId)) throw scanInProgress(app, ctx, tenant.tenantId, kind);
    const actor = actorOf(ctx.principal);
    const wantsStream = (ctx.req.headers.get("accept") ?? "").toLowerCase().includes("text/event-stream");
    if (!wantsStream) {
      const run = await app.scans.run({ tenantId: tenant.tenantId, kind, trigger: "operator", actor, signal: ctx.req.signal });
      return json(run);
    }
    return sseResponse(ctx.req, async (channel, signal) => {
      // Abort the core process when the request is aborted or the stream is cancelled.
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener("abort", abort, { once: true });
      const poll = setInterval(() => {
        if (channel.closed) abort();
      }, 1000);
      try {
        await app.scans.run({
          tenantId: tenant.tenantId,
          kind,
          trigger: "operator",
          actor,
          signal: controller.signal,
          onEvent: (event) => channel.send(event.type, event),
        });
      } catch (error) {
        const event: ScanStreamEvent =
          error instanceof HttpError
            ? { type: "error", status: error.status, code: error.code, message: error.message }
            : { type: "error", status: 500, code: "scan_failed", message: "The scan failed unexpectedly; see the bridge log." };
        channel.send(event.type, event);
      } finally {
        clearInterval(poll);
        signal.removeEventListener("abort", abort);
      }
    });
  });

  router.get("/api/tenants/:tenantId/scans", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const limit = intParam(ctx.url.searchParams.get("limit"), "limit", 1, 500, 50);
    return json({ runs: listRuns(app, tenant.tenantId, tenant.workspace, limit) });
  });

  router.get("/api/tenants/:tenantId/scans/:runId", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const run = findRun(app, tenant.tenantId, ctx.params.runId);
    if (!run) throw new HttpError(404, "run_not_found", "Scan run not found");
    return json(run);
  });

  // ── findings ────────────────────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/findings", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const params = ctx.url.searchParams;
    const state = oneOf(params.get("state") ?? "open", "state", FINDING_STATES);
    const source = params.get("source") ? oneOf(params.get("source"), "source", FINDING_SOURCES) : undefined;
    const severity = params.get("severity") ? oneOf(params.get("severity"), "severity", SEVERITIES) : undefined;
    const findings = listFindings(app.db, tenant.tenantId, tenant.workspace, { state, source, severity }).map(toFindingView);
    return json({ findings });
  });

  router.get("/api/tenants/:tenantId/findings/:findingId", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json(toFindingView(getFinding(app.db, tenant.tenantId, ctx.params.findingId)));
  });

  router.post("/api/tenants/:tenantId/findings/:findingId/triage", { auth: "session", permission: "finding:triage" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const findingId = ctx.params.findingId;
    const body = await ctx.readJson();
    const verdict = oneOf(body.verdict, "verdict", TRIAGE_VERDICTS);
    const reason = requiredString(body, "reason", { min: 1, max: 2000 });
    const previous = getFinding(app.db, tenant.tenantId, findingId).triage?.verdict ?? null;
    const updated = await audited(
      app,
      ctx.principal,
      { action: "finding_triaged", tenantId: tenant.tenantId, target: findingId, details: { findingId, verdict, previousVerdict: previous } },
      () => triageFinding(app.db, tenant.tenantId, findingId, { verdict, reason, by: ctx.principal.label, at: nowIso() }),
    );
    return json(toFindingView(updated));
  });

  // ── workspace file viewer ───────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/files", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const raw = (ctx.url.searchParams.get("path") ?? "").replace(/\\/g, "/");
    if (!raw || raw.length > 1024) throw new HttpError(400, "invalid_request", "'path' must be a workspace-relative path of 1-1024 characters");
    if (path.isAbsolute(raw) || /^[A-Za-z]:/.test(raw)) {
      throw new HttpError(400, "invalid_path", "'path' must be relative to the workspace root");
    }
    const root = app.workspaces.workspaceRoot(tenant);
    // "./" keeps resolveInside from treating a leading "a/" or "b/" directory as a diff prefix.
    const { absolute, relative } = resolveInside(root, `./${raw.replace(/^\.\/+/, "")}`);
    const denied = deniedReason(relative);
    if (denied) throw new HttpError(403, "path_denied", `This path cannot be viewed: ${denied}`);
    if (isWithin(app.config.dataDir, absolute)) throw new HttpError(403, "path_denied", "Sentra data files cannot be viewed");
    let stat: fs.Stats;
    try {
      stat = fs.statSync(absolute);
    } catch {
      throw new HttpError(404, "file_not_found", `'${relative}' does not exist in the workspace`);
    }
    if (!stat.isFile()) throw new HttpError(400, "not_a_file", `'${relative}' is not a regular file`);
    const buffer = readPrefix(absolute, stat.size);
    if (buffer.includes(0)) throw new HttpError(415, "binary_file", `'${relative}' looks like a binary file`);
    const truncated = stat.size > buffer.byteLength;
    let content = new TextDecoder("utf-8").decode(buffer);
    if (truncated) {
      // Drop the trailing partial line (it may also end inside a multi-byte character).
      const lastNewline = content.lastIndexOf("\n");
      if (lastNewline >= 0) content = content.slice(0, lastNewline + 1);
    }
    const redactions = new Map<number, string[]>();
    for (const secret of openSecretLines(app.db, tenant.tenantId, tenant.workspace)) {
      if (!samePath(secret.filePath, relative)) continue;
      redactions.set(secret.line, [...(redactions.get(secret.line) ?? []), secret.ruleId]);
    }
    const lines = content.split("\n");
    if (redactions.size > 0) {
      for (const [line, ruleIds] of redactions) {
        const index = line - 1;
        if (index < 0 || index >= lines.length) continue;
        const carriageReturn = lines[index].endsWith("\r") ? "\r" : "";
        lines[index] = `[redacted by Sentra: ${[...new Set(ruleIds)].join(", ")}]${carriageReturn}`;
      }
      content = lines.join("\n");
    }
    const lineCount = content.length === 0 ? 0 : content.endsWith("\n") ? lines.length - 1 : lines.length;
    const body: FileContentView = { path: relative, sizeBytes: stat.size, lineCount, content, truncated, language: languageOf(relative) };
    return json(body);
  });

  // ── overview & trends ───────────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/overview", { auth: "session", permission: "read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    // Sequential on purpose: both run `sentra status` against the same core store.
    const tenantView = await app.workspaces.view(tenant);
    const session = await app.coreStore.session(tenant, ctx.req.signal);
    const coreCounts = app.coreStore.counts(tenant);
    const counts = findingCounts(app.db, tenant.tenantId, tenant.workspace);
    const lastResult = lastResultRunAt(app, tenant.tenantId, tenant.workspace);
    const body: OverviewView = {
      tenant: tenantView,
      lastRun: listRuns(app, tenant.tenantId, tenant.workspace, 1)[0] ?? null,
      lastCompletedRunAt: lastCompletedRunAt(app, tenant.tenantId, tenant.workspace),
      lastResultRunAt: lastResult,
      openFindings: { total: counts.openTotal, bySeverity: counts.bySeverity, bySource: counts.bySource, byTriage: counts.byTriage },
      resolvedFindings: counts.resolved,
      patches: patchCounts(app, tenant.tenantId),
      core: { ...session, taskCount: coreCounts.tasks, auditEventCount: coreCounts.auditEvents },
      operatorAuditEntries: app.audit.count(tenant.tenantId, { includeGlobal: false }),
      // Only a run that produced SAST or dependency results can back a score; otherwise the
      // empty findings table would read as "nothing found" (100).
      riskScore: lastResult ? { value: riskScoreValue(counts.bySeverity), formula: RISK_SCORE_FORMULA } : null,
    };
    return json(body);
  });

  router.get("/api/tenants/:tenantId/trends", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const days = intParam(ctx.url.searchParams.get("days"), "days", 1, 365, 30);
    return json({ points: computeTrends(app.db, tenant.tenantId, tenant.workspace, days) });
  });

  // ── SARIF export ────────────────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/export/sarif", { auth: "session", permission: "read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const findings = listFindings(app.db, tenant.tenantId, tenant.workspace, { state: "open" }).filter(
      (finding) => finding.triage?.verdict !== "rejected",
    );
    const generatedAt = nowIso();
    const sarif = buildSarif(
      findings,
      { version: await coreVersion(app), informationUri: readRepositoryUrl(path.join(app.config.repoRoot, "Cargo.toml")) },
      tenant.tenantId,
      generatedAt,
    );
    const fileName = `sentra-${tenant.tenantId}-${generatedAt.slice(0, 10)}.sarif`;
    return new Response(JSON.stringify(sarif, null, 2), {
      headers: {
        "Content-Type": "application/sarif+json; charset=utf-8",
        "Content-Disposition": `attachment; filename="${fileName}"`,
      },
    });
  });

  // ── dependency inventory (core lockfile parsers, no network) ────────────
  router.get("/api/tenants/:tenantId/dependencies", { auth: "session", permission: "read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json(await app.osv.inventory(app.workspaces.workspaceRoot(tenant), ctx.req.signal));
  });

  // ── snippet scan (no persistence) ───────────────────────────────────────
  router.post("/api/scan/snippet", { auth: "session", permission: "scan:run" }, async (ctx) => {
    const body = await ctx.readJson();
    if (typeof body.code !== "string" || body.code.length === 0) {
      throw new HttpError(400, "invalid_request", "'code' is required and must be a non-empty string");
    }
    const code = body.code;
    const codeBytes = Buffer.byteLength(code, "utf8");
    if (codeBytes > MAX_SNIPPET_BYTES) throw new HttpError(413, "payload_too_large", `'code' exceeds ${MAX_SNIPPET_BYTES} bytes`);
    if (code.includes("\u0000")) throw new HttpError(400, "invalid_request", "'code' contains a NUL byte");
    const fileName = requiredString(body, "fileName", { max: 100, pattern: SNIPPET_FILE_NAME });
    if (fileName === "." || fileName === "..") throw new HttpError(400, "invalid_request", "'fileName' must name a file");
    const view = await audited(
      app,
      ctx.principal,
      { action: "snippet_scanned", target: fileName, details: { fileName, codeBytes } },
      async (): Promise<SnippetScanView> => {
        // The code travels on stdin, never on argv.
        const result = await app.cli.run(["scan", "-", "--file-name", cliValue(fileName, "fileName"), "--json"], {
          stdin: code,
          timeoutMs: app.config.cliTimeoutMs,
          signal: ctx.req.signal,
        });
        if (result.timedOut) throw new HttpError(504, "core_timeout", "sentra scan timed out");
        if (result.code !== 0 || result.json === undefined) throw cliFailure("scan", result);
        const parsed = parseScanOutput(result.json);
        return { fileName, filesScanned: parsed.filesScanned, signalsFound: parsed.signalsFound, matches: parsed.matches.map(toSastMatchView) };
      },
      (result) => ({ signalsFound: result.signalsFound }),
    );
    return json(view);
  });

  // ── allowlisted core console ────────────────────────────────────────────
  router.post("/api/tenants/:tenantId/console", { auth: "session", permission: "console:run" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = await ctx.readJson();
    const command = oneOf(body.command, "command", CONSOLE_COMMANDS);
    const view = await audited(
      app,
      ctx.principal,
      { action: "console_command_run", tenantId: tenant.tenantId, target: command, details: { command } },
      async (): Promise<ConsoleRunView> => {
        const workspace = () => cliValue(app.workspaces.workspaceRoot(tenant), "workspace");
        let args: string[];
        switch (command) {
          case "version":
            args = ["--version", "--json"];
            break;
          case "status": {
            const ws = workspace();
            await app.workspaces.coreStoreState(tenant);
            args = ["status", "--database", cliValue(app.workspaces.coreStorePath(tenant.tenantId), "database"), "--workspace", ws, "--json"];
            break;
          }
          case "scan":
            args = ["scan", "--workspace", workspace(), "--json"];
            break;
          case "codeql":
            args = ["codeql", "--workspace", workspace(), "--json"];
            break;
          case "inventory":
            args = ["inventory", "--workspace", workspace(), "--json"];
            break;
          case "skills":
            args = ["skills", "list", "--json"];
            break;
          case "plugins":
            if (!app.config.pluginDir) {
              throw new HttpError(412, "plugins_not_configured", "No plugin directory is configured. An admin can set SENTRA_PLUGIN_DIR and restart the bridge.");
            }
            args = ["plugin", "list", "--dir", cliValue(app.config.pluginDir, "pluginDir"), "--json"];
            break;
        }
        const result = await app.cli.run(args, { timeoutMs: app.config.cliLongTimeoutMs, signal: ctx.req.signal });
        return {
          command,
          argv: ["sentra", ...args],
          exitCode: result.code,
          stdout: capOutput(result.stdout),
          stderr: capOutput(result.stderr),
          durationMs: result.durationMs,
          timedOut: result.timedOut,
        };
      },
      (result) => ({ exitCode: result.exitCode, durationMs: result.durationMs, timedOut: result.timedOut }),
    );
    return json(view);
  });

  // ── snapshot diff between two directories inside registered workspaces ──
  router.post("/api/tenants/:tenantId/diff", { auth: "session", permission: "scan:run" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = await ctx.readJson();
    const requested = (field: "base" | "head") => (typeof body[field] === "string" ? (body[field] as string).slice(0, 1024) : null);
    const outcome = await audited(
      app,
      ctx.principal,
      {
        action: "workspace_diff",
        tenantId: tenant.tenantId,
        target: `${requested("base") ?? "?"} -> ${requested("head") ?? "?"}`,
        details: { base: requested("base"), head: requested("head") },
      },
      async () => {
        const base = resolveDiffDirectory(app, body, "base");
        const head = resolveDiffDirectory(app, body, "head");
        const view = mapDiff(
          await app.cli.runJson(["diff", "--base", cliValue(base, "base"), "--head", cliValue(head, "head"), "--json"], {
            timeoutMs: app.config.cliLongTimeoutMs,
            signal: ctx.req.signal,
          }),
        );
        return { base, head, view };
      },
      (result) => ({
        resolvedBase: result.base,
        resolvedHead: result.head,
        deltas: result.view.deltas.length,
        netBytesDelta: result.view.summary.netBytesDelta,
      }),
    );
    return json(outcome.view);
  });
}
