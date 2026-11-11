import crypto from "node:crypto";
import type {
  CodeqlProbeView,
  FindingSource,
  ScanKind,
  ScanRunSummary,
  ScanRunView,
  ScanStatus,
  ScanStreamEvent,
  ScanTrigger,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { markAuditHandled } from "../audit-log.ts";
import { nowIso, parseJsonColumn } from "../db.ts";
import { readHead } from "../git-meta.ts";
import { HttpError } from "../http-error.ts";
import { log } from "../logger.ts";
import { cliFailure, cliValue, type CliResult } from "../sentra-cli.ts";
import { emptySeverityCounts, parseScanOutput, reconcileFindings, sastCandidates, type CandidateFinding } from "./findings.ts";
import { auditDependencies, OSV_ENDPOINT, OsvClient, readInventory, type OsvFetcher } from "./osv.ts";
import type { ActorRef, ScanRunInput, ScanService } from "./types.ts";

/**
 * Scan pipeline: SAST through the core CLI, dependency vulnerabilities through OSV.dev over
 * the core lockfile inventory, and the CodeQL language probe. Runs are persisted in
 * `scan_runs`; findings are reconciled in one transaction per run.
 *
 * `sentra audit` is deliberately NOT used for dependencies: its vulnerability knowledge is a
 * small hand-written advisory sample bundled with the core (reported as
 * `advisory_db_source: "bundled_pinned_sample"`, dated by its curation time), not a synchronized
 * advisory feed, so it cannot back real findings.
 */

type Stage = "sast" | "dependency" | "codeql";
type ScanApp = Omit<AppContext, "scans">;

const STAGES_BY_KIND: Record<ScanKind, Stage[]> = {
  sast: ["sast"],
  dependency: ["dependency"],
  codeql: ["codeql"],
  all: ["sast", "dependency", "codeql"],
};

const CANCELLED = "cancelled by client";

interface ScanRunRow {
  run_id: string;
  tenant_id: string;
  workspace: string;
  kind: string;
  trigger: ScanTrigger;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  actor: string;
  files_scanned: number | null;
  signals_found: number | null;
  packages_audited: number | null;
  vulnerable_packages: number | null;
  git_head: string | null;
  error: string | null;
  summary_json: string | null;
}

export function rowToRun(row: ScanRunRow): ScanRunView {
  return {
    runId: row.run_id,
    tenantId: row.tenant_id,
    workspace: row.workspace,
    kind: row.kind as ScanKind,
    trigger: row.trigger,
    status: row.status,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    actor: row.actor,
    filesScanned: row.files_scanned,
    signalsFound: row.signals_found,
    packagesAudited: row.packages_audited,
    vulnerablePackages: row.vulnerable_packages,
    gitHead: row.git_head,
    error: row.error,
    summary: parseJsonColumn<ScanRunSummary | null>(row.summary_json, null),
  };
}

export function listRuns(app: Pick<AppContext, "db">, tenantId: string, workspace: string, limit: number): ScanRunView[] {
  const rows = app.db
    .query("SELECT * FROM scan_runs WHERE tenant_id = ? AND workspace = ? ORDER BY started_at DESC, run_id DESC LIMIT ?")
    .all(tenantId, workspace, limit) as ScanRunRow[];
  return rows.map(rowToRun);
}

export function findRun(app: Pick<AppContext, "db">, tenantId: string, runId: string): ScanRunView | null {
  const row = app.db.query("SELECT * FROM scan_runs WHERE tenant_id = ? AND run_id = ?").get(tenantId, runId) as ScanRunRow | null;
  return row ? rowToRun(row) : null;
}

export function lastCompletedRunAt(app: Pick<AppContext, "db">, tenantId: string, workspace: string): string | null {
  const row = app.db
    .query("SELECT finished_at FROM scan_runs WHERE tenant_id = ? AND workspace = ? AND status = 'completed' ORDER BY finished_at DESC LIMIT 1")
    .get(tenantId, workspace) as { finished_at: string | null } | null;
  return row?.finished_at ?? null;
}

/**
 * Finish time of the newest completed run that produced SAST or dependency results. A CodeQL
 * language probe, or a dependency stage skipped by policy, completes without either, so it
 * cannot back a statement about the workspace's findings (such as the heuristic risk score).
 */
export function lastResultRunAt(app: Pick<AppContext, "db">, tenantId: string, workspace: string): string | null {
  const row = app.db
    .query(
      `SELECT finished_at FROM scan_runs
       WHERE tenant_id = ? AND workspace = ? AND status = 'completed'
         AND (json_extract(summary_json, '$.sast') IS NOT NULL OR json_extract(summary_json, '$.dependency') IS NOT NULL)
       ORDER BY finished_at DESC LIMIT 1`,
    )
    .get(tenantId, workspace) as { finished_at: string | null } | null;
  return row?.finished_at ?? null;
}

/** Maps `sentra codeql --workspace <dir> --json` (probe mode). CodeQL itself is never run. */
export function mapCodeqlProbe(raw: unknown, codeqlInstalled: boolean): CodeqlProbeView {
  const doc = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
  const languages = Array.isArray(doc.detected_languages) ? doc.detected_languages : [];
  return {
    primaryLanguage: typeof doc.primary_language === "string" ? doc.primary_language : null,
    detectedLanguages: languages
      .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object")
      .filter((entry) => typeof entry.language === "string")
      .map((entry) => ({ language: entry.language as string, filesCount: typeof entry.files_count === "number" ? entry.files_count : 0 })),
    suggestedCreateCommand: typeof doc.database_create_command === "string" ? doc.database_create_command : null,
    suggestedAnalyzeCommand: typeof doc.database_analyze_command === "string" ? doc.database_analyze_command : null,
    codeqlInstalled,
  };
}

function errorText(error: unknown): string {
  if (error instanceof HttpError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}

function emptySummary(): ScanRunSummary {
  return {
    sast: null,
    dependency: null,
    dependencySkippedReason: null,
    codeql: null,
    newFindings: 0,
    resolvedFindings: 0,
    stillOpen: 0,
    stageErrors: [],
  };
}

class CancelledError extends Error {
  constructor() {
    super(CANCELLED);
  }
}

/**
 * One execution of the pipeline. Narration (`log` events with stream 'bridge') states only
 * what the bridge observed: commands, exit codes, durations and counts.
 */
class ScanExecution {
  private readonly app: ScanApp;
  private readonly osvClient: OsvClient;
  private readonly input: ScanRunInput;
  private readonly workspace: string;
  private readonly registeredWorkspace: string;
  private readonly runId: string;
  readonly summary = emptySummary();
  readonly candidates: CandidateFinding[] = [];
  readonly completedSources: FindingSource[] = [];
  filesScanned: number | null = null;
  signalsFound: number | null = null;
  packagesAudited: number | null = null;
  vulnerablePackages: number | null = null;

  constructor(app: ScanApp, osvClient: OsvClient, input: ScanRunInput, workspace: string, registeredWorkspace: string, runId: string) {
    this.app = app;
    this.osvClient = osvClient;
    this.input = input;
    this.workspace = workspace;
    this.registeredWorkspace = registeredWorkspace;
    this.runId = runId;
  }

  emit(event: ScanStreamEvent): void {
    if (!this.input.onEvent) return;
    try {
      this.input.onEvent(event);
    } catch (error) {
      log.debug("scan event listener failed", { runId: this.runId, error: errorText(error) });
    }
  }

  bridge(text: string): void {
    this.emit({ type: "log", stream: "bridge", text, ts: nowIso() });
  }

  private checkCancelled(): void {
    if (this.input.signal?.aborted) throw new CancelledError();
  }

  private async runCli(command: string, args: string[]): Promise<CliResult> {
    this.bridge(`Running: sentra ${args.join(" ")}`);
    const result = await this.app.cli.run(args, {
      timeoutMs: this.app.config.cliLongTimeoutMs,
      signal: this.input.signal,
      onOutput: (stream, text) => {
        // stdout is a single JSON document; only diagnostics are streamed.
        if (stream === "stderr" && text.trim()) this.emit({ type: "log", stream: "stderr", text, ts: nowIso() });
      },
    });
    this.checkCancelled();
    this.bridge(`sentra ${command} exited with code ${result.code} after ${result.durationMs} ms (${Buffer.byteLength(result.stdout)} bytes of stdout).`);
    if (result.timedOut) throw new HttpError(504, "core_timeout", `sentra ${command} timed out after ${this.app.config.cliLongTimeoutMs} ms`);
    if (result.code !== 0 || result.json === undefined) throw cliFailure(command, result);
    return result;
  }

  async sast(storePath: string): Promise<void> {
    const result = await this.runCli("scan", [
      "scan",
      "--workspace",
      cliValue(this.workspace, "workspace"),
      "--database",
      cliValue(storePath, "database"),
      "--json",
    ]);
    const parsed = parseScanOutput(result.json);
    const bySeverity = emptySeverityCounts();
    for (const match of parsed.matches) bySeverity[match.severity] += 1;
    this.summary.sast = { filesScanned: parsed.filesScanned, signalsFound: parsed.signalsFound, bySeverity };
    this.filesScanned = parsed.filesScanned;
    this.signalsFound = parsed.signalsFound;
    this.candidates.push(...sastCandidates(parsed.matches));
    this.completedSources.push("sast");
    this.emit({
      type: "stage",
      stage: "sast",
      status: "completed",
      message: `sentra scan reported ${parsed.filesScanned} files scanned and ${parsed.signalsFound} signals (unvalidated candidates).`,
    });
  }

  async dependency(): Promise<void> {
    if (!this.app.osv.enabled()) {
      const reason =
        "OSV lookups are disabled by policy, so no dependency vulnerabilities were looked up. An admin can enable them under Settings > Threat intelligence (package names and versions are then sent to https://api.osv.dev).";
      this.summary.dependencySkippedReason = reason;
      this.emit({ type: "stage", stage: "dependency", status: "skipped", message: reason });
      return;
    }
    this.bridge(`Running: sentra inventory --workspace ${this.workspace} --json`);
    const started = performance.now();
    const inventory = await readInventory(this.app, this.workspace, this.input.signal);
    this.checkCancelled();
    this.bridge(
      `sentra inventory found ${inventory.lockfiles.length} lockfile(s) and ${inventory.totalPackages} package entries in ${Math.round(performance.now() - started)} ms.`,
    );
    for (const lockfile of inventory.lockfiles) {
      if (lockfile.parseError) this.bridge(`Lockfile ${lockfile.path} could not be fully parsed: ${lockfile.parseError}`);
    }
    if (inventory.truncated) this.bridge("The core reported a truncated inventory; packages beyond its limit were not queried.");
    this.bridge(`Querying ${OSV_ENDPOINT} for ${inventory.packages.length} package entries.`);
    const audit = await auditDependencies(this.osvClient, inventory.packages);
    this.checkCancelled();
    this.bridge(
      `OSV.dev: ${audit.packagesAudited} distinct packages queried, ${audit.packagesSkipped} entries without an OSV ecosystem or version skipped, ${audit.fetchedRecords} advisory records fetched, ${audit.cachedRecords} served from the local cache, ${audit.withdrawnSkipped} withdrawn matches ignored.`,
    );
    this.summary.dependency = {
      lockfiles: inventory.lockfiles,
      packagesAudited: audit.packagesAudited,
      vulnerablePackages: audit.vulnerablePackages,
      vulnerabilities: audit.vulnerabilities,
      advisorySource: "osv.dev",
      queriedAt: audit.queriedAt,
    };
    this.packagesAudited = audit.packagesAudited;
    this.vulnerablePackages = audit.vulnerablePackages;
    this.candidates.push(...audit.candidates);
    this.completedSources.push("dependency");
    this.emit({
      type: "stage",
      stage: "dependency",
      status: "completed",
      message: `${audit.vulnerablePackages} of ${audit.packagesAudited} packages match ${audit.vulnerabilities} OSV vulnerabilities (counted per package version, aliased advisories once; presence in a lockfile, reachability not assessed).`,
    });
  }

  async codeql(): Promise<void> {
    const result = await this.runCli("codeql", ["codeql", "--workspace", cliValue(this.workspace, "workspace"), "--json"]);
    // Presence only: the same search as the system page (process PATH, persisted PATH, well-known
    // install directories). codeql itself is never executed.
    const executables = this.app.executables;
    const snapshot = await executables.current();
    const codeqlPath = executables.locate("codeql", snapshot).path;
    const probe = mapCodeqlProbe(result.json, !!codeqlPath);
    this.summary.codeql = probe;
    this.emit({
      type: "stage",
      stage: "codeql",
      status: "completed",
      message: `Language probe: ${probe.detectedLanguages.length} language(s) detected by file extension, primary ${probe.primaryLanguage ?? "none"}. CodeQL was not executed; codeql is ${codeqlPath ? `installed at ${codeqlPath}` : `not found (searched ${executables.searchScope(snapshot)})`}.`,
    });
  }

  persist(): void {
    this.emit({ type: "stage", stage: "persist", status: "started", message: "Reconciling findings in one transaction." });
    const result = reconcileFindings(this.app.db, {
      tenantId: this.input.tenantId,
      workspace: this.registeredWorkspace,
      runId: this.runId,
      at: nowIso(),
      candidates: this.candidates,
      completedSources: this.completedSources,
    });
    this.summary.newFindings = result.created + result.reopened;
    this.summary.resolvedFindings = result.resolved;
    this.summary.stillOpen = result.stillOpen;
    this.emit({
      type: "stage",
      stage: "persist",
      status: "completed",
      message: `${result.created} new, ${result.reopened} reopened, ${result.stillOpen} still open, ${result.resolved} resolved (sources reconciled: ${this.completedSources.join(", ") || "none"}).`,
    });
  }
}


function auditRun(app: ScanApp, actor: ActorRef, run: ScanRunView, durationMs: number): void {
  const summary = run.summary;
  app.audit.append(actor, {
    action: run.status === "completed" ? "scan_completed" : "scan_failed",
    outcome: run.status === "completed" ? "success" : "failure",
    tenantId: run.tenantId,
    target: run.runId,
    details: {
      runId: run.runId,
      kind: run.kind,
      trigger: run.trigger,
      status: run.status,
      durationMs,
      filesScanned: run.filesScanned,
      signalsFound: run.signalsFound,
      packagesAudited: run.packagesAudited,
      vulnerablePackages: run.vulnerablePackages,
      newFindings: summary?.newFindings ?? 0,
      resolvedFindings: summary?.resolvedFindings ?? 0,
      stillOpen: summary?.stillOpen ?? 0,
      dependencySkipped: summary?.dependencySkippedReason !== null && summary?.dependencySkippedReason !== undefined,
      stageErrors: (summary?.stageErrors ?? []).map((entry) => ({ stage: entry.stage, message: entry.message.slice(0, 300) })),
      error: run.error ? run.error.slice(0, 300) : null,
    },
  });
}

export interface ScanServiceOptions {
  /** Replaces the HTTPS client for OSV.dev (tests inject a fake; production uses the default). */
  osvFetcher?: OsvFetcher;
}

export function createScanService(app: Omit<AppContext, "scans">, options: ScanServiceOptions = {}): ScanService {
  const running = new Set<string>();
  const osvClient = new OsvClient(app.db, app.settings, options.osvFetcher);

  // A run that was still 'running' when the bridge stopped can never finish.
  const interrupted = app.db
    .query("UPDATE scan_runs SET status = 'failed', finished_at = ?, error = ? WHERE status = 'running'")
    .run(nowIso(), "interrupted: the bridge stopped before the scan finished");
  if (interrupted.changes > 0) log.warn("marked interrupted scan runs as failed", { count: interrupted.changes });

  async function run(input: ScanRunInput): Promise<ScanRunView> {
    const tenant = app.workspaces.get(input.tenantId);
    const stages = STAGES_BY_KIND[input.kind];
    if (!stages) throw new HttpError(400, "invalid_request", "Unknown scan kind");
    const rejected = (error: HttpError): never => {
      app.audit.append(input.actor, {
        action: "scan_failed",
        outcome: "failure",
        tenantId: tenant.tenantId,
        details: { kind: input.kind, trigger: input.trigger, error: `${error.code}: ${error.message}` },
      });
      throw markAuditHandled(error);
    };
    if (running.has(tenant.tenantId)) {
      rejected(new HttpError(409, "scan_in_progress", `A scan is already running for '${tenant.tenantId}'`));
    }
    running.add(tenant.tenantId);
    const startedMs = performance.now();
    let runId: string | null = null;
    try {
      let workspace: string;
      try {
        workspace = app.workspaces.workspaceRoot(tenant);
      } catch (error) {
        return rejected(error instanceof HttpError ? error : new HttpError(409, "workspace_missing", errorText(error)));
      }
      runId = `run_${crypto.randomUUID()}`;
      const head = readHead(workspace);
      app.db
        .query(
          `INSERT INTO scan_runs (run_id, tenant_id, workspace, kind, trigger, status, started_at, actor, git_head)
           VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?)`,
        )
        .run(runId, tenant.tenantId, tenant.workspace, input.kind, input.trigger, nowIso(), input.actor.label, head?.sha ?? null);
      const execution = new ScanExecution(app, osvClient, input, workspace, tenant.workspace, runId);
      execution.emit({ type: "run", run: findRun(app, tenant.tenantId, runId) as ScanRunView });
      execution.bridge(
        `Scan ${runId} started (${input.kind}, trigger ${input.trigger}) on ${workspace}${head?.sha ? ` at ${head.branch ?? "detached"} ${head.sha.slice(0, 12)}` : " (no git HEAD found)"}.`,
      );

      let cancelled = false;
      let failedStages = 0;
      for (const stage of stages) {
        if (input.signal?.aborted) {
          cancelled = true;
          break;
        }
        execution.emit({ type: "stage", stage, status: "started", message: `Stage ${stage} started.` });
        try {
          if (stage === "sast") {
            const store = await app.workspaces.coreStoreState(tenant);
            if (!store.initialized) {
              throw new HttpError(409, "core_store_unavailable", `The tenant core store is not usable: ${store.error ?? "unknown error"}`);
            }
            await execution.sast(app.workspaces.coreStorePath(tenant.tenantId));
          } else if (stage === "dependency") {
            await execution.dependency();
          } else {
            await execution.codeql();
          }
        } catch (error) {
          if (error instanceof CancelledError || input.signal?.aborted) {
            cancelled = true;
            break;
          }
          failedStages += 1;
          const message = errorText(error);
          execution.summary.stageErrors.push({ stage, message });
          execution.emit({ type: "stage", stage, status: "failed", message });
        }
      }

      let status: ScanStatus;
      let runError: string | null = null;
      if (cancelled || input.signal?.aborted) {
        status = "failed";
        runError = CANCELLED;
        execution.bridge("The client disconnected; the core process was stopped and no findings were reconciled.");
      } else {
        execution.persist();
        if (failedStages === stages.length) {
          status = "failed";
          runError = execution.summary.stageErrors.map((entry) => `${entry.stage}: ${entry.message}`).join("; ");
        } else {
          status = "completed";
        }
      }
      app.db
        .query(
          `UPDATE scan_runs SET status = ?, finished_at = ?, files_scanned = ?, signals_found = ?, packages_audited = ?,
             vulnerable_packages = ?, error = ?, summary_json = ? WHERE run_id = ?`,
        )
        .run(
          status,
          nowIso(),
          execution.filesScanned,
          execution.signalsFound,
          execution.packagesAudited,
          execution.vulnerablePackages,
          runError,
          JSON.stringify(execution.summary),
          runId,
        );
      const finalRun = findRun(app, tenant.tenantId, runId) as ScanRunView;
      auditRun(app, input.actor, finalRun, Math.round(performance.now() - startedMs));
      execution.bridge(`Scan ${runId} ${status} after ${Math.round(performance.now() - startedMs)} ms.`);
      execution.emit({ type: "complete", run: finalRun });
      return finalRun;
    } catch (error) {
      if (runId) {
        // Unexpected failure after the run row exists (e.g. a database error): close it out.
        const message = errorText(error);
        try {
          app.db.query("UPDATE scan_runs SET status = 'failed', finished_at = ?, error = ? WHERE run_id = ? AND status = 'running'").run(nowIso(), message, runId);
          const failed = findRun(app, tenant.tenantId, runId);
          if (failed) {
            auditRun(app, input.actor, failed, Math.round(performance.now() - startedMs));
            markAuditHandled(error);
          }
        } catch (inner) {
          log.error("could not record scan failure", { runId, error: errorText(inner) });
        }
      }
      throw error;
    } finally {
      running.delete(tenant.tenantId);
    }
  }

  return {
    run,
    isRunning: (tenantId: string) => running.has(tenantId),
  };
}
