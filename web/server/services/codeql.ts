import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type {
  CodeqlAnalysisOutcome,
  CodeqlAnalysisView,
  CodeqlFindingDetails,
  CodeqlIngestView,
  CodeqlLanguageResultView,
  CodeqlProgressView,
  CodeqlRunningView,
  CodeqlSettings,
  CodeqlSettingsView,
  CodeqlSkipReason,
  CodeqlSuite,
  FindingOrigin,
  Severity,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { licenseFileNear, type LauncherChoice } from "../codeql-launcher.ts";
import type { ServerConfig } from "../config.ts";
import { nowIso } from "../db.ts";
import type { GitHubRepoRef } from "../git-meta.ts";
import { bunRuntime, codeqlLauncherChoice, hostToolsDeps, type HostFactsDeps } from "../host-tools.ts";
import { HttpError } from "../http-error.ts";
import { isWithin } from "../paths.ts";
import { readScoopShimTarget } from "../shims.ts";
import type { SearchSnapshot } from "../executables.ts";
import { cliValue, coreErrorDocument, sanitizeCoreMessage, type CliResult } from "../sentra-cli.ts";
import { reconcileFindings, sha256Hex, type CandidateFinding, type ReconcileResult, type ReconcileScope } from "./findings.ts";
import { progressFromLine } from "./codeql-progress.ts";
import type { SettingsStore } from "./settings-store.ts";
import type { TenantRecord } from "./workspaces.ts";

/**
 * CodeQL in the bridge (ADR-0011):
 *
 * - Result IMPORT is always available: a CodeQL SARIF produced elsewhere (a local run, GitHub
 *   Actions) is parsed by `sentra codeql import`, and open GitHub code scanning alerts of tool
 *   CodeQL are read (read-only) for the tenant's repository.
 * - HOST ANALYSIS (`sentra codeql analyze`, build mode none only) is OFF by default. An admin
 *   enables it in Settings > CodeQL in the same request that accepts the CodeQL licence terms. At
 *   most one analysis runs on the bridge at a time.
 *
 * Every CodeQL finding carries an origin (host_analysis, sarif_import, github_code_scanning), and
 * each origin is reconciled on its own, so one never closes another's findings.
 */

export const CODEQL_SETTINGS_KEY = "codeql_analysis";
export const CODEQL_SUITES: readonly CodeqlSuite[] = ["code-scanning", "security-extended"];
export const TIMEOUT_MINUTES_BOUNDS = { min: 5, max: 180 } as const;
export const DEFAULT_TIMEOUT_MINUTES = 30;
/** Budget of query pack downloads (--download-timeout-secs), separate from the analysis budget. */
export const DOWNLOAD_TIMEOUT_MINUTES_BOUNDS = { min: 5, max: 180 } as const;
export const DEFAULT_DOWNLOAD_TIMEOUT_MINUTES = 30;
export const RAM_MB_MIN = 1024;
/** Automatic --ram (ramMb unset): this share of the available memory, within RAM_MB_MIN..RAM_AUTO_MAX_MB. */
export const RAM_AUTO_SHARE = 0.5;
export const RAM_AUTO_MAX_MB = 8192;
/** Automatic --ram when the available memory cannot be read. */
export const RAM_AUTO_FALLBACK_MB = 2048;
/**
 * Globs left out of extraction by default (--exclude, CodeQL's LGTM_INDEX_FILTERS): dependency and
 * build output, which CodeQL otherwise extracts (rustdoc HTML under target/, a built web/dist).
 */
export const DEFAULT_EXCLUDE_PATHS: readonly string[] = ["**/node_modules", "**/target", "**/dist", "**/.git"];
/** Limits of excludePaths, the same as the core's (MAX_EXCLUDE_GLOBS, MAX_EXCLUDE_GLOB_CHARS). */
export const EXCLUDE_PATHS_MAX_ENTRIES = 50;
export const EXCLUDE_PATH_MAX_CHARS = 200;
/** Upper bound of a SARIF upload (the request body of the import route). */
export const CODEQL_IMPORT_MAX_BYTES = 64 * 1024 * 1024;
/** --max-results passed to `sentra codeql analyze` and `sentra codeql import`. */
export const CODEQL_MAX_RESULTS = 5000;
/** Extra time the bridge gives the core beyond --timeout-secs before it stops the core itself. */
export const BRIDGE_TIMEOUT_MARGIN_MS = 120_000;
/** Cap on stdout of `sentra codeql analyze/import` (CODEQL_MAX_RESULTS findings fit well within it). */
const CODEQL_MAX_OUTPUT_BYTES = 48 * 1024 * 1024;
/** Upper bound of GitHub code scanning alerts read per sync (10 pages of 100). */
export const GITHUB_ALERTS_CAP = 1000;
const GITHUB_ALERTS_PAGE_SIZE = 100;

export const CODEQL_TERMS_LOCATION =
  "LICENSE.md in the root of the CodeQL distribution (next to the codeql launcher); the file shipped with the distribution you run applies.";
export const CODEQL_TERMS_REFERENCE_URL = "https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md";

/**
 * Summary of the conditions of the GitHub CodeQL Terms and Conditions, quoted from LICENSE.md of
 * the CodeQL CLI 2.27.4 distribution read on 2026-11-11. The licence file itself is authoritative;
 * this summary is not legal advice.
 */
export const CODEQL_TERMS_SUMMARY: readonly string[] = [
  "The Software is licensed on a per user basis.",
  "Permitted uses: academic research; demonstrating the Software; testing CodeQL queries released under an OSI-approved licence.",
  "Only with an Open Source Codebase (released under an OSI-approved licence): perform analysis on it, and, if it is hosted and maintained on GitHub.com, generate CodeQL databases for or during automated analysis, CI or CD.",
  "Not authorized: generating CodeQL databases for or during automated analysis, CI or CD in any other context, and use in connection with any codebase that is not an Open Source Codebase (e.g. code in a private repo).",
  "These two restrictions do not apply if your use is under a paid customer licence for GitHub Advanced Security.",
  "You may not provide or make available the Software as a hosted solution for others to use; consider whether running it from a shared console does so.",
];

export const CODEQL_ISOLATION_NOTE =
  "Host analysis runs `sentra codeql analyze` on the bridge host with --build-mode=none only: no autobuild, no build command and no tracing, so no target code is executed. go and swift (no none mode) and rust, csharp and java (their none-mode extractors run project code: Cargo build scripts and procedural macros, dotnet restore, the project's Gradle wrapper or Maven) are skipped. CodeQL's extractors still parse untrusted workspace code on the host, outside the VM boundary of ADR-0004; ADR-0011 records this narrow exception, its threats and its residual risks. The core runs CodeQL from a private run directory outside the workspace with an allow-listed environment (no GitHub token, provider keys or bridge secrets), a time budget for the CodeQL steps (the codeql version step is also capped at 120 s) and a separate one for query pack downloads, bounded output and an explicit pack cache; it kills the process tree on timeout and when the scan is cancelled, and deletes the temporary databases. The paths in Exclude from extraction are left out through CodeQL's LGTM_INDEX_FILTERS. On Windows it refuses workspace paths containing & ^ ! or %, because CodeQL's extractor batch scripts expand the source directory unquoted and cmd.exe would run part of such a path as a command.";

/**
 * The sentence of the isolation note on TypeScript extraction, from what the bridge can actually
 * pass: only when it passes its own Bun as --typescript-runtime is no Node.js needed for sure.
 */
export function typescriptIsolationSentence(runtime: Pick<TypescriptRuntimeChoice, "path">): string {
  return runtime.path
    ? "TypeScript is parsed with Bun (the bridge's own runtime, passed as --typescript-runtime unless it lies inside the scanned workspace); no Node.js is needed."
    : "The bridge cannot pass its own Bun as --typescript-runtime here (see TypeScript runtime), so the core uses the first bun on its PATH, and without one CodeQL needs Node.js to extract TypeScript files.";
}

/** The isolation note of Settings > CodeQL, with the TypeScript sentence that applies on this host. */
export function codeqlIsolationNote(runtime: Pick<TypescriptRuntimeChoice, "path">): string {
  return `${CODEQL_ISOLATION_NOTE} ${typescriptIsolationSentence(runtime)}`;
}

/** What holds a CodeqlAnalysisLock: a scan's host analysis, a query pack download, or a SARIF import (importLock). */
export type CodeqlOperation = "analysis" | "pack_download" | "sarif_import";

export interface CodeqlRunningState {
  operation: CodeqlOperation;
  /** Workspace of an analysis or import; null for a pack download. */
  tenantId: string | null;
  startedAt: string;
  /** Who started a pack download. */
  actor: string | null;
}

/**
 * At most one CodeQL operation at a time. `lock` is shared bridge-wide by host analysis and query
 * pack downloads (both run CodeQL and write the pack cache); `importLock` serialises SARIF imports.
 */
export class CodeqlAnalysisLock {
  private current_: CodeqlRunningState | null = null;

  get current(): CodeqlRunningState | null {
    return this.current_;
  }

  /** A release function, or null when an operation is already running. */
  tryAcquire(tenantId: string | null, operation: CodeqlOperation = "analysis", actor: string | null = null): (() => void) | null {
    if (this.current_) return null;
    const state: CodeqlRunningState = { operation, tenantId, startedAt: nowIso(), actor };
    this.current_ = state;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (this.current_ === state) this.current_ = null;
    };
  }
}

// ───────────────────────────── settings ─────────────────────────────

/** Logical CPUs of the bridge host (upper bound of --threads). */
export function hostCpuCount(): number {
  const available = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, available);
}

/** Total memory of the bridge host in MiB (upper bound of --ram). */
export function hostMemoryMb(): number {
  return Math.max(RAM_MB_MIN, Math.floor(os.totalmem() / (1024 * 1024)));
}

export interface CodeqlHostLimits {
  cpus: number;
  memoryMb: number;
}

export function defaultCodeqlSettings(limits: CodeqlHostLimits): CodeqlSettings {
  return {
    enabled: false,
    termsAcceptedBy: null,
    termsAcceptedAt: null,
    allowPackDownload: false,
    suite: "code-scanning",
    timeoutMinutes: DEFAULT_TIMEOUT_MINUTES,
    downloadTimeoutMinutes: DEFAULT_DOWNLOAD_TIMEOUT_MINUTES,
    threads: Math.min(4, limits.cpus),
    ramMb: null,
    excludePaths: [...DEFAULT_EXCLUDE_PATHS],
  };
}

/**
 * The --ram a host analysis gets: the ramMb setting when an admin set one, otherwise
 * floor(available MiB * RAM_AUTO_SHARE) kept within RAM_MB_MIN..RAM_AUTO_MAX_MB, from the same
 * available-memory reading as the Host page. Without --ram CodeQL sizes its Java VM from the
 * host's total memory, which failed on a host whose memory was mostly in use (ADR-0011).
 */
export function chooseRamMb(
  settings: Pick<CodeqlSettings, "ramMb">,
  availableBytes: number | null,
  /** Set when the reading is only os.freemem() standing in for the platform reading (see hostMemoryReading). */
  fallbackNote: string | null = null,
): { ramMb: number; source: "setting" | "automatic"; availableMb: number | null; note: string } {
  const availableMb = availableBytes !== null && Number.isFinite(availableBytes) && availableBytes >= 0 ? Math.floor(availableBytes / (1024 * 1024)) : null;
  if (settings.ramMb !== null) {
    return { ramMb: settings.ramMb, source: "setting", availableMb, note: `CodeQL memory limit: --ram ${settings.ramMb} MiB, the RAM setting in Settings > CodeQL.` };
  }
  if (availableMb === null) {
    return {
      ramMb: RAM_AUTO_FALLBACK_MB,
      source: "automatic",
      availableMb,
      note: `CodeQL memory limit: --ram ${RAM_AUTO_FALLBACK_MB} MiB, chosen automatically because the host's memory could not be read at all (not even os.freemem()). Set a RAM limit in Settings > CodeQL to choose it yourself.`,
    };
  }
  const half = Math.floor(availableMb * RAM_AUTO_SHARE);
  const ramMb = Math.min(RAM_AUTO_MAX_MB, Math.max(RAM_MB_MIN, half));
  const bound =
    half < RAM_MB_MIN
      ? `; that is below the minimum, so ${RAM_MB_MIN} MiB is used and CodeQL may still run short of memory`
      : half > RAM_AUTO_MAX_MB
        ? `, capped at ${RAM_AUTO_MAX_MB} MiB`
        : "";
  const reading = fallbackNote ? ` (${fallbackNote})` : "";
  return {
    ramMb,
    source: "automatic",
    availableMb,
    note: `CodeQL memory limit: --ram ${ramMb} MiB, chosen automatically: half of the ${availableMb} MiB available on the host now${reading}${bound}. Set a RAM limit in Settings > CodeQL to choose it yourself.`,
  };
}

/**
 * The available-memory reading of the Host page for the automatic --ram. HostPlatform falls back to
 * os.freemem() when /proc/meminfo (Linux) or vm_stat (macOS) cannot be read; that reading is named,
 * because on macOS it counts only free pages and gives a lower limit than necessary. On Windows
 * os.freemem() is the platform reading (available physical memory). null only when even that throws.
 */
export async function hostMemoryReading(hostPlatform: Pick<AppContext["hostPlatform"], "availableMemory" | "platform">): Promise<{ availableBytes: number | null; fallbackNote: string | null }> {
  try {
    const memory = await hostPlatform.availableMemory(os.totalmem());
    const fallback =
      memory.source === "os" && hostPlatform.platform !== "win32"
        ? `read with os.freemem() because ${hostPlatform.platform === "darwin" ? "vm_stat" : hostPlatform.platform === "linux" ? "/proc/meminfo" : "no platform reading"} was not available${hostPlatform.platform === "darwin" ? "; it counts only free pages, so this limit may be lower than necessary" : ""}`
        : null;
    return { availableBytes: memory.availableBytes, fallbackNote: fallback };
  } catch {
    return { availableBytes: null, fallbackNote: null };
  }
}

/**
 * Why an exclude glob is refused, or null when it is accepted. The same rules as the core's
 * validate_exclude_glob: relative to the workspace (no leading /, drive, UNC path or ':'), / as the
 * separator, no '..' segment, no control characters (a line break would add a filter line), at most
 * EXCLUDE_PATH_MAX_CHARS characters. The length is counted in UTF-16 code units, as cliValue counts
 * it when a scan passes the glob on: never fewer than the core's characters, so a glob accepted here
 * is accepted by both (counting code points here let a saved glob fail every later scan).
 */
export function excludeGlobProblem(glob: string): string | null {
  if (glob.trim() === "") return "an exclude glob must not be empty";
  // The core's argument parser reads a value starting with '-' as a flag.
  if (glob.startsWith("-")) return "an exclude glob must not start with '-'";
  if (glob.length > EXCLUDE_PATH_MAX_CHARS) {
    return `an exclude glob must be at most ${EXCLUDE_PATH_MAX_CHARS} characters long (characters outside the Basic Multilingual Plane, such as emoji, count twice)`;
  }
  // oxlint-disable-next-line no-control-regex -- intentional: refuses control characters in a glob
  if (/[\u0000-\u001f\u007f-\u009f]/.test(glob)) return "an exclude glob must not contain control characters (line breaks included)";
  if (glob.includes("\\")) return "an exclude glob must use / as the path separator, not \\";
  if (glob.startsWith("/") || glob.includes(":")) return "an exclude glob must be relative to the workspace (no leading /, drive, UNC path or ':')";
  if (glob.split("/").includes("..")) return "an exclude glob must not contain a '..' segment";
  return null;
}

/** Valid, distinct exclude globs of a stored value (invalid entries dropped); the defaults when it is not a list. */
function storedExcludePaths(value: unknown): string[] {
  if (!Array.isArray(value)) return [...DEFAULT_EXCLUDE_PATHS];
  const globs: string[] = [];
  for (const entry of value) {
    if (typeof entry === "string" && excludeGlobProblem(entry) === null && !globs.includes(entry)) globs.push(entry);
    if (globs.length >= EXCLUDE_PATHS_MAX_ENTRIES) break;
  }
  return globs;
}

function intIn(value: unknown, min: number, max: number): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max ? value : null;
}

/** Stored settings, with every malformed or out-of-range field replaced by its default. */
export function parseCodeqlSettings(raw: unknown, limits: CodeqlHostLimits): CodeqlSettings {
  const defaults = defaultCodeqlSettings(limits);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return defaults;
  const value = raw as Record<string, unknown>;
  const termsAcceptedAt = typeof value.termsAcceptedAt === "string" && value.termsAcceptedAt ? value.termsAcceptedAt : null;
  const termsAcceptedBy = typeof value.termsAcceptedBy === "string" && value.termsAcceptedBy ? value.termsAcceptedBy : null;
  return {
    // Enabled only together with a recorded acceptance of the terms.
    enabled: value.enabled === true && termsAcceptedAt !== null,
    termsAcceptedBy: termsAcceptedAt ? termsAcceptedBy : null,
    termsAcceptedAt,
    allowPackDownload: value.allowPackDownload === true,
    suite: CODEQL_SUITES.includes(value.suite as CodeqlSuite) ? (value.suite as CodeqlSuite) : defaults.suite,
    timeoutMinutes: intIn(value.timeoutMinutes, TIMEOUT_MINUTES_BOUNDS.min, TIMEOUT_MINUTES_BOUNDS.max) ?? defaults.timeoutMinutes,
    downloadTimeoutMinutes:
      intIn(value.downloadTimeoutMinutes, DOWNLOAD_TIMEOUT_MINUTES_BOUNDS.min, DOWNLOAD_TIMEOUT_MINUTES_BOUNDS.max) ?? defaults.downloadTimeoutMinutes,
    threads: intIn(value.threads, 1, limits.cpus) ?? defaults.threads,
    ramMb: value.ramMb === null || value.ramMb === undefined ? null : intIn(value.ramMb, RAM_MB_MIN, limits.memoryMb),
    excludePaths: storedExcludePaths(value.excludePaths),
  };
}

/** A validated settings change (PUT /api/settings/codeql). */
export interface CodeqlSettingsUpdate {
  enabled?: boolean;
  acceptTerms?: boolean;
  allowPackDownload?: boolean;
  suite?: CodeqlSuite;
  timeoutMinutes?: number;
  downloadTimeoutMinutes?: number;
  threads?: number;
  ramMb?: number | null;
  excludePaths?: string[];
}

/** Validates a PUT body; throws 400 naming the field. Enabling requires acceptTerms: true in the same body. */
export function parseCodeqlSettingsUpdate(body: Record<string, unknown>, limits: CodeqlHostLimits): CodeqlSettingsUpdate {
  const known = new Set(["enabled", "acceptTerms", "allowPackDownload", "suite", "timeoutMinutes", "downloadTimeoutMinutes", "threads", "ramMb", "excludePaths"]);
  for (const key of Object.keys(body)) {
    if (!known.has(key)) throw new HttpError(400, "invalid_request", `Unknown field '${key}'`);
  }
  const update: CodeqlSettingsUpdate = {};
  const bool = (field: "enabled" | "acceptTerms" | "allowPackDownload") => {
    const value = body[field];
    if (value === undefined) return;
    if (typeof value !== "boolean") throw new HttpError(400, "invalid_request", `'${field}' must be a boolean`);
    update[field] = value;
  };
  bool("enabled");
  bool("acceptTerms");
  bool("allowPackDownload");
  if (body.suite !== undefined) {
    if (!CODEQL_SUITES.includes(body.suite as CodeqlSuite)) throw new HttpError(400, "invalid_request", `'suite' must be one of: ${CODEQL_SUITES.join(", ")}`);
    update.suite = body.suite as CodeqlSuite;
  }
  const int = (field: "timeoutMinutes" | "downloadTimeoutMinutes" | "threads", min: number, max: number) => {
    const value = body[field];
    if (value === undefined) return;
    const parsed = intIn(value, min, max);
    if (parsed === null) throw new HttpError(400, "invalid_request", `'${field}' must be an integer between ${min} and ${max}`);
    update[field] = parsed;
  };
  int("timeoutMinutes", TIMEOUT_MINUTES_BOUNDS.min, TIMEOUT_MINUTES_BOUNDS.max);
  int("downloadTimeoutMinutes", DOWNLOAD_TIMEOUT_MINUTES_BOUNDS.min, DOWNLOAD_TIMEOUT_MINUTES_BOUNDS.max);
  int("threads", 1, limits.cpus);
  if (body.ramMb !== undefined) {
    if (body.ramMb === null) update.ramMb = null;
    else {
      const parsed = intIn(body.ramMb, RAM_MB_MIN, limits.memoryMb);
      if (parsed === null) throw new HttpError(400, "invalid_request", `'ramMb' must be null or an integer between ${RAM_MB_MIN} and ${limits.memoryMb}`);
      update.ramMb = parsed;
    }
  }
  if (body.excludePaths !== undefined) {
    const value = body.excludePaths;
    if (!Array.isArray(value) || value.length > EXCLUDE_PATHS_MAX_ENTRIES) {
      throw new HttpError(400, "invalid_request", `'excludePaths' must be an array of at most ${EXCLUDE_PATHS_MAX_ENTRIES} globs`);
    }
    const globs: string[] = [];
    value.forEach((entry: unknown, index: number) => {
      if (typeof entry !== "string") throw new HttpError(400, "invalid_request", `'excludePaths' entry ${index + 1} must be a string`);
      const problem = excludeGlobProblem(entry);
      if (problem) throw new HttpError(400, "invalid_request", `'excludePaths' entry ${index + 1} is refused: ${problem}`);
      if (!globs.includes(entry)) globs.push(entry);
    });
    update.excludePaths = globs;
  }
  if (update.enabled === true && update.acceptTerms !== true) {
    throw new HttpError(
      400,
      "codeql_terms_required",
      "Enabling CodeQL host analysis requires accepting the CodeQL licence terms in the same request (acceptTerms: true).",
    );
  }
  return update;
}

export interface CodeqlService {
  readonly lock: CodeqlAnalysisLock;
  /** At most one SARIF import is received and parsed at a time (bounds bridge and core memory). */
  readonly importLock: CodeqlAnalysisLock;
  /** Explicit pack cache passed as --pack-cache (inside the bridge data directory, never ~/.codeql). */
  readonly packCache: string;
  readonly limits: CodeqlHostLimits;
  settings(): CodeqlSettings;
  meta(): { updatedAt: string; updatedBy: string } | null;
  /** True when host analysis is enabled with recorded acceptance of the terms. */
  analysisEnabled(): boolean;
  update(update: CodeqlSettingsUpdate, actor: string): CodeqlSettings;
  /** Records that the pack cache changed (a download ran), so the next pack listing is read fresh. */
  markPacksChanged(): void;
  /** True once after markPacksChanged. */
  takePacksChanged(): boolean;
}

export function createCodeqlService(
  settings: SettingsStore,
  config: Pick<ServerConfig, "dataDir">,
  limits: CodeqlHostLimits = { cpus: hostCpuCount(), memoryMb: hostMemoryMb() },
): CodeqlService {
  const lock = new CodeqlAnalysisLock();
  const importLock = new CodeqlAnalysisLock();
  const read = () => parseCodeqlSettings(settings.get<unknown>(CODEQL_SETTINGS_KEY, null), limits);
  let packsChanged = false;
  return {
    lock,
    importLock,
    markPacksChanged: () => {
      packsChanged = true;
    },
    takePacksChanged: () => {
      const changed = packsChanged;
      packsChanged = false;
      return changed;
    },
    packCache: path.join(config.dataDir, "codeql-packages"),
    limits,
    settings: read,
    meta: () => settings.meta(CODEQL_SETTINGS_KEY),
    analysisEnabled: () => {
      const current = read();
      return current.enabled && current.termsAcceptedAt !== null;
    },
    update(update, actor) {
      const current = read();
      const next: CodeqlSettings = { ...current };
      if (update.acceptTerms === true) {
        next.termsAcceptedBy = actor;
        next.termsAcceptedAt = nowIso();
      }
      if (update.enabled !== undefined) next.enabled = update.enabled;
      if (update.allowPackDownload !== undefined) next.allowPackDownload = update.allowPackDownload;
      if (update.suite !== undefined) next.suite = update.suite;
      if (update.timeoutMinutes !== undefined) next.timeoutMinutes = update.timeoutMinutes;
      if (update.downloadTimeoutMinutes !== undefined) next.downloadTimeoutMinutes = update.downloadTimeoutMinutes;
      if (update.threads !== undefined) next.threads = update.threads;
      if (update.ramMb !== undefined) next.ramMb = update.ramMb;
      if (update.excludePaths !== undefined) next.excludePaths = [...update.excludePaths];
      if (next.enabled && !next.termsAcceptedAt) {
        throw new HttpError(400, "codeql_terms_required", "CodeQL host analysis cannot be enabled before the CodeQL licence terms are accepted.");
      }
      settings.set(CODEQL_SETTINGS_KEY, next, actor);
      return read();
    },
  };
}

// ───────────────────────────── skip decisions ─────────────────────────────

export interface CodeqlSkip {
  reason: CodeqlSkipReason;
  message: string;
}

export const SKIP_DISABLED_MESSAGE =
  "CodeQL host analysis is disabled (the default). An admin can enable it in Settings > CodeQL after accepting the CodeQL licence terms; CodeQL results can also be imported from a SARIF file or synced from GitHub code scanning on the Findings tab.";

/** Why a scan's CodeQL stage would not start host analysis now (busy is decided when the lock is taken). */
export function analysisPrecondition(settings: CodeqlSettings, launcher: LauncherChoice, coreAvailable: boolean): CodeqlSkip | null {
  if (!settings.enabled) return { reason: "disabled", message: SKIP_DISABLED_MESSAGE };
  if (!settings.termsAcceptedAt) {
    return { reason: "terms_not_accepted", message: "CodeQL host analysis is enabled, but no acceptance of the CodeQL licence terms is recorded. An admin must accept them in Settings > CodeQL." };
  }
  if (!coreAvailable) return { reason: "core_unavailable", message: "The sentra core binary was not found, so `sentra codeql analyze` cannot run." };
  if (!launcher.path) return { reason: "launcher_unavailable", message: `No codeql launcher can be run: ${launcher.problem ?? "none was found"}` };
  return null;
}

/** What the running CodeQL operation is, in words (for busy messages). */
export function describeRunning(running: CodeqlRunningState): string {
  if (running.operation === "pack_download") {
    return `A CodeQL query pack download is running on this bridge (started ${running.startedAt}${running.actor ? ` by ${running.actor}` : ""})`;
  }
  return `Another CodeQL analysis is running on this bridge (workspace '${running.tenantId ?? "unknown"}', started ${running.startedAt})`;
}

export function busySkip(running: CodeqlRunningState): CodeqlSkip {
  return {
    reason: "analysis_busy",
    message: `${describeRunning(running)}; CodeQL runs one operation at a time on the bridge, so this run did not start host analysis.`,
  };
}

/** The lock state as the API reports it (null when nothing runs or only an import runs). */
export function runningView(running: CodeqlRunningState | null): CodeqlRunningView | null {
  if (!running || running.operation === "sarif_import") return null;
  return { operation: running.operation, tenantId: running.tenantId, startedAt: running.startedAt, actor: running.actor };
}

// ───────────────────────────── CLI output ─────────────────────────────

const CLI_SEVERITY: Record<string, Severity> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };

export interface CodeqlCliFinding {
  ruleId: string;
  ruleName: string | null;
  message: string;
  severity: Severity;
  securitySeverity: number | null;
  problemSeverity: string | null;
  precision: string | null;
  cwe: string[];
  tags: string[];
  path: string;
  startLine: number;
  endLine: number;
  startColumn: number | null;
  endColumn: number | null;
  fingerprint: string;
  helpUri: string | null;
  language: string | null;
}

export interface CodeqlCliDocument {
  command: "codeql analyze" | "codeql import";
  codeqlVersion: string | null;
  suite: CodeqlSuite | null;
  packDownloadAllowed: boolean;
  targetCodeExecuted: boolean;
  languages: CodeqlLanguageResultView[];
  /**
   * Rule ids the core reports as run, per language (`languages[].rules`: every query CodeQL ran,
   * also those without results). A language without the list (an older core) is absent.
   */
  rulesByLanguage: Map<string, string[]>;
  findings: CodeqlCliFinding[];
  resultsTotal: number;
  resultsOutsideWorkspace: number;
  truncated: boolean;
  warnings: string[];
  sourceTool: { name: string; version: string | null } | null;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function str(value: unknown, max = 2000): string | null {
  return typeof value === "string" && value.length > 0 ? value.slice(0, max) : null;
}

function nonNegativeInt(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

function strings(value: unknown, maxItems = 50): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0).slice(0, maxItems).map((item) => item.slice(0, 200)) : [];
}

/**
 * A workspace-relative path with forward slashes that stays inside the workspace, or null. The core
 * already drops absolute and escaping paths; the bridge checks again before storing anything.
 */
export function safeRelativePath(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 1024) return null;
  // oxlint-disable-next-line no-control-regex -- intentional: refuses control characters in a result path
  if (/[\u0000-\u001f]/.test(raw)) return null;
  const value = raw.replace(/\\/g, "/");
  if (value.startsWith("/") || /^[A-Za-z]:/.test(value) || /^[a-z][a-z0-9+.-]*:/i.test(value)) return null;
  const segments = value.split("/").filter((segment) => segment !== "" && segment !== ".");
  if (segments.length === 0 || segments.some((segment) => segment === "..")) return null;
  return segments.join("/");
}

function invalid(command: string, detail: string): HttpError {
  return new HttpError(502, "core_output_invalid", `sentra ${command} returned an unexpected document: ${detail}`);
}

/** Per-language outcomes of a CLI document (or of the partial report in a core error); malformed entries are dropped. */
export function parseLanguageResults(raw: unknown): CodeqlLanguageResultView[] {
  const languages: CodeqlLanguageResultView[] = [];
  if (!Array.isArray(raw)) return languages;
  for (const item of raw.slice(0, 50)) {
    const entry = record(item);
    const language = str(entry?.language, 40);
    if (!entry || !language) continue;
    const status = entry.status === "analyzed" || entry.status === "skipped" || entry.status === "failed" ? entry.status : null;
    if (!status) continue;
    languages.push({
      language,
      status,
      reason: sanitizeCoreMessage(entry.reason),
      results: nonNegativeInt(entry.results) ?? 0,
      durationMs: nonNegativeInt(entry.duration_ms),
    });
  }
  return languages;
}

/** Most rule ids read per language from `languages[].rules` (the core lists at most 10 000). */
const MAX_RULES_PER_LANGUAGE = 10_000;

/** `languages[].rules` per language; languages without an array are left out. */
export function parseRulesByLanguage(raw: unknown): Map<string, string[]> {
  const rules = new Map<string, string[]>();
  if (!Array.isArray(raw)) return rules;
  for (const item of raw.slice(0, 50)) {
    const entry = record(item);
    const language = str(entry?.language, 40);
    if (!entry || !language || !Array.isArray(entry.rules)) continue;
    // Sliced like a finding's rule id (str(rule_id, 200)) so the two compare equal.
    rules.set(language, strings(entry.rules, MAX_RULES_PER_LANGUAGE));
  }
  return rules;
}

/** Maps the JSON document of `sentra codeql analyze|import --json` (schema_version 1). */
export function parseCodeqlCliOutput(raw: unknown, expected: CodeqlCliDocument["command"]): CodeqlCliDocument {
  const doc = record(raw);
  if (!doc) throw invalid(expected, "not a JSON object");
  if (doc.schema_version !== 1) throw invalid(expected, `unsupported schema_version ${String(doc.schema_version)}`);
  if (doc.command !== expected) throw invalid(expected, `command is ${String(doc.command)}`);
  if (!Array.isArray(doc.findings) || !Array.isArray(doc.languages)) throw invalid(expected, "findings or languages missing");
  const languages = parseLanguageResults(doc.languages);
  let outside = nonNegativeInt(doc.results_outside_workspace) ?? 0;
  const findings: CodeqlCliFinding[] = [];
  for (const item of doc.findings) {
    const entry = record(item);
    if (!entry) continue;
    const ruleId = str(entry.rule_id, 200);
    const fingerprint = str(entry.fingerprint, 200);
    const severity = typeof entry.severity === "string" ? CLI_SEVERITY[entry.severity] : undefined;
    const startLine = typeof entry.start_line === "number" && Number.isInteger(entry.start_line) && entry.start_line > 0 ? entry.start_line : null;
    if (!ruleId || !fingerprint || !severity || startLine === null) continue;
    const relative = safeRelativePath(entry.path);
    if (!relative) {
      outside += 1;
      continue;
    }
    const endLine = typeof entry.end_line === "number" && Number.isInteger(entry.end_line) && entry.end_line >= startLine ? entry.end_line : startLine;
    const securitySeverity =
      typeof entry.security_severity === "number" && Number.isFinite(entry.security_severity) && entry.security_severity >= 0 && entry.security_severity <= 10
        ? entry.security_severity
        : null;
    findings.push({
      ruleId,
      ruleName: str(entry.rule_name, 300),
      message: str(entry.message, 4000) ?? ruleId,
      severity,
      securitySeverity,
      problemSeverity: str(entry.problem_severity, 40),
      precision: str(entry.precision, 40),
      cwe: strings(entry.cwe).filter((cwe) => /^CWE-\d{1,5}$/.test(cwe)),
      tags: strings(entry.tags),
      path: relative,
      startLine,
      endLine,
      startColumn: nonNegativeInt(entry.start_column),
      endColumn: nonNegativeInt(entry.end_column),
      fingerprint,
      helpUri: typeof entry.help_uri === "string" && /^https:\/\/[^\s]{1,500}$/.test(entry.help_uri) ? entry.help_uri : null,
      language: str(entry.language, 40),
    });
  }
  const tool = record(doc.source_tool);
  const toolName = str(tool?.name, 100);
  return {
    command: expected,
    codeqlVersion: str(doc.codeql_version, 60),
    suite: CODEQL_SUITES.includes(doc.suite as CodeqlSuite) ? (doc.suite as CodeqlSuite) : null,
    packDownloadAllowed: doc.pack_download_allowed === true,
    // Anything but an explicit false is treated as a violation of the build-mode-none contract.
    targetCodeExecuted: doc.target_code_executed !== false,
    languages,
    rulesByLanguage: parseRulesByLanguage(doc.languages),
    findings,
    resultsTotal: nonNegativeInt(doc.results_total) ?? findings.length,
    resultsOutsideWorkspace: outside,
    truncated: doc.truncated === true,
    warnings: strings(doc.warnings, 50).map((warning) => sanitizeCoreMessage(warning) ?? "").filter(Boolean),
    sourceTool: toolName ? { name: toolName, version: str(tool?.version, 60) } : null,
  };
}

/** Stored identity of a CodeQL result: origin, rule, path and the CLI fingerprint. */
export function codeqlFingerprint(origin: FindingOrigin, ruleId: string, filePath: string, fingerprint: string): string {
  return sha256Hex(`codeql|${origin}|${ruleId}|${filePath}|${fingerprint}`);
}

export const CODEQL_CATEGORY = "CODEQL";

/** Candidates from a parsed CLI document. */
export function codeqlCandidates(doc: CodeqlCliDocument, origin: Exclude<FindingOrigin, "github_code_scanning">): CandidateFinding[] {
  return doc.findings.map((finding) => {
    const details: CodeqlFindingDetails = {
      origin,
      language: finding.language,
      securitySeverity: finding.securitySeverity,
      problemSeverity: finding.problemSeverity,
      precision: finding.precision,
      cwes: finding.cwe,
      tags: finding.tags,
      helpUri: finding.helpUri,
      startLine: finding.startLine,
      endLine: finding.endLine,
      startColumn: finding.startColumn,
      endColumn: finding.endColumn,
      toolName: doc.sourceTool?.name ?? "CodeQL",
      toolVersion: doc.sourceTool?.version ?? doc.codeqlVersion,
      repository: null,
      alertNumber: null,
      alertUrl: null,
      fingerprintSource: /^[0-9a-f]{64}$/.test(finding.fingerprint) ? "cli_digest" : "sarif_partial_fingerprint",
    };
    return {
      fingerprint: codeqlFingerprint(origin, finding.ruleId, finding.path, finding.fingerprint),
      source: "codeql",
      origin,
      codeql: details,
      ruleId: finding.ruleId,
      ruleName: finding.ruleName ?? finding.ruleId,
      cwe: finding.cwe.length > 0 ? finding.cwe.join(", ") : null,
      severity: finding.severity,
      category: CODEQL_CATEGORY,
      filePath: finding.path,
      line: finding.startLine,
      snippet: null,
      rationale: finding.message,
      taintTrace: null,
      dependency: null,
    };
  });
}

/** Language bucket of a language id: "" for no language (the core's "unknown" bucket). */
export function languageBucket(language: string | null | undefined): string {
  return !language || language === "unknown" ? "" : language;
}

/** Language bucket of a stored CodeQL finding. */
function languageOf(details: unknown): string {
  const value = record(details)?.language;
  return languageBucket(typeof value === "string" ? value : null);
}

/** Rule ids that ran, per language bucket. */
export type RanRules = ReadonlyMap<string, ReadonlySet<string>>;

/**
 * The rules a CLI document ran, per language bucket: for every analyzed language the rules the
 * core lists (CodeQL lists every query it ran, also those without results), plus the rule of
 * every finding. A language listed without rules (an older core) covers only the rules that
 * produced findings, so nothing is resolved for a rule that may not have run.
 */
export function ranRules(doc: Pick<CodeqlCliDocument, "languages" | "rulesByLanguage" | "findings">): Map<string, Set<string>> {
  const ran = new Map<string, Set<string>>();
  const rulesOf = (bucket: string) => {
    let rules = ran.get(bucket);
    if (!rules) {
      rules = new Set<string>();
      ran.set(bucket, rules);
    }
    return rules;
  };
  for (const entry of doc.languages) {
    if (entry.status !== "analyzed") continue;
    const rules = rulesOf(languageBucket(entry.language));
    for (const rule of doc.rulesByLanguage.get(entry.language) ?? []) rules.add(rule);
  }
  for (const finding of doc.findings) rulesOf(languageBucket(finding.language)).add(finding.ruleId);
  return ran;
}

/**
 * Scope covering the stored findings whose language and rule ran: a finding of a rule that did
 * not run this time (another query suite, another query pack version, a SARIF of a narrower
 * suite) is never resolved, because its absence says nothing about the code.
 */
export function languageScope(origin: FindingOrigin, ran: RanRules, resolve: boolean): ReconcileScope {
  return { source: "codeql", origin, resolve, covers: ({ details, ruleId }) => ran.get(languageOf(details))?.has(ruleId) ?? false };
}

function describeLanguages(languages: CodeqlLanguageResultView[]): string {
  return languages
    .map((entry) => {
      if (entry.status === "analyzed") return `${entry.language} analyzed (${entry.results} result${entry.results === 1 ? "" : "s"}${entry.durationMs !== null ? `, ${Math.round(entry.durationMs / 1000)} s` : ""})`;
      return `${entry.language} ${entry.status}${entry.reason ? `: ${entry.reason}` : ""}`;
    })
    .join("; ");
}

// ───────────────────────────── host analysis (scan stage) ─────────────────────────────

export function emptyAnalysis(skip: CodeqlSkip, attempted = false, outcome: CodeqlAnalysisOutcome = "skipped"): CodeqlAnalysisView {
  return {
    outcome,
    attempted,
    skipReason: skip.reason,
    message: skip.message,
    codeqlVersion: null,
    suite: null,
    packDownloadAllowed: false,
    languages: [],
    resultsTotal: 0,
    resultsOutsideWorkspace: 0,
    truncated: false,
    warnings: [],
    durationMs: null,
  };
}

export interface HostAnalysisOutcome {
  view: CodeqlAnalysisView;
  /** "completed": analyzed or skipped; "failed": the analysis failed (stage error). */
  status: "completed" | "failed";
  candidates: CandidateFinding[];
  scope: ReconcileScope | null;
}

/** Text the core puts in a language reason when CodeQL's Java VM got no memory (JVM_MEMORY_HINT in codeql_host.rs). */
export const JVM_MEMORY_HINT_MARKER = "Java VM could not get the memory";
export const MEMORY_SETTING_HINT =
  "CodeQL's Java VM could not get enough memory: set a RAM limit in Settings > CodeQL that fits the memory the host has free, or free memory on the host (without a limit the bridge passes half of the memory available when the analysis starts, at most 8192 MiB).";

export const PACKS_MISSING_MESSAGE =
  "The CodeQL query packs for the selected suite are not in the pack cache and pack download is off. An admin can download them once with Settings > CodeQL > Query packs > Download missing packs, or allow pack download in Settings > CodeQL (scans then download missing packs from GitHub's container registry, ghcr.io, into the bridge's pack cache); the host operator can also install the CodeQL bundle, which ships the query packs.";

/**
 * Time the bridge gives `sentra codeql analyze` before it stops the core itself: the analysis
 * budget, plus the separate pack download budget when downloads are allowed, plus a margin.
 */
export function analysisBridgeTimeoutMs(settings: Pick<CodeqlSettings, "timeoutMinutes" | "downloadTimeoutMinutes" | "allowPackDownload">): number {
  const downloadSecs = settings.allowPackDownload ? settings.downloadTimeoutMinutes * 60 : 0;
  return (settings.timeoutMinutes * 60 + downloadSecs) * 1000 + BRIDGE_TIMEOUT_MARGIN_MS;
}

/** The time budgets of an analysis, in words. */
export function budgetNote(settings: Pick<CodeqlSettings, "timeoutMinutes" | "downloadTimeoutMinutes" | "allowPackDownload">): string {
  const analysis = `CodeQL steps (version, database creation, analysis): ${settings.timeoutMinutes} min in total (--timeout-secs ${settings.timeoutMinutes * 60})`;
  return settings.allowPackDownload
    ? `Time budgets: ${analysis}; query pack downloads: ${settings.downloadTimeoutMinutes} min of their own (--download-timeout-secs ${settings.downloadTimeoutMinutes * 60}), not counted against the analysis.`
    : `Time budget: ${analysis}. Pack download is off, so missing query packs are not downloaded.`;
}

/** The runtime CodeQL's JavaScript extractor parses TypeScript with, as the bridge passes it. */
export interface TypescriptRuntimeChoice {
  /** Passed as --typescript-runtime; null when it cannot be passed. */
  path: string | null;
  /** Why no path is passed, or how it was chosen. */
  note: string;
}

/**
 * The Bun executable the bridge runs on, for --typescript-runtime: the located installation the
 * running file is (a Scoop shim replaced by its target), else process.execPath (under `bun run` a
 * hard link of the real bun in a temporary bun-node directory, which exists while the bridge runs).
 * On Windows a path containing & ^ ! or % is not passed (the core would refuse it); the core then
 * looks for bun on its own PATH. AGENTS.md: Bun is the only JavaScript runtime Sentra introduces.
 */
export async function typescriptRuntimeChoice(deps: HostFactsDeps, snapshot: SearchSnapshot, execPath = process.execPath): Promise<TypescriptRuntimeChoice> {
  const platform = deps.executables.platform;
  let chosen = execPath;
  try {
    const runtime = await bunRuntime(deps, snapshot, execPath);
    chosen = runtime.match ? ((await readScoopShimTarget(runtime.match.path, platform)) ?? runtime.match.path) : runtime.path;
  } catch {
    chosen = execPath;
  }
  if (!(platform === "win32" ? path.win32 : path.posix).isAbsolute(chosen)) {
    return { path: null, note: `The bridge's Bun path (${chosen}) is not absolute, so it is not passed as --typescript-runtime; the core looks for bun on its own PATH instead.` };
  }
  if (platform === "win32" && /[&^!%]/.test(chosen)) {
    return {
      path: null,
      note: `The bridge's Bun (${chosen}) is not passed as --typescript-runtime because its path contains & ^ ! or %, which CodeQL's Windows scripts would interpret; the core looks for bun on its own PATH instead.`,
    };
  }
  return { path: chosen, note: `TypeScript is parsed with Bun (${chosen}), the runtime the bridge runs on; no Node.js is needed.` };
}

/**
 * The runtime choice for one workspace: the core refuses a --typescript-runtime inside the workspace
 * (its files are untrusted) and then fails the whole analysis, so such a path is not passed; the
 * core falls back to the first bun on its PATH outside the workspace and warns when it finds none.
 */
export function runtimeForWorkspace(runtime: TypescriptRuntimeChoice | undefined, workspace: string): TypescriptRuntimeChoice | undefined {
  if (!runtime?.path) return runtime;
  const real = (candidate: string) => {
    try {
      return fs.realpathSync.native(candidate);
    } catch {
      return candidate;
    }
  };
  // The core compares canonical paths; compare both the given and the resolved ones.
  if (!isWithin(workspace, runtime.path) && !isWithin(real(workspace), real(runtime.path))) return runtime;
  return {
    path: null,
    note: `The bridge's Bun (${runtime.path}) lies inside the workspace being scanned, whose files are untrusted, so it is not passed as --typescript-runtime; the core uses the first bun on its PATH outside the workspace instead, and without one CodeQL needs Node.js to extract TypeScript files.`,
  };
}

/** What is excluded from extraction and which runtime parses TypeScript, in words. */
export function extractionNote(settings: Pick<CodeqlSettings, "excludePaths">, runtime: TypescriptRuntimeChoice | undefined): string {
  const excluded =
    settings.excludePaths.length > 0
      ? `Excluded from extraction: ${settings.excludePaths.join(", ")}.`
      : "Nothing is excluded from extraction (Settings > CodeQL > Exclude from extraction is empty).";
  return runtime ? `${excluded} ${runtime.note}` : excluded;
}

/**
 * Runs `sentra codeql analyze --progress` for one workspace. The caller holds the bridge-wide
 * lock. The work directory is created under the bridge temporary directory and removed afterwards.
 * Progress events on stderr go to onProgress as readable text; other stderr lines to onStderr.
 */
export async function runHostAnalysis(
  app: Pick<AppContext, "cli" | "config" | "codeql" | "hostPlatform">,
  input: {
    workspace: string;
    launcher: string;
    signal?: AbortSignal;
    /** A stderr line of the core that is not a progress event. */
    onStderr?: (line: string) => void;
    onProgress?: (progress: CodeqlProgressView) => void;
    onCommand?: (args: string[]) => void;
    /** The chosen --ram and the time budgets, in words, before the core starts. */
    onLimits?: (text: string) => void;
    /** --typescript-runtime (the bridge's Bun); without it the core looks for bun on its PATH. */
    typescriptRuntime?: TypescriptRuntimeChoice;
  },
): Promise<HostAnalysisOutcome> {
  const settings = app.codeql.settings();
  const timeoutSecs = settings.timeoutMinutes * 60;
  const memory = await hostMemoryReading(app.hostPlatform);
  const ram = chooseRamMb(settings, memory.availableBytes, memory.fallbackNote);
  const runtime = runtimeForWorkspace(input.typescriptRuntime, input.workspace);
  input.onLimits?.(`${ram.note} ${budgetNote(settings)} ${extractionNote(settings, runtime)}`);
  fs.mkdirSync(app.config.tmpDir, { recursive: true, mode: 0o700 });
  const workDir = fs.mkdtempSync(path.join(app.config.tmpDir, "codeql-"));
  const started = performance.now();
  const failed = (message: string, attempted = true): HostAnalysisOutcome => ({
    view: { ...emptyAnalysis({ reason: "disabled", message }, attempted, "failed"), skipReason: null, message },
    status: "failed",
    candidates: [],
    scope: null,
  });
  try {
    if (isWithin(input.workspace, workDir)) return failed(`work_dir_inside_workspace: the CodeQL work directory ${workDir} is inside the workspace.`, false);
    fs.mkdirSync(app.codeql.packCache, { recursive: true, mode: 0o700 });
    const args = [
      "codeql",
      "analyze",
      "--workspace",
      cliValue(input.workspace, "workspace"),
      "--codeql",
      cliValue(input.launcher, "codeql"),
      "--work-dir",
      cliValue(workDir, "workDir"),
      "--pack-cache",
      cliValue(app.codeql.packCache, "packCache"),
      "--accept-codeql-terms",
      "--suite",
      settings.suite,
      "--threads",
      String(settings.threads),
      "--timeout-secs",
      String(timeoutSecs),
      "--max-results",
      String(CODEQL_MAX_RESULTS),
      "--ram",
      String(ram.ramMb),
    ];
    if (runtime?.path) args.push("--typescript-runtime", cliValue(runtime.path, "typescriptRuntime"));
    for (const glob of settings.excludePaths) args.push("--exclude", cliValue(glob, "excludePaths", EXCLUDE_PATH_MAX_CHARS));
    if (settings.allowPackDownload) {
      // Pack downloads have their own budget and do not consume --timeout-secs.
      args.push("--allow-pack-download", "--download-timeout-secs", String(settings.downloadTimeoutMinutes * 60));
    }
    // Cancelling the scan closes the core's stdin; the core then kills the CodeQL process tree
    // itself (on Unix CodeQL runs in its own process group, which a signal to the core would
    // not reach) and exits, and only then does this call return and the lock get released.
    // --progress: one JSON progress object per stderr line (steps and a heartbeat every 15 s).
    args.push("--cancel-on-stdin-eof", "--progress", "--json");
    input.onCommand?.(args);
    const result = await app.cli.run(args, {
      timeoutMs: analysisBridgeTimeoutMs(settings),
      signal: input.signal,
      cancelViaStdinEof: true,
      maxOutputBytes: CODEQL_MAX_OUTPUT_BYTES,
      onStderrLine: (line) => {
        const progress = progressFromLine(line, { suite: settings.suite, typescriptRuntime: runtime?.path ? "Bun" : null, scan: true });
        if (progress) input.onProgress?.(progress);
        else if (line.trim()) input.onStderr?.(line);
      },
    });
    return interpretAnalysis(result, settings, Math.round(performance.now() - started), ram);
  } finally {
    // Temporary CodeQL databases live here; the core deletes them, the bridge removes what is left.
    try {
      fs.rmSync(workDir, { recursive: true, force: true, maxRetries: 3 });
    } catch {
      // Best effort: the bridge temporary directory is private to the bridge.
    }
  }
}

/** Turns the CLI result of `sentra codeql analyze` into the stage outcome. */
export function interpretAnalysis(
  result: CliResult,
  settings: CodeqlSettings,
  durationMs: number,
  /** The --ram the analysis ran with, named in a memory failure. */
  ram?: { ramMb: number; source: "setting" | "automatic" },
): HostAnalysisOutcome {
  const failed = (message: string): HostAnalysisOutcome => ({
    view: { ...emptyAnalysis({ reason: "disabled", message }, true, "failed"), skipReason: null, message, durationMs },
    status: "failed",
    candidates: [],
    scope: null,
  });
  const budgets = `the analysis budget is ${settings.timeoutMinutes} minutes${settings.allowPackDownload ? ` and the pack download budget ${settings.downloadTimeoutMinutes} minutes` : ""}`;
  if (result.timedOut) {
    return failed(`codeql_timeout: the bridge stopped \`sentra codeql analyze\` after ${Math.round(analysisBridgeTimeoutMs(settings) / 1000)} s (${budgets}).`);
  }
  if (result.code !== 0) {
    const core = coreErrorDocument(result);
    const detail = core?.message ? `: ${core.message}` : "";
    // The core attaches the partial per-language report to analysis errors.
    const partial = (outcome: HostAnalysisOutcome): HostAnalysisOutcome => {
      const languages = parseLanguageResults(core?.details.languages);
      const version = typeof core?.details.codeql_version === "string" ? core.details.codeql_version.slice(0, 60) : null;
      return { ...outcome, view: { ...outcome.view, languages, codeqlVersion: version } };
    };
    switch (core?.code) {
      case "codeql_query_pack_missing":
        return partial({
          view: { ...emptyAnalysis({ reason: "packs_missing", message: `${PACKS_MISSING_MESSAGE}${core.message ? ` (core: ${core.message})` : ""}` }, true), durationMs },
          status: "completed",
          candidates: [],
          scope: null,
        });
      case "codeql_timeout":
        return partial(failed(`codeql_timeout: a CodeQL step ran out of its time budget (${budgets}); the core stopped its process tree${detail}`));
      case "codeql_not_found":
        return failed(`codeql_not_found: the core refused the codeql launcher${detail}`);
      case "codeql_terms_not_accepted":
        return failed(`codeql_terms_not_accepted${detail}`);
      case "codeql_cancelled":
        return partial(failed(`codeql_cancelled: the scan was cancelled; the core stopped the CodeQL process tree${detail}`));
      case "codeql_failed": {
        // The reasons are in the per-language report; name them in the stage message.
        const languages = parseLanguageResults(core.details.languages);
        const text = describeLanguages(languages);
        return partial(failed(`codeql_failed: CodeQL failed for every language it was run for${text ? `: ${text}.` : detail}${memoryHint(languages, ram)}`));
      }
      default:
        return partial(failed(core ? `${core.code}${detail}` : `sentra codeql analyze exited with code ${result.code}`));
    }
  }
  let doc: CodeqlCliDocument;
  try {
    doc = parseCodeqlCliOutput(result.json, "codeql analyze");
  } catch (error) {
    return failed(error instanceof Error ? error.message : String(error));
  }
  if (doc.targetCodeExecuted) {
    return failed("The core did not report target_code_executed: false, which ADR-0011 requires for host analysis; the results were discarded.");
  }
  const analyzed = doc.languages.filter((entry) => entry.status === "analyzed");
  const base: CodeqlAnalysisView = {
    outcome: "analyzed",
    attempted: true,
    skipReason: null,
    message: "",
    codeqlVersion: doc.codeqlVersion,
    suite: doc.suite ?? settings.suite,
    packDownloadAllowed: doc.packDownloadAllowed,
    languages: doc.languages,
    resultsTotal: doc.resultsTotal,
    resultsOutsideWorkspace: doc.resultsOutsideWorkspace,
    truncated: doc.truncated,
    warnings: doc.warnings,
    durationMs,
  };
  const languagesText = describeLanguages(doc.languages);
  if (analyzed.length === 0) {
    if (doc.languages.length > 0 && doc.languages.every((entry) => entry.status === "failed")) {
      return { view: { ...base, outcome: "failed", message: `CodeQL analysis failed for every language: ${languagesText}.${memoryHint(doc.languages, ram)}` }, status: "failed", candidates: [], scope: null };
    }
    const needBuild = doc.languages.length > 0;
    const message = needBuild
      ? `No detected language could be analyzed on the host: ${languagesText}. Languages that need building the project, or whose build-mode-none extraction would run project code, are not analyzed there, because Sentra does not build projects or run their code on the host.`
      : "CodeQL found no language it can analyze in this workspace.";
    return { view: { ...base, outcome: "skipped", skipReason: needBuild ? "languages_need_build" : "no_languages", message }, status: "completed", candidates: [], scope: null };
  }
  const candidates = codeqlCandidates(doc, "host_analysis");
  const message =
    `CodeQL ${doc.codeqlVersion ?? "(version not reported)"} analyzed the workspace on the bridge host (suite ${base.suite}, build mode none; target code was not executed): ${languagesText}. ` +
    `${candidates.length} result(s) kept${doc.resultsOutsideWorkspace > 0 ? `, ${doc.resultsOutsideWorkspace} outside the workspace dropped` : ""}` +
    `${doc.truncated ? `; the result list was cut at ${CODEQL_MAX_RESULTS}, so no host-analysis finding is resolved by this run` : ""}.` +
    memoryHint(doc.languages, ram);
  return {
    view: { ...base, message },
    status: "completed",
    candidates,
    scope: languageScope("host_analysis", ranRules(doc), !doc.truncated),
  };
}

/**
 * MEMORY_SETTING_HINT (with a leading space) when a language failed because CodeQL's Java VM got
 * no memory, naming the --ram the analysis ran with when it is known.
 */
function memoryHint(languages: readonly CodeqlLanguageResultView[], ram?: { ramMb: number; source: "setting" | "automatic" }): string {
  if (!languages.some((entry) => entry.reason?.includes(JVM_MEMORY_HINT_MARKER))) return "";
  const used = ram ? ` This analysis ran with --ram ${ram.ramMb} MiB (${ram.source === "setting" ? "the RAM setting" : "chosen automatically"}).` : "";
  return ` ${MEMORY_SETTING_HINT}${used}`;
}

// ───────────────────────────── import + GitHub sync ─────────────────────────────

/**
 * Uploads up to this size are also parsed by the bridge before the core starts, so the common
 * mistakes (not JSON, not SARIF, not CodeQL) are answered at once. Larger uploads are checked only
 * by the core, which reads SARIF in one bounded streaming pass: a full JSON.parse of a 64 MiB
 * upload would cost the bridge far more memory than the file itself.
 */
export const SARIF_PRECHECK_MAX_BYTES = 256 * 1024;

/** Bytes of an upload read to check that it starts like a JSON object. */
const SARIF_HEAD_BYTES = 64 * 1024;

/** Quick checks of a small uploaded SARIF (at most SARIF_PRECHECK_MAX_BYTES); the core checks again. */
export function precheckSarif(text: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "sarif_invalid", "The uploaded file is not valid JSON.");
  }
  const doc = record(parsed);
  if (!doc || !Array.isArray(doc.runs)) throw new HttpError(400, "sarif_invalid", "The uploaded JSON is not a SARIF log (no runs array).");
  if (doc.runs.length === 0) throw new HttpError(400, "sarif_invalid", "The SARIF log has no runs.");
  for (const run of doc.runs) {
    const name = record(record(record(run)?.tool)?.driver)?.name;
    if (typeof name !== "string" || name.trim().toLowerCase() !== "codeql") {
      throw new HttpError(400, "sarif_not_codeql", `Only CodeQL SARIF can be imported; a run's tool.driver.name is ${typeof name === "string" ? `'${name.slice(0, 80)}'` : "missing"}.`);
    }
  }
}

const IMPORT_ERRORS: Record<string, [number, string]> = {
  sarif_not_codeql: [400, "Only CodeQL SARIF can be imported."],
  sarif_too_large: [413, `The SARIF file is larger than the import limit (${CODEQL_IMPORT_MAX_BYTES / (1024 * 1024)} MiB).`],
  sarif_invalid: [400, "The SARIF file could not be parsed."],
};

function ingestCounts(result: ReconcileResult): CodeqlIngestView["findings"] {
  return { created: result.created, reopened: result.reopened, stillOpen: result.stillOpen, resolved: result.resolved };
}

export const SARIF_TOO_LARGE_MESSAGE = `The SARIF file is larger than the import limit (${CODEQL_IMPORT_MAX_BYTES / (1024 * 1024)} MiB).`;

/**
 * Streams a request body into `file` (created new, mode 0600) without holding it in memory, and
 * refuses it with 413 sarif_too_large past `maxBytes` (by Content-Length up front, or while
 * reading). Returns the number of bytes written.
 */
export async function receiveUpload(req: Request, file: string, maxBytes: number): Promise<number> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isFinite(length) || length < 0) throw new HttpError(400, "invalid_request", "Invalid Content-Length header");
    if (length > maxBytes) throw new HttpError(413, "sarif_too_large", SARIF_TOO_LARGE_MESSAGE);
  }
  const fd = fs.openSync(file, "wx", 0o600);
  let total = 0;
  try {
    if (!req.body) return 0;
    const reader = req.body.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new HttpError(413, "sarif_too_large", SARIF_TOO_LARGE_MESSAGE);
      }
      let offset = 0;
      while (offset < value.byteLength) offset += fs.writeSync(fd, value, offset, value.byteLength - offset);
    }
    return total;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Bridge-side checks of a received upload before the core runs: empty bodies and bodies that do
 * not start like a JSON object are refused from the first bytes, and uploads up to
 * SARIF_PRECHECK_MAX_BYTES are parsed (precheckSarif). Larger uploads are left to the core.
 */
export function precheckSarifFile(file: string, size: number): void {
  if (size <= SARIF_PRECHECK_MAX_BYTES) {
    const text = fs.readFileSync(file, "utf8");
    if (!text.trim()) throw new HttpError(400, "sarif_invalid", "The request body is empty; send the SARIF document.");
    precheckSarif(text);
    return;
  }
  const fd = fs.openSync(file, "r");
  try {
    const head = Buffer.alloc(SARIF_HEAD_BYTES);
    const read = fs.readSync(fd, head, 0, head.length, 0);
    const text = head.subarray(0, read).toString("utf8").replace(/^\uFEFF/, "");
    const first = /\S/.exec(text)?.[0];
    if (first !== "{") throw new HttpError(400, "sarif_invalid", "The uploaded file is not a JSON object, so it is not a SARIF log.");
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Imports a CodeQL SARIF document produced elsewhere, sent as a request body: streamed into a
 * private file under the bridge temporary directory (never held in memory as a whole), parsed by
 * `sentra codeql import` (one bounded streaming pass), reconciled with origin sarif_import. A
 * re-import resolves earlier imported findings only of the rules the new file ran (CodeQL lists
 * every query it ran, also those without results) that it no longer reports.
 */
export async function importCodeqlSarif(
  app: Pick<AppContext, "cli" | "config" | "db">,
  tenant: TenantRecord,
  workspace: string,
  req: Request,
  signal?: AbortSignal,
): Promise<CodeqlIngestView> {
  fs.mkdirSync(app.config.tmpDir, { recursive: true, mode: 0o700 });
  const dir = fs.mkdtempSync(path.join(app.config.tmpDir, "codeql-import-"));
  const file = path.join(dir, "upload.sarif");
  let result: CliResult;
  try {
    const size = await receiveUpload(req, file, CODEQL_IMPORT_MAX_BYTES);
    precheckSarifFile(file, size);
    result = await app.cli.run(
      ["codeql", "import", "--sarif", cliValue(file, "sarif"), "--workspace", cliValue(workspace, "workspace"), "--max-results", String(CODEQL_MAX_RESULTS), "--json"],
      { timeoutMs: app.config.cliLongTimeoutMs, signal, maxOutputBytes: CODEQL_MAX_OUTPUT_BYTES },
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  if (result.timedOut) throw new HttpError(504, "core_timeout", "sentra codeql import timed out");
  if (result.code !== 0) {
    const core = coreErrorDocument(result);
    const known = core ? IMPORT_ERRORS[core.code] : undefined;
    if (core && known) throw new HttpError(known[0], core.code, core.message ? `${known[1]} ${core.message}` : known[1]);
    throw new HttpError(422, "core_command_failed", `sentra codeql import failed: ${core ? `${core.code}${core.message ? `: ${core.message}` : ""}` : `exit code ${result.code}`}`, {
      coreError: core?.code ?? null,
    });
  }
  const doc = parseCodeqlCliOutput(result.json, "codeql import");
  const candidates = codeqlCandidates(doc, "sarif_import");
  const ran = ranRules(doc);
  const at = nowIso();
  const reconciled = reconcileFindings(app.db, {
    tenantId: tenant.tenantId,
    workspace: tenant.workspace,
    runId: `cqimport_${crypto.randomUUID()}`,
    at,
    candidates,
    scopes: [languageScope("sarif_import", ran, !doc.truncated)],
  });
  const covered = [...ran.entries()]
    .filter(([, rules]) => rules.size > 0)
    .map(([language, rules]) => `${language || "(no language)"} (${rules.size} rule${rules.size === 1 ? "" : "s"})`)
    .sort();
  return {
    origin: "sarif_import",
    tenantId: tenant.tenantId,
    receivedAt: at,
    sourceTool: doc.sourceTool,
    repository: null,
    resultsTotal: doc.resultsTotal,
    resultsOutsideWorkspace: doc.resultsOutsideWorkspace,
    truncated: doc.truncated,
    languages: doc.languages,
    warnings: doc.warnings,
    findings: ingestCounts(reconciled),
    note: doc.truncated
      ? `The result list was cut at ${CODEQL_MAX_RESULTS}; earlier imported findings were kept open (none resolved).`
      : covered.length > 0
        ? `Earlier imported findings of the rules this file ran (${covered.join(", ")}) that it no longer reports were resolved; findings of rules it did not run stay open. Findings from host analysis and GitHub code scanning are not affected.`
        : "The file listed no rules and no results, so no earlier imported finding was resolved.",
  };
}

interface GithubAlert {
  number?: unknown;
  html_url?: unknown;
  state?: unknown;
  rule?: unknown;
  tool?: unknown;
  most_recent_instance?: unknown;
}

const GITHUB_SECURITY_SEVERITY: Record<string, Severity> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const GITHUB_RULE_SEVERITY: Record<string, Severity> = { error: "Medium", warning: "Low", note: "Informational", none: "Informational" };

/** CWE ids from code scanning tags such as `external/cwe/cwe-079` (as CWE-79). */
export function cweFromTags(tags: readonly string[]): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const match = /^external\/cwe\/cwe-0*(\d{1,5})$/i.exec(tag);
    if (match) {
      const cwe = `CWE-${match[1]}`;
      if (!out.includes(cwe)) out.push(cwe);
    }
  }
  return out;
}

function alertLanguage(instance: Record<string, unknown> | null): string | null {
  const category = str(instance?.category, 200);
  const fromCategory = category ? /(?:^|\/)language:([A-Za-z0-9_+-]{1,40})/.exec(category)?.[1] : undefined;
  if (fromCategory) return fromCategory.toLowerCase();
  const environment = str(instance?.environment, 2000);
  if (environment) {
    try {
      const language = record(JSON.parse(environment))?.language;
      if (typeof language === "string" && /^[A-Za-z0-9_+-]{1,40}$/.test(language)) return language.toLowerCase();
    } catch {
      // not JSON
    }
  }
  return null;
}

/** Maps one code scanning alert; "outside" for an alert whose path cannot be stored, null when malformed. */
export function mapGithubAlert(raw: unknown, repository: string): CandidateFinding | "outside" | null {
  const alert = record(raw) as GithubAlert | null;
  if (!alert || typeof alert.number !== "number" || !Number.isSafeInteger(alert.number) || alert.number < 1) return null;
  const rule = record(alert.rule);
  const instance = record(alert.most_recent_instance);
  const location = record(instance?.location);
  const ruleId = str(rule?.id, 200) ?? str(rule?.name, 200);
  if (!ruleId) return null;
  const filePath = safeRelativePath(location?.path);
  if (!filePath) return "outside";
  const startLine = typeof location?.start_line === "number" && Number.isInteger(location.start_line) && location.start_line > 0 ? location.start_line : null;
  const endLine = typeof location?.end_line === "number" && Number.isInteger(location.end_line) && startLine !== null && location.end_line >= startLine ? location.end_line : startLine;
  const securityLevel = typeof rule?.security_severity_level === "string" ? rule.security_severity_level.toLowerCase() : null;
  const ruleSeverity = typeof rule?.severity === "string" ? rule.severity.toLowerCase() : null;
  const severity = (securityLevel ? GITHUB_SECURITY_SEVERITY[securityLevel] : undefined) ?? (ruleSeverity ? GITHUB_RULE_SEVERITY[ruleSeverity] : undefined) ?? "Unknown";
  const tags = strings(rule?.tags);
  const cwes = cweFromTags(tags);
  const tool = record(alert.tool);
  const message = str(record(instance?.message)?.text, 4000) ?? str(rule?.description, 400) ?? ruleId;
  const alertUrl = typeof alert.html_url === "string" && /^https:\/\/[^\s]{1,500}$/.test(alert.html_url) ? alert.html_url : null;
  const details: CodeqlFindingDetails = {
    origin: "github_code_scanning",
    language: alertLanguage(instance),
    securitySeverity: null,
    problemSeverity: ruleSeverity,
    precision: null,
    cwes,
    tags,
    helpUri: null,
    startLine,
    endLine,
    startColumn: nonNegativeInt(location?.start_column),
    endColumn: nonNegativeInt(location?.end_column),
    toolName: str(tool?.name, 100) ?? "CodeQL",
    toolVersion: str(tool?.version, 60),
    repository,
    alertNumber: alert.number,
    alertUrl,
    fingerprintSource: "github_alert_number",
  };
  return {
    fingerprint: sha256Hex(`codeql|github_code_scanning|${repository}|${alert.number}`),
    source: "codeql",
    origin: "github_code_scanning",
    codeql: details,
    ruleId,
    ruleName: str(rule?.description, 300) ?? str(rule?.name, 300) ?? ruleId,
    cwe: cwes.length > 0 ? cwes.join(", ") : null,
    severity,
    category: CODEQL_CATEGORY,
    filePath,
    line: startLine,
    snippet: null,
    rationale: message,
    taintTrace: null,
    dependency: null,
  };
}

/** The part of GitHubService the sync uses (read-only REST). */
export interface CodeScanningReader {
  rest<T = unknown>(method: string, apiPath: string, body?: unknown, options?: { maxResponseBytes?: number }): Promise<T | null>;
}

/**
 * Reads open CodeQL alerts page by page (at most GITHUB_ALERTS_CAP); maps 403 and 404 to explicit
 * errors. When the cap is reached with a full page, one more page is requested: the list is
 * truncated only when that page is not empty.
 */
export async function fetchCodeScanningAlerts(github: CodeScanningReader, repo: GitHubRepoRef): Promise<{ alerts: unknown[]; truncated: boolean }> {
  const repository = `${repo.owner}/${repo.repo}`;
  const alerts: unknown[] = [];
  const pages = Math.ceil(GITHUB_ALERTS_CAP / GITHUB_ALERTS_PAGE_SIZE);
  for (let page = 1; page <= pages + 1; page += 1) {
    let batch: unknown;
    try {
      batch = await github.rest(
        "GET",
        `/repos/${repo.owner}/${repo.repo}/code-scanning/alerts?tool_name=CodeQL&state=open&per_page=${GITHUB_ALERTS_PAGE_SIZE}&page=${page}`,
        undefined,
        { maxResponseBytes: 16 * 1024 * 1024 },
      );
    } catch (error) {
      if (error instanceof HttpError && error.code === "github_forbidden") {
        throw new HttpError(
          403,
          "github_code_scanning_forbidden",
          `GitHub refused to list the code scanning alerts of ${repository} (HTTP 403). Code scanning or GitHub Advanced Security may not be enabled for the repository, or the credential lacks access: a classic token needs the security_events scope (public_repo for public repositories), a fine-grained token the "Code scanning alerts: read" permission. ${error.message}`,
          { githubStatus: 403 },
        );
      }
      if (error instanceof HttpError && error.code === "github_not_found") {
        throw new HttpError(
          404,
          "github_code_scanning_not_found",
          `GitHub answered 404 for the code scanning alerts of ${repository}: the repository does not exist or the credential cannot see it, or code scanning has no analysis for it yet. ${error.message}`,
          { githubStatus: 404 },
        );
      }
      throw error;
    }
    if (!Array.isArray(batch)) throw new HttpError(502, "github_request_failed", "GitHub returned an unexpected code scanning alerts response (not an array).");
    // The page after the cap only tells whether more alerts exist; none of it is stored.
    if (page > pages) return { alerts, truncated: batch.length > 0 };
    alerts.push(...batch);
    if (batch.length < GITHUB_ALERTS_PAGE_SIZE) return { alerts, truncated: false };
  }
  return { alerts: alerts.slice(0, GITHUB_ALERTS_CAP), truncated: true };
}

/**
 * Syncs open GitHub code scanning alerts of tool CodeQL for the tenant's repository (read-only):
 * reconciled with origin github_code_scanning, resolving earlier synced alerts of the same
 * repository that are no longer open (unless the list was truncated).
 */
export async function syncGithubCodeScanning(
  app: Pick<AppContext, "db">,
  github: CodeScanningReader,
  tenant: TenantRecord,
  repo: GitHubRepoRef,
): Promise<CodeqlIngestView> {
  const repository = `${repo.owner}/${repo.repo}`.toLowerCase();
  const { alerts, truncated } = await fetchCodeScanningAlerts(github, repo);
  const candidates: CandidateFinding[] = [];
  let outside = 0;
  let malformed = 0;
  let toolVersion: string | null = null;
  for (const alert of alerts) {
    const mapped = mapGithubAlert(alert, repository);
    if (mapped === "outside") outside += 1;
    else if (mapped === null) malformed += 1;
    else {
      candidates.push(mapped);
      toolVersion ??= mapped.codeql?.toolVersion ?? null;
    }
  }
  const at = nowIso();
  const reconciled = reconcileFindings(app.db, {
    tenantId: tenant.tenantId,
    workspace: tenant.workspace,
    runId: `cqsync_${crypto.randomUUID()}`,
    at,
    candidates,
    scopes: [
      {
        source: "codeql",
        origin: "github_code_scanning",
        resolve: !truncated,
        covers: ({ details }) => record(details)?.repository === repository,
      },
    ],
  });
  const warnings: string[] = [];
  if (malformed > 0) warnings.push(`${malformed} alert(s) without a number or rule were ignored.`);
  if (outside > 0) warnings.push(`${outside} alert(s) without a repository-relative file path were not stored.`);
  return {
    origin: "github_code_scanning",
    tenantId: tenant.tenantId,
    receivedAt: at,
    sourceTool: { name: "CodeQL", version: toolVersion },
    repository,
    resultsTotal: alerts.length,
    resultsOutsideWorkspace: outside,
    truncated,
    languages: [],
    warnings,
    findings: ingestCounts(reconciled),
    note: truncated
      ? `More than ${GITHUB_ALERTS_CAP} open alerts exist; the first ${GITHUB_ALERTS_CAP} were stored and no earlier synced alert was resolved.`
      : `Earlier synced alerts of ${repository} that are no longer open on GitHub were resolved. Paths are repository-relative and are matched to the workspace as they are. Nothing was written to GitHub.`,
  };
}

// ───────────────────────────── settings view ─────────────────────────────

export async function codeqlSettingsView(app: Pick<AppContext, "codeql" | "cli" | "config" | "executables" | "hostPlatform" | "toolPaths">): Promise<CodeqlSettingsView> {
  const settings = app.codeql.settings();
  const meta = app.codeql.meta();
  const snapshot = await app.executables.current();
  const launcher = codeqlLauncherChoice(hostToolsDeps(app), snapshot);
  const running = app.codeql.lock.current;
  const skip = analysisPrecondition(settings, launcher, app.cli.available()) ?? (running ? busySkip(running) : null);
  const memory = await hostMemoryReading(app.hostPlatform);
  const automatic = chooseRamMb({ ramMb: null }, memory.availableBytes, memory.fallbackNote);
  const runtime = await typescriptRuntimeChoice(hostToolsDeps(app), snapshot);
  return {
    settings,
    updatedAt: meta?.updatedAt ?? null,
    updatedBy: meta?.updatedBy ?? null,
    bounds: {
      timeoutMinutes: { ...TIMEOUT_MINUTES_BOUNDS },
      downloadTimeoutMinutes: { ...DOWNLOAD_TIMEOUT_MINUTES_BOUNDS },
      threads: { min: 1, max: app.codeql.limits.cpus },
      ramMb: { min: RAM_MB_MIN, max: app.codeql.limits.memoryMb },
      excludePaths: { maxEntries: EXCLUDE_PATHS_MAX_ENTRIES, maxChars: EXCLUDE_PATH_MAX_CHARS },
    },
    ramAuto: {
      mb: automatic.ramMb,
      availableMb: automatic.availableMb,
      rule: `Without a RAM setting, each analysis gets half of the memory available on the host when it starts (the Host page reading), at least ${RAM_MB_MIN} and at most ${RAM_AUTO_MAX_MB} MiB${automatic.availableMb !== null ? ` (now ${automatic.ramMb} MiB of ${automatic.availableMb} MiB available${memory.fallbackNote ? `, ${memory.fallbackNote}` : ""})` : ` (the host's memory cannot be read now, not even with os.freemem(), so ${RAM_AUTO_FALLBACK_MB} MiB would be used)`}.`,
    },
    typescriptRuntime: runtime.path,
    typescriptRuntimeNote: runtime.note,
    launcher: {
      available: launcher.path !== null,
      path: launcher.path,
      source: launcher.source,
      problem: launcher.problem,
      licenseFile: launcher.path ? licenseFileNear(launcher.path, app.executables.platform) : null,
    },
    packCache: app.codeql.packCache,
    skipReason: skip?.reason ?? null,
    skipMessage: skip?.message ?? null,
    running: runningView(running),
    terms: { summary: [...CODEQL_TERMS_SUMMARY], location: CODEQL_TERMS_LOCATION, referenceUrl: CODEQL_TERMS_REFERENCE_URL },
    isolationNote: codeqlIsolationNote(runtime),
  };
}
