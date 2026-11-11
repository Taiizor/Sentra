import fs from "node:fs";
import type {
  CodeqlPackSource,
  CodeqlPackStatus,
  CodeqlPacksDownloadView,
  CodeqlPacksView,
  CodeqlPackView,
  CodeqlProgressView,
  CodeqlSuite,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { nowIso } from "../db.ts";
import { codeqlLauncherChoice, hostToolsDeps } from "../host-tools.ts";
import { HttpError } from "../http-error.ts";
import { cliValue, coreErrorDocument, sanitizeCoreMessage, type CliResult } from "../sentra-cli.ts";
import { BRIDGE_TIMEOUT_MARGIN_MS, CODEQL_SUITES, describeRunning, runningView } from "./codeql.ts";
import { formatElapsed, progressFromLine } from "./codeql-progress.ts";

/**
 * CodeQL query packs (`sentra codeql packs`): which packs the configured suite needs per language,
 * whether each is in the CodeQL distribution or the bridge's pack cache, and an explicit download
 * of the missing ones (Settings > CodeQL > Query packs), so that a scan does not spend its first
 * minutes downloading. A download holds the bridge-wide CodeQL lock (`app.codeql.lock`), shared
 * with host analysis, because both run CodeQL and write the pack cache.
 *
 * The bridge reads this JSON document of `sentra codeql packs --json` (schema_version 1), and
 * parses it defensively:
 *
 *   {"schema_version":1,"command":"codeql packs","suite":"code-scanning","pack_cache":"...",
 *    "languages":[{"language":"javascript","pack":"codeql/javascript-queries","analysable":true,
 *      "status":"present"|"missing"|"downloaded"|"failed"|"not_analysable",
 *      "source":"distribution"|"pack_cache"|null,"version":"2.5.0"|null,"location":"..."|null,
 *      "size_bytes":53477376|null,"reason":string|null}]}
 *
 * A failed download exits non-zero with the error document codeql_pack_download_failed (CodeQL's
 * message, sanitised by the core) that carries the same `languages` list as its partial report.
 */

/** Languages Sentra analyses on the host (build mode none without running project code). */
export const HOST_ANALYSABLE_LANGUAGES: readonly string[] = ["actions", "cpp", "javascript", "python", "ruby"];
/** A pack listing is reused for this long (an explicit refresh or a download reads it again). */
export const PACKS_CACHE_TTL_MS = 30_000;
/** Time limit of a pack listing (no download; the core only reads the file system). */
export const PACKS_LIST_TIMEOUT_MS = 60_000;
const PACKS_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

type PacksApp = Pick<AppContext, "cli" | "codeql" | "config" | "executables" | "hostPlatform" | "toolPaths">;

const STATUS_ALIASES: Record<string, CodeqlPackStatus> = {
  present: "present",
  available: "present",
  missing: "missing",
  downloaded: "downloaded",
  failed: "failed",
  download_failed: "failed",
  not_analysable: "not_analysable",
  not_analyzable: "not_analysable",
  skipped: "not_analysable",
  unsupported: "not_analysable",
};

const LANGUAGE_ID = /^[a-z][a-z0-9_+#-]{0,39}$/;
const PACK_NAME = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,59}$/;

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function hostPath(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) return null;
  // oxlint-disable-next-line no-control-regex -- intentional: refuses control characters in a reported path
  return /[\u0000-\u001f\u007f]/.test(value) ? null : value;
}

/** One entry of `languages`; null when it names no valid language. */
export function parsePackEntry(raw: unknown): CodeqlPackView | null {
  const entry = record(raw);
  const language = typeof entry?.language === "string" ? entry.language.toLowerCase() : null;
  if (!entry || !language || !LANGUAGE_ID.test(language)) return null;
  const flag = entry.analysable ?? entry.analyzable;
  let analysable = typeof flag === "boolean" ? flag : HOST_ANALYSABLE_LANGUAGES.includes(language);
  let status: CodeqlPackStatus | undefined = typeof entry.status === "string" ? STATUS_ALIASES[entry.status] : undefined;
  if (!status) {
    const present = entry.available ?? entry.present;
    status = !analysable ? "not_analysable" : present === true ? "present" : "missing";
  }
  if (status === "not_analysable") analysable = false;
  const source: CodeqlPackSource | null = entry.source === "distribution" ? "distribution" : entry.source === "pack_cache" || entry.source === "cache" ? "pack_cache" : null;
  const size = entry.size_bytes;
  return {
    language,
    pack: typeof entry.pack === "string" && PACK_NAME.test(entry.pack) ? entry.pack : analysable ? `codeql/${language}-queries` : null,
    analysable,
    status,
    source,
    version: typeof entry.version === "string" && VERSION.test(entry.version) ? entry.version : null,
    location: hostPath(entry.location ?? entry.path),
    sizeBytes: typeof size === "number" && Number.isSafeInteger(size) && size >= 0 ? size : null,
    reason: sanitizeCoreMessage(entry.reason) ?? sanitizeCoreMessage(entry.message) ?? sanitizeCoreMessage(entry.error),
  };
}

/** Pack entries of a document's (or error document's) `languages`; malformed entries and repeats are dropped. */
export function parsePackEntries(raw: unknown): CodeqlPackView[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const entries: CodeqlPackView[] = [];
  for (const item of raw.slice(0, 50)) {
    const entry = parsePackEntry(item);
    if (!entry || seen.has(entry.language)) continue;
    seen.add(entry.language);
    entries.push(entry);
  }
  return entries;
}

/** The `sentra codeql packs --json` document; throws 502 core_output_invalid when it is not one. */
export function parsePacksDocument(raw: unknown): { suite: CodeqlSuite | null; languages: CodeqlPackView[] } {
  const doc = record(raw);
  const invalid = (detail: string) => new HttpError(502, "core_output_invalid", `sentra codeql packs returned an unexpected document: ${detail}`);
  if (!doc) throw invalid("not a JSON object");
  if (doc.schema_version !== 1) throw invalid(`unsupported schema_version ${String(doc.schema_version)}`);
  if (doc.command !== undefined && doc.command !== "codeql packs") throw invalid(`command is ${String(doc.command)}`);
  if (!Array.isArray(doc.languages)) throw invalid("languages missing");
  return {
    suite: CODEQL_SUITES.includes(doc.suite as CodeqlSuite) ? (doc.suite as CodeqlSuite) : null,
    languages: parsePackEntries(doc.languages),
  };
}

/** Analysable languages whose pack is missing (or whose download failed). */
export function missingLanguages(languages: readonly CodeqlPackView[]): string[] {
  return languages.filter((entry) => entry.analysable && (entry.status === "missing" || entry.status === "failed")).map((entry) => entry.language);
}

/** Validates the `languages` of a download request: analysable ids, at most 10, no repeats; undefined when omitted. */
export function parsePackLanguages(body: Record<string, unknown>): string[] | undefined {
  for (const key of Object.keys(body)) {
    if (key !== "languages") throw new HttpError(400, "invalid_request", `Unknown field '${key.slice(0, 40)}'`);
  }
  if (body.languages === undefined || body.languages === null) return undefined;
  if (!Array.isArray(body.languages) || body.languages.length === 0 || body.languages.length > 10) {
    throw new HttpError(400, "invalid_request", "'languages' must be a non-empty array of at most 10 language ids");
  }
  const languages: string[] = [];
  for (const value of body.languages) {
    if (typeof value !== "string" || !HOST_ANALYSABLE_LANGUAGES.includes(value)) {
      throw new HttpError(400, "invalid_request", `'languages' may only contain ${HOST_ANALYSABLE_LANGUAGES.join(", ")} (the languages Sentra analyses on the host)`);
    }
    if (!languages.includes(value)) languages.push(value);
  }
  return languages;
}

interface PacksContext {
  launcherPath: string | null;
  problem: string | null;
}

async function packsContext(app: PacksApp): Promise<PacksContext> {
  if (!app.cli.available()) return { launcherPath: null, problem: "The sentra core binary was not found, so `sentra codeql packs` cannot run." };
  const launcher = codeqlLauncherChoice(hostToolsDeps(app), await app.executables.current());
  if (!launcher.path) return { launcherPath: null, problem: `No codeql launcher can be run: ${launcher.problem ?? "none was found"}` };
  return { launcherPath: launcher.path, problem: null };
}

/**
 * A download runs the CodeQL CLI on the bridge host, which Sentra does only while an admin has
 * enabled host analysis with recorded acceptance of the CodeQL terms (ADR-0011). The query packs
 * themselves are MIT-licensed; the gate is about running CodeQL, not about the packs.
 */
export const PACKS_DISABLED_MESSAGE =
  "Query packs can be downloaded only while CodeQL host analysis is enabled with the CodeQL licence terms accepted (Settings > CodeQL), because the download runs the CodeQL CLI on this host.";

function baseView(app: PacksApp, context: PacksContext): Omit<CodeqlPacksView, "available" | "problem" | "languages" | "missing"> {
  const running = app.codeql.lock.current;
  return {
    suite: app.codeql.settings().suite,
    packCache: app.codeql.packCache,
    launcherPath: context.launcherPath,
    checkedAt: nowIso(),
    running: runningView(running),
    downloadBlockedReason:
      context.problem ??
      (!app.codeql.analysisEnabled() ? PACKS_DISABLED_MESSAGE : running ? `${describeRunning(running)}; CodeQL runs one operation at a time on the bridge.` : null),
  };
}

/** Shown when parsing the core's packs report threw something other than an Error. */
const PACKS_REPORT_UNREADABLE = "The core's query pack report could not be read.";

function unavailable(app: PacksApp, context: PacksContext, problem: string): CodeqlPacksView {
  return { ...baseView(app, context), available: false, problem, languages: [], missing: [] };
}

function failureText(command: string, result: CliResult): string {
  const core = coreErrorDocument(result);
  return core ? `sentra ${command} failed: ${core.code}${core.message ? `: ${core.message}` : ""}` : `sentra ${command} exited with code ${result.code}`;
}

/**
 * The query packs of the configured suite (GET /api/settings/codeql/packs). Never downloads.
 * Shared by concurrent callers and reused for PACKS_CACHE_TTL_MS unless `fresh` or a download ran.
 */
export async function readPacks(app: PacksApp, options: { fresh?: boolean; signal?: AbortSignal } = {}): Promise<CodeqlPacksView> {
  const context = await packsContext(app);
  if (context.problem || !context.launcherPath) return unavailable(app, context, context.problem ?? "No codeql launcher can be run.");
  fs.mkdirSync(app.codeql.packCache, { recursive: true, mode: 0o700 });
  const args = [
    "codeql",
    "packs",
    "--codeql",
    cliValue(context.launcherPath, "codeql"),
    "--pack-cache",
    cliValue(app.codeql.packCache, "packCache"),
    "--suite",
    app.codeql.settings().suite,
    "--json",
  ];
  const fresh = app.codeql.takePacksChanged() || options.fresh === true;
  const result = await app.cli.runShared(args, { ttlMs: PACKS_CACHE_TTL_MS, timeoutMs: PACKS_LIST_TIMEOUT_MS, signal: options.signal, fresh });
  if (result.timedOut) return unavailable(app, context, `sentra codeql packs did not answer within ${PACKS_LIST_TIMEOUT_MS / 1000} s.`);
  if (result.code !== 0 || result.json === undefined) return unavailable(app, context, failureText("codeql packs", result));
  let parsed: ReturnType<typeof parsePacksDocument>;
  try {
    parsed = parsePacksDocument(result.json);
  } catch (error) {
    // parsePacksDocument throws Errors with a validation message; any other thrown value is not
    // echoed to the client (it could carry anything, a stack trace included).
    return unavailable(app, context, error instanceof Error ? error.message : PACKS_REPORT_UNREADABLE);
  }
  return { ...baseView(app, context), suite: parsed.suite ?? app.codeql.settings().suite, available: true, problem: null, languages: parsed.languages, missing: missingLanguages(parsed.languages) };
}

export interface PackDownloadInput {
  /** Languages to download; undefined: every missing analysable language. */
  languages: string[] | undefined;
  signal?: AbortSignal;
  onProgress?: (progress: CodeqlProgressView) => void;
  /** Bridge narration and stderr lines of the core that are not progress events. */
  onLog?: (stream: "bridge" | "stderr", text: string) => void;
  /**
   * Called once the core has exited, before the pack listing of the result is read: the caller
   * releases the CodeQL lock here, so that the listing does not report this download as running.
   */
  onCoreExited?: () => void;
}

/**
 * Runs `sentra codeql packs --download` (one `codeql pack download` per pack in the core, so a
 * completed pack stays in the cache when a later one fails). The caller holds the bridge-wide
 * CodeQL lock. Cancelling closes the core's stdin; the core kills CodeQL's process tree.
 */
export async function downloadPacks(app: PacksApp, input: PackDownloadInput): Promise<CodeqlPacksDownloadView> {
  const context = await packsContext(app);
  if (!app.cli.available()) throw new HttpError(503, "core_unavailable", context.problem ?? "The sentra core binary was not found.");
  if (!context.launcherPath) throw new HttpError(409, "codeql_launcher_unavailable", context.problem ?? "No codeql launcher can be run.");
  const settings = app.codeql.settings();
  const timeoutSecs = settings.downloadTimeoutMinutes * 60;
  fs.mkdirSync(app.codeql.packCache, { recursive: true, mode: 0o700 });
  const args = [
    "codeql",
    "packs",
    "--codeql",
    cliValue(context.launcherPath, "codeql"),
    "--pack-cache",
    cliValue(app.codeql.packCache, "packCache"),
    "--suite",
    settings.suite,
  ];
  for (const language of input.languages ?? []) args.push("--language", cliValue(language, "language"));
  args.push("--download", "--timeout-secs", String(timeoutSecs), "--cancel-on-stdin-eof", "--progress", "--json");
  input.onLog?.("bridge", `Running: sentra ${args.join(" ")}`);
  input.onLog?.(
    "bridge",
    `Query packs are downloaded from the registry CodeQL is configured for (by default GitHub's container registry, ghcr.io) into ${app.codeql.packCache}. Budget: ${settings.downloadTimeoutMinutes} min. A pack is tens of MB; on a slow connection one can take several minutes.`,
  );
  const started = performance.now();
  let result: CliResult;
  try {
    result = await app.cli.run(args, {
      timeoutMs: timeoutSecs * 1000 + BRIDGE_TIMEOUT_MARGIN_MS,
      signal: input.signal,
      cancelViaStdinEof: true,
      maxOutputBytes: PACKS_MAX_OUTPUT_BYTES,
      onStderrLine: (line) => {
        const progress = progressFromLine(line);
        if (progress) input.onProgress?.(progress);
        else if (line.trim()) input.onLog?.("stderr", line);
      },
    });
  } finally {
    // Whatever happened, completed packs may now be in the cache.
    app.codeql.markPacksChanged();
    // CodeQL has stopped: the lock can go before the listing is read (it reports `running`).
    input.onCoreExited?.();
  }
  const durationMs = Math.round(performance.now() - started);
  input.onLog?.("bridge", `sentra codeql packs exited with code ${result.code} after ${formatElapsed(durationMs)}.`);
  const packs = await readPacks(app, { fresh: true }).catch((error: unknown) =>
    unavailable(app, context, `The pack listing could not be read after the download: ${error instanceof Error ? error.message : String(error)}`),
  );
  return interpretDownload(result, { requested: input.languages, durationMs, packs, settingsMinutes: settings.downloadTimeoutMinutes });
}

/** After any download that did not complete: what stays (the core moves only complete packs into the cache). */
const KEPT = "Packs that finished downloading stay in the pack cache.";
/**
 * After a download that was stopped (cancelled or out of time) while a pack was still downloading:
 * the core deletes its staging directory, so no partial pack is kept. Whether a scan downloads it
 * again depends on allowPackDownload, so the text does not promise it.
 */
const INTERRUPTED = `${KEPT} A pack that was still downloading was discarded (Sentra keeps no partial pack); download it again here, or let the next scan download it if pack download is allowed.`;

/** Turns the CLI result of `sentra codeql packs --download` into the download view. */
export function interpretDownload(
  result: CliResult,
  context: { requested: string[] | undefined; durationMs: number; packs: CodeqlPacksView; settingsMinutes: number },
): CodeqlPacksDownloadView {
  const core = result.code === 0 ? null : coreErrorDocument(result);
  let entries: CodeqlPackView[] = [];
  let documentProblem: string | null = null;
  if (result.code === 0 && !result.timedOut) {
    try {
      entries = parsePacksDocument(result.json).languages;
    } catch (error) {
      documentProblem = error instanceof Error ? error.message : PACKS_REPORT_UNREADABLE;
    }
  } else {
    entries = parsePackEntries(core?.details.languages);
  }
  const downloaded = entries.filter((entry) => entry.status === "downloaded").map((entry) => entry.language);
  const failed = entries
    .filter((entry) => entry.status === "failed")
    .map((entry) => ({ language: entry.language, message: entry.reason ?? "the download failed" }));
  const requested = context.requested ?? entries.filter((entry) => entry.status === "downloaded" || entry.status === "failed").map((entry) => entry.language);
  const base = { requested, downloaded, failed, durationMs: context.durationMs, packs: context.packs };
  const took = formatElapsed(context.durationMs);
  const done = downloaded.length > 0 ? `Downloaded ${downloaded.join(", ")} in ${took}. ` : "";
  const failedText = failed.map((entry) => `${entry.language}: ${entry.message}`).join("; ");

  if (result.timedOut) {
    return { ...base, outcome: downloaded.length > 0 ? "partial" : "failed", message: `${done}The bridge stopped the download after ${took} (the download budget is ${context.settingsMinutes} minutes). ${INTERRUPTED}` };
  }
  if (result.code === 0) {
    if (documentProblem) return { ...base, outcome: "failed", message: documentProblem };
    if (failed.length > 0) return { ...base, outcome: downloaded.length > 0 ? "partial" : "failed", message: `${done}Failed: ${failedText}.` };
    if (downloaded.length === 0) return { ...base, outcome: "nothing_to_do", message: "Every requested query pack was already present; nothing was downloaded." };
    return { ...base, outcome: "completed", message: `${done}They stay in the pack cache, so scans no longer download them.` };
  }
  const detail = core ? `${core.code}${core.message ? `: ${core.message}` : ""}` : `sentra codeql packs exited with code ${result.code}`;
  if (core?.code === "codeql_cancelled") return { ...base, outcome: "cancelled", message: `${done}The download was stopped. ${INTERRUPTED}` };
  if (core?.code === "codeql_timeout") {
    return { ...base, outcome: downloaded.length > 0 ? "partial" : "failed", message: `${done}The download ran out of its ${context.settingsMinutes}-minute budget (${detail}). ${INTERRUPTED}` };
  }
  // The core's codeql_pack_download_failed message already names each failed pack's reason and says
  // that completed packs stay; repeat neither (nor claim an interruption that did not happen).
  const coreMessage = core?.message ?? "";
  const reasons = failed.length > 0 && !failed.every((entry) => coreMessage.includes(entry.message)) ? ` (${failedText})` : "";
  const kept = /stay in the pack cache/i.test(coreMessage) ? "" : ` ${KEPT}`;
  return { ...base, outcome: downloaded.length > 0 ? "partial" : "failed", message: `${done}${detail}${reasons}.${kept}` };
}
