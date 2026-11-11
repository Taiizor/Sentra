import fs from "node:fs";
import type { PluginDiagnosticSeverity, PluginDiagnosticView, PluginDirectorySource } from "../src/types/api.ts";
import { envValue, pathApi } from "./executables.ts";
import { HttpError } from "./http-error.ts";
import { cliFailure, type CliResult, type CliRunOptions } from "./sentra-cli.ts";

/**
 * The plugin directory the bridge lists, probes and runs adapters from.
 *
 * 1. SENTRA_PLUGIN_DIR in the bridge environment (validated once at startup: config.pluginDir).
 * 2. Otherwise the core's own platform default plugin directory. The bridge does not compute it:
 *    it asks the core once (`sentra plugin list --json` without --dir), passing the variables the
 *    core derives the default from on this platform explicitly and SENTRA_PLUGIN_DIR removed, and
 *    uses the directory the core reports. That run only reads manifests; it starts no adapter.
 * 3. Otherwise none: listing reports why, probe and run answer 412.
 *
 * A platform default is refused (source none plus a diagnostic) when it is not an absolute path
 * (on Windows: on a drive letter), when on Windows its real path (links, junctions and mapped
 * drives resolved, as far as the host's realpath reports them) is a UNC or device path, or when it
 * overlaps the bridge data directory, the bridge or OS temporary directory, the repository checkout
 * or a registered workspace: adapters found in the directory are executed on the bridge host
 * without a sandbox, so it must not be a place that repository content or other local users can
 * write to. Network mounts on macOS and Linux (NFS, SMB) are not detected.
 *
 * On Windows the core scans <APPDATA>\sentra\plugins while answering, so APPDATA is never handed
 * to it when it is a UNC or device path, or when the real path of that directory (or of its
 * nearest existing ancestor) is one; when that check does not answer in time (an offline network
 * drive), the core is not asked and the check is repeated on the next listing.
 *
 * Every file-system check (realpath, stat) is asynchronous and bounded by PLUGIN_DIR_PROBE_TIMEOUT_MS,
 * and a call still pending for the same path is joined instead of started again, so a slow or
 * unreachable drive neither blocks the bridge nor piles up calls.
 *
 * The directory is never created, and it cannot be chosen from the web console. Its existence and
 * the refusal rules (registered workspaces change at runtime) are evaluated on every listing, so a
 * directory created later is picked up without a restart; a changed SENTRA_PLUGIN_DIR or a changed
 * platform variable needs a restart.
 */

export const PLUGIN_DIR_ENV = "SENTRA_PLUGIN_DIR";

/**
 * Variables `default_plugin_dir_from` in sentra-core derives the platform default from once
 * SENTRA_PLUGIN_DIR is unset: APPDATA on Windows, HOME on macOS, XDG_CONFIG_HOME then HOME on other
 * Unix systems. Only the variables of the bridge's platform are passed to the query.
 */
export function platformDefaultVariables(platform: NodeJS.Platform): readonly string[] {
  if (platform === "win32") return ["APPDATA"];
  if (platform === "darwin") return ["HOME"];
  return ["XDG_CONFIG_HOME", "HOME"];
}

/** Deadline for each file-system check of a plugin directory on the bridge host (realpath, stat). */
export const PLUGIN_DIR_PROBE_TIMEOUT_MS = 2_000;

/**
 * Real path of a location (see hostCanonicalPath): null when nothing resolves; rejects when a
 * component exists but cannot be resolved. Synchronous answers are accepted for tests.
 */
export type CanonicalProbe = (value: string) => Promise<string | null> | string | null;
/** Whether a path is an existing directory. Synchronous answers are accepted for tests. */
export type DirectoryProbe = (value: string) => Promise<boolean> | boolean;

const MAX_DIAGNOSTICS = 200;
const MAX_MESSAGE_CHARS = 2000;
const MAX_CODE_CHARS = 128;
const MAX_PATH_CHARS = 4096;

/** A location the platform default must neither be inside of nor contain. */
export interface ProtectedLocation {
  /** Human-readable name, for example "the bridge data directory". */
  label: string;
  path: string;
}

/** The core's answer to "which platform default directory would you use?". */
export interface PlatformDefaultAnswer {
  /** Directory exactly as the core reported it; null when the core has no platform default. */
  reported: string | null;
  /** Diagnostics about the query itself (withheld variables, no default available). */
  diagnostics: PluginDiagnosticView[];
  /** True when the answer must not be kept: a check did not answer and the core was not asked. */
  transient?: boolean;
}

export interface PluginDirectoryState {
  /** Directory in use (native separators); null when none. */
  directory: string | null;
  source: PluginDirectorySource;
  exists: boolean;
  /** Bridge diagnostics about the directory itself. */
  diagnostics: PluginDiagnosticView[];
  /** Set when a platform default was found but refused. */
  refusedDirectory: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** UNC (\\server\share, in any separator form) and device (\\?\, \\.\, \??\) paths on Windows. */
export function isWindowsNetworkOrDevicePath(value: string): boolean {
  return /^[\\/]{2}/.test(value) || /^[\\/]\?\?[\\/]/.test(value);
}

function timeoutError(what: string, ms: number): Error {
  const limit = ms % 1000 === 0 ? `${ms / 1000} s` : `${ms} ms`;
  return Object.assign(new Error(`${what} did not answer within ${limit}`), { code: "ETIMEDOUT" });
}

/**
 * `start()`, rejected with ETIMEDOUT when it does not settle within `ms`. A file-system call cannot
 * be cancelled, so a call still pending under the same key (a hung network drive, for example) is
 * joined instead of started again: repeated listings never pile up blocked calls.
 */
export function boundedProbe<T>(pending: Map<string, Promise<unknown>>, key: string, what: string, ms: number, start: () => Promise<T> | T): Promise<T> {
  let call = pending.get(key) as Promise<T> | undefined;
  if (!call) {
    const started: Promise<T> = Promise.resolve()
      .then(start)
      .finally(() => {
        if (pending.get(key) === started) pending.delete(key);
      });
    pending.set(key, started);
    call = started;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(timeoutError(what, ms)), ms);
  });
  return Promise.race([call, deadline]).finally(() => clearTimeout(timer));
}

/** Why a file-system check failed, for a diagnostic. */
export function probeProblem(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  const message = error instanceof Error ? error.message : String(error);
  if (code === "ETIMEDOUT") return `${message}; the drive or network share it is on may be slow or unreachable`;
  return code ? `${code}: ${message}` : message;
}

/**
 * Environment overrides for the platform-default query: SENTRA_PLUGIN_DIR removed (it is handled
 * by the bridge itself) and the variables the core reads on this platform (platformDefaultVariables)
 * set to the bridge's values, or removed when unset. On Windows a UNC or device APPDATA is withheld
 * and reported instead. Variables the core does not read on this platform are left alone and not
 * reported (for example a HOME on a share, as Git for Windows or a home-drive policy may set).
 */
export function platformDefaultQueryEnv(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): { overrides: Record<string, string | undefined>; diagnostics: PluginDiagnosticView[] } {
  const overrides: Record<string, string | undefined> = { [PLUGIN_DIR_ENV]: undefined };
  const diagnostics: PluginDiagnosticView[] = [];
  for (const name of platformDefaultVariables(platform)) {
    const value = envValue(env, name, platform);
    if (value !== undefined && platform === "win32" && isWindowsNetworkOrDevicePath(value.trim())) {
      overrides[name] = undefined;
      diagnostics.push({
        severity: "warning",
        code: "plugin_dir_network_path",
        message: `${name} is a UNC network path or a device path; the bridge does not use a plugin directory there and did not pass it to the core.`,
        path: clip(value, MAX_PATH_CHARS),
      });
      continue;
    }
    overrides[name] = value;
  }
  return { overrides, diagnostics };
}

/** Error code a failed `sentra ...  --json` run printed on stderr or stdout, if any. */
function coreErrorCode(result: Pick<CliResult, "stdout" | "stderr">): string | null {
  for (const candidate of [result.stderr, result.stdout]) {
    const trimmed = candidate.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const value = (JSON.parse(trimmed) as Record<string, unknown>).error;
      if (typeof value === "string") return value;
    } catch {
      // not JSON
    }
  }
  return null;
}

export const NO_PLATFORM_DEFAULT_MESSAGE =
  "SENTRA_PLUGIN_DIR is not set and the core reports no platform default plugin directory (it derives one from APPDATA on Windows, HOME on macOS, and XDG_CONFIG_HOME or HOME elsewhere, each only when it is an absolute path).";

/**
 * Interprets `sentra plugin list --json` run without --dir: the first reported directory, or no
 * default when the core answers plugin_dir_unavailable. Anything else is an error.
 */
export function parsePlatformDefaultResult(result: CliResult): PlatformDefaultAnswer {
  if (result.timedOut) throw new HttpError(504, "core_timeout", "sentra plugin list timed out while resolving the default plugin directory");
  if (result.code !== 0) {
    if (coreErrorCode(result) === "plugin_dir_unavailable") {
      return { reported: null, diagnostics: [{ severity: "info", code: "plugin_dir_unavailable", message: NO_PLATFORM_DEFAULT_MESSAGE, path: null }] };
    }
    throw cliFailure("plugin list", result);
  }
  const doc = asRecord(result.json);
  const directories = doc?.directories;
  if (!Array.isArray(directories) || typeof directories[0] !== "string" || directories[0].length === 0) {
    throw new HttpError(502, "core_output_invalid", "sentra plugin list returned an unexpected document: no directories array");
  }
  return { reported: directories[0], diagnostics: [] };
}

/**
 * Asks the core for its platform default plugin directory (see the module comment). `canonical`
 * should be bounded (the resolver passes its bounded probe); it defaults to hostCanonicalPath.
 */
export async function queryPlatformDefault(deps: {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  runCli(args: string[], options: CliRunOptions): Promise<CliResult>;
  timeoutMs: number;
  canonical?: CanonicalProbe;
}): Promise<PlatformDefaultAnswer> {
  const { overrides, diagnostics } = platformDefaultQueryEnv(deps.env, deps.platform);
  const appData = overrides.APPDATA;
  if (deps.platform === "win32" && appData !== undefined && /^[A-Za-z]:[\\/]/.test(appData)) {
    // The core scans <APPDATA>\sentra\plugins while answering. A drive-letter APPDATA may still be
    // a mapped network drive, and a component of that path a link to a share: resolve it first.
    const candidate = pathApi("win32").join(appData, "sentra", "plugins");
    let real: string | null;
    try {
      real = await (deps.canonical ?? hostCanonicalPath)(candidate);
    } catch (error) {
      return {
        reported: null,
        transient: true,
        diagnostics: [
          ...diagnostics,
          {
            severity: "warning",
            code: "plugin_dir_not_answering",
            message: `The bridge could not check ${candidate} (${probeProblem(error)}). It did not ask the core for its default plugin directory and checks again on the next listing.`,
            path: clip(candidate, MAX_PATH_CHARS),
          },
        ],
      };
    }
    if (real !== null && isWindowsNetworkOrDevicePath(real)) {
      overrides.APPDATA = undefined;
      diagnostics.push({
        severity: "warning",
        code: "plugin_dir_network_path",
        message: `APPDATA resolves to a UNC network path or a device path (${clip(real, MAX_PATH_CHARS)}), for example through a mapped network drive or a link; the bridge does not use a plugin directory there and did not pass it to the core.`,
        path: clip(appData, MAX_PATH_CHARS),
      });
    }
  }
  const answer = parsePlatformDefaultResult(await deps.runCli(["plugin", "list", "--json"], { timeoutMs: deps.timeoutMs, env: overrides }));
  return { reported: answer.reported, diagnostics: [...diagnostics, ...answer.diagnostics] };
}

function comparable(value: string, platform: NodeJS.Platform): string {
  return platform === "win32" || platform === "darwin" ? value.toLowerCase() : value;
}

/** True when `child` equals `parent` or lies underneath it (both absolute). */
export function isWithinOn(parent: string, child: string, platform: NodeJS.Platform): boolean {
  const api = pathApi(platform);
  const p = comparable(api.resolve(parent), platform);
  const c = comparable(api.resolve(child), platform);
  if (p === c) return true;
  return c.startsWith(p.endsWith(api.sep) ? p : p + api.sep);
}

/** The path, or one of its parent components, does not exist (yet). */
function isMissing(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/**
 * Real path of `value` on this host: the nearest existing ancestor with links, junctions and (as
 * far as the host's realpath reports them) mapped network drives resolved, joined with the
 * remaining (not yet existing) components. Null when nothing resolves. Rejects when a component
 * exists but cannot be resolved (access denied, a link whose target does not answer), so such a
 * path is never taken for a local one. Unbounded: callers add a deadline (boundedProbe).
 */
export async function hostCanonicalPath(value: string, realpath: (value: string) => Promise<string> = (target) => fs.promises.realpath(target)): Promise<string | null> {
  const api = pathApi(process.platform);
  let current = value;
  const rest: string[] = [];
  for (let depth = 0; depth < 128; depth += 1) {
    try {
      const real = await realpath(current);
      return rest.length ? api.join(real, ...rest.reverse()) : real;
    } catch (error) {
      if (!isMissing(error)) throw error;
      const parent = api.dirname(current);
      if (parent === current) return null;
      rest.push(api.basename(current));
      current = parent;
    }
  }
  return null;
}

/**
 * Why a platform default directory must not be used, or null when it may be. `canonical` returns
 * the real path of a location (see hostCanonicalPath); both the reported and the real form of the
 * directory are compared with both forms of every protected location. On Windows the real form of
 * the directory must not be a UNC or device path either (a mapped network drive or a link to a
 * share), and a directory whose real path cannot be determined is refused. A protected location
 * whose real path cannot be determined is compared in its reported form only.
 */
export async function platformDefaultRefusal(
  directory: string,
  locations: readonly ProtectedLocation[],
  platform: NodeJS.Platform,
  canonical: CanonicalProbe = hostCanonicalPath,
): Promise<string | null> {
  // oxlint-disable-next-line no-control-regex -- intentional: a directory name with control characters is refused
  if (/[\u0000-\u001f\u007f]/.test(directory)) return "contains control characters";
  if (platform === "win32") {
    if (isWindowsNetworkOrDevicePath(directory)) return "is a UNC network path or a device path";
    if (!/^[A-Za-z]:[\\/]/.test(directory)) return "is not an absolute path on a local drive";
  } else if (!directory.startsWith("/")) {
    return "is not an absolute path";
  }
  const api = pathApi(platform);
  const lexical = api.resolve(directory);
  let real: string | null;
  try {
    real = await canonical(lexical);
  } catch (error) {
    return `could not be resolved to its real path (${probeProblem(error)})`;
  }
  if (platform === "win32" && real !== null && isWindowsNetworkOrDevicePath(real)) {
    return `resolves to a UNC network path or a device path (${clip(real, MAX_PATH_CHARS)}), for example through a mapped network drive or a link`;
  }
  const forms = [lexical, real].filter((form): form is string => typeof form === "string");
  const locationForms = await Promise.all(
    locations.map(async (location) => {
      const locationLexical = api.resolve(location.path);
      const locationReal = await Promise.resolve()
        .then(() => canonical(locationLexical))
        .catch(() => null);
      return [locationLexical, locationReal].filter((form): form is string => typeof form === "string");
    }),
  );
  for (const [index, location] of locations.entries()) {
    for (const form of forms) {
      for (const locationForm of locationForms[index]) {
        if (isWithinOn(locationForm, form, platform)) return `is inside ${location.label} (${location.path})`;
        if (isWithinOn(form, locationForm, platform)) return `contains ${location.label} (${location.path})`;
      }
    }
  }
  return null;
}

/** Unbounded: the resolver adds a deadline (boundedProbe). */
async function hostIsDirectory(value: string): Promise<boolean> {
  try {
    return (await fs.promises.stat(value)).isDirectory();
  } catch {
    return false;
  }
}

export interface PluginDirectoryDeps {
  platform: NodeJS.Platform;
  /** SENTRA_PLUGIN_DIR as validated at startup (config.pluginDir); null when unset. */
  environmentDir: string | null;
  /** Bridge environment the platform-default query reads platformDefaultVariables from. */
  env: Readonly<Record<string, string | undefined>>;
  runCli(args: string[], options: CliRunOptions): Promise<CliResult>;
  timeoutMs: number;
  /** Evaluated on every call: registered workspaces change while the bridge runs. */
  protectedLocations(): ProtectedLocation[];
  /** Defaults to hostCanonicalPath; every call is bounded by probeTimeoutMs. */
  canonical?: CanonicalProbe;
  /** Defaults to an asynchronous stat; every call is bounded by probeTimeoutMs. */
  isDirectory?: DirectoryProbe;
  /** Deadline of each file-system check (default PLUGIN_DIR_PROBE_TIMEOUT_MS). */
  probeTimeoutMs?: number;
}

export class PluginDirectoryResolver {
  private readonly deps: PluginDirectoryDeps;
  private platformDefault: Promise<PlatformDefaultAnswer> | null = null;
  /** File-system checks still pending, joined by later calls for the same path (boundedProbe). */
  private readonly pendingProbes = new Map<string, Promise<unknown>>();
  private readonly canonical: (value: string) => Promise<string | null>;
  private readonly isDirectory: (value: string) => Promise<boolean>;

  constructor(deps: PluginDirectoryDeps) {
    this.deps = deps;
    const timeoutMs = deps.probeTimeoutMs ?? PLUGIN_DIR_PROBE_TIMEOUT_MS;
    const canonical = deps.canonical ?? hostCanonicalPath;
    const isDirectory = deps.isDirectory ?? hostIsDirectory;
    this.canonical = (value) => boundedProbe(this.pendingProbes, `canonical\0${value}`, value, timeoutMs, () => canonical(value));
    this.isDirectory = (value) => boundedProbe(this.pendingProbes, `directory\0${value}`, value, timeoutMs, () => isDirectory(value));
  }

  /**
   * The core's answer is kept for the bridge's lifetime (it depends only on the bridge
   * environment); a query that failed (core missing, busy, timed out) or a transient answer (a
   * file-system check did not answer, so the core was not asked) is retried on the next call.
   */
  private platformDefaultAnswer(): Promise<PlatformDefaultAnswer> {
    if (!this.platformDefault) {
      const pending: Promise<PlatformDefaultAnswer> = queryPlatformDefault({ ...this.deps, canonical: this.canonical }).then(
        (answer) => {
          if (answer.transient && this.platformDefault === pending) this.platformDefault = null;
          return answer;
        },
        (error: unknown) => {
          if (this.platformDefault === pending) this.platformDefault = null;
          throw error;
        },
      );
      this.platformDefault = pending;
    }
    return this.platformDefault;
  }

  /** Whether `value` is a directory, or why that could not be determined in time. */
  private async directoryCheck(value: string): Promise<{ exists: boolean; problem: string | null }> {
    try {
      return { exists: await this.isDirectory(value), problem: null };
    } catch (error) {
      return { exists: false, problem: probeProblem(error) };
    }
  }

  async current(): Promise<PluginDirectoryState> {
    const environmentDir = this.deps.environmentDir;
    if (environmentDir !== null) {
      const { exists, problem } = await this.directoryCheck(environmentDir);
      return {
        directory: environmentDir,
        source: "environment",
        exists,
        refusedDirectory: null,
        diagnostics: exists
          ? []
          : [
              problem === null
                ? {
                    severity: "error",
                    code: "plugin_dir_not_found",
                    message: "SENTRA_PLUGIN_DIR no longer exists or is not a directory; nothing is loaded from it.",
                    path: environmentDir,
                  }
                : {
                    severity: "error",
                    code: "plugin_dir_not_answering",
                    message: `SENTRA_PLUGIN_DIR could not be checked (${problem}); nothing is loaded from it until it answers.`,
                    path: environmentDir,
                  },
            ],
      };
    }
    const answer = await this.platformDefaultAnswer();
    if (answer.reported === null) {
      return { directory: null, source: "none", exists: false, refusedDirectory: null, diagnostics: answer.diagnostics };
    }
    const refusal = await platformDefaultRefusal(answer.reported, this.deps.protectedLocations(), this.deps.platform, this.canonical);
    if (refusal) {
      return {
        directory: null,
        source: "none",
        exists: false,
        refusedDirectory: answer.reported,
        diagnostics: [
          ...answer.diagnostics,
          {
            severity: "warning",
            code: "plugin_dir_refused",
            message: `The core's platform default plugin directory is not used: it ${refusal}. Adapters in the plugin directory run as programs on the bridge host.`,
            path: clip(answer.reported, MAX_PATH_CHARS),
          },
        ],
      };
    }
    const directory = pathApi(this.deps.platform).normalize(answer.reported);
    const { exists, problem } = await this.directoryCheck(directory);
    const missing: PluginDiagnosticView =
      problem === null
        ? {
            severity: "info",
            code: "plugin_dir_not_found",
            message: "The platform default plugin directory does not exist. The bridge does not create it; once it exists, its adapters are listed without a restart.",
            path: directory,
          }
        : {
            severity: "warning",
            code: "plugin_dir_not_answering",
            message: `The platform default plugin directory could not be checked (${problem}); nothing is loaded from it until it answers.`,
            path: directory,
          };
    return {
      directory,
      source: "platform_default",
      exists,
      refusedDirectory: null,
      diagnostics: [...answer.diagnostics, ...(exists ? [] : [missing])],
    };
  }
}

function severityOf(value: unknown): PluginDiagnosticSeverity {
  return value === "error" || value === "info" ? value : "warning";
}

/**
 * The `diagnostics` and `has_errors` of a `plugin list --json` document, field for field: the core
 * reports severity "error" (entry skipped) or "warning" (entry loaded); an unknown severity is
 * shown as a warning. At most 200 entries are kept; the last one then says how many were left out.
 */
export function mapCoreDiagnostics(document: unknown): { diagnostics: PluginDiagnosticView[]; hasErrors: boolean } {
  const doc = asRecord(document);
  const raw = Array.isArray(doc?.diagnostics) ? doc.diagnostics : [];
  const diagnostics: PluginDiagnosticView[] = [];
  for (const item of raw) {
    const entry = asRecord(item);
    if (!entry) continue;
    if (diagnostics.length === MAX_DIAGNOSTICS) {
      diagnostics.push({
        severity: "warning",
        code: "plugin_diagnostics_truncated",
        message: `${raw.length - MAX_DIAGNOSTICS} more diagnostics were reported by the core and are not shown; run \`sentra plugin list --dir <directory>\` on the bridge host to see all of them.`,
        path: null,
      });
      break;
    }
    diagnostics.push({
      severity: severityOf(entry.severity),
      code: typeof entry.code === "string" && entry.code ? clip(entry.code, MAX_CODE_CHARS) : "unknown",
      message: typeof entry.message === "string" ? clip(entry.message, MAX_MESSAGE_CHARS) : "",
      path: typeof entry.path === "string" && entry.path ? clip(entry.path, MAX_PATH_CHARS) : null,
    });
  }
  const hasErrors = doc?.has_errors === true || diagnostics.some((diagnostic) => diagnostic.severity === "error");
  return { diagnostics, hasErrors };
}
