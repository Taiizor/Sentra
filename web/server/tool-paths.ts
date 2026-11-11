import fs from "node:fs";
import os from "node:os";
import type { BinaryFormat, BinaryInfo, CpuArch } from "../src/types/api.ts";
import { inspectBinary, NATIVE_FORMATS, osLabel, type HostArch } from "./binary-info.ts";
import { buildDirectoryIndex, executableFileNames, pathApi, releaseAssetNames, windowsPathExtensions } from "./executables.ts";
import type { ToolName } from "./host-tools.ts";
import type { SettingsStore } from "./services/settings-store.ts";

/**
 * Tool paths set by an admin in the web console (Host & workers > tools), for tools automatic
 * detection cannot find, such as a CodeQL bundle extracted to D:\CodeQL or a semgrep installed
 * into a virtual environment that is not on any PATH.
 *
 * A configured path is used for REPORTING only: the tools table, the CodeQL presence message of
 * scans, and the tools listed in topology reports. It is never passed to anything that starts a
 * program: ExecutableLocator (executables.ts), the gh credential lookup (github.ts) and the sentra
 * binary resolution (config.ts) do not import this module, so a path typed into the web console
 * can never become a program the bridge runs. The legacy bridge's "command execution through
 * client-supplied paths" was a critical issue; this module must not reintroduce it.
 *
 * For the same reason only tools the bridge never runs are configurable. gh is run by the bridge
 * (`gh auth token`), so it is pinned by the HOST operator through SENTRA_GH_BIN instead; bun runs
 * the bridge itself and is always the running executable.
 *
 * Validation only reads: it checks that the path exists, follows links, lists at most one
 * directory (plus two subdirectories for a suggestion), checks execute permission on macOS and
 * Linux, and reads at most 64 KiB of the file's header. Nothing is executed. On the bridge host
 * every file-system call has a deadline (PROBE_TIMEOUT_MS) and a whole check another
 * (TOOL_PATH_CHECK_TIMEOUT_MS), so a path on a slow or unreachable drive or network mount is
 * reported as not answering instead of holding the request.
 */

/** Tools whose path an admin may set in the console: none of them is ever run by the bridge. */
export const CONFIGURABLE_TOOLS = ["git", "cargo", "codeql", "semgrep", "osv-scanner", "docker"] as const satisfies readonly ToolName[];
export type ConfigurableTool = (typeof CONFIGURABLE_TOOLS)[number];

export function isConfigurableTool(name: string): name is ConfigurableTool {
  return (CONFIGURABLE_TOOLS as readonly string[]).includes(name);
}

/** Settings key holding every configured tool path (bridge-wide, not per tenant). */
export const TOOL_PATHS_SETTING = "tool_paths";
export const MAX_TOOL_PATH_LENGTH = 1024;

/** How the gh row says its path can be set while SENTRA_GH_BIN is unset. */
export const GH_PATH_HINT = "Set SENTRA_GH_BIN on the bridge host, or store a GitHub token in Settings.";
/** How the gh row says its path can be changed while SENTRA_GH_BIN is set. */
export const GH_PINNED_HINT = "Pinned by SENTRA_GH_BIN on the bridge host; change it there and restart the bridge.";

/** Why a tool's path cannot be set in the console (the 409 message of PUT /api/system/tools/:name). */
export function notConfigurableReason(name: ToolName): string {
  if (name === "gh") {
    return "The path of gh cannot be set in the web console: the bridge runs gh (`gh auth token`), and a path entered in the web console must never become a program the bridge runs. Set SENTRA_GH_BIN to the absolute path of the gh executable on the bridge host and restart the bridge, or store a GitHub token in Settings.";
  }
  if (name === "bun") {
    return "The path of bun cannot be set: bun runs the bridge itself, so the reported path is always the running executable.";
  }
  return `The path of ${name} cannot be set in the web console.`;
}

// ───────────────────────────── storage ─────────────────────────────

export interface StoredToolPath {
  /** Normalised absolute path as entered: the executable, or the folder that contains it. */
  path: string;
  setAt: string;
  setBy: string;
}

export type StoredToolPaths = Partial<Record<ConfigurableTool, StoredToolPath>>;

/** Read access to the configured paths, as the reporting layer needs it. */
export interface ConfiguredToolPaths {
  list(): StoredToolPaths;
}

export const NO_CONFIGURED_TOOL_PATHS: ConfiguredToolPaths = { list: () => ({}) };

/** True for a path the store keeps; anything else is dropped when the setting is read. */
function isStorablePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_TOOL_PATH_LENGTH;
}

/**
 * Configured paths from the stored settings value. Entries for unknown or non-configurable tools
 * (a gh or bun entry written to the database directly) and malformed entries are dropped, so they
 * can never reach a tool row.
 */
export function parseStoredToolPaths(raw: unknown): StoredToolPaths {
  const out: StoredToolPaths = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!isConfigurableTool(name) || !value || typeof value !== "object" || Array.isArray(value)) continue;
    const entry = value as Record<string, unknown>;
    if (!isStorablePath(entry.path)) continue;
    out[name] = {
      path: entry.path,
      setAt: typeof entry.setAt === "string" ? entry.setAt : "",
      setBy: typeof entry.setBy === "string" ? entry.setBy : "",
    };
  }
  return out;
}

/** Configured tool paths in the bridge settings table (one key for all tools). */
export class ToolPathStore implements ConfiguredToolPaths {
  private readonly settings: SettingsStore;

  constructor(settings: SettingsStore) {
    this.settings = settings;
  }

  list(): StoredToolPaths {
    return parseStoredToolPaths(this.settings.get<unknown>(TOOL_PATHS_SETTING, {}));
  }

  /**
   * Stores a checked path. A path that list() would drop is refused here, so a save can never
   * report success for a path that then has no effect.
   */
  set(tool: ConfigurableTool, toolPath: string, actor: string): StoredToolPath {
    if (!isStorablePath(toolPath)) {
      throw new Error(`A tool path must have 1 to ${MAX_TOOL_PATH_LENGTH} characters; refusing to store ${String(toolPath).length}.`);
    }
    const entry: StoredToolPath = { path: toolPath, setAt: new Date().toISOString(), setBy: actor };
    this.settings.set(TOOL_PATHS_SETTING, { ...this.list(), [tool]: entry }, actor);
    return entry;
  }

  /** Removes a tool's configured path; returns the removed entry (null when none was set). */
  clear(tool: ConfigurableTool, actor: string): StoredToolPath | null {
    const current = this.list();
    const previous = current[tool] ?? null;
    if (!previous) return null;
    delete current[tool];
    if (Object.keys(current).length === 0) this.settings.delete(TOOL_PATHS_SETTING);
    else this.settings.set(TOOL_PATHS_SETTING, current, actor);
    return previous;
  }
}

// ───────────────────────────── validation ─────────────────────────────

export type PathKind = "file" | "directory" | "other";

/** Host access behind checkToolPath; injectable so Windows, macOS and Linux rules are tested anywhere. */
export interface ToolPathProbes {
  platform: NodeJS.Platform;
  /** Environment read for PATHEXT (Windows). */
  env: Readonly<Record<string, string | undefined>>;
  /** Home directory of the bridge user, for a leading ~ on macOS and Linux. */
  homedir: string;
  /** Native architecture of the host OS, for release-asset names and header compatibility. */
  nativeArch: CpuArch | null;
  /** What a path leads to after following links; throws an errno-style error when it cannot be checked. */
  kind(target: string): Promise<PathKind>;
  /** Entry names of a directory; throws when it cannot be listed. */
  listDirectory(dir: string): Promise<string[]>;
  /**
   * macOS and Linux: execute permission for the bridge user (false when it is missing); throws only
   * when the question could not be answered, such as a call that did not answer in time. Not
   * consulted on Windows.
   */
  isExecutable(file: string): Promise<boolean>;
  /** Header facts from a bounded read of the file (never executed); throws only when it did not answer in time. */
  inspect(file: string, host: HostArch): Promise<BinaryInfo>;
}

export type ToolPathCheck =
  | {
      ok: true;
      /** Normalised path to store (what was entered: the file or its folder). */
      input: string;
      /** The executable the path leads to. */
      file: string;
      binary: BinaryInfo;
      /** Soft remark (the file name does not look like the tool); never blocks saving. */
      warning: string | null;
    }
  | { ok: false; input: string | null; problem: string };

/** Deadline for each file-system call of a check on the bridge host (stat, listing, permission, header read). */
export const PROBE_TIMEOUT_MS = 2_000;
/** Deadline for a whole check, however many calls it makes. */
export const TOOL_PATH_CHECK_TIMEOUT_MS = 5_000;

function isAccessError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === "EACCES" || code === "EPERM";
}

function isTimeout(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | null)?.code === "ETIMEDOUT";
}

function formatDeadline(ms: number): string {
  return ms % 1000 === 0 ? `${ms / 1000} s` : `${ms} ms`;
}

/** Message for a path whose drive or network share did not answer within `ms`. */
export function slowPathProblem(target: string, ms: number): string {
  return `${target} did not answer within ${formatDeadline(ms)}; the drive or network share it is on may be slow or unreachable.`;
}

function timeoutError(what: string, ms: number): Error {
  return Object.assign(new Error(`${what} did not answer within ${ms} ms`), { code: "ETIMEDOUT", timeoutMs: ms });
}

/** `call`, or an ETIMEDOUT rejection when it does not settle within `ms`. */
async function withDeadline<T>(call: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(timeoutError(what, ms)), ms);
  });
  try {
    return await Promise.race([call, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** The call still pending under `key`, or a new one. Settled calls are forgotten. */
function joinOrStart<T>(pending: Map<string, Promise<unknown>>, key: string, start: () => Promise<T>): Promise<T> {
  const existing = pending.get(key);
  if (existing) return existing as Promise<T>;
  const call: Promise<T> = Promise.resolve()
    .then(start)
    .finally(() => {
      if (pending.get(key) === call) pending.delete(key);
    });
  pending.set(key, call);
  return call;
}

/**
 * Probes whose every call settles within `timeoutMs`; one that does not answer in time rejects with
 * ETIMEDOUT. A file-system call cannot be cancelled, so a call still pending for the same target (a
 * hung network mount, for example) is joined instead of started again: repeated checks never pile
 * up blocked calls.
 */
export function boundedToolPathProbes(
  probes: ToolPathProbes,
  options: { timeoutMs?: number; pending?: Map<string, Promise<unknown>> } = {},
): ToolPathProbes {
  const timeoutMs = options.timeoutMs ?? PROBE_TIMEOUT_MS;
  const pending = options.pending ?? new Map<string, Promise<unknown>>();
  const bounded = <T>(key: string, target: string, start: () => Promise<T>): Promise<T> =>
    withDeadline(joinOrStart(pending, key, start), timeoutMs, target);
  return {
    ...probes,
    kind: (target) => bounded(`kind\0${target}`, target, () => probes.kind(target)),
    listDirectory: (dir) => bounded(`list\0${dir}`, dir, () => probes.listDirectory(dir)),
    isExecutable: (file) => bounded(`exec\0${file}`, file, () => probes.isExecutable(file)),
    inspect: (file, host) => bounded(`inspect\0${host.platform}\0${host.nativeArch}\0${file}`, file, () => probes.inspect(file, host)),
  };
}

/** Calls of the real host probes still pending, shared by every check (see boundedToolPathProbes). */
const HOST_PENDING_CALLS = new Map<string, Promise<unknown>>();

/** Real file-system probes for the bridge host, each call bounded by PROBE_TIMEOUT_MS. */
export function hostToolPathProbes(options: {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  nativeArch: CpuArch | null;
  homedir?: string;
}): ToolPathProbes {
  const { platform } = options;
  const raw: ToolPathProbes = {
    platform,
    env: options.env,
    homedir: options.homedir ?? os.homedir(),
    nativeArch: options.nativeArch,
    kind: async (target) => {
      try {
        const stat = await fs.promises.stat(target);
        return stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other";
      } catch (error) {
        // A Windows App Execution Alias is a reparse point that lstat reports as a link and stat
        // refuses; Windows can start it, so it counts as a file (its header is not readable).
        if (platform === "win32" && isAccessError(error)) {
          const link = await fs.promises.lstat(target).catch(() => null);
          if (link?.isSymbolicLink()) return "file";
        }
        throw error;
      }
    },
    listDirectory: (dir) => fs.promises.readdir(dir),
    isExecutable: async (file) => {
      try {
        await fs.promises.access(file, fs.constants.X_OK);
        return true;
      } catch {
        return false;
      }
    },
    inspect: (file, host) => inspectBinary(file, host),
  };
  return boundedToolPathProbes(raw, { pending: HOST_PENDING_CALLS });
}

// oxlint-disable-next-line no-control-regex -- intentional: rejects C0/C1 control characters in a tool path
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;

function stripTrailingSeparators(value: string, platform: NodeJS.Platform): string {
  if (platform === "win32") {
    const trimmed = value.replace(/[\\/]+$/, "");
    return /^[A-Za-z]:$/.test(trimmed) ? `${trimmed}\\` : trimmed;
  }
  const trimmed = value.replace(/\/+$/, "");
  return trimmed === "" ? "/" : trimmed;
}

/**
 * Normalises a path entered in the console, or says precisely why it is refused. Nothing is
 * expanded except a leading `~` or `~/` on macOS and Linux (the home directory of the user the
 * bridge runs as); `~user`, `$VAR` and Windows `%VAR%` are not. One pair of surrounding double
 * quotes (as Windows Explorer's "Copy as path" adds) is removed.
 * - Windows: a drive-rooted path only. UNC (\\server\share) and device (\\?\, \\.\) paths are
 *   refused before any file-system call, since checking them would make the bridge authenticate
 *   to another host; so are drive-relative forms (C:foo), which depend on a per-drive current
 *   directory, and characters Windows does not allow in names (including alternate data streams).
 * - macOS and Linux: a path starting with /.
 * The length limit applies to the path as entered and again to the normalised result (after ~ is
 * expanded), which is what is stored.
 */
export function normalizeToolPathInput(raw: string, platform: NodeJS.Platform, homedir: string): { path: string } | { problem: string } {
  let value = raw.trim();
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1).trim();
  if (!value) return { problem: "Enter the absolute path of the executable or of the folder that contains it." };
  if (value.length > MAX_TOOL_PATH_LENGTH) return { problem: `The path is longer than ${MAX_TOOL_PATH_LENGTH} characters.` };
  if (CONTROL_CHARACTERS.test(value)) return { problem: "The path contains control characters (such as a line break or a tab)." };
  const result = (normalized: string, expandedHome: boolean): { path: string } | { problem: string } => {
    if (normalized.length > MAX_TOOL_PATH_LENGTH) {
      return {
        problem: expandedHome
          ? `The path is longer than ${MAX_TOOL_PATH_LENGTH} characters once ~ is expanded to ${homedir}.`
          : `The path is longer than ${MAX_TOOL_PATH_LENGTH} characters.`,
      };
    }
    // Only the home directory can bring one in: the entered text was checked above.
    if (expandedHome && CONTROL_CHARACTERS.test(normalized)) return { problem: `The path contains control characters once ~ is expanded to ${homedir}.` };
    return { path: normalized };
  };
  if (platform === "win32") {
    if (/^[\\/]{2}/.test(value)) {
      return {
        problem:
          "Network (\\\\server\\share) and device (\\\\?\\, \\\\.\\) paths are not accepted: checking them would make the bridge connect to another computer. Use a path on a local drive.",
      };
    }
    const variable = /%[^%\\/]+%/.exec(value);
    if (variable) {
      return {
        problem: `Environment variables such as ${variable[0]} are not expanded. Enter the full path, for example C:\\Users\\you\\AppData\\Local\\Programs\\tool\\tool.exe.`,
      };
    }
    const drive = /^([A-Za-z]):(?![\\/])/.exec(value);
    if (drive) {
      const letter = drive[1].toUpperCase();
      return {
        problem: `"${value.slice(0, 2)}" without a backslash is relative to the current folder of drive ${letter}:. Enter a full path such as ${letter}:\\${value.slice(2)}.`,
      };
    }
    if (!/^[A-Za-z]:[\\/]/.test(value)) {
      return { problem: "Enter an absolute path that starts with a drive letter, for example D:\\CodeQL or D:\\CodeQL\\codeql.exe." };
    }
    const rest = value.slice(2);
    if (/[<>"|?*:]/.test(rest)) {
      return { problem: 'The path contains characters Windows does not allow in file names (< > " | ? * or a colon after the drive letter).' };
    }
    return result(stripTrailingSeparators(pathApi("win32").normalize(value), "win32"), false);
  }
  const expandedHome = value === "~" || value.startsWith("~/");
  if (expandedHome) {
    value = pathApi(platform).join(homedir, value.slice(1));
  } else if (value.startsWith("~")) {
    return { problem: "Only ~ and ~/ (the home directory of the user the bridge runs as) are expanded; ~user is not. Enter the full path." };
  }
  if (value.startsWith("$")) {
    const variable = /^\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)/.exec(value)?.[0] ?? "$HOME";
    return { problem: `Environment variables such as ${variable} are not expanded. Enter the full path.` };
  }
  if (!value.startsWith("/")) return { problem: "Enter an absolute path that starts with /, for example /opt/homebrew/bin/semgrep." };
  return result(stripTrailingSeparators(pathApi(platform).normalize(value), platform), expandedHome);
}

function errorCode(error: unknown): string {
  return (error as NodeJS.ErrnoException | null)?.code ?? "error";
}

/** Message for a path that could not be checked. */
export function accessProblem(target: string, error: unknown): string {
  const code = errorCode(error);
  if (code === "ENOENT" || code === "ENOTDIR") return `Nothing exists at ${target}.`;
  if (code === "EACCES" || code === "EPERM") return `The bridge cannot access ${target} (permission denied for the user it runs as).`;
  if (code === "ELOOP") return `${target} leads to a loop of symbolic links.`;
  if (code === "ETIMEDOUT") {
    const ms = (error as { timeoutMs?: unknown }).timeoutMs;
    return typeof ms === "number"
      ? slowPathProblem(target, ms)
      : `${target} did not answer (ETIMEDOUT); the drive or network share it is on may be slow or unreachable.`;
  }
  return `${target} could not be checked (${code}).`;
}

/** Why a file cannot be a program on this OS (Windows: PATHEXT extension; macOS/Linux: execute permission). */
async function fileProblem(file: string, probes: ToolPathProbes): Promise<string | null> {
  const p = pathApi(probes.platform);
  if (probes.platform === "win32") {
    const extensions = windowsPathExtensions(probes.env);
    const extension = p.extname(file).toLowerCase();
    if (!extensions.includes(extension)) {
      const list = extensions.join(", ");
      const why = extension ? `its extension ${extension} is not one of ${list} (PATHEXT)` : `it has no extension (it needs one of ${list}, from PATHEXT)`;
      return `${p.basename(file)} is not a program Windows can start: ${why}.`;
    }
    return null;
  }
  try {
    return (await probes.isExecutable(file)) ? null : `${file} is not executable by the user the bridge runs as (it lacks execute permission; chmod +x adds it).`;
  } catch (error) {
    return accessProblem(file, error);
  }
}

interface DirectorySearch {
  file: string | null;
  /** Candidates that exist but are not executable (macOS/Linux). */
  notExecutable: string[];
  /** Why the folder could not be searched, such as a folder or candidate that did not answer in time. */
  problem: string | null;
}

/** First executable for the tool in one directory, using the same names as automatic detection. */
async function searchDirectory(names: readonly string[], dir: string, probes: ToolPathProbes): Promise<DirectorySearch> {
  const { platform } = probes;
  const p = pathApi(platform);
  const notExecutable: string[] = [];
  const failed = (problem: string): DirectorySearch => ({ file: null, notExecutable, problem });
  let index: ReadonlyMap<string, string> | null;
  try {
    index = buildDirectoryIndex(await probes.listDirectory(dir), platform);
  } catch (error) {
    // Without read permission a folder may still be searchable: the candidates are then probed by
    // name. Any other failure, a folder that did not answer in time included, is reported as it is:
    // probing name by name would only wait on the same drive again, and "no executable" would be wrong.
    if (!isAccessError(error)) return failed(accessProblem(dir, error));
    index = null;
  }
  for (const name of names) {
    let entry = name;
    if (index) {
      const real = index.get(platform === "win32" ? name.toLowerCase() : name);
      if (real === undefined) continue;
      entry = real;
    }
    const candidate = p.join(dir, entry);
    let kind: PathKind;
    try {
      kind = await probes.kind(candidate);
    } catch (error) {
      if (isTimeout(error)) return failed(accessProblem(candidate, error));
      continue;
    }
    if (kind !== "file") continue;
    if (platform !== "win32") {
      let executable: boolean;
      try {
        executable = await probes.isExecutable(candidate);
      } catch (error) {
        return failed(accessProblem(candidate, error));
      }
      if (!executable) {
        notExecutable.push(candidate);
        continue;
      }
    }
    return { file: candidate, notExecutable, problem: null };
  }
  return { file: null, notExecutable, problem: null };
}

/** Subfolders checked only to suggest a better folder when the entered one holds no executable. */
function suggestionFolders(tool: ConfigurableTool): string[] {
  return [...new Set([tool, "bin"])];
}

async function findInDirectory(tool: ConfigurableTool, dir: string, probes: ToolPathProbes): Promise<{ file: string } | { problem: string }> {
  const names = executableFileNames(tool, probes.platform, probes.env, probes.nativeArch);
  const found = await searchDirectory(names, dir, probes);
  if (found.problem) return { problem: found.problem };
  if (found.file) return { file: found.file };
  const shown = names.length > 8 ? `${names.slice(0, 8).join(", ")}, ...` : names.join(", ");
  let problem = `No ${tool} executable in ${dir} (looked for ${shown}).`;
  if (found.notExecutable.length > 0) {
    problem += ` ${found.notExecutable[0]} exists but is not executable by the user the bridge runs as.`;
    return { problem };
  }
  const p = pathApi(probes.platform);
  for (const sub of suggestionFolders(tool)) {
    const nested = p.join(dir, sub);
    try {
      if ((await probes.kind(nested)) !== "directory") continue;
    } catch (error) {
      // A suggestion is not worth waiting on a slow drive again.
      if (isTimeout(error)) break;
      continue;
    }
    const inner = await searchDirectory(names, nested, probes);
    if (inner.file) return { problem: `${problem} ${inner.file} exists: enter ${nested} or the file itself.` };
    if (inner.problem) break;
  }
  return { problem };
}

const BUILT_FOR: Record<BinaryFormat, string> = {
  pe: "a Windows (PE)",
  elf: "a Linux (ELF)",
  macho: "a macOS (Mach-O)",
  macho_universal: "a macOS universal",
  script: "a script",
  unknown: "an unrecognised",
};

/** Names what an incompatible file is built for and what this host is. */
export function incompatibleProblem(file: string, binary: BinaryInfo, host: HostArch): string {
  const architectures = binary.architectures.filter((arch) => arch !== "unknown");
  const built = `${BUILT_FOR[binary.format]} binary${architectures.length > 0 ? ` built for ${architectures.join(", ")}` : ""}`;
  const hostText = `${osLabel(host.platform)} on ${host.nativeArch ?? "an undetermined architecture"}`;
  // The compatibility note explains architecture mismatches (24H2 and ARM32, binfmt_misc); for a
  // file of another OS's format it would only repeat the sentence.
  const detail = NATIVE_FORMATS[host.platform]?.includes(binary.format) && binary.note ? ` (${binary.note})` : "";
  return `${file} is ${built}, and this bridge host is ${hostText}, so it cannot run here${detail}.`;
}

/** Soft warning when a file name does not look like the tool (compared without case and PATHEXT extension). */
export function nameWarning(tool: ConfigurableTool, file: string, probes: Pick<ToolPathProbes, "platform" | "env" | "nativeArch">): string | null {
  const p = pathApi(probes.platform);
  const base = p.basename(file);
  let stem = base;
  if (probes.platform === "win32") {
    const extension = p.extname(base).toLowerCase();
    if (extension && windowsPathExtensions(probes.env).includes(extension)) stem = base.slice(0, -extension.length);
  }
  const expected = [tool, ...releaseAssetNames(tool, probes.platform, probes.nativeArch)].map((name) => name.toLowerCase());
  if (expected.includes(stem.toLowerCase())) return null;
  return `The file name ${base} does not look like ${tool}. The path was saved; check that it is the right program.`;
}

/**
 * Checks a path for a tool without executing anything: normalised (normalizeToolPathInput), it must
 * exist; a folder is searched for the tool with the names automatic detection uses (PATHEXT on
 * Windows, execute permission elsewhere, osv-scanner_<os>_<arch> release assets); a file must be a
 * regular file after following links, with a PATHEXT extension on Windows (scripts such as .cmd are
 * fine, since nothing is run) or execute permission on macOS and Linux. A header built for another
 * OS or an architecture this host cannot run is refused. The whole check settles within
 * `timeoutMs` (default TOOL_PATH_CHECK_TIMEOUT_MS); a path that does not answer in time is refused
 * with a message that says so.
 */
export async function checkToolPath(
  tool: ConfigurableTool,
  raw: string,
  probes: ToolPathProbes,
  options: { timeoutMs?: number } = {},
): Promise<ToolPathCheck> {
  const normalized = normalizeToolPathInput(raw, probes.platform, probes.homedir);
  if ("problem" in normalized) return { ok: false, input: null, problem: normalized.problem };
  const input = normalized.path;
  const timeoutMs = options.timeoutMs ?? TOOL_PATH_CHECK_TIMEOUT_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<ToolPathCheck>((resolve) => {
    timer = setTimeout(() => resolve({ ok: false, input, problem: slowPathProblem(input, timeoutMs) }), timeoutMs);
  });
  try {
    return await Promise.race([
      checkNormalizedPath(tool, input, probes).catch((error): ToolPathCheck => ({ ok: false, input, problem: accessProblem(input, error) })),
      deadline,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function checkNormalizedPath(tool: ConfigurableTool, input: string, probes: ToolPathProbes): Promise<ToolPathCheck> {
  const fail = (problem: string): ToolPathCheck => ({ ok: false, input, problem });
  let kind: PathKind;
  try {
    kind = await probes.kind(input);
  } catch (error) {
    return fail(accessProblem(input, error));
  }
  let file: string;
  if (kind === "directory") {
    const found = await findInDirectory(tool, input, probes);
    if ("problem" in found) return fail(found.problem);
    file = found.file;
  } else if (kind === "file") {
    const problem = await fileProblem(input, probes);
    if (problem) return fail(problem);
    file = input;
  } else {
    return fail(`${input} is neither a regular file nor a folder (it is a device, pipe or socket).`);
  }
  const host: HostArch = { platform: probes.platform, nativeArch: probes.nativeArch };
  let binary: BinaryInfo;
  try {
    binary = await probes.inspect(file, host);
  } catch (error) {
    return fail(accessProblem(file, error));
  }
  if (binary.compatibility === "incompatible") return fail(incompatibleProblem(file, binary, host));
  return { ok: true, input, file, binary, warning: kind === "file" ? nameWarning(tool, file, probes) : null };
}
