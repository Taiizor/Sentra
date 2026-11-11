import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { CpuArch, ExecutableSource, ToolSearchStatus } from "../src/types/api.ts";

/**
 * Executable discovery for the bridge host.
 *
 * The bridge process inherits PATH once, when it starts. Directories added to PATH after that (by an
 * installer, or in the Windows environment dialog) and directories a GUI/launchd/systemd parent never
 * had (Homebrew, ~/.local/bin, /snap/bin, ...) are invisible to `Bun.which`; tools installed later
 * into a directory that was already on its PATH are found. The locator therefore searches, in order:
 * the process PATH, the persisted system PATH, the persisted user PATH, and well-known install
 * directories. Nothing found here is ever executed by the search itself.
 *
 * UNC and device paths are never touched, whether they come from a PATH entry or from an
 * install-location variable (APPDATA redirected to a share by Folder Redirection, for example):
 * listing a share makes the bridge authenticate to that host on every refresh. Snapshot refreshes
 * check and list directories asynchronously, each bounded by a deadline, so a slow or unreachable
 * drive cannot block the event loop.
 *
 * Finding a tool and choosing a file to RUN are separate decisions. Standard install locations are
 * searched for presence reporting only: some of them can be created by any local user (for example
 * a missing package-manager directory under C:\ProgramData), or belong to another user than the one
 * running the bridge (Homebrew prefixes when the bridge runs as root). `locateForExecution` and
 * `findOnProcessPathForExecution` therefore only consider the process PATH and the persisted PATH,
 * only real executables on Windows (never batch scripts, which run through cmd.exe), and on macOS
 * and Linux only persisted-PATH files owned by root or the bridge user that neither others nor a
 * non-root group can modify (see ownershipProblem).
 *
 * Paths an admin sets in the web console (tool-paths.ts) are never passed to this module: they are
 * applied by the reporting layer (host-tools.ts) only, so no configured path can become a program
 * the bridge runs.
 *
 * Everything that depends on the host is injected so Windows, macOS and Linux behaviour can be
 * unit-tested on any host.
 */

/**
 * Sources the automatic search can produce. The console-configured and environment sources of the
 * tools table are deliberately not part of it: this module never sees a configured path, so nothing
 * it returns (and in particular nothing locateForExecution chooses to run) can come from one.
 */
export type SearchSource = Exclude<ExecutableSource, "configured" | "environment">;

export interface SearchDirectory {
  /** Absolute, normalised directory (no trailing separator except for a root). */
  dir: string;
  source: SearchSource;
}

export interface PersistedPathEntries {
  /**
   * Persisted machine-wide entries in OS order: the Windows registry machine Path, macOS
   * /etc/paths then /etc/paths.d/* (sorted), Linux /etc/environment PATH.
   */
  system: string[];
  /** Persisted per-user entries (Windows HKCU\Environment Path); empty on other platforms. */
  user: string[];
}

export interface PersistedPathResult {
  entries: PersistedPathEntries;
  /** True when the persisted sources were read (a missing optional file counts as read). */
  read: boolean;
  error: string | null;
}

export interface SearchEnvironment {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  homedir: string;
  persisted: PersistedPathEntries | null;
  isDirectory(dir: string): boolean;
  /** Entry names of a directory; throws when it cannot be listed. */
  listDirectory(dir: string): string[];
}

export interface SearchPlan {
  directories: SearchDirectory[];
  /** PATH entries skipped on purpose because they are UNC or device paths (Windows). */
  skippedNetworkEntries: number;
}

/** Directory created by `bun run` (in os.tmpdir()) holding hard links named bun and node. */
const BUN_SHIM_DIR = /^bun-node-[0-9a-f]+$/i;
const DEFAULT_PATHEXT = [".com", ".exe", ".bat", ".cmd"];
/** Tools whose release assets are commonly installed under the asset name. */
const RELEASE_ASSET_TOOLS = new Set(["osv-scanner"]);
const MAX_MATCHES = 5;
const MAX_DIRECTORY_ENTRIES = 50_000;
export const SEARCH_SNAPSHOT_TTL_MS = 60_000;
const DIRECTORY_LIST_TIMEOUT_MS = 2_000;

export function pathApi(platform: NodeJS.Platform): typeof path.posix {
  return platform === "win32" ? path.win32 : path.posix;
}

/** Environment lookup; case-insensitive on Windows like the OS itself. */
export function envValue(env: Readonly<Record<string, string | undefined>>, name: string, platform: NodeJS.Platform): string | undefined {
  const direct = env[name];
  if (direct !== undefined || platform !== "win32") return direct;
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(env)) {
    if (key.toLowerCase() === wanted) return value;
  }
  return undefined;
}

export function splitPathList(value: string, platform: NodeJS.Platform): string[] {
  return value.split(platform === "win32" ? ";" : ":");
}

function stripTrailingSeparators(dir: string, platform: NodeJS.Platform): string {
  if (platform === "win32") {
    const trimmed = dir.replace(/[\\/]+$/, "");
    return /^[A-Za-z]:$/.test(trimmed) ? `${trimmed}\\` : trimmed;
  }
  const trimmed = dir.replace(/\/+$/, "");
  return trimmed === "" ? "/" : trimmed;
}

export function isBunShimDir(dir: string, platform: NodeJS.Platform): boolean {
  return BUN_SHIM_DIR.test(pathApi(platform).basename(stripTrailingSeparators(dir, platform)));
}

/**
 * Expands `%NAME%` references of a REG_EXPAND_SZ value. Returns null when a referenced variable is
 * unknown or empty: the entry would point somewhere unintended, so it is dropped.
 */
export function expandWindowsVariables(value: string, env: Readonly<Record<string, string | undefined>>): string | null {
  let unresolved = false;
  const expanded = value.replace(/%([^%;\\/]+)%/g, (_match, name: string) => {
    const resolved = envValue(env, name, "win32");
    if (resolved === undefined || resolved === "") {
      unresolved = true;
      return "";
    }
    return resolved;
  });
  return unresolved ? null : expanded;
}

function expandTilde(value: string, homedir: string, platform: NodeJS.Platform): string {
  if (value === "~") return homedir;
  if (value.startsWith("~/") || (platform === "win32" && value.startsWith("~\\"))) {
    return pathApi(platform).join(homedir, value.slice(2));
  }
  return value;
}

/** Absolute, drive-rooted on Windows (UNC and device paths are refused: touching them can leak credentials). */
function isAcceptedAbsolute(dir: string, platform: NodeJS.Platform): boolean {
  if (platform === "win32") return /^[A-Za-z]:[\\/]/.test(dir);
  return dir.startsWith("/");
}

/**
 * True for a Windows UNC (\\server\share) or device (\\?\, \\.\) path. Such PATH entries are
 * skipped: listing them would make the bridge authenticate to a remote host every refresh.
 */
export function isWindowsNetworkOrDevicePath(raw: string): boolean {
  let value = raw.trim();
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1).trim();
  return /^[\\/]{2}/.test(value);
}

/**
 * Normalises one raw PATH-like entry, or returns null when it must be ignored: empty, NUL bytes,
 * unknown %VAR% (Windows persisted values), relative (never search the cwd) or a Bun shim dir.
 */
export function normalizeSearchEntry(
  raw: string,
  platform: NodeJS.Platform,
  options: { env: Readonly<Record<string, string | undefined>>; expandVariables?: boolean; homedir?: string } = { env: {} },
): string | null {
  let value = raw.trim();
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1).trim();
  if (!value || value.includes("\u0000")) return null;
  if (platform === "win32" && options.expandVariables && value.includes("%")) {
    const expanded = expandWindowsVariables(value, options.env);
    if (expanded === null) return null;
    value = expanded.trim();
  }
  if (options.homedir !== undefined) value = expandTilde(value, options.homedir, platform);
  if (!isAcceptedAbsolute(value, platform)) return null;
  const normalized = stripTrailingSeparators(pathApi(platform).normalize(value), platform);
  if (isBunShimDir(normalized, platform)) return null;
  return normalized;
}

export function directoryKey(dir: string, platform: NodeJS.Platform): string {
  return platform === "win32" ? dir.toLowerCase() : dir;
}

type HostLocations = Pick<SearchEnvironment, "platform" | "env" | "homedir">;

/** An install-location variable (trimmed, `~` expanded), or undefined when unset or empty. */
function locationVariable(input: HostLocations, name: string): string | undefined {
  const value = envValue(input.env, name, input.platform)?.trim();
  return value ? expandTilde(value, input.homedir, input.platform) : undefined;
}

export interface PythonInstallBase {
  /** Absolute local directory holding one subdirectory per Python version. */
  dir: string;
  /** Matches a version subdirectory name; group 1 is the minor version (newest is searched first). */
  version: RegExp;
  /** Script directory inside a version subdirectory. */
  scripts: string;
}

/**
 * Per-user Python install bases whose version subdirectories are listed: python.org installs and
 * `pip install --user` on Windows (%LOCALAPPDATA%\Programs\Python, %APPDATA%\Python), and
 * `pip install --user` on macOS (~/Library/Python). Each base is normalised like a PATH entry
 * before anything lists it, so a UNC or device base (AppData redirected to a share) or a relative
 * one is never touched.
 */
export function pythonInstallBases(input: HostLocations): PythonInstallBase[] {
  const { platform } = input;
  const p = pathApi(platform);
  const candidates: [string | null, RegExp, string][] = [];
  if (platform === "win32") {
    const localAppData = locationVariable(input, "LOCALAPPDATA");
    const appData = locationVariable(input, "APPDATA");
    candidates.push([localAppData ? p.join(localAppData, "Programs", "Python") : null, /^Python3(\d+)$/i, "Scripts"]);
    candidates.push([appData ? p.join(appData, "Python") : null, /^Python3(\d+)$/i, "Scripts"]);
  } else if (platform === "darwin") {
    candidates.push([p.join(input.homedir, "Library", "Python"), /^3\.(\d+)$/, "bin"]);
  }
  const bases: PythonInstallBase[] = [];
  for (const [raw, version, scripts] of candidates) {
    const dir = raw === null ? null : normalizeSearchEntry(raw, platform, { env: {} });
    if (dir !== null) bases.push({ dir, version, scripts });
  }
  return bases;
}

/** Script directories of the version subdirectories of a base, newest version first. */
function pythonScriptDirs(base: PythonInstallBase, platform: NodeJS.Platform, listDirectory: (dir: string) => string[]): string[] {
  let names: string[];
  try {
    names = listDirectory(base.dir);
  } catch {
    return [];
  }
  return names
    .map((name) => ({ name, match: base.version.exec(name) }))
    .filter((entry): entry is { name: string; match: RegExpExecArray } => entry.match !== null)
    .sort((a, b) => Number(b.match[1]) - Number(a.match[1]))
    .map((entry) => pathApi(platform).join(base.dir, entry.name, base.scripts));
}

/** Candidate well-known install directories (existence is checked by the caller). */
export function wellKnownDirectories(input: SearchEnvironment): string[] {
  const { platform, homedir } = input;
  const p = pathApi(platform);
  const get = (name: string) => locationVariable(input, name);
  const pythonDirs = () => pythonInstallBases(input).flatMap((base) => pythonScriptDirs(base, platform, input.listDirectory));
  const dirs: string[] = [];

  const bunInstall = get("BUN_INSTALL");
  dirs.push(bunInstall ? p.join(bunInstall, "bin") : p.join(homedir, ".bun", "bin"));
  const cargoHome = get("CARGO_HOME");
  dirs.push(cargoHome ? p.join(cargoHome, "bin") : p.join(homedir, ".cargo", "bin"));
  const gopath = get("GOPATH");
  if (gopath) {
    for (const entry of splitPathList(gopath, platform)) {
      if (entry.trim()) dirs.push(p.join(expandTilde(entry.trim(), homedir, platform), "bin"));
    }
  } else {
    dirs.push(p.join(homedir, "go", "bin"));
  }
  dirs.push(p.join(homedir, ".local", "bin"));

  if (platform === "win32") {
    const programDirs = [...new Set([get("ProgramFiles"), get("ProgramW6432"), get("ProgramFiles(x86)")].filter((value): value is string => !!value))];
    for (const base of programDirs) {
      dirs.push(p.join(base, "GitHub CLI"), p.join(base, "Git", "cmd"), p.join(base, "Docker", "Docker", "resources", "bin"));
    }
    const localAppData = get("LOCALAPPDATA");
    if (localAppData) dirs.push(p.join(localAppData, "Microsoft", "WinGet", "Links"));
    const scoop = get("SCOOP");
    dirs.push(scoop ? p.join(scoop, "shims") : p.join(homedir, "scoop", "shims"));
    // Chocolatey always sets ChocolateyInstall machine-wide. There is deliberately no
    // %ProgramData%\chocolatey fallback: any local user can create that directory.
    const chocolatey = get("ChocolateyInstall");
    if (chocolatey) dirs.push(p.join(chocolatey, "bin"));
    dirs.push(...pythonDirs());
  } else if (platform === "darwin") {
    dirs.push("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/opt/local/bin", "/Applications/Docker.app/Contents/Resources/bin");
    dirs.push(...pythonDirs());
    dirs.push("/usr/bin", "/bin", "/usr/sbin", "/sbin");
  } else if (platform === "linux") {
    dirs.push(
      "/usr/local/sbin",
      "/usr/local/bin",
      "/usr/sbin",
      "/usr/bin",
      "/sbin",
      "/bin",
      "/snap/bin",
      "/home/linuxbrew/.linuxbrew/bin",
      p.join(homedir, ".linuxbrew", "bin"),
    );
  } else {
    dirs.push("/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin", "/sbin");
  }
  return dirs;
}

/**
 * Search order: process PATH, persisted system PATH, persisted user PATH (Windows composes PATH as
 * system then user), then existing well-known directories. The first occurrence of a directory
 * wins, so a directory on the process PATH keeps the `process_path` source. UNC and device PATH
 * entries are skipped and counted; well-known candidates under a UNC or device install location are
 * dropped before any file-system call (pythonInstallBases, normalizeSearchEntry).
 */
export function buildSearchPlan(input: SearchEnvironment, options: { wellKnown?: boolean } = {}): SearchPlan {
  const { platform } = input;
  const out: SearchDirectory[] = [];
  const seen = new Set<string>();
  let skippedNetworkEntries = 0;
  const add = (raw: string, source: SearchSource, entryOptions: { expandVariables?: boolean; homedir?: string } = {}) => {
    const dir = normalizeSearchEntry(raw, platform, { env: input.env, ...entryOptions });
    if (dir === null) {
      if (platform === "win32" && isWindowsNetworkOrDevicePath(entryOptions.expandVariables ? (expandWindowsVariables(raw, input.env) ?? raw) : raw)) {
        skippedNetworkEntries += 1;
      }
      return;
    }
    const key = directoryKey(dir, platform);
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ dir, source });
  };

  const processPath = envValue(input.env, "PATH", platform);
  if (processPath) for (const entry of splitPathList(processPath, platform)) add(entry, "process_path");
  if (input.persisted) {
    for (const entry of input.persisted.system) add(entry, "persisted_system_path", { expandVariables: true });
    for (const entry of input.persisted.user) add(entry, "persisted_user_path", { expandVariables: true });
  }
  if (options.wellKnown !== false) {
    for (const dir of wellKnownDirectories(input)) {
      const normalized = normalizeSearchEntry(dir, platform, { env: input.env });
      if (normalized === null || seen.has(directoryKey(normalized, platform))) continue;
      if (!input.isDirectory(normalized)) continue;
      add(normalized, "well_known");
    }
  }
  return { directories: out, skippedNetworkEntries };
}

export function buildSearchDirectories(input: SearchEnvironment): SearchDirectory[] {
  return buildSearchPlan(input).directories;
}

// ───────────────────────────── name candidates ─────────────────────────────

/** Lower-cased PATHEXT entries (default .COM;.EXE;.BAT;.CMD). */
export function windowsPathExtensions(env: Readonly<Record<string, string | undefined>>): string[] {
  const raw = envValue(env, "PATHEXT", "win32");
  const list = (raw ?? "")
    .split(";")
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => /^\.[a-z0-9]+$/.test(entry));
  return list.length > 0 ? [...new Set(list)] : [...DEFAULT_PATHEXT];
}

const GOOS: Partial<Record<NodeJS.Platform, string>> = { win32: "windows", linux: "linux", darwin: "darwin" };
const GOARCH: Partial<Record<CpuArch, string>> = { x64: "amd64", arm64: "arm64", ia32: "386", arm: "arm" };

/**
 * Architectures whose binaries the host OS may start (natively, under emulation or as 32-bit),
 * consistent with binaryCompatibility in binary-info.ts. Used only to build release-asset names
 * (RELEASE_ASSET_TOOLS), which affect presence reporting: none of those tools is ever run by the
 * bridge, so listing a "may run" architecture here (32-bit Arm on Linux arm64, which needs AArch32
 * support in the CPU and kernel) never makes the bridge execute anything.
 * - Windows on Arm: arm64, x64 and x86 run; 32-bit Arm apps are not supported on Windows 11 24H2
 *   and later, so arm is not listed.
 * - macOS on Apple silicon: arm64, and x64 under Rosetta 2; 32-bit code does not run.
 * - Linux: x64 runs ia32 (IA-32 emulation in the kernel), arm64 may run arm (AArch32).
 */
export function runnableArchitectures(platform: NodeJS.Platform, nativeArch: CpuArch | null): CpuArch[] {
  if (!nativeArch || nativeArch === "unknown") return [];
  if (platform === "win32") {
    if (nativeArch === "arm64") return ["arm64", "x64", "ia32"];
    if (nativeArch === "x64") return ["x64", "ia32"];
    return [nativeArch];
  }
  if (platform === "darwin") return nativeArch === "arm64" ? ["arm64", "x64"] : [nativeArch];
  if (platform === "linux" && nativeArch === "x64") return ["x64", "ia32"];
  if (platform === "linux" && nativeArch === "arm64") return ["arm64", "arm"];
  return [nativeArch];
}

/** Release-asset names (`osv-scanner_<goos>_<goarch>`) that may be installed as-is. */
export function releaseAssetNames(name: string, platform: NodeJS.Platform, nativeArch: CpuArch | null): string[] {
  const goos = GOOS[platform];
  if (!RELEASE_ASSET_TOOLS.has(name) || !goos) return [];
  return runnableArchitectures(platform, nativeArch)
    .map((arch) => GOARCH[arch])
    .filter((goarch): goarch is string => !!goarch)
    .map((goarch) => `${name}_${goos}_${goarch}`);
}

/**
 * File names tried in each directory, in order. On Windows the bare name is tried only when it
 * already carries a PATHEXT extension; otherwise every PATHEXT extension is appended, so an
 * extension-less file (such as the bash launcher `codeql` next to codeql.exe) never matches.
 */
export function executableFileNames(
  name: string,
  platform: NodeJS.Platform,
  env: Readonly<Record<string, string | undefined>>,
  nativeArch: CpuArch | null,
): string[] {
  const bases = [name, ...releaseAssetNames(name, platform, nativeArch)];
  if (platform !== "win32") return bases;
  const extensions = windowsPathExtensions(env);
  const out: string[] = [];
  for (const base of bases) {
    const extension = path.win32.extname(base).toLowerCase();
    if (extension && extensions.includes(extension)) out.push(base);
    else for (const candidate of extensions) out.push(`${base}${candidate}`);
  }
  return out;
}

// ───────────────────────────── locating ─────────────────────────────

export interface ExecutableMatch {
  path: string;
  source: SearchSource;
}

export interface LocatedExecutable {
  /** First match in search order; null when nothing matched. */
  path: string | null;
  source: SearchSource | null;
  /** True when the first match is in a directory of the bridge process PATH. */
  onProcessPath: boolean;
  /** Later matches (max 4). */
  shadowed: string[];
  /** All matches (first + shadowed). */
  matches: ExecutableMatch[];
}

export interface LocateProbes {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  nativeArch: CpuArch | null;
  /** Lookup key -> real entry name of a directory, or null when it cannot be listed. */
  directoryIndex(dir: string): ReadonlyMap<string, string> | null;
  isExecutableFile(file: string): boolean;
  /**
   * Identity of the file a path leads to (links followed), or null when unknown. Matches with an
   * identity already seen are the same file reached through another directory (merged /usr,
   * symlinked bin directories) and are not reported again.
   */
  fileIdentity?(file: string): string | null;
}

export function buildDirectoryIndex(names: readonly string[], platform: NodeJS.Platform): ReadonlyMap<string, string> | null {
  if (names.length > MAX_DIRECTORY_ENTRIES) return null;
  const index = new Map<string, string>();
  for (const name of names) {
    const key = platform === "win32" ? name.toLowerCase() : name;
    if (!index.has(key)) index.set(key, name);
  }
  return index;
}

export function locateExecutable(name: string, directories: readonly SearchDirectory[], probes: LocateProbes): LocatedExecutable {
  const p = pathApi(probes.platform);
  const fileNames = executableFileNames(name, probes.platform, probes.env, probes.nativeArch);
  const matches: ExecutableMatch[] = [];
  const identities = new Set<string>();
  search: for (const directory of directories) {
    const index = probes.directoryIndex(directory.dir);
    for (const fileName of fileNames) {
      let entryName = fileName;
      if (index) {
        const real = index.get(probes.platform === "win32" ? fileName.toLowerCase() : fileName);
        if (real === undefined) continue;
        entryName = real;
      }
      const candidate = p.join(directory.dir, entryName);
      if (!probes.isExecutableFile(candidate)) continue;
      const identity = probes.fileIdentity?.(candidate) ?? null;
      if (identity !== null) {
        if (identities.has(identity)) continue;
        identities.add(identity);
      }
      matches.push({ path: candidate, source: directory.source });
      if (matches.length >= MAX_MATCHES) break search;
    }
  }
  const first = matches[0] ?? null;
  return {
    path: first?.path ?? null,
    source: first?.source ?? null,
    onProcessPath: first?.source === "process_path",
    shadowed: matches.slice(1).map((match) => match.path),
    matches,
  };
}

function isAccessError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === "EACCES" || code === "EPERM";
}

/**
 * Host predicate for "an executable file": a regular file after following links, with execute
 * permission on POSIX. On Windows an App Execution Alias (a reparse point that lstat reports as a
 * link and stat refuses with EACCES) counts, because Windows can start it.
 */
export function defaultIsExecutableFile(platform: NodeJS.Platform = process.platform): (file: string) => boolean {
  return (file) => {
    try {
      if (platform === "win32") {
        const link = fs.lstatSync(file);
        if (link.isFile()) return true;
        if (!link.isSymbolicLink()) return false;
        try {
          return fs.statSync(file).isFile();
        } catch (error) {
          return isAccessError(error);
        }
      }
      if (!fs.statSync(file).isFile()) return false;
      fs.accessSync(file, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  };
}

/**
 * Device + inode of the file a path leads to (links followed), or null when it cannot be read or
 * the file system reports no inode number (0, as some FAT/exFAT drivers do).
 */
export function fileIdentitySync(file: string): string | null {
  try {
    const stat = fs.statSync(file, { bigint: true });
    return stat.ino === 0n ? null : `${stat.dev}:${stat.ino}`;
  } catch {
    return null;
  }
}

/** Asynchronous fileIdentitySync. */
export async function fileIdentity(file: string): Promise<string | null> {
  try {
    const stat = await fs.promises.stat(file, { bigint: true });
    return stat.ino === 0n ? null : `${stat.dev}:${stat.ino}`;
  } catch {
    return null;
  }
}

// ───────────────────────────── execution policy ─────────────────────────────

/** Sources whose directories may supply a program the bridge runs. Standard install locations never do. */
export const EXECUTION_SOURCES: readonly SearchSource[] = ["process_path", "persisted_system_path", "persisted_user_path"];

/** Only these are started directly on Windows; a .cmd/.bat would run through cmd.exe and re-parse its arguments. */
const WINDOWS_DIRECT_EXECUTABLE = /\.(exe|com)$/i;

export interface SkippedForExecution {
  path: string;
  reason: string;
}

export interface ExecutionChoice {
  /** The file the bridge runs for this tool, or null when no match qualifies. */
  path: string | null;
  source: SearchSource | null;
  /** Matches passed over before the chosen one (or all of them), with the reason. */
  skipped: SkippedForExecution[];
}

export interface OwnershipFacts {
  uid: number;
  gid: number;
  mode: number;
}

/** gid -> group name, for messages only (null when unknown). */
export type GroupNameLookup = (gid: number) => string | null;

/** Group names from /etc/group text (`name:password:gid:members`). */
export function parseEtcGroup(text: string): Map<number, string> {
  const names = new Map<number, string>();
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(":");
    if (fields.length < 3 || !fields[0] || !/^\d+$/.test(fields[2])) continue;
    const gid = Number(fields[2]);
    if (!names.has(gid)) names.set(gid, fields[0]);
  }
  return names;
}

const MAX_ETC_GROUP_BYTES = 256 * 1024;
let etcGroupNames: Map<number, string> | null = null;

/** Group names from the local /etc/group (read once, bounded); directory-service groups stay numeric. */
export function etcGroupName(gid: number): string | null {
  if (etcGroupNames === null) {
    etcGroupNames = new Map();
    let fd: number | null = null;
    try {
      fd = fs.openSync("/etc/group", "r");
      if (fs.fstatSync(fd).isFile()) {
        const buffer = Buffer.alloc(MAX_ETC_GROUP_BYTES);
        const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
        etcGroupNames = parseEtcGroup(buffer.subarray(0, bytesRead).toString("utf8"));
      }
    } catch {
      // Unreadable: groups are reported by number.
    } finally {
      if (fd !== null) fs.closeSync(fd);
    }
  }
  return etcGroupNames.get(gid) ?? null;
}

/**
 * Ownership rule for running a POSIX file found through the persisted PATH: owned by root or the
 * bridge's effective user, not writable by others, and not group-writable unless the group is root.
 * Returns why the rule fails, or null when it holds. The Homebrew prefixes (/opt/homebrew/bin, and
 * /usr/local/bin on Intel Macs) are group-writable by the admin group, so they fail on purpose: any
 * member of that group could replace the file.
 */
export function ownershipProblem(facts: OwnershipFacts, euid: number, groupName: GroupNameLookup = () => null): string | null {
  if (facts.uid !== 0 && facts.uid !== euid) {
    return `owned by uid ${facts.uid}, which is neither root nor the bridge user (uid ${euid})`;
  }
  if ((facts.mode & 0o002) !== 0) return "writable by others";
  if ((facts.mode & 0o020) !== 0 && facts.gid !== 0) {
    const name = groupName(facts.gid);
    return `writable by group ${name ? `${name} (gid ${facts.gid})` : `gid ${facts.gid}`}, which is not root`;
  }
  return null;
}

export function isTrustedOwnership(facts: OwnershipFacts, euid: number): boolean {
  return ownershipProblem(facts, euid) === null;
}

/** Why a file must not be run (null when it may be); applied to persisted-PATH matches on POSIX. */
export type ExecutionTrustCheck = (file: string) => string | null;

export interface ExecutionTrustOptions {
  euid?: number;
  groupName?: GroupNameLookup;
  stat?: (file: string) => OwnershipFacts;
  realpath?: (file: string) => string;
}

/**
 * Host check applied (on macOS and Linux) to persisted-PATH matches before they are run: the
 * directory the match was found in, the file it resolves to and that file's directory must all pass
 * ownershipProblem. Process-PATH matches are not checked (the operator chose that PATH). Windows
 * ACLs cannot be read without starting a program, so on Windows this check accepts every file and
 * only the source and file-type restrictions of chooseForExecution apply.
 */
export function defaultExecutionTrustCheck(platform: NodeJS.Platform = process.platform, options: ExecutionTrustOptions = {}): ExecutionTrustCheck {
  if (platform === "win32") return () => null;
  const euid = options.euid ?? (typeof process.geteuid === "function" ? process.geteuid() : -1);
  const groupName = options.groupName ?? etcGroupName;
  const stat = options.stat ?? ((file: string) => fs.statSync(file));
  const realpath = options.realpath ?? ((file: string) => fs.realpathSync(file));
  return (file) => {
    let real: string;
    try {
      real = realpath(file);
    } catch (error) {
      return `its target could not be resolved (${(error as NodeJS.ErrnoException).code ?? "error"})`;
    }
    const targets: [string, string][] = [
      ["the directory", path.posix.dirname(file)],
      ["the file", real],
      ["the directory", path.posix.dirname(real)],
    ];
    const seen = new Set<string>();
    for (const [kind, target] of targets) {
      if (seen.has(target)) continue;
      seen.add(target);
      let facts: OwnershipFacts;
      try {
        facts = stat(target);
      } catch (error) {
        return `${kind} ${target} could not be checked (${(error as NodeJS.ErrnoException).code ?? "error"})`;
      }
      const problem = ownershipProblem(facts, euid, groupName);
      if (problem) return `${kind} ${target} is ${problem}`;
    }
    return null;
  };
}

/** Picks the first match the bridge may run, recording why earlier matches were passed over. */
export function chooseForExecution(
  matches: readonly ExecutableMatch[],
  platform: NodeJS.Platform,
  trustCheck: ExecutionTrustCheck,
): ExecutionChoice {
  const skipped: SkippedForExecution[] = [];
  for (const match of matches) {
    if (!EXECUTION_SOURCES.includes(match.source)) {
      skipped.push({ path: match.path, reason: "found only in a standard install location, which is never used to run a program" });
      continue;
    }
    if (platform === "win32" && !WINDOWS_DIRECT_EXECUTABLE.test(match.path)) {
      skipped.push({ path: match.path, reason: "not a .exe or .com (a script would run through its interpreter, such as cmd.exe)" });
      continue;
    }
    if (platform !== "win32" && match.source !== "process_path") {
      const problem = trustCheck(match.path);
      if (problem !== null) {
        skipped.push({ path: match.path, reason: `found through the persisted PATH, but ${problem}` });
        continue;
      }
    }
    return { path: match.path, source: match.source, skipped };
  }
  return { path: null, source: null, skipped };
}

/**
 * A missing entry holds nothing; an unlistable directory (no read permission, but maybe search
 * permission) falls back to probing candidate files directly (null).
 */
function indexForListingError(error: unknown): ReadonlyMap<string, string> | null {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR" ? new Map() : null;
}

function defaultIsDirectory(dir: string): boolean {
  try {
    return fs.statSync(dir).isDirectory();
  } catch {
    return false;
  }
}

function defaultListDirectory(dir: string): string[] {
  return fs.readdirSync(dir);
}

async function defaultIsDirectoryAsync(dir: string): Promise<boolean> {
  return (await fs.promises.stat(dir)).isDirectory();
}

/** Result of `operation`, or `fallback` when it fails or does not settle within `ms`. */
async function settleWithin<T>(operation: () => Promise<T>, ms: number, fallback: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(fallback), ms);
  });
  try {
    return await Promise.race([
      Promise.resolve()
        .then(operation)
        .catch(() => fallback),
      deadline,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export function nodeArchToCpuArch(arch: string): CpuArch {
  switch (arch) {
    case "x64":
    case "arm64":
    case "ia32":
    case "arm":
    case "riscv64":
    case "ppc64":
    case "s390x":
    case "loong64":
      return arch;
    default:
      return "unknown";
  }
}

// ───────────────────────────── snapshot + locator ─────────────────────────────

export interface SearchSnapshot {
  directories: readonly SearchDirectory[];
  skippedNetworkEntries: number;
  persistedPathRead: boolean;
  persistedPathError: string | null;
  refreshedAt: string;
  /** Monotonic build time (ms) used for the TTL. */
  builtAt: number;
  /** Lazily filled directory listings, valid for this snapshot only. */
  indexes: Map<string, ReadonlyMap<string, string> | null>;
}

export interface ExecutableLocatorOptions {
  platform?: NodeJS.Platform;
  env?: Readonly<Record<string, string | undefined>>;
  homedir?: string;
  /** Synchronous checks, used only for the snapshot built by the constructor. */
  isDirectory?: (dir: string) => boolean;
  listDirectory?: (dir: string) => string[];
  /**
   * Asynchronous existence check of well-known directories for a refreshed snapshot. Defaults to
   * fs.promises.stat, or to isDirectory when only that is injected.
   */
  isDirectoryAsync?: (dir: string) => Promise<boolean>;
  /**
   * Asynchronous listing used to build and pre-index a refreshed snapshot off the event loop.
   * Defaults to fs.promises.readdir, or to listDirectory when only that is injected.
   */
  listDirectoryAsync?: (dir: string) => Promise<string[]>;
  isExecutableFile?: (file: string) => boolean;
  /** File identity used to drop the same file reached through another directory. */
  fileIdentity?: (file: string) => string | null;
  /** Ownership check for running a persisted-PATH match (POSIX); see defaultExecutionTrustCheck. */
  executionTrustCheck?: ExecutionTrustCheck;
  /** Persisted PATH loader; never expected to throw (failures are reported in the result). */
  loadPersisted?: () => Promise<PersistedPathResult>;
  /** Native host architecture used for release-asset names (osv-scanner_<goos>_<goarch>). */
  nativeArch?: () => CpuArch | null;
  ttlMs?: number;
  /** Deadline for each asynchronous directory check or listing of a refresh (default 2 s). */
  listTimeoutMs?: number;
  now?: () => number;
}

export class ExecutableLocator {
  readonly platform: NodeJS.Platform;
  /** Environment the search reads (PATH, PATHEXT, install-location variables). */
  readonly env: Readonly<Record<string, string | undefined>>;
  private readonly homedir: string;
  private readonly isDirectory: (dir: string) => boolean;
  private readonly listDirectory: (dir: string) => string[];
  private readonly isDirectoryAsync: (dir: string) => Promise<boolean>;
  private readonly listDirectoryAsync: (dir: string) => Promise<string[]>;
  private readonly isExecutableFile: (file: string) => boolean;
  private readonly fileIdentity: (file: string) => string | null;
  private readonly executionTrustCheck: ExecutionTrustCheck;
  private readonly loadPersisted: (() => Promise<PersistedPathResult>) | null;
  private readonly nativeArch: () => CpuArch | null;
  private readonly ttlMs: number;
  private readonly listTimeoutMs: number;
  private readonly now: () => number;
  private current_: SearchSnapshot;
  private loaded = false;
  private inFlight: Promise<SearchSnapshot> | null = null;

  constructor(options: ExecutableLocatorOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.env = options.env ?? process.env;
    this.homedir = options.homedir ?? os.homedir();
    this.isDirectory = options.isDirectory ?? defaultIsDirectory;
    this.listDirectory = options.listDirectory ?? defaultListDirectory;
    const injectedIsDirectory = options.isDirectory;
    this.isDirectoryAsync = options.isDirectoryAsync ?? (injectedIsDirectory ? async (dir) => injectedIsDirectory(dir) : defaultIsDirectoryAsync);
    const injectedList = options.listDirectory;
    this.listDirectoryAsync =
      options.listDirectoryAsync ?? (injectedList ? async (dir) => injectedList(dir) : (dir) => fs.promises.readdir(dir));
    this.isExecutableFile = options.isExecutableFile ?? defaultIsExecutableFile(this.platform);
    this.fileIdentity = options.fileIdentity ?? fileIdentitySync;
    this.executionTrustCheck = options.executionTrustCheck ?? defaultExecutionTrustCheck(this.platform);
    this.loadPersisted = options.loadPersisted ?? null;
    this.nativeArch = options.nativeArch ?? (() => nodeArchToCpuArch(process.arch));
    this.ttlMs = options.ttlMs ?? SEARCH_SNAPSHOT_TTL_MS;
    this.listTimeoutMs = options.listTimeoutMs ?? DIRECTORY_LIST_TIMEOUT_MS;
    this.now = options.now ?? (() => performance.now());
    // Without a persisted loader this synchronous snapshot is the complete one. With a loader,
    // responses wait for the first refresh, and until then the snapshot only serves
    // locateForExecution, which never uses well-known directories: they are not probed here, so
    // startup makes no synchronous file-system call for them.
    this.current_ = this.build(null, { isDirectory: this.isDirectory, listDirectory: this.listDirectory }, this.loadPersisted === null);
    this.loaded = this.loadPersisted === null;
  }

  private build(
    persisted: PersistedPathResult | null,
    probes: Pick<SearchEnvironment, "isDirectory" | "listDirectory">,
    wellKnown = true,
  ): SearchSnapshot {
    const plan = buildSearchPlan(
      {
        platform: this.platform,
        env: this.env,
        homedir: this.homedir,
        persisted: persisted?.entries ?? null,
        isDirectory: probes.isDirectory,
        listDirectory: probes.listDirectory,
      },
      { wellKnown },
    );
    return {
      directories: plan.directories,
      skippedNetworkEntries: plan.skippedNetworkEntries,
      persistedPathRead: persisted?.read ?? false,
      persistedPathError: persisted ? persisted.error : this.loadPersisted ? "The persisted PATH has not been read yet." : null,
      refreshedAt: new Date().toISOString(),
      builtAt: this.now(),
      indexes: new Map(),
    };
  }

  /**
   * Current snapshot without waiting. Until the first refresh: the process PATH, plus well-known
   * directories when there is no persisted loader.
   */
  snapshot(): SearchSnapshot {
    return this.current_;
  }

  /**
   * Snapshot built without synchronous file-system calls: the Python install bases are listed and
   * the well-known candidates checked asynchronously first, each bounded by the listing deadline
   * (one that does not answer in time counts as missing for this snapshot), then the plan is built
   * from those answers.
   */
  private async buildAsync(persisted: PersistedPathResult | null): Promise<SearchSnapshot> {
    const host = { platform: this.platform, env: this.env, homedir: this.homedir };
    const listings = new Map<string, string[]>();
    await Promise.all(
      pythonInstallBases(host).map(async ({ dir }) => {
        const names = await settleWithin<string[] | null>(() => this.listDirectoryAsync(dir), this.listTimeoutMs, null);
        if (names) listings.set(dir, names);
      }),
    );
    const listDirectory = (dir: string): string[] => {
      const names = listings.get(dir);
      if (!names) throw Object.assign(new Error(`${dir} was not listed`), { code: "ENOENT" });
      return names;
    };
    const existing = new Set<string>();
    await Promise.all(
      wellKnownDirectories({ ...host, persisted: null, isDirectory: () => false, listDirectory }).map(async (candidate) => {
        const dir = normalizeSearchEntry(candidate, this.platform, { env: this.env });
        if (dir === null) return;
        if (await settleWithin(() => this.isDirectoryAsync(dir), this.listTimeoutMs, false)) existing.add(dir);
      }),
    );
    return this.build(persisted, { isDirectory: (dir) => existing.has(dir), listDirectory });
  }

  /** Rebuilds the snapshot, reading the persisted PATH again. Concurrent calls share one rebuild. */
  refresh(): Promise<SearchSnapshot> {
    if (this.inFlight) return this.inFlight;
    const run = async () => {
      let persisted: PersistedPathResult | null = null;
      if (this.loadPersisted) {
        try {
          persisted = await this.loadPersisted();
        } catch (error) {
          persisted = { entries: { system: [], user: [] }, read: false, error: error instanceof Error ? error.message : String(error) };
        }
      }
      const snapshot = await this.buildAsync(persisted);
      await this.prefetchIndexes(snapshot);
      this.current_ = snapshot;
      this.loaded = true;
      return snapshot;
    };
    this.inFlight = run().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  /**
   * Snapshot for a response: waits for the first full refresh, then serves the cached snapshot and
   * revalidates it in the background once it is older than the TTL.
   */
  async current(): Promise<SearchSnapshot> {
    if (!this.loaded) return this.refresh();
    if (this.now() - this.current_.builtAt > this.ttlMs) void this.refresh();
    return this.current_;
  }

  /**
   * Lists every searched directory asynchronously, so later (synchronous) lookups never block the
   * event loop on a slow drive. A directory that does not answer within the deadline is treated
   * as empty for this snapshot instead of being probed synchronously.
   */
  private async prefetchIndexes(snapshot: SearchSnapshot): Promise<void> {
    await Promise.all(
      snapshot.directories.map(async ({ dir }) => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const deadline = new Promise<"timeout">((resolve) => {
          timer = setTimeout(() => resolve("timeout"), this.listTimeoutMs);
        });
        try {
          const names = await Promise.race([this.listDirectoryAsync(dir), deadline]);
          snapshot.indexes.set(dir, names === "timeout" ? new Map() : buildDirectoryIndex(names, this.platform));
        } catch (error) {
          snapshot.indexes.set(dir, indexForListingError(error));
        } finally {
          clearTimeout(timer);
        }
      }),
    );
  }

  private directoryIndex(snapshot: SearchSnapshot, dir: string): ReadonlyMap<string, string> | null {
    if (snapshot.indexes.has(dir)) return snapshot.indexes.get(dir) ?? null;
    let index: ReadonlyMap<string, string> | null = null;
    try {
      index = buildDirectoryIndex(this.listDirectory(dir), this.platform);
    } catch (error) {
      index = indexForListingError(error);
    }
    snapshot.indexes.set(dir, index);
    return index;
  }

  private probes(snapshot: SearchSnapshot): LocateProbes {
    return {
      platform: this.platform,
      env: this.env,
      nativeArch: this.nativeArch(),
      directoryIndex: (dir) => this.directoryIndex(snapshot, dir),
      isExecutableFile: this.isExecutableFile,
      fileIdentity: this.fileIdentity,
    };
  }

  /** Presence search over every directory of the snapshot, standard install locations included. */
  locate(name: string, snapshot: SearchSnapshot = this.current_): LocatedExecutable {
    return locateExecutable(name, snapshot.directories, this.probes(snapshot));
  }

  /**
   * The file the bridge may RUN for a tool: searched only on the process PATH and the persisted
   * PATH, never in standard install locations; see chooseForExecution for the file rules.
   */
  locateForExecution(name: string, snapshot: SearchSnapshot = this.current_): ExecutionChoice {
    const directories = snapshot.directories.filter((entry) => EXECUTION_SOURCES.includes(entry.source));
    const located = locateExecutable(name, directories, this.probes(snapshot));
    return chooseForExecution(located.matches, this.platform, this.executionTrustCheck);
  }

  /** Human-readable list of what this snapshot searched, honest about a failed persisted PATH read. */
  searchScope(snapshot: SearchSnapshot = this.current_): string {
    return describeSearchScope(snapshot, this.platform);
  }

  /** Source of a directory in the snapshot's search order, or null when it is not searched. */
  sourceOfDirectory(dir: string, snapshot: SearchSnapshot = this.current_): SearchSource | null {
    const normalized = normalizeSearchEntry(dir, this.platform, { env: {} }) ?? dir;
    const key = directoryKey(normalized, this.platform);
    return snapshot.directories.find((entry) => directoryKey(entry.dir, this.platform) === key)?.source ?? null;
  }

  status(snapshot: SearchSnapshot = this.current_): ToolSearchStatus {
    return {
      persistedPathRead: snapshot.persistedPathRead,
      persistedPathError: snapshot.persistedPathError,
      searchedDirectories: snapshot.directories.length,
      skippedNetworkEntries: snapshot.skippedNetworkEntries,
      refreshedAt: snapshot.refreshedAt,
    };
  }
}

/** Where the persisted PATH comes from on a platform, for messages. */
export function persistedPathLabel(platform: NodeJS.Platform): string {
  if (platform === "win32") return "the persisted system and user PATH (registry)";
  if (platform === "darwin") return "the persisted PATH (/etc/paths and /etc/paths.d)";
  if (platform === "linux") return "the persisted PATH (/etc/environment)";
  return "the persisted PATH";
}

/**
 * What a search snapshot covered. The persisted PATH is only named as searched when it was read;
 * a partial read (macOS: one unreadable /etc/paths.d file) is reported as such.
 */
export function describeSearchScope(status: Pick<ToolSearchStatus, "persistedPathRead" | "persistedPathError">, platform: NodeJS.Platform): string {
  const persisted = persistedPathLabel(platform);
  if (status.persistedPathRead && !status.persistedPathError) return `the bridge process PATH, ${persisted} and standard install locations`;
  if (status.persistedPathRead) {
    return `the bridge process PATH, ${persisted} (only partly read: ${status.persistedPathError}) and standard install locations`;
  }
  if (!status.persistedPathError) return `the bridge process PATH and standard install locations (${persisted} was not read)`;
  return `the bridge process PATH and standard install locations; ${persisted} could not be read (${status.persistedPathError})`;
}

export interface ProcessPathLookupOptions {
  platform?: NodeJS.Platform;
  env?: Readonly<Record<string, string | undefined>>;
  listDirectory?: (dir: string) => string[];
  isExecutableFile?: (file: string) => boolean;
  fileIdentity?: (file: string) => string | null;
}

/**
 * Synchronous lookup of a program to RUN, on the bridge process PATH only (relative, UNC and shim
 * entries skipped; on Windows only a .exe or .com). Used at startup, before the persisted PATH has
 * been read, and as the default when no locator service is injected.
 */
export function findOnProcessPathForExecution(name: string, options: ProcessPathLookupOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const listDirectory = options.listDirectory ?? defaultListDirectory;
  const { directories } = buildSearchPlan(
    { platform, env, homedir: "", persisted: null, isDirectory: () => false, listDirectory },
    { wellKnown: false },
  );
  const located = locateExecutable(name, directories, {
    platform,
    env,
    nativeArch: nodeArchToCpuArch(process.arch),
    directoryIndex: (dir) => {
      try {
        return buildDirectoryIndex(listDirectory(dir), platform);
      } catch (error) {
        return indexForListingError(error);
      }
    },
    isExecutableFile: options.isExecutableFile ?? defaultIsExecutableFile(platform),
    fileIdentity: options.fileIdentity ?? fileIdentitySync,
  });
  // Process-PATH matches are never ownership-checked, so the trust check is not consulted here.
  return chooseForExecution(located.matches, platform, () => null).path;
}
