import fs from "node:fs";
import os from "node:os";
import type { BinaryInfo, HostInfo, ToolAvailability, ToolUsage } from "../src/types/api.ts";
import { inspectBinary, type HostArch } from "./binary-info.ts";
import {
  fileIdentity,
  isBunShimDir,
  nodeArchToCpuArch,
  pathApi,
  type ExecutableLocator,
  type ExecutableMatch,
  type ExecutionChoice,
  type LocatedExecutable,
  type SearchSnapshot,
} from "./executables.ts";
import { isArchEmulated, type HostPlatform } from "./host-platform.ts";
import { CHOCOLATEY_SHIM_NOTE, isChocolateyShim, readScoopShimTarget } from "./shims.ts";

/** Tools reported on the system page, with how the bridge actually uses each one. */
export const TOOL_NAMES = ["git", "gh", "cargo", "bun", "codeql", "semgrep", "osv-scanner", "docker"] as const;

export const TOOL_USAGE: Record<(typeof TOOL_NAMES)[number], { usage: ToolUsage; note: string }> = {
  git: {
    usage: "not_used",
    note: "Never executed. Repository metadata (HEAD, branch, remotes) is parsed directly from .git files, so no repository hook, alias or config can run.",
  },
  gh: {
    usage: "executed",
    note: "Executed as `gh auth token --hostname <GitHub host>` to read the GitHub CLI credential when no token is stored in the console and GITHUB_TOKEN/GH_TOKEN are unset. Only a match on the process PATH or the persisted PATH is run (on Windows only a .exe or .com), never one from a standard install location.",
  },
  cargo: {
    usage: "not_used",
    note: "Not used by the bridge. The sentra core binary is taken from SENTRA_BIN, target/release, target/debug or the bridge process PATH; the bridge never builds it.",
  },
  bun: {
    usage: "runtime",
    // How the path was chosen is appended per row (BUN_MATCHED_NOTE, BUN_UNMATCHED_NOTE, UNMATCHED_SHIM_NOTE).
    note: "Runs this bridge process.",
  },
  codeql: {
    usage: "presence_only",
    note: "Never executed. Scans and topology reports only record whether it is installed; their language probe is `sentra codeql`, which counts files by extension.",
  },
  semgrep: {
    usage: "not_used",
    note: "Not run by the bridge itself. An installed semgrep plugin adapter (see examples/adapters) started from the Plugins tab runs it; the adapter looks semgrep up on the PATH the bridge passes on (its own process PATH), not at the path shown here.",
  },
  "osv-scanner": {
    usage: "not_used",
    note: "Not used. Dependency advisories come from the OSV.dev API for lockfiles parsed by `sentra inventory`.",
  },
  docker: {
    usage: "not_used",
    note: "Not used by the bridge.",
  },
};

export interface HostToolsDeps {
  executables: ExecutableLocator;
  hostPlatform: HostPlatform;
}

export async function hostArch(deps: HostToolsDeps): Promise<HostArch> {
  return { platform: deps.hostPlatform.platform, nativeArch: (await deps.hostPlatform.nativeArch()) ?? deps.hostPlatform.processArch };
}

function samePath(a: string, b: string, platform: NodeJS.Platform): boolean {
  return platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

export interface BunRuntime {
  /** Path reported for the runtime: the located install that is the running file, else process.execPath. */
  path: string;
  /** The located `bun` that is the same file as the running executable, if any. */
  match: ExecutableMatch | null;
  /** Device + inode of the running executable; null when it cannot be read. */
  identity: string | null;
  /** Set when process.execPath is a bun-node shim that no located install matches. */
  note: string | null;
}

export const UNMATCHED_SHIM_NOTE =
  "process.execPath is the temporary bun-node shim of `bun run`, and no Bun in the searched directories is the same file (the shim may be a copy, or Bun was started from a directory outside the search), so the installation it came from is unknown. The path shown is the shim.";

/** Appended to the bun usage note when the running executable matched a located install. */
export const BUN_MATCHED_NOTE =
  "The path is the installation the running executable was started from (matched by file identity, through a Scoop shim's target where there is one), not the temporary bun-node shim that `bun run` puts first on PATH.";

/** Appended when nothing matched and the running executable is not a bun-node shim. */
export const BUN_UNMATCHED_NOTE =
  "The path is the running executable (process.execPath). No Bun in the searched directories was matched to it by file identity, so it is reported as it is, not as an installation found by the search.";

/** How the bun row's path was chosen, appended to its usage note. */
export function bunRuntimeNote(runtime: Pick<BunRuntime, "match" | "note">): string {
  if (runtime.match) return BUN_MATCHED_NOTE;
  return runtime.note ?? BUN_UNMATCHED_NOTE;
}

/**
 * The Bun executable running the bridge, tied to a located install by file identity (device +
 * inode, links followed), never by comparing path strings:
 * - Windows: `bun run` starts scripts through hard links in a temporary bun-node-<hex> directory,
 *   and process.execPath names that link.
 * - macOS and Linux: process.execPath is already resolved (Homebrew /opt/homebrew/bin/bun becomes
 *   .../Cellar/bun/<version>/bin/bun), so the PATH entry differs from it as a string.
 * - Scoop: the located `shims\bun.exe` is a copy of Scoop's shim.exe that starts the executable
 *   named in `shims\bun.shim`; that target, not the shim, is compared with the running file.
 * Only an identity match is reported as the install; another Bun that merely exists is not.
 */
export async function resolveBunRuntime(execPath: string, platform: NodeJS.Platform, matches: readonly ExecutableMatch[]): Promise<BunRuntime> {
  const identity = await fileIdentity(execPath);
  if (identity) {
    for (const match of matches) {
      if ((await installIdentity(match.path, platform)) === identity) return { path: match.path, match, identity, note: null };
    }
  }
  const shim = isBunShimDir(pathApi(platform).dirname(execPath), platform);
  return { path: execPath, match: null, identity, note: shim ? UNMATCHED_SHIM_NOTE : null };
}

/** File identity of what a located executable runs: a Scoop shim's target, else the file itself (links followed). */
async function installIdentity(file: string, platform: NodeJS.Platform): Promise<string | null> {
  return fileIdentity((await readScoopShimTarget(file, platform)) ?? file);
}

/** File-system calls behind resolvedTarget (injectable so every platform's rules can be tested anywhere). */
export interface LinkProbes {
  realpath(file: string): Promise<string>;
  readlink(file: string): Promise<string>;
  lstat(file: string): Promise<{ isSymbolicLink(): boolean }>;
}

const FS_LINK_PROBES: LinkProbes = {
  realpath: (file) => fs.promises.realpath(file),
  readlink: (file) => fs.promises.readlink(file),
  lstat: (file) => fs.promises.lstat(file),
};

/** Bound on the components walked by hasLinkComponent (deeper paths are not expected). */
const MAX_PATH_COMPONENTS = 256;

/**
 * True when the path or one of its parent directories is a symlink (or, on Windows, a junction or
 * another reparse point lstat reports as a link). True as well when a component cannot be checked,
 * since the canonical path then differs for a reason that cannot be told apart from a link.
 */
async function hasLinkComponent(file: string, platform: NodeJS.Platform, probes: LinkProbes): Promise<boolean> {
  const p = pathApi(platform);
  let current = file;
  for (let depth = 0; depth < MAX_PATH_COMPONENTS; depth += 1) {
    try {
      if ((await probes.lstat(current)).isSymbolicLink()) return true;
    } catch {
      return true;
    }
    const parent = p.dirname(current);
    if (parent === current) return false;
    current = parent;
  }
  return true;
}

/**
 * The target a located path leads to through a symlink or junction, or null when it leads nowhere
 * else. The canonical path alone is not enough: on Windows it also expands 8.3 short names
 * (C:\PROGRA~1 becomes C:\Program Files) and resolves subst and mapped drives, and on
 * case-insensitive file systems it can differ in letter case, none of which is a link. A target is
 * therefore reported only when a component of the path is a link.
 */
export async function resolvedTarget(file: string, platform: NodeJS.Platform, probes: LinkProbes = FS_LINK_PROBES): Promise<string | null> {
  let real: string;
  try {
    real = await probes.realpath(file);
  } catch {
    if (platform !== "win32") return null;
    // App Execution Aliases cannot be opened, but their link target can be read.
    try {
      const target = await probes.readlink(file);
      return pathApi(platform).isAbsolute(target) && !samePath(target, file, platform) ? target : null;
    } catch {
      return null;
    }
  }
  if (samePath(real, file, platform)) return null;
  return (await hasLinkComponent(file, platform, probes)) ? real : null;
}

interface ToolsCacheEntry {
  execPath: string;
  promise: Promise<ToolAvailability[]>;
}

const toolsCache = new WeakMap<SearchSnapshot, ToolsCacheEntry>();
const runtimeCache = new WeakMap<SearchSnapshot, Promise<BunRuntime>>();

/** Bun runtime of the bridge for a snapshot (cached per snapshot for the real process.execPath). */
export function bunRuntime(deps: HostToolsDeps, snapshot: SearchSnapshot, execPath = process.execPath): Promise<BunRuntime> {
  let cached = runtimeCache.get(snapshot);
  if (!cached || execPath !== process.execPath) {
    cached = resolveBunRuntime(execPath, deps.executables.platform, deps.executables.locate("bun", snapshot).matches);
    if (execPath === process.execPath) runtimeCache.set(snapshot, cached);
  }
  return cached;
}

const WELL_KNOWN_ONLY_REASON = "found only in a standard install location, which is never used to run a program";

/**
 * Which gh file the bridge actually runs, appended to the gh usage note. The presence search may
 * report a file that is not run: a batch script on Windows, a standard install location, or on
 * macOS/Linux a persisted-PATH file with unsafe ownership.
 */
export function ghExecutionNote(located: LocatedExecutable, choice: ExecutionChoice, platform: NodeJS.Platform): string | null {
  if (!located.path && !choice.path) return null;
  if (choice.path && located.path && samePath(choice.path, located.path, platform)) return "The file shown is the one run.";
  const firstSkipped = choice.skipped[0] ?? (located.path ? { path: located.path, reason: WELL_KNOWN_ONLY_REASON } : null);
  const skippedText = firstSkipped ? `${firstSkipped.path} is not run: ${firstSkipped.reason}` : null;
  if (choice.path) return `The file run is ${choice.path}${skippedText ? `; ${skippedText}` : ""}.`;
  return `Nothing is run on this host${skippedText ? `: ${skippedText}` : ""}.`;
}

async function describeTool(name: (typeof TOOL_NAMES)[number], deps: HostToolsDeps, snapshot: SearchSnapshot, host: HostArch, execPath: string): Promise<ToolAvailability> {
  const { executables } = deps;
  const platform = executables.platform;
  const located = executables.locate(name, snapshot);
  const usage = TOOL_USAGE[name];
  let filePath = located.path;
  let source = located.source;
  let onProcessPath = located.onProcessPath;
  let shadowed = located.shadowed;
  let usageNote = usage.note;
  if (name === "bun") {
    const runtime = await bunRuntime(deps, snapshot, execPath);
    filePath = runtime.path;
    source = runtime.match?.source ?? executables.sourceOfDirectory(pathApi(platform).dirname(runtime.path), snapshot);
    onProcessPath = source === "process_path";
    // Other installations: located matches that are not the running file.
    const others: string[] = [];
    for (const entry of located.matches) {
      if (entry === runtime.match) continue;
      if (runtime.identity !== null && (await installIdentity(entry.path, platform)) === runtime.identity) continue;
      others.push(entry.path);
    }
    shadowed = others.slice(0, 4);
    usageNote = `${usage.note} ${bunRuntimeNote(runtime)}`;
  } else if (name === "gh") {
    const executionNote = ghExecutionNote(located, executables.locateForExecution(name, snapshot), platform);
    if (executionNote) usageNote = `${usage.note} ${executionNote}`;
  }
  const resolved = filePath ? await describeFile(filePath, host, executables.env, platform) : null;
  return {
    name,
    available: filePath !== null,
    path: filePath,
    resolvedPath: resolved?.resolvedPath ?? null,
    resolvedVia: resolved?.resolvedVia ?? null,
    source,
    onProcessPath,
    binary: resolved?.binary ?? null,
    usage: usage.usage,
    usageNote,
    shadowed,
  };
}

function joinNotes(...notes: (string | null)[]): string | null {
  const present = notes.filter((note): note is string => !!note);
  return present.length > 0 ? present.join("; ") : null;
}

/**
 * Header and resolved target of a located file. A Scoop shim is reported with its target (the
 * header is read from the target, since the shim is the same generic shim.exe for every app); a
 * Chocolatey shim cannot be resolved and says so; anything else reports its symlink target.
 */
export async function describeFile(
  file: string,
  host: HostArch,
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): Promise<{ binary: BinaryInfo; resolvedPath: string | null; resolvedVia: ToolAvailability["resolvedVia"] }> {
  const scoopTarget = await readScoopShimTarget(file, platform);
  if (scoopTarget) {
    const binary = await inspectBinary(scoopTarget, host);
    return {
      binary: { ...binary, note: joinNotes(`Scoop shim for ${scoopTarget}; the header shown is the target's`, binary.note) },
      resolvedPath: scoopTarget,
      resolvedVia: "scoop_shim",
    };
  }
  const [binary, resolvedPath] = await Promise.all([inspectBinary(file, host), resolvedTarget(file, platform)]);
  const note = isChocolateyShim(file, env, platform) ? joinNotes(binary.note, CHOCOLATEY_SHIM_NOTE) : binary.note;
  return { binary: { ...binary, note }, resolvedPath, resolvedVia: resolvedPath ? "link" : null };
}

/**
 * Availability of the reported tools on the bridge host: located through the search snapshot
 * (process PATH, persisted PATH, well-known directories), headers read, nothing executed. Cached
 * per snapshot, so a newly installed tool shows up after the next snapshot refresh (about 60 s).
 */
export async function describeTools(deps: HostToolsDeps, options: { snapshot?: SearchSnapshot; execPath?: string } = {}): Promise<ToolAvailability[]> {
  const snapshot = options.snapshot ?? (await deps.executables.current());
  const execPath = options.execPath ?? process.execPath;
  const cached = toolsCache.get(snapshot);
  if (cached && cached.execPath === execPath) return cached.promise;
  const promise = (async () => {
    const host = await hostArch(deps);
    return Promise.all(TOOL_NAMES.map((name) => describeTool(name, deps, snapshot, host, execPath)));
  })();
  toolsCache.set(snapshot, { execPath, promise });
  promise.catch(() => toolsCache.delete(snapshot));
  return promise;
}

/**
 * Upgrades a tool entry stored by an older bridge ({name, available, path}) to the current shape,
 * so persisted topology reports stay readable. Fields that were never measured stay null/false.
 */
export function normalizeStoredTool(raw: unknown): ToolAvailability | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const entry = raw as Record<string, unknown>;
  if (typeof entry.name !== "string") return null;
  const known = TOOL_USAGE[entry.name as (typeof TOOL_NAMES)[number]];
  const usage = typeof entry.usage === "string" ? (entry.usage as ToolUsage) : (known?.usage ?? "not_used");
  const resolvedPath = typeof entry.resolvedPath === "string" ? entry.resolvedPath : null;
  return {
    name: entry.name,
    available: entry.available === true,
    path: typeof entry.path === "string" ? entry.path : null,
    resolvedPath,
    resolvedVia: resolvedPath === null ? null : entry.resolvedVia === "scoop_shim" ? "scoop_shim" : "link",
    source: typeof entry.source === "string" ? (entry.source as ToolAvailability["source"]) : null,
    onProcessPath: entry.onProcessPath === true,
    binary: entry.binary && typeof entry.binary === "object" ? (entry.binary as BinaryInfo) : null,
    usage,
    usageNote: typeof entry.usageNote === "string" ? entry.usageNote : (known?.note ?? ""),
    shadowed: Array.isArray(entry.shadowed) ? entry.shadowed.filter((item): item is string => typeof item === "string") : [],
  };
}

/** Host facts for the system page; awaits the snapshot so runtimePath is matched to a located install. */
export async function collectHostInfo(deps: HostToolsDeps, cliQueued: number): Promise<HostInfo> {
  const { hostPlatform } = deps;
  const total = os.totalmem();
  const snapshot = await deps.executables.current();
  const [nativeArch, osName, memory, runtime] = await Promise.all([
    hostPlatform.nativeArch(),
    hostPlatform.osName(),
    hostPlatform.availableMemory(total),
    bunRuntime(deps, snapshot),
  ]);
  const cpus = os.cpus();
  return {
    hostname: os.hostname(),
    platform: hostPlatform.platform,
    release: os.release(),
    osName,
    arch: os.arch(),
    nativeArch,
    archEmulated: isArchEmulated(hostPlatform.platform, nodeArchToCpuArch(os.arch()), nativeArch),
    cpuModel: cpus[0]?.model ?? null,
    cpuCount: cpus.length,
    loadAverage: hostPlatform.platform === "win32" ? null : os.loadavg(),
    totalMemoryBytes: total,
    availableMemoryBytes: memory.availableBytes,
    memorySource: memory.source,
    uptimeSeconds: Math.round(os.uptime()),
    processRssBytes: process.memoryUsage().rss,
    bunVersion: Bun.version,
    runtimePath: runtime.path,
    runtimePathNote: runtime.note,
    cliQueued,
    sampledAt: new Date().toISOString(),
  };
}
