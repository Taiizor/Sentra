import fs from "node:fs";
import { MAX_HEADER_BYTES, NATIVE_FORMATS, osLabel, parseExecutableHeader } from "./binary-info.ts";
import { pathApi, type ExecutableLocator, type SearchSnapshot } from "./executables.ts";

/**
 * The CodeQL launcher the bridge hands to `sentra codeql analyze --codeql <launcher>` when CodeQL
 * host analysis is enabled (ADR-0011). codeql is therefore an EXECUTED tool, chosen like gh:
 *
 * 1. SENTRA_CODEQL_BIN, set by the host operator and validated at startup (resolveCodeqlBinary);
 *    when set, no other codeql is ever run.
 * 2. Otherwise the locator's execution choice (ExecutableLocator.locateForExecution): the process
 *    PATH or the persisted PATH, never a standard install location. On Windows only a .exe.
 *
 * A path set in the web console is never consulted here (tool-paths.ts does not even accept one
 * for codeql any more): a path entered in the web console must never become a program the bridge
 * runs.
 *
 * Launcher rules (also enforced by the core for --codeql):
 * - Windows: a file named codeql.exe with a PE header. Never .cmd or .bat, which would run through
 *   cmd.exe.
 * - macOS and Linux: a regular file named codeql with execute permission. The official entry point
 *   `codeql` is a shell-script launcher, so a script is accepted, but only inside a CodeQL
 *   distribution.
 * - Everywhere: the file must live in a CodeQL distribution: its directory holds a `tools`
 *   directory and either `.codeqlmanifest.json` or an extractor directory with
 *   `codeql-extractor.yml`. On macOS and Linux a symlinked launcher (for example in
 *   /usr/local/bin) is followed to its real file first, and that real path is what is run.
 *
 * Validation only reads (status, at most one directory listing plus one status per listed entry,
 * a bounded header read). Nothing is executed here.
 */

export const CODEQL_BIN_VARIABLE = "SENTRA_CODEQL_BIN";

/** File-system access behind the launcher checks (injectable so every platform is tested anywhere). */
export interface CodeqlLauncherProbes {
  /** What the path leads to after following links; "missing" when nothing exists there. Throws on other errors. */
  kind(target: string): "file" | "directory" | "other" | "missing";
  /** Execute permission for the bridge user (macOS and Linux). */
  isExecutable(file: string): boolean;
  /** At most MAX_HEADER_BYTES from the start of the file. */
  readHeader(file: string): Uint8Array;
  /** Real path (links resolved); throws when it cannot be resolved. */
  realpath(file: string): string;
  /** Entry names of a directory; throws when it cannot be listed. */
  listDirectory(dir: string): string[];
}

export const HOST_CODEQL_PROBES: CodeqlLauncherProbes = {
  kind(target) {
    try {
      const stat = fs.statSync(target);
      return stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other";
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return "missing";
      throw error;
    }
  },
  isExecutable(file) {
    try {
      fs.accessSync(file, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  },
  readHeader(file) {
    const fd = fs.openSync(file, "r");
    try {
      const buffer = Buffer.alloc(MAX_HEADER_BYTES);
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
      return buffer.subarray(0, bytesRead);
    } finally {
      fs.closeSync(fd);
    }
  },
  realpath: (file) => fs.realpathSync(file),
  listDirectory: (dir) => fs.readdirSync(dir),
};

/** Entries of the distribution directory inspected for an extractor (bounded). */
const MAX_DISTRIBUTION_ENTRIES = 256;

function errorCode(error: unknown): string {
  return (error as NodeJS.ErrnoException | null)?.code ?? "error";
}

/** Why `dir` is not the root of a CodeQL distribution, or null when it is. */
export function distributionProblem(dir: string, platform: NodeJS.Platform, probes: CodeqlLauncherProbes): string | null {
  const p = pathApi(platform);
  const kindOf = (target: string) => {
    try {
      return probes.kind(target);
    } catch {
      return "missing" as const;
    }
  };
  if (kindOf(p.join(dir, "tools")) !== "directory") {
    return `${dir} is not a CodeQL distribution: it has no tools directory next to the launcher.`;
  }
  if (kindOf(p.join(dir, ".codeqlmanifest.json")) === "file") return null;
  let entries: string[];
  try {
    entries = probes.listDirectory(dir);
  } catch (error) {
    return `${dir} could not be listed (${errorCode(error)}).`;
  }
  for (const entry of entries.slice(0, MAX_DISTRIBUTION_ENTRIES)) {
    if (kindOf(p.join(dir, entry, "codeql-extractor.yml")) === "file") return null;
  }
  return `${dir} is not a CodeQL distribution: it has neither .codeqlmanifest.json nor an extractor directory with codeql-extractor.yml.`;
}

export type LauncherCheck = { ok: true; file: string } | { ok: false; problem: string };

/**
 * Checks an absolute launcher path against the launcher rules. On macOS and Linux the result is
 * the real path (symlinks followed); on Windows the path as given (realpath could turn a mapped
 * drive into a UNC path).
 */
export function checkCodeqlLauncher(file: string, platform: NodeJS.Platform, probes: CodeqlLauncherProbes = HOST_CODEQL_PROBES): LauncherCheck {
  const fail = (problem: string): LauncherCheck => ({ ok: false, problem });
  let kind: ReturnType<CodeqlLauncherProbes["kind"]>;
  try {
    kind = probes.kind(file);
  } catch (error) {
    return fail(`${file} could not be checked (${errorCode(error)}).`);
  }
  if (kind === "missing") return fail(`Nothing exists at ${file}.`);
  if (kind !== "file") return fail(`${file} is not a regular file.`);
  let real = file;
  const p = pathApi(platform);
  if (platform === "win32") {
    if (!/\.exe$/i.test(file)) {
      return fail(`${file} is not a .exe. On Windows only codeql.exe is run, never codeql.cmd or a batch file (they run through cmd.exe).`);
    }
    if (p.basename(file).toLowerCase() !== "codeql.exe") return fail(`${file} is not named codeql.exe, the launcher of a CodeQL distribution.`);
  } else {
    try {
      real = probes.realpath(file);
    } catch (error) {
      return fail(`${file} could not be resolved (${errorCode(error)}).`);
    }
    if (p.basename(real) !== "codeql") return fail(`${real} is not named codeql, the launcher at the top of a CodeQL distribution.`);
    if (!probes.isExecutable(real)) return fail(`${real} is not executable by the user the bridge runs as.`);
  }
  let header: ReturnType<typeof parseExecutableHeader>;
  try {
    header = parseExecutableHeader(probes.readHeader(real));
  } catch (error) {
    return fail(`${real} could not be read (${errorCode(error)}).`);
  }
  if (platform === "win32") {
    if (header.format !== "pe") return fail(`${real} is not a Windows (PE) executable${header.note ? ` (${header.note})` : ""}.`);
  } else if (header.format !== "script") {
    const expected = NATIVE_FORMATS[platform];
    if (expected && !expected.includes(header.format)) {
      return fail(`${real} is neither the CodeQL launcher script nor a native ${osLabel(platform)} executable${header.note ? ` (${header.note})` : ""}.`);
    }
  }
  const problem = distributionProblem(pathApi(platform).dirname(real), platform, probes);
  if (problem) return fail(problem);
  return { ok: true, file: real };
}

/**
 * Validates SENTRA_CODEQL_BIN at startup. Returns the launcher to run, null when the variable is
 * unset, or the reason it is refused (the caller turns it into a ConfigError).
 */
export function resolveCodeqlBinary(
  input: string | null,
  platform: NodeJS.Platform = process.platform,
  probes: CodeqlLauncherProbes = HOST_CODEQL_PROBES,
): { file: string | null } | { problem: string } {
  if (input === null) return { file: null };
  const raw = /^"[^"]+"$/.test(input) ? input.slice(1, -1).trim() : input;
  // oxlint-disable-next-line no-control-regex -- intentional: rejects control characters in SENTRA_CODEQL_BIN
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { problem: `${CODEQL_BIN_VARIABLE} contains control characters` };
  if (platform === "win32") {
    if (/^[\\/]{2}/.test(raw)) {
      return { problem: `${CODEQL_BIN_VARIABLE} must be a path on a local drive; UNC (\\\\server\\share) and device (\\\\?\\, \\\\.\\) paths are not accepted` };
    }
    if (!/^[A-Za-z]:[\\/]/.test(raw)) return { problem: `${CODEQL_BIN_VARIABLE} must be an absolute path such as D:\\CodeQL\\codeql.exe: ${raw}` };
  } else if (!raw.startsWith("/")) {
    return { problem: `${CODEQL_BIN_VARIABLE} must be an absolute path such as /opt/codeql/codeql: ${raw}` };
  }
  const check = checkCodeqlLauncher(pathApi(platform).normalize(raw), platform, probes);
  if (!check.ok) return { problem: `${CODEQL_BIN_VARIABLE} is refused: ${check.problem}` };
  return { file: check.file };
}

export interface LauncherChoice {
  path: string | null;
  source: "environment" | "process_path" | "persisted_system_path" | "persisted_user_path" | null;
  problem: string | null;
}

/**
 * The launcher to run now: SENTRA_CODEQL_BIN (checked again, since the file may have changed since
 * startup) or the locator's execution choice, checked against the launcher rules. Never a path set
 * in the console.
 */
export function chooseCodeqlLauncher(
  pinned: string | null,
  executables: Pick<ExecutableLocator, "locateForExecution" | "platform">,
  snapshot?: SearchSnapshot,
  probes: CodeqlLauncherProbes = HOST_CODEQL_PROBES,
): LauncherChoice {
  const platform = executables.platform;
  if (pinned) {
    const check = checkCodeqlLauncher(pinned, platform, probes);
    if (check.ok) return { path: check.file, source: "environment", problem: null };
    return { path: null, source: "environment", problem: `${CODEQL_BIN_VARIABLE}: ${check.problem} No other codeql is run while ${CODEQL_BIN_VARIABLE} is set.` };
  }
  const choice = snapshot ? executables.locateForExecution("codeql", snapshot) : executables.locateForExecution("codeql");
  if (!choice.path || !choice.source || choice.source === "well_known") {
    const skipped = choice.skipped[0];
    return {
      path: null,
      source: null,
      problem: `No codeql launcher qualifies on the bridge process PATH or the persisted PATH${skipped ? ` (${skipped.path} is not run: ${skipped.reason})` : ""}. Set ${CODEQL_BIN_VARIABLE} on the bridge host to the codeql launcher of a CodeQL distribution and restart the bridge.`,
    };
  }
  const check = checkCodeqlLauncher(choice.path, platform, probes);
  if (!check.ok) return { path: null, source: choice.source, problem: `${choice.path} is not run: ${check.problem}` };
  return { path: check.file, source: choice.source, problem: null };
}

/** LICENSE.md next to a launcher (the CodeQL terms shipped in the distribution), when it exists. */
export function licenseFileNear(launcher: string, platform: NodeJS.Platform, probes: CodeqlLauncherProbes = HOST_CODEQL_PROBES): string | null {
  const candidate = pathApi(platform).join(pathApi(platform).dirname(launcher), "LICENSE.md");
  try {
    return probes.kind(candidate) === "file" ? candidate : null;
  } catch {
    return null;
  }
}
