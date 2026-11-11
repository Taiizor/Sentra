import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { API_CONTRACT_VERSION, type BinaryInfo, type CpuArch, type SetToolPathResponse, type SystemStatus, type ToolAvailability } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { describeBinary, parseExecutableHeader, windowsScriptNote, type HostArch } from "../binary-info.ts";
import { ConfigError, loadConfig, parseTokenGrants, resolveGhBinary, type GhBinaryProbes, type ServerConfig } from "../config.ts";
import { openWebDb } from "../db.ts";
import { ExecutableLocator } from "../executables.ts";
import { GH_TOKEN_TIMEOUT_MS, GitHubService } from "../github.ts";
import { HostPlatform } from "../host-platform.ts";
import { codeqlLauncherChoice, describeTools, GH_PINNED_NOTE, hostToolsDeps, normalizeStoredTool, reportedToolLocation, TOOL_NAMES, type HostToolsDeps } from "../host-tools.ts";
import type { Router } from "../http.ts";
import { createApp, handleRequest } from "../main.ts";
import { SecretStore } from "../secrets.ts";
import { SettingsStore } from "../services/settings-store.ts";
import {
  boundedToolPathProbes,
  checkToolPath,
  CONFIGURABLE_TOOLS,
  GH_PATH_HINT,
  CODEQL_PATH_HINT,
  ignoredStoredToolPaths,
  GH_PINNED_HINT,
  hostToolPathProbes,
  MAX_TOOL_PATH_LENGTH,
  NO_CONFIGURED_TOOL_PATHS,
  normalizeToolPathInput,
  parseStoredToolPaths,
  PROBE_TIMEOUT_MS,
  slowPathProblem,
  TOOL_PATHS_SETTING,
  ToolPathStore,
  type PathKind,
  type StoredToolPath,
  type ToolPathCheck,
  type ToolPathProbes,
} from "../tool-paths.ts";
import { elfHeader, hostExecutableName, hostNativeHeader, machoHeader, peHeader, ELF_ARM64, ELF_X64, MACHO_ARM64, MACHO_X64, PE_X64 } from "./native-header.ts";

// Canonical, so paths built here compare equal to the paths the code under test reports.
const TEST_ROOT = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentra-tool-paths-")));
const openDbs: { close(): void }[] = [];

afterAll(() => {
  for (const db of openDbs) {
    try {
      db.close();
    } catch {
      // already closed
    }
  }
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(TEST_ROOT, prefix));
}

const POSIX_SCRIPT = new TextEncoder().encode("#!/bin/sh\nexit 0\n");
const PE_ARM32 = 0x01c4;

// ───────────────────────────── in-memory file system ─────────────────────────────

interface FakeEntry {
  kind: PathKind;
  bytes?: Uint8Array;
  /** macOS/Linux execute permission (default true). */
  exec?: boolean;
}

interface FakeFs {
  probes: ToolPathProbes;
  /** Every path handed to kind() or listDirectory(), to prove some inputs are refused before any file-system call. */
  touched: string[];
}

function fakeFs(
  platform: NodeJS.Platform,
  nativeArch: CpuArch,
  entries: Record<string, FakeEntry>,
  options: { env?: Record<string, string>; unlistable?: string[]; homedir?: string } = {},
): FakeFs {
  const p = platform === "win32" ? path.win32 : path.posix;
  const key = (value: string) => (platform === "win32" ? value.toLowerCase() : value);
  const table = new Map(Object.entries(entries).map(([file, entry]) => [key(file), { file, entry }]));
  const touched: string[] = [];
  const missing = (target: string) => Object.assign(new Error(`ENOENT: ${target}`), { code: "ENOENT" });
  const probes: ToolPathProbes = {
    platform,
    env: options.env ?? {},
    homedir: options.homedir ?? (platform === "win32" ? "C:\\Users\\u" : "/home/u"),
    nativeArch,
    kind: async (target) => {
      touched.push(target);
      const found = table.get(key(target));
      if (!found) throw missing(target);
      return found.entry.kind;
    },
    listDirectory: async (dir) => {
      touched.push(dir);
      if (options.unlistable?.includes(dir)) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      if (!table.has(key(dir))) throw missing(dir);
      return [...table.values()].filter(({ file }) => key(p.dirname(file)) === key(dir) && file !== dir).map(({ file }) => p.basename(file));
    },
    isExecutable: async (file) => table.get(key(file))?.entry.exec !== false,
    inspect: async (file, host: HostArch): Promise<BinaryInfo> => {
      const scriptNote = windowsScriptNote(file, host.platform);
      if (scriptNote) return { format: "script", architectures: [], compatibility: "script", note: scriptNote };
      return describeBinary(parseExecutableHeader(table.get(key(file))?.entry.bytes ?? new Uint8Array()), host);
    },
  };
  return { probes, touched };
}

const dir = (): FakeEntry => ({ kind: "directory" });
const file = (bytes: Uint8Array, exec = true): FakeEntry => ({ kind: "file", bytes, exec });

function problemOf(check: ToolPathCheck): string {
  if (check.ok) throw new Error(`expected a refusal, got ${check.file}`);
  return check.problem;
}

function accepted(check: ToolPathCheck): Extract<ToolPathCheck, { ok: true }> {
  if (!check.ok) throw new Error(`expected acceptance, got: ${check.problem}`);
  return check;
}

// ───────────────────────────── input normalisation ─────────────────────────────

describe("tool path input", () => {
  test("Windows: drive-rooted paths only; quotes and trailing separators are removed, nothing is expanded", () => {
    expect(normalizeToolPathInput('  "D:\\CodeQL\\"  ', "win32", "C:\\Users\\u")).toEqual({ path: "D:\\CodeQL" });
    expect(normalizeToolPathInput("D:/CodeQL/codeql.exe", "win32", "C:\\Users\\u")).toEqual({ path: "D:\\CodeQL\\codeql.exe" });
    expect(normalizeToolPathInput("C:\\", "win32", "C:\\Users\\u")).toEqual({ path: "C:\\" });
    const problem = (raw: string) => {
      const result = normalizeToolPathInput(raw, "win32", "C:\\Users\\u");
      if (!("problem" in result)) throw new Error(`accepted ${raw}`);
      return result.problem;
    };
    for (const network of ["\\\\server\\share\\codeql.exe", "//server/share/codeql.exe", "\\\\?\\C:\\CodeQL\\codeql.exe", "\\\\.\\pipe\\codeql"]) {
      expect(problem(network)).toContain("Network (\\\\server\\share) and device");
    }
    expect(problem("C:codeql.exe")).toContain('"C:" without a backslash is relative to the current folder of drive C:');
    expect(problem("codeql.exe")).toContain("starts with a drive letter");
    expect(problem("\\tools\\codeql.exe")).toContain("starts with a drive letter");
    expect(problem("~\\bin\\codeql.exe")).toContain("starts with a drive letter");
    expect(problem("%LOCALAPPDATA%\\Programs\\codeql.exe")).toContain("such as %LOCALAPPDATA% are not expanded");
    expect(problem("%USERPROFILE%\\codeql")).toContain("such as %USERPROFILE% are not expanded");
    expect(problem("D:\\tools\\semgrep.exe:stream")).toContain("characters Windows does not allow");
    expect(problem("D:\\tools\\sem*grep.exe")).toContain("characters Windows does not allow");
    expect(problem("D:\\to\tols\\semgrep.exe")).toContain("control characters");
    expect(problem("D:\\tools\\sem\u0085grep.exe")).toContain("control characters");
    expect(problem("   ")).toContain("Enter the absolute path");
    expect(problem(`D:\\${"a".repeat(MAX_TOOL_PATH_LENGTH)}`)).toContain(`longer than ${MAX_TOOL_PATH_LENGTH} characters`);
  });

  test("macOS and Linux: absolute paths, a leading ~ is the bridge user's home, ~user and variables are not expanded", () => {
    expect(normalizeToolPathInput("~/bin/semgrep", "linux", "/home/u")).toEqual({ path: "/home/u/bin/semgrep" });
    expect(normalizeToolPathInput("~", "darwin", "/Users/u")).toEqual({ path: "/Users/u" });
    expect(normalizeToolPathInput("/opt//homebrew/bin/", "darwin", "/Users/u")).toEqual({ path: "/opt/homebrew/bin" });
    expect(normalizeToolPathInput("/opt/tools/../bin/semgrep", "linux", "/home/u")).toEqual({ path: "/opt/bin/semgrep" });
    const problem = (raw: string) => {
      const result = normalizeToolPathInput(raw, "linux", "/home/u");
      if (!("problem" in result)) throw new Error(`accepted ${raw}`);
      return result.problem;
    };
    expect(problem("~bob/bin/semgrep")).toContain("~user is not");
    expect(problem("$HOME/bin/semgrep")).toContain("such as $HOME are not expanded");
    expect(problem("${SEMGREP_HOME}/bin/semgrep")).toContain("such as ${SEMGREP_HOME} are not expanded");
    expect(problem("bin/semgrep")).toContain("starts with /");
    expect(problem("./semgrep")).toContain("starts with /");
    expect(problem("/opt/sem\u0000grep")).toContain("control characters");
  });

  test("the length limit applies to the path that is stored, after ~ is expanded", () => {
    const home = "/home/sentra-bridge";
    // 1020 characters typed, 1038 once ~ is expanded: refused, instead of being stored and then dropped when read back.
    const typed = `~/${"a".repeat(1018)}`;
    expect(typed.length).toBeLessThanOrEqual(MAX_TOOL_PATH_LENGTH);
    expect(normalizeToolPathInput(typed, "linux", home)).toEqual({
      problem: `The path is longer than ${MAX_TOOL_PATH_LENGTH} characters once ~ is expanded to ${home}.`,
    });
    const fits = `~/${"a".repeat(MAX_TOOL_PATH_LENGTH - home.length - 1)}`;
    const accepted = normalizeToolPathInput(fits, "darwin", home);
    expect("path" in accepted && accepted.path.length).toBe(MAX_TOOL_PATH_LENGTH);
    expect(parseStoredToolPaths({ semgrep: { path: "path" in accepted ? accepted.path : "" } }).semgrep?.path).toBe("path" in accepted ? accepted.path : "");
  });
});

// ───────────────────────────── validation per platform ─────────────────────────────

describe("tool path validation (nothing is executed)", () => {
  test("Windows: a folder is searched like PATH (PATHEXT, never the extension-less launcher)", async () => {
    const fake = fakeFs("win32", "x64", {
      "D:\\Semgrep": dir(),
      "D:\\Semgrep\\semgrep": file(POSIX_SCRIPT),
      "D:\\Semgrep\\SEMGREP.EXE": file(peHeader(PE_X64)),
    });
    const check = accepted(await checkToolPath("semgrep", '"D:\\semgrep\\"', fake.probes));
    expect(check).toMatchObject({ input: "D:\\semgrep", file: "D:\\semgrep\\SEMGREP.EXE", warning: null });
    expect(check.binary).toMatchObject({ format: "pe", compatibility: "native" });
  });

  test("Windows: a file needs a PATHEXT extension; a .cmd is accepted because nothing is run", async () => {
    const fake = fakeFs(
      "win32",
      "x64",
      {
        "D:\\tools": dir(),
        "D:\\tools\\semgrep.py": file(POSIX_SCRIPT),
        "D:\\tools\\semgrep": file(POSIX_SCRIPT),
        "D:\\tools\\semgrep.cmd": file(new TextEncoder().encode("@echo off\r\n")),
      },
      { env: { PATHEXT: ".COM;.EXE;.BAT;.CMD" } },
    );
    expect(problemOf(await checkToolPath("semgrep", "D:\\tools\\semgrep.py", fake.probes))).toBe(
      "semgrep.py is not a program Windows can start: its extension .py is not one of .com, .exe, .bat, .cmd (PATHEXT).",
    );
    expect(problemOf(await checkToolPath("semgrep", "D:\\tools\\semgrep", fake.probes))).toBe(
      "semgrep is not a program Windows can start: it has no extension (it needs one of .com, .exe, .bat, .cmd, from PATHEXT).",
    );
    const script = accepted(await checkToolPath("semgrep", "D:\\tools\\semgrep.cmd", fake.probes));
    expect(script.binary).toMatchObject({ format: "script", compatibility: "script" });
    expect(script.warning).toBeNull();
  });

  test("Windows: a binary for another OS or a 32-bit Arm binary on Windows on Arm is refused with both sides named", async () => {
    const fake = fakeFs("win32", "x64", { "D:\\linux\\semgrep.exe": file(elfHeader(ELF_X64)) });
    expect(problemOf(await checkToolPath("semgrep", "D:\\linux\\semgrep.exe", fake.probes))).toBe(
      "D:\\linux\\semgrep.exe is a Linux (ELF) binary built for x64, and this bridge host is Windows on x64, so it cannot run here.",
    );
    const arm = fakeFs("win32", "arm64", { "D:\\arm\\docker.exe": file(peHeader(PE_ARM32)) });
    const problem = problemOf(await checkToolPath("docker", "D:\\arm\\docker.exe", arm.probes));
    expect(problem).toContain("is a Windows (PE) binary built for arm, and this bridge host is Windows on arm64, so it cannot run here");
    expect(problem).toContain("Windows 11 24H2");
    // An x64 binary on Windows on Arm runs under emulation and is accepted.
    const emulated = fakeFs("win32", "arm64", { "D:\\x64\\docker.exe": file(peHeader(PE_X64)) });
    expect(accepted(await checkToolPath("docker", "D:\\x64\\docker.exe", emulated.probes)).binary.compatibility).toBe("emulated");
  });

  test("Windows: release-asset names count as the tool; another name only warns", async () => {
    const fake = fakeFs("win32", "x64", {
      "D:\\osv": dir(),
      "D:\\osv\\osv-scanner_windows_amd64.exe": file(peHeader(PE_X64)),
      "D:\\tools\\scanner.exe": file(peHeader(PE_X64)),
    });
    expect(accepted(await checkToolPath("osv-scanner", "D:\\osv", fake.probes)).file).toBe("D:\\osv\\osv-scanner_windows_amd64.exe");
    expect(accepted(await checkToolPath("osv-scanner", "D:\\osv\\osv-scanner_windows_amd64.exe", fake.probes)).warning).toBeNull();
    const renamed = accepted(await checkToolPath("semgrep", "D:\\tools\\scanner.exe", fake.probes));
    expect(renamed.warning).toBe("The file name scanner.exe does not look like semgrep. The path was saved; check that it is the right program.");
  });

  test("Windows: a folder without the tool names what was looked for and suggests the subfolder that has it", async () => {
    const fake = fakeFs("win32", "x64", {
      "D:\\Semgrep": dir(),
      "D:\\Semgrep\\semgrep": dir(),
      "D:\\Semgrep\\semgrep\\semgrep.exe": file(peHeader(PE_X64)),
    });
    expect(problemOf(await checkToolPath("semgrep", "D:\\Semgrep", fake.probes))).toBe(
      "No semgrep executable in D:\\Semgrep (looked for semgrep.com, semgrep.exe, semgrep.bat, semgrep.cmd). D:\\Semgrep\\semgrep\\semgrep.exe exists: enter D:\\Semgrep\\semgrep or the file itself.",
    );
    expect(problemOf(await checkToolPath("semgrep", "D:\\nowhere\\semgrep.exe", fake.probes))).toBe("Nothing exists at D:\\nowhere\\semgrep.exe.");
  });

  test("Windows: network, device and drive-relative paths are refused before any file-system call", async () => {
    const fake = fakeFs("win32", "x64", {});
    for (const raw of ["\\\\server\\share\\semgrep", "\\\\?\\UNC\\server\\share", "\\\\.\\C:\\semgrep.exe", "C:semgrep.exe", "semgrep"]) {
      expect((await checkToolPath("semgrep", raw, fake.probes)).ok).toBe(false);
    }
    expect(fake.touched).toEqual([]);
  });

  test("Linux arm64: release assets for the native architecture, execute permission, foreign architectures", async () => {
    const fake = fakeFs(
      "linux",
      "arm64",
      {
        "/opt/osv": dir(),
        "/opt/osv/osv-scanner_linux_arm64": file(elfHeader(ELF_ARM64)),
        "/opt/x64/semgrep": file(elfHeader(ELF_X64)),
        "/opt/noexec": dir(),
        "/opt/noexec/semgrep": file(elfHeader(ELF_ARM64), false),
        "/opt/win/semgrep": file(peHeader(PE_X64)),
        "/opt/scripts/semgrep": file(POSIX_SCRIPT),
        "/opt/fifo": { kind: "other" },
        "/srv/locked": dir(),
        "/srv/locked/docker": file(elfHeader(ELF_ARM64)),
        "/home/u/bin/semgrep": file(elfHeader(ELF_ARM64)),
      },
      { unlistable: ["/srv/locked"] },
    );
    expect(accepted(await checkToolPath("osv-scanner", "/opt/osv/", fake.probes))).toMatchObject({ input: "/opt/osv", file: "/opt/osv/osv-scanner_linux_arm64" });
    const foreign = problemOf(await checkToolPath("semgrep", "/opt/x64/semgrep", fake.probes));
    expect(foreign).toContain("/opt/x64/semgrep is a Linux (ELF) binary built for x64, and this bridge host is Linux on arm64, so it cannot run here");
    expect(foreign).toContain("binfmt_misc/qemu-user");
    expect(problemOf(await checkToolPath("semgrep", "/opt/noexec/semgrep", fake.probes))).toBe(
      "/opt/noexec/semgrep is not executable by the user the bridge runs as (it lacks execute permission; chmod +x adds it).",
    );
    expect(problemOf(await checkToolPath("semgrep", "/opt/noexec", fake.probes))).toBe(
      "No semgrep executable in /opt/noexec (looked for semgrep). /opt/noexec/semgrep exists but is not executable by the user the bridge runs as.",
    );
    expect(problemOf(await checkToolPath("semgrep", "/opt/win/semgrep", fake.probes))).toContain("is a Windows (PE) binary built for x64, and this bridge host is Linux on arm64");
    // Scripts are fine on macOS and Linux: nothing is run, the header is only read.
    expect(accepted(await checkToolPath("semgrep", "/opt/scripts/semgrep", fake.probes)).binary.format).toBe("script");
    expect(problemOf(await checkToolPath("semgrep", "/opt/fifo", fake.probes))).toBe("/opt/fifo is neither a regular file nor a folder (it is a device, pipe or socket).");
    // A folder that cannot be listed is probed by candidate name.
    expect(accepted(await checkToolPath("docker", "/srv/locked", fake.probes)).file).toBe("/srv/locked/docker");
    expect(accepted(await checkToolPath("semgrep", "~/bin/semgrep", fake.probes)).input).toBe("/home/u/bin/semgrep");
  });

  test("macOS on Apple silicon: x64 runs under Rosetta 2, universal binaries are native, ELF is refused", async () => {
    const fake = fakeFs("darwin", "arm64", {
      "/opt/homebrew/bin": dir(),
      "/opt/homebrew/bin/semgrep": file(machoHeader(MACHO_ARM64)),
      "/usr/local/bin/docker": file(machoHeader(MACHO_X64)),
      "/opt/linux/git": file(elfHeader(ELF_ARM64)),
    });
    expect(accepted(await checkToolPath("semgrep", "/opt/homebrew/bin/", fake.probes)).file).toBe("/opt/homebrew/bin/semgrep");
    expect(accepted(await checkToolPath("docker", "/usr/local/bin/docker", fake.probes)).binary.compatibility).toBe("emulated");
    expect(problemOf(await checkToolPath("git", "/opt/linux/git", fake.probes))).toBe(
      "/opt/linux/git is a Linux (ELF) binary built for arm64, and this bridge host is macOS on arm64, so it cannot run here.",
    );
  });
});

// ───────────────────────────── slow or unreachable drives ─────────────────────────────

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("tool path checks on slow or unreachable drives", () => {
  test("a folder that does not answer in time is reported as such, not searched name by name or called empty", async () => {
    const fake = fakeFs("win32", "x64", { "Z:\\Semgrep": dir(), "Z:\\Semgrep\\semgrep.exe": file(peHeader(PE_X64)) });
    const kinds: string[] = [];
    const probes: ToolPathProbes = {
      ...fake.probes,
      kind: (target) => {
        kinds.push(target);
        return fake.probes.kind(target);
      },
      listDirectory: async (target) => {
        throw Object.assign(new Error(`${target} timed out`), { code: "ETIMEDOUT", timeoutMs: PROBE_TIMEOUT_MS });
      },
    };
    expect(problemOf(await checkToolPath("semgrep", "Z:\\Semgrep", probes))).toBe(slowPathProblem("Z:\\Semgrep", PROBE_TIMEOUT_MS));
    expect(slowPathProblem("Z:\\Semgrep", PROBE_TIMEOUT_MS)).toBe(
      "Z:\\Semgrep did not answer within 2 s; the drive or network share it is on may be slow or unreachable.",
    );
    // Only the folder itself was checked: no per-name probing after the listing timed out.
    expect(kinds).toEqual(["Z:\\Semgrep"]);
  });

  test("every call of the bounded probes has a deadline, and a call that never returns is joined, not repeated", async () => {
    const hung = deferred<PathKind>();
    let kindCalls = 0;
    const raw: ToolPathProbes = {
      ...fakeFs("linux", "x64", {}).probes,
      kind: () => {
        kindCalls += 1;
        return hung.promise;
      },
    };
    const probes = boundedToolPathProbes(raw, { timeoutMs: 30 });
    const started = performance.now();
    expect(problemOf(await checkToolPath("semgrep", "/mnt/nfs/semgrep", probes))).toBe(slowPathProblem("/mnt/nfs/semgrep", 30));
    expect(problemOf(await checkToolPath("semgrep", "/mnt/nfs/semgrep", probes))).toBe(slowPathProblem("/mnt/nfs/semgrep", 30));
    expect(performance.now() - started).toBeLessThan(2_000);
    // The stat that never returned is still pending: the second check waited on it instead of starting another.
    expect(kindCalls).toBe(1);
    hung.resolve("file");
    await hung.promise;
    await Bun.sleep(0);
    await checkToolPath("semgrep", "/mnt/nfs/semgrep", probes);
    expect(kindCalls).toBe(2);
  });

  test("macOS and Linux: a permission check or header read that does not answer is not reported as a missing permission", async () => {
    const fake = fakeFs("linux", "x64", { "/mnt/nfs/semgrep": file(elfHeader(ELF_X64)), "/mnt/nfs/tools": dir(), "/mnt/nfs/tools/semgrep": file(elfHeader(ELF_X64)) });
    const never = <T>() => new Promise<T>(() => undefined);
    const slowExec = boundedToolPathProbes({ ...fake.probes, isExecutable: () => never<boolean>() }, { timeoutMs: 20 });
    expect(problemOf(await checkToolPath("semgrep", "/mnt/nfs/semgrep", slowExec))).toBe(slowPathProblem("/mnt/nfs/semgrep", 20));
    expect(problemOf(await checkToolPath("semgrep", "/mnt/nfs/tools", slowExec))).toBe(slowPathProblem("/mnt/nfs/tools/semgrep", 20));
    const slowHeader = boundedToolPathProbes({ ...fake.probes, inspect: () => never<BinaryInfo>() }, { timeoutMs: 20 });
    expect(problemOf(await checkToolPath("semgrep", "/mnt/nfs/semgrep", slowHeader))).toBe(slowPathProblem("/mnt/nfs/semgrep", 20));
  });

  test("a whole check is bounded, however many calls each answer just in time", async () => {
    const fake = fakeFs("win32", "x64", { "D:\\slow": dir(), "D:\\slow\\semgrep.exe": file(peHeader(PE_X64)) });
    const slowly: ToolPathProbes = {
      ...fake.probes,
      kind: async (target) => {
        await Bun.sleep(40);
        return fake.probes.kind(target);
      },
    };
    expect(problemOf(await checkToolPath("semgrep", "D:\\slow", slowly, { timeoutMs: 60 }))).toBe(slowPathProblem("D:\\slow", 60));
    expect(accepted(await checkToolPath("semgrep", "D:\\slow", slowly, { timeoutMs: 1_000 })).file).toBe("D:\\slow\\semgrep.exe");
  });

  test("the bridge host probes are bounded", async () => {
    const probes = hostToolPathProbes({ platform: process.platform, env: process.env, nativeArch: null });
    // A real folder answers well within the deadline.
    expect(await probes.kind(TEST_ROOT)).toBe("directory");
    expect(await checkToolPath("semgrep", path.join(TEST_ROOT, "no-such-tool"), probes)).toEqual({
      ok: false,
      input: path.join(TEST_ROOT, "no-such-tool"),
      problem: `Nothing exists at ${path.join(TEST_ROOT, "no-such-tool")}.`,
    });
  });
});

// ───────────────────────────── storage ─────────────────────────────

describe("tool path storage", () => {
  test("only configurable tools are stored and read back; gh, codeql, bun and malformed entries are dropped", () => {
    expect(CONFIGURABLE_TOOLS).toEqual(["git", "cargo", "semgrep", "osv-scanner", "docker"]);
    expect(TOOL_NAMES.filter((name) => !(CONFIGURABLE_TOOLS as readonly string[]).includes(name))).toEqual(["gh", "bun", "codeql"]);
    const stored = {
      gh: { path: "/tmp/gh", setAt: "x", setBy: "y" },
      bun: { path: "/tmp/bun" },
      codeql: { path: "D:\\CodeQL", setAt: "2026-11-11T00:00:00.000Z", setBy: "alice" },
      semgrep: { path: 5 },
      docker: { path: "x".repeat(MAX_TOOL_PATH_LENGTH + 1) },
      git: { path: "C:\\Git\\cmd", setAt: "2026-11-11T00:00:00.000Z", setBy: "alice" },
      nope: { path: "/tmp/nope" },
    };
    expect(parseStoredToolPaths(stored)).toEqual({ git: { path: "C:\\Git\\cmd", setAt: "2026-11-11T00:00:00.000Z", setBy: "alice" } });
    // A codeql path stored by an earlier bridge is only reported as ignored.
    expect(ignoredStoredToolPaths(stored)).toEqual({ codeql: { path: "D:\\CodeQL", setAt: "2026-11-11T00:00:00.000Z", setBy: "alice" } });
    expect(parseStoredToolPaths(null)).toEqual({});
    expect(parseStoredToolPaths([1, 2])).toEqual({});

    const db = openWebDb(path.join(tempDir("store-"), "web.db"));
    openDbs.push(db);
    const settings = new SettingsStore(db);
    const store = new ToolPathStore(settings);
    const entry = store.set("semgrep", "D:\\Semgrep", "alice");
    store.set("git", "C:\\Git\\cmd", "bob");
    expect(store.list()).toEqual({ semgrep: entry, git: expect.objectContaining({ path: "C:\\Git\\cmd", setBy: "bob" }) });
    expect(store.clear("semgrep", "alice")).toEqual(entry);
    expect(store.clear("semgrep", "alice")).toBeNull();
    expect(store.clear("git", "bob")?.path).toBe("C:\\Git\\cmd");
    // The key is removed once nothing is configured.
    expect(settings.meta(TOOL_PATHS_SETTING)).toBeNull();
    // A path list() would drop is refused instead of being reported as saved.
    expect(() => store.set("semgrep", `/${"a".repeat(MAX_TOOL_PATH_LENGTH)}`, "alice")).toThrow("1 to 1024 characters");
    expect(() => store.set("semgrep", "", "alice")).toThrow("1 to 1024 characters");
    expect(store.list()).toEqual({});
  });

  test("tool rows of reports stored before contract version 3 get the selection fields", () => {
    // Version 3 introduced the selection fields; later versions keep them.
    expect(API_CONTRACT_VERSION).toBeGreaterThanOrEqual(3);
    expect(normalizeStoredTool({ name: "gh", available: false, path: null })).toMatchObject({
      selection: "automatic",
      configuredPath: null,
      configuredPathProblem: null,
      pathConfigurable: false,
      pathHint: GH_PATH_HINT,
    });
    expect(normalizeStoredTool({ name: "semgrep", available: true, path: "D:\\Semgrep\\semgrep.exe", source: "configured", configuredPath: "D:\\Semgrep" })).toMatchObject({
      selection: "configured",
      configuredPath: "D:\\Semgrep",
      pathConfigurable: true,
      pathHint: null,
    });
    // A stored report keeps what it recorded; codeql is no longer settable in the console.
    expect(normalizeStoredTool({ name: "codeql", available: true, path: "D:\\CodeQL\\codeql.exe", source: "configured", configuredPath: "D:\\CodeQL" })).toMatchObject({
      selection: "configured",
      configuredPath: "D:\\CodeQL",
      pathConfigurable: false,
      pathHint: CODEQL_PATH_HINT,
    });
    expect(normalizeStoredTool({ name: "custom-tool", available: false })).toMatchObject({ selection: "automatic", pathConfigurable: false, pathHint: null });
  });
});

// ───────────────────────────── SENTRA_GH_BIN ─────────────────────────────

function ghProbes(files: Record<string, { kind: ReturnType<GhBinaryProbes["kind"]>; bytes?: Uint8Array; exec?: boolean }>): GhBinaryProbes {
  return {
    kind: (target) => files[target]?.kind ?? "missing",
    isExecutable: (target) => files[target]?.exec !== false,
    readHeader: (target) => files[target]?.bytes ?? new Uint8Array(),
  };
}

const ENV_KEYS = ["SENTRA_WEB_TOKENS", "SENTRA_WEB_DATA_DIR", "SENTRA_REPO_ROOT", "SENTRA_WEB_HOST", "SENTRA_BIN", "SENTRA_GH_BIN", "SENTRA_PLUGIN_DIR", "SENTRA_WEB_WORKSPACE_ROOTS"];

function withEnv<T>(values: Record<string, string | undefined>, run: () => T): T {
  const saved = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  try {
    for (const key of ENV_KEYS) delete process.env[key];
    for (const [key, value] of Object.entries(values)) if (value !== undefined) process.env[key] = value;
    return run();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function configError(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof ConfigError) return error.message;
    throw error;
  }
  throw new Error("expected a ConfigError");
}

describe("SENTRA_GH_BIN", () => {
  test("Windows: an absolute local .exe/.com with a PE header; no UNC, script or foreign binary", () => {
    const probes = ghProbes({
      "C:\\Program Files\\GitHub CLI\\gh.exe": { kind: "file", bytes: peHeader(PE_X64) },
      "C:\\tools\\gh.cmd": { kind: "file", bytes: new TextEncoder().encode("@echo off\r\n") },
      "C:\\tools\\gh-linux.exe": { kind: "file", bytes: elfHeader(ELF_X64) },
      "C:\\tools": { kind: "directory" },
    });
    expect(resolveGhBinary(null, "win32", probes)).toBeNull();
    expect(resolveGhBinary("C:/Program Files/GitHub CLI/gh.exe", "win32", probes)).toBe("C:\\Program Files\\GitHub CLI\\gh.exe");
    expect(resolveGhBinary('"C:\\Program Files\\GitHub CLI\\gh.exe"', "win32", probes)).toBe("C:\\Program Files\\GitHub CLI\\gh.exe");
    expect(configError(() => resolveGhBinary("\\\\server\\share\\gh.exe", "win32", probes))).toContain("UNC");
    expect(configError(() => resolveGhBinary("gh.exe", "win32", probes))).toContain("must be an absolute path");
    expect(configError(() => resolveGhBinary("C:\\missing\\gh.exe", "win32", probes))).toBe("SENTRA_GH_BIN points to a missing file: C:\\missing\\gh.exe");
    expect(configError(() => resolveGhBinary("C:\\tools", "win32", probes))).toBe("SENTRA_GH_BIN is not a regular file: C:\\tools");
    expect(configError(() => resolveGhBinary("C:\\tools\\gh.cmd", "win32", probes))).toContain("must name a .exe or .com file");
    expect(configError(() => resolveGhBinary("C:\\tools\\gh-linux.exe", "win32", probes))).toContain("is not a native Windows executable");
  });

  test("macOS and Linux: an executable Mach-O or ELF file, never a script", () => {
    const probes = ghProbes({
      "/usr/bin/gh": { kind: "file", bytes: elfHeader(ELF_X64) },
      "/opt/homebrew/bin/gh": { kind: "file", bytes: machoHeader(MACHO_ARM64) },
      "/usr/local/bin/gh-wrapper": { kind: "file", bytes: POSIX_SCRIPT },
      "/usr/local/bin/gh-noexec": { kind: "file", bytes: elfHeader(ELF_X64), exec: false },
    });
    expect(resolveGhBinary("/usr/bin/gh", "linux", probes)).toBe("/usr/bin/gh");
    expect(resolveGhBinary("/opt/homebrew/bin/gh", "darwin", probes)).toBe("/opt/homebrew/bin/gh");
    expect(configError(() => resolveGhBinary("/usr/bin/gh", "darwin", probes))).toContain("is not a native macOS executable");
    expect(configError(() => resolveGhBinary("/usr/local/bin/gh-wrapper", "linux", probes))).toBe(
      "SENTRA_GH_BIN must be a native executable, not a script (#!/bin/sh): /usr/local/bin/gh-wrapper",
    );
    expect(configError(() => resolveGhBinary("/usr/local/bin/gh-noexec", "linux", probes))).toContain("not executable by the bridge user");
    expect(configError(() => resolveGhBinary("bin/gh", "linux", probes))).toContain("must be an absolute path");
    expect(configError(() => resolveGhBinary("/usr/bin/g\nh", "linux", probes))).toContain("control characters");
  });

  test("loadConfig validates SENTRA_GH_BIN at startup", () => {
    const base = { SENTRA_REPO_ROOT: tempDir("cfg-repo-"), SENTRA_BIN: process.execPath };
    const missing = path.join(TEST_ROOT, "no-such-gh", hostExecutableName("gh"));
    expect(() => withEnv({ ...base, SENTRA_WEB_DATA_DIR: tempDir("cfg-data-"), SENTRA_GH_BIN: missing }, () => loadConfig())).toThrow(ConfigError);
    // The running Bun is a real native executable of this host.
    const config = withEnv({ ...base, SENTRA_WEB_DATA_DIR: tempDir("cfg-data-"), SENTRA_GH_BIN: process.execPath }, () => loadConfig());
    expect(config.ghBin).toBe(path.normalize(process.execPath));
    expect(withEnv({ ...base, SENTRA_WEB_DATA_DIR: tempDir("cfg-data-") }, () => loadConfig()).ghBin).toBeNull();
  });

  test("GitHubService runs SENTRA_GH_BIN and never consults the automatic lookup while it is set", () => {
    const db = openWebDb(path.join(tempDir("gh-pin-"), "web.db"));
    openDbs.push(db);
    const secrets = new SecretStore(db, crypto.randomBytes(32));
    let lookups = 0;
    const locateGh = () => {
      lookups += 1;
      return null;
    };
    const missingPin = path.join(TEST_ROOT, "absent", hostExecutableName("gh"));
    expect(new GitHubService(secrets, null, TEST_ROOT, { ghBin: missingPin, locateGh, ghTimeoutMs: 2_000 }).resolveAuth()).toBeNull();
    expect(lookups).toBe(0);
    new GitHubService(secrets, null, TEST_ROOT, { locateGh }).resolveAuth();
    expect(lookups).toBe(1);
  });

  // Starts a real process with GH_TOKEN_TIMEOUT_MS as its limit, so the test's own limit lies above it.
  test.if(process.platform !== "win32")("POSIX: the pinned gh is the one whose token is used", () => {
    const db = openWebDb(path.join(tempDir("gh-pin-run-"), "web.db"));
    openDbs.push(db);
    const secrets = new SecretStore(db, crypto.randomBytes(32));
    const token = "ghp_pinnedpinnedpinnedpinned0123456789";
    const pinned = path.join(tempDir("gh-pinned-"), "gh");
    fs.writeFileSync(pinned, `#!/bin/sh\necho ${token}\n`, { mode: 0o755 });
    const other = path.join(tempDir("gh-other-"), "gh");
    fs.writeFileSync(other, "#!/bin/sh\necho ghp_otherotherotherotherother0123456789\n", { mode: 0o755 });
    expect(new GitHubService(secrets, null, TEST_ROOT, { ghBin: pinned, locateGh: () => other }).resolveAuth()).toEqual({ source: "gh_cli", token });
  }, GH_TOKEN_TIMEOUT_MS + 10_000);
});

// ───────────────────────────── tools table ─────────────────────────────

function quietHostPlatform(): HostPlatform {
  return new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null });
}

function emptyLocator(pathDirs: string[] = []): ExecutableLocator {
  const searchPath = pathDirs.length > 0 ? pathDirs.join(path.delimiter) : tempDir("empty-path-");
  return new ExecutableLocator({
    env: { PATH: searchPath, PATHEXT: ".EXE;.CMD" },
    homedir: tempDir("home-"),
    isDirectory: () => false,
    loadPersisted: async () => ({ entries: { system: [], user: [] }, read: true, error: null }),
  });
}

function writeTool(dirPath: string, name: string, bytes: Uint8Array = hostNativeHeader()): string {
  const target = path.join(dirPath, name);
  fs.writeFileSync(target, bytes, { mode: 0o755 });
  return target;
}

describe("tools table with configured paths and SENTRA_GH_BIN", () => {
  test("SENTRA_GH_BIN takes precedence over a gh on PATH; a pin that disappears is reported without fallback", async () => {
    const onPath = tempDir("gh-on-path-");
    const pathGh = writeTool(onPath, hostExecutableName("gh"));
    const pinnedDir = tempDir("gh-pinned-dir-");
    const pinned = writeTool(pinnedDir, hostExecutableName("gh"));
    const deps: HostToolsDeps = { executables: emptyLocator([onPath]), hostPlatform: quietHostPlatform(), toolPaths: NO_CONFIGURED_TOOL_PATHS, ghBin: pinned };
    const gh = (await describeTools(deps)).find((tool) => tool.name === "gh")!;
    expect(gh).toMatchObject({
      available: true,
      path: pinned,
      source: "environment",
      selection: "environment",
      configuredPath: null,
      configuredPathProblem: null,
      pathConfigurable: false,
      pathHint: GH_PINNED_HINT,
      shadowed: [pathGh],
    });
    expect(gh.usageNote).toContain(GH_PINNED_NOTE);

    fs.rmSync(pinned);
    // Checked once per search snapshot: the same snapshot keeps the row, a new one checks again.
    expect((await describeTools(deps)).find((tool) => tool.name === "gh")).toEqual(gh);
    await deps.executables.refresh();
    const broken = (await describeTools(deps)).find((tool) => tool.name === "gh")!;
    expect(broken).toMatchObject({ available: false, path: pinned, selection: "environment", binary: null });
    expect(broken.configuredPathProblem).toBe(
      `SENTRA_GH_BIN: Nothing exists at ${pinned}. gh cannot be run until this is fixed; automatic detection is not used for gh while SENTRA_GH_BIN is set.`,
    );
  });

  test("a configured path is checked once per search snapshot and per save, shared by the tools table and scans", async () => {
    const bundle = tempDir("cached-semgrep-");
    const semgrepFile = writeTool(bundle, hostExecutableName("semgrep"));
    let stored: StoredToolPath = { path: bundle, setAt: "2026-11-11T00:00:00.000Z", setBy: "admin" };
    let calls = 0;
    const deps: HostToolsDeps = {
      executables: emptyLocator(),
      hostPlatform: quietHostPlatform(),
      toolPaths: { list: () => ({ semgrep: stored }) },
      ghBin: null,
      toolPathProbes: (host) => {
        const real = hostToolPathProbes({ platform: process.platform, env: process.env, nativeArch: host.nativeArch });
        return {
          ...real,
          kind: (target) => {
            calls += 1;
            return real.kind(target);
          },
        };
      },
    };
    const semgrepRow = async () => (await describeTools(deps)).find((tool) => tool.name === "semgrep")!;
    expect(await semgrepRow()).toMatchObject({ selection: "configured", path: semgrepFile });
    const afterFirst = calls;
    expect(afterFirst).toBeGreaterThan(0);
    // Further requests of the same snapshot, and the scan's semgrep message, reuse that check.
    await semgrepRow();
    await semgrepRow();
    const snapshot = await deps.executables.current();
    expect(await reportedToolLocation(deps, "semgrep", snapshot)).toMatchObject({ path: semgrepFile, selection: "configured" });
    expect(calls).toBe(afterFirst);
    // Saving the path again checks it again.
    stored = { ...stored, setAt: "2026-11-11T00:01:00.000Z" };
    await semgrepRow();
    expect(calls).toBeGreaterThan(afterFirst);
    const afterSave = calls;
    // So does the next snapshot.
    await deps.executables.refresh();
    await semgrepRow();
    expect(calls).toBeGreaterThan(afterSave);
  });

  test("a configured path or SENTRA_GH_BIN on a drive that never answers yields a bounded row with the reason", async () => {
    const offline = path.join(TEST_ROOT, "offline-share");
    const hungKind = (): ToolPathProbes => ({
      ...hostToolPathProbes({ platform: process.platform, env: process.env, nativeArch: null }),
      kind: () => new Promise<PathKind>(() => undefined),
    });
    const ghBin = path.join(offline, hostExecutableName("gh"));
    const deps: HostToolsDeps = {
      executables: emptyLocator(),
      hostPlatform: quietHostPlatform(),
      toolPaths: { list: () => ({ semgrep: { path: offline, setAt: "2026-11-11T00:00:00.000Z", setBy: "admin" } }) },
      ghBin,
      toolPathProbes: hungKind,
      toolPathTimeoutMs: 50,
    };
    const started = performance.now();
    const tools = await describeTools(deps);
    expect(performance.now() - started).toBeLessThan(2_000);
    const semgrep = tools.find((tool) => tool.name === "semgrep")!;
    expect(semgrep).toMatchObject({ selection: "automatic", available: false, configuredPath: offline, configuredPathProblem: slowPathProblem(offline, 50) });
    const gh = tools.find((tool) => tool.name === "gh")!;
    expect(gh).toMatchObject({ selection: "environment", available: false, path: ghBin });
    expect(gh.configuredPathProblem).toContain(`SENTRA_GH_BIN: ${slowPathProblem(ghBin, 50)}`);
  });
});

// ───────────────────────────── routes ─────────────────────────────

const ADMIN_TOKEN = "a".repeat(40);
const OPERATOR_TOKEN = "o".repeat(40);
const VIEWER_TOKEN = "v".repeat(40);
const PORT = 3997;

function bridgeConfig(): ServerConfig {
  const dataDir = tempDir("bridge-data-");
  const tmp = path.join(dataDir, "tmp");
  fs.mkdirSync(tmp);
  return {
    repoRoot: tempDir("bridge-repo-"),
    webRoot: TEST_ROOT,
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
    cliMaxConcurrency: 1,
    trustProxy: false,
    workspaceRoots: [],
    pluginDir: null,
    tmpDir: tmp,
  };
}

function bridge(executables: ExecutableLocator = emptyLocator()) {
  const { app, router } = createApp(bridgeConfig(), { executables, hostPlatform: quietHostPlatform() });
  openDbs.push(app.db);
  const server = { requestIP: () => ({ address: "127.0.0.1", family: "IPv4" as const, port: 1 }), timeout: () => undefined };
  const send = async (method: string, pathname: string, token: string, body?: unknown) => {
    const response = await handleRequest(
      new Request(`http://127.0.0.1:${PORT}${pathname}`, {
        method,
        headers: { host: `127.0.0.1:${PORT}`, authorization: `Bearer ${token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      }),
      server,
      app as AppContext,
      router as Router,
    );
    const text = await response.text();
    return { status: response.status, body: text ? (JSON.parse(text) as Record<string, any>) : {} };
  };
  const systemTool = async (name: string): Promise<ToolAvailability> => {
    const response = await send("GET", "/api/system", ADMIN_TOKEN);
    expect(response.status).toBe(200);
    return (response.body as SystemStatus).tools.find((tool) => tool.name === name)!;
  };
  return { app, router, send, systemTool };
}

describe("PUT and DELETE /api/system/tools/:name", () => {
  test("declare settings:write", () => {
    const { router } = bridge();
    const routes = Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]));
    expect(routes["PUT /api/system/tools/:name"]).toBe("settings:write");
    expect(routes["DELETE /api/system/tools/:name"]).toBe("settings:write");
  });

  test("an admin sets a folder, the row and GET /api/system follow it, a removed file falls back, a reset returns to automatic; everything is audited", async () => {
    const h = bridge();
    const bundle = tempDir("semgrep-bundle-");
    const semgrepFile = writeTool(bundle, hostExecutableName("semgrep"));

    const saved = await h.send("PUT", "/api/system/tools/semgrep", ADMIN_TOKEN, { path: `  ${bundle}${path.sep}  ` });
    expect(saved.status).toBe(200);
    const body = saved.body as SetToolPathResponse;
    expect(body.warning).toBeNull();
    expect(body.tool).toMatchObject({
      name: "semgrep",
      available: true,
      path: semgrepFile,
      source: "configured",
      selection: "configured",
      configuredPath: bundle,
      configuredPathProblem: null,
      pathConfigurable: true,
      pathHint: null,
    });
    expect(body.tool.binary?.compatibility).not.toBe("incompatible");
    expect(await h.systemTool("semgrep")).toEqual(body.tool);
    expect(await h.systemTool("gh")).toMatchObject({ pathConfigurable: false, pathHint: GH_PATH_HINT, selection: "automatic" });
    expect(await h.systemTool("bun")).toMatchObject({ pathConfigurable: false, pathHint: null, selection: "automatic" });
    expect(h.app.toolPaths.list().semgrep).toMatchObject({ path: bundle, setBy: "admin" });

    // The file goes away. GET /api/system does not check the path again within the same search
    // snapshot; the next snapshot does: the row keeps the configured path, says why it fails and
    // reports automatic detection.
    fs.rmSync(semgrepFile);
    expect(await h.systemTool("semgrep")).toEqual(body.tool);
    await h.app.executables.refresh();
    const broken = await h.systemTool("semgrep");
    expect(broken).toMatchObject({ available: false, path: null, source: null, selection: "automatic", configuredPath: bundle });
    expect(broken.configuredPathProblem).toContain(`No semgrep executable in ${bundle}`);

    const reset = await h.send("DELETE", "/api/system/tools/semgrep", ADMIN_TOKEN);
    expect(reset.status).toBe(200);
    expect((reset.body as SetToolPathResponse).tool).toMatchObject({ selection: "automatic", configuredPath: null, configuredPathProblem: null });
    expect((reset.body as SetToolPathResponse).warning).toBeNull();
    expect(h.app.toolPaths.list()).toEqual({});

    const entries = h.app.audit.list({ limit: 20 }).reverse();
    expect(entries.map((entry) => `${entry.action}:${entry.outcome}`)).toEqual(["tool_path_configured:success", "tool_path_cleared:success"]);
    expect(entries[0]).toMatchObject({ actor: "admin", target: "semgrep", details: { tool: "semgrep", path: bundle } });
    expect(entries[1]).toMatchObject({ target: "semgrep", details: { tool: "semgrep", path: bundle } });
    expect(h.app.audit.verify().valid).toBe(true);
  });

  test("a file whose name does not look like the tool is saved with a warning", async () => {
    const h = bridge();
    const target = writeTool(tempDir("renamed-"), hostExecutableName("my-scanner"));
    const saved = await h.send("PUT", "/api/system/tools/semgrep", ADMIN_TOKEN, { path: target });
    expect(saved.status).toBe(200);
    expect((saved.body as SetToolPathResponse).warning).toBe(
      `The file name ${path.basename(target)} does not look like semgrep. The path was saved; check that it is the right program.`,
    );
    expect((saved.body as SetToolPathResponse).tool).toMatchObject({ path: target, configuredPath: target, selection: "configured" });
  });

  test("codeql is not settable in the console: PUT and DELETE answer 409, and a path stored by an earlier bridge is ignored and explained", async () => {
    const h = bridge();
    const bundle = tempDir("codeql-bundle-");
    writeTool(bundle, hostExecutableName("codeql"));
    const refused = await h.send("PUT", "/api/system/tools/codeql", ADMIN_TOKEN, { path: bundle });
    expect(refused.status).toBe(409);
    expect(refused.body.error.code).toBe("tool_path_not_configurable");
    expect(refused.body.error.message).toContain("SENTRA_CODEQL_BIN");
    expect(refused.body.error.message).toContain("must never become a program the bridge runs");
    expect((await h.send("DELETE", "/api/system/tools/codeql", ADMIN_TOKEN)).status).toBe(409);

    // An entry an earlier bridge stored for codeql is reported as ignored, never used.
    h.app.settings.set(TOOL_PATHS_SETTING, { codeql: { path: bundle, setAt: "2026-11-10T00:00:00.000Z", setBy: "admin" } }, "admin");
    const row = await h.systemTool("codeql");
    expect(row).toMatchObject({ selection: "automatic", configuredPath: null, pathConfigurable: false, usage: "presence_only" });
    expect(row.pathHint).toContain(CODEQL_PATH_HINT);
    expect(row.pathHint).toContain(`The path set earlier in the console (${bundle}) is ignored`);
    expect(row.path).not.toBe(path.join(bundle, hostExecutableName("codeql")));
    expect(h.app.toolPaths.list()).toEqual({});

    const entries = h.app.audit.list({ limit: 5 }).reverse();
    expect(entries.map((entry) => `${entry.action}:${entry.outcome}`)).toEqual(["tool_path_configured:failure", "tool_path_cleared:failure"]);
    expect(String(entries[0].details?.error)).toContain("tool_path_not_configurable");
  });

  test("404 for unknown tools, 409 for gh and bun, 400 for invalid paths, 403 below SecurityAdmin", async () => {
    const h = bridge();
    const target = writeTool(tempDir("semgrep-"), hostExecutableName("semgrep"));

    const unknown = await h.send("PUT", "/api/system/tools/nmap", ADMIN_TOKEN, { path: target });
    expect(unknown.status).toBe(404);
    expect(unknown.body.error.code).toBe("tool_not_found");

    const gh = await h.send("PUT", "/api/system/tools/gh", ADMIN_TOKEN, { path: target });
    expect(gh.status).toBe(409);
    expect(gh.body.error.code).toBe("tool_path_not_configurable");
    expect(gh.body.error.message).toContain("must never become a program the bridge runs");
    expect(gh.body.error.message).toContain("SENTRA_GH_BIN");
    expect((await h.send("PUT", "/api/system/tools/bun", ADMIN_TOKEN, { path: target })).status).toBe(409);
    expect((await h.send("DELETE", "/api/system/tools/gh", ADMIN_TOKEN)).status).toBe(409);

    const relative = await h.send("PUT", "/api/system/tools/semgrep", ADMIN_TOKEN, { path: "semgrep" });
    expect(relative.status).toBe(400);
    expect(relative.body.error.code).toBe("invalid_tool_path");
    expect(relative.body.error.message).toContain("absolute path");
    const notString = await h.send("PUT", "/api/system/tools/semgrep", ADMIN_TOKEN, { path: 5 });
    expect(notString.status).toBe(400);
    expect(notString.body.error.code).toBe("invalid_request");
    const missing = await h.send("PUT", "/api/system/tools/semgrep", ADMIN_TOKEN, { path: path.join(TEST_ROOT, "missing-dir") });
    expect(missing.body.error.message).toBe(`Nothing exists at ${path.join(TEST_ROOT, "missing-dir")}.`);

    expect((await h.send("PUT", "/api/system/tools/semgrep", OPERATOR_TOKEN, { path: target })).status).toBe(403);
    expect((await h.send("PUT", "/api/system/tools/semgrep", VIEWER_TOKEN, { path: target })).status).toBe(403);
    expect((await h.send("DELETE", "/api/system/tools/semgrep", VIEWER_TOKEN)).status).toBe(403);
    expect(h.app.toolPaths.list()).toEqual({});

    const entries = h.app.audit.list({ limit: 20 }).reverse();
    expect(entries.map((entry) => `${entry.action}:${entry.outcome}`)).toEqual([
      "request_rejected:failure",
      "tool_path_configured:failure",
      "tool_path_configured:failure",
      "tool_path_cleared:failure",
      "tool_path_configured:failure",
      "tool_path_configured:failure",
      "tool_path_configured:failure",
      "authorization_denied:denied",
      "authorization_denied:denied",
      "authorization_denied:denied",
    ]);
    expect(entries[1].details).toMatchObject({ tool: "gh", path: target, error: expect.stringContaining("tool_path_not_configurable") });
    expect(entries[4].details).toMatchObject({ tool: "semgrep", path: "semgrep", error: expect.stringContaining("invalid_tool_path") });
    expect(entries[5].details).toMatchObject({ tool: "semgrep", path: null });
    expect(h.app.audit.verify().valid).toBe(true);
  });
});

// ───────────────────────────── execution paths ─────────────────────────────

describe("configured paths never reach anything that runs a program", () => {
  test("locateForExecution, the gh credential lookup and the gh row ignore configured paths (even a gh entry written to the database)", async () => {
    const h = bridge();
    const configured = tempDir("configured-tools-");
    const git = writeTool(configured, hostExecutableName("git"));
    // If this gh were ever run, it would print a token (POSIX) and resolveAuth would return it.
    const ghFile = path.join(configured, hostExecutableName("gh"));
    fs.writeFileSync(ghFile, process.platform === "win32" ? hostNativeHeader() : "#!/bin/sh\necho ghp_configuredconfiguredconfigured0123\n", { mode: 0o755 });
    h.app.settings.set(
      TOOL_PATHS_SETTING,
      { git: { path: configured, setAt: "2026-11-11T00:00:00.000Z", setBy: "admin" }, gh: { path: configured, setAt: "2026-11-11T00:00:00.000Z", setBy: "admin" } },
      "admin",
    );
    expect(await h.systemTool("git")).toMatchObject({ selection: "configured", path: git });
    expect(await h.systemTool("gh")).toMatchObject({ selection: "automatic", available: false, path: null, configuredPath: null });

    await h.app.executables.refresh();
    for (const name of ["git", "gh", "codeql"] as const) expect(h.app.executables.locateForExecution(name).path).toBeNull();
    expect(h.app.github.resolveAuth()).toBeNull();
  });

  test("a codeql path written to the database never becomes the launcher that host analysis would run", async () => {
    const h = bridge();
    const bundle = tempDir("configured-codeql-");
    // A complete CodeQL distribution layout, so only the source of the path could refuse it.
    writeTool(bundle, hostExecutableName("codeql"));
    fs.mkdirSync(path.join(bundle, "tools"));
    fs.writeFileSync(path.join(bundle, ".codeqlmanifest.json"), "{}");
    h.app.settings.set(TOOL_PATHS_SETTING, { codeql: { path: bundle, setAt: "2026-11-11T00:00:00.000Z", setBy: "admin" } }, "admin");
    await h.app.executables.refresh();
    const choice = codeqlLauncherChoice(hostToolsDeps(h.app), await h.app.executables.current());
    expect(choice.path).toBeNull();
    expect(choice.problem).toContain("SENTRA_CODEQL_BIN");
    const view = await h.send("GET", "/api/settings/codeql", VIEWER_TOKEN);
    expect(view.status).toBe(200);
    expect(view.body.launcher).toMatchObject({ available: false, path: null });
  });

  test("the modules that start programs do not import the configured tool paths", () => {
    for (const module of ["executables.ts", "github.ts", "config.ts", "sentra-cli.ts", "host-platform.ts", "codeql-launcher.ts"]) {
      const source = fs.readFileSync(path.join(import.meta.dir, "..", module), "utf8");
      expect({ module, importsToolPaths: /from\s+["']\.\/tool-paths(\.ts)?["']/.test(source) }).toEqual({ module, importsToolPaths: false });
    }
    for (const module of ["services/codeql.ts", "services/scans.ts", "routes/codeql.ts"]) {
      const source = fs.readFileSync(path.join(import.meta.dir, "..", module), "utf8");
      expect({ module, importsToolPaths: /from\s+["']\.\.\/tool-paths(\.ts)?["']/.test(source) }).toEqual({ module, importsToolPaths: false });
    }
  });
});
