import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { persistedPathReadState, stalePathAdvice, toolSearchLocations } from "../../src/components/dashboard/host-path-advice.ts";
import { contractMismatch, reportedContractVersion } from "../../src/lib/contract.ts";
import { API_CONTRACT_VERSION, type CpuArch, type HealthResponse, type SystemStatus, type ToolAvailability, type TopologyReportView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { binaryCompatibility, inspectBinary, MAX_HEADER_BYTES, parseExecutableHeader, type HostArch, type ParsedHeader } from "../binary-info.ts";
import { configuredGrantCount, loadConfig, parseTokenGrants, sha256, type ServerConfig } from "../config.ts";
import { openWebDb } from "../db.ts";
import {
  buildSearchDirectories,
  buildSearchPlan,
  chooseForExecution,
  defaultExecutionTrustCheck,
  describeSearchScope,
  executableFileNames,
  ExecutableLocator,
  expandWindowsVariables,
  findOnProcessPathForExecution,
  isBunShimDir,
  isTrustedOwnership,
  locateExecutable,
  ownershipProblem,
  parseEtcGroup,
  pythonInstallBases,
  releaseAssetNames,
  runnableArchitectures,
  type PersistedPathResult,
  type SearchDirectory,
  type SearchEnvironment,
} from "../executables.ts";
import { ghEnvironment, GitHubService } from "../github.ts";
import {
  createSystemProgramRunner,
  HostPlatform,
  isArchEmulated,
  machineToCpuArch,
  parseEtcEnvironmentPath,
  parseEtcPaths,
  parseOsRelease,
  parseProcMeminfo,
  parseSwVers,
  parseVmStat,
  parseWindowsRegistryJson,
  registryRetryDelayMs,
  resolveNativeArch,
  WINDOWS_POWERSHELL_ARGS,
  WINDOWS_REGISTRY_SCRIPT,
  WINDOWS_REGISTRY_TTL_MS,
  windowsOsName,
  windowsPowerShellPath,
  type SystemProgramResult,
} from "../host-platform.ts";
import {
  BUN_MATCHED_NOTE,
  BUN_UNMATCHED_NOTE,
  bunRuntimeNote,
  describeTools,
  ghExecutionNote,
  normalizeStoredTool,
  resolveBunRuntime,
  resolvedTarget,
  TOOL_NAMES,
  TOOL_USAGE,
  UNMATCHED_SHIM_NOTE,
  type LinkProbes,
} from "../host-tools.ts";
import { Router } from "../http.ts";
import { createApp, handleRequest } from "../main.ts";
import { SecretStore } from "../secrets.ts";
import { CHOCOLATEY_SHIM_NOTE, isChocolateyShim, parseScoopShim, scoopShimFile } from "../shims.ts";
import { latestTopologyReport, saveTopologyReport } from "../services/topology.ts";

// Canonical (links and 8.3 short names resolved, e.g. /private/var on macOS or RUNNER~1 on Windows CI
// runners), so paths built here compare equal to the real paths the code under test reports.
const TEST_ROOT = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentra-host-tools-")));
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

// ───────────────────────────── synthetic headers ─────────────────────────────

function pe(machine: number, peOffset = 0x80): Uint8Array {
  const bytes = new Uint8Array(peOffset + 24);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  view.setUint32(0x3c, peOffset, true);
  bytes.set([0x50, 0x45, 0, 0], peOffset);
  view.setUint16(peOffset + 4, machine, true);
  return bytes;
}

function elf(machine: number, elfClass: 1 | 2 = 2, data: 1 | 2 = 1): Uint8Array {
  const bytes = new Uint8Array(64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, elfClass, data, 1]);
  new DataView(bytes.buffer).setUint16(18, machine, data === 1);
  return bytes;
}

function macho(cpuType: number, littleEndian = true, magic = 0xfeedfacf): Uint8Array {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, magic, littleEndian);
  view.setUint32(4, cpuType, littleEndian);
  return bytes;
}

function fat(cpuTypes: number[], magic = 0xcafebabe): Uint8Array {
  const entrySize = magic === 0xcafebabf ? 32 : 20;
  const bytes = new Uint8Array(8 + cpuTypes.length * entrySize);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, magic, false);
  view.setUint32(4, cpuTypes.length, false);
  cpuTypes.forEach((cpu, index) => view.setUint32(8 + index * entrySize, cpu, false));
  return bytes;
}

function javaClass(): Uint8Array {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xcafebabe, false);
  view.setUint16(4, 0, false); // minor
  view.setUint16(6, 65, false); // major (Java 21)
  return bytes;
}

const CPU_X64 = 0x01000007;
const CPU_ARM64 = 0x0100000c;

describe("executable header parsing", () => {
  test("PE machines, including bounds-checked e_lfanew", () => {
    expect(parseExecutableHeader(pe(0x8664))).toEqual({ format: "pe", architectures: ["x64"], note: null });
    expect(parseExecutableHeader(pe(0xaa64)).architectures).toEqual(["arm64"]);
    expect(parseExecutableHeader(pe(0x14c)).architectures).toEqual(["ia32"]);
    expect(parseExecutableHeader(pe(0x1c4)).architectures).toEqual(["arm"]);
    expect(parseExecutableHeader(pe(0x1c0)).architectures).toEqual(["arm"]);
    expect(parseExecutableHeader(pe(0x1234))).toMatchObject({ format: "pe", architectures: ["unknown"] });

    const outOfBounds = pe(0x8664);
    new DataView(outOfBounds.buffer).setUint32(0x3c, 0xfffffff0, true);
    expect(parseExecutableHeader(outOfBounds).format).toBe("unknown");
    const dos = pe(0x8664);
    dos.set([0, 0, 0, 0], 0x80);
    expect(parseExecutableHeader(dos)).toMatchObject({ format: "unknown", note: expect.stringContaining("without a PE signature") });
    expect(parseExecutableHeader(new Uint8Array([0x4d, 0x5a, 0, 0])).format).toBe("unknown");
  });

  test("ELF machines in both byte orders and classes", () => {
    expect(parseExecutableHeader(elf(0x3e))).toEqual({ format: "elf", architectures: ["x64"], note: null });
    expect(parseExecutableHeader(elf(0xb7)).architectures).toEqual(["arm64"]);
    expect(parseExecutableHeader(elf(0x03, 1)).architectures).toEqual(["ia32"]);
    expect(parseExecutableHeader(elf(0x28, 1)).architectures).toEqual(["arm"]);
    expect(parseExecutableHeader(elf(0xf3)).architectures).toEqual(["riscv64"]);
    expect(parseExecutableHeader(elf(0x15, 2, 2)).architectures).toEqual(["ppc64"]);
    expect(parseExecutableHeader(elf(0x16, 2, 2)).architectures).toEqual(["s390x"]);
    expect(parseExecutableHeader(elf(0x102)).architectures).toEqual(["loong64"]);
    // 32-bit RISC-V is not riscv64.
    expect(parseExecutableHeader(elf(0xf3, 1)).architectures).toEqual(["unknown"]);
    expect(parseExecutableHeader(elf(0x3e, 2, 3 as 1)).format).toBe("unknown");
  });

  test("Mach-O in both byte orders, universal binaries and Java class files", () => {
    expect(parseExecutableHeader(macho(CPU_ARM64))).toEqual({ format: "macho", architectures: ["arm64"], note: null });
    expect(parseExecutableHeader(macho(CPU_X64)).architectures).toEqual(["x64"]);
    expect(parseExecutableHeader(macho(CPU_X64, false)).architectures).toEqual(["x64"]);
    expect(parseExecutableHeader(macho(7, true, 0xfeedface)).architectures).toEqual(["ia32"]);
    expect(parseExecutableHeader(fat([CPU_X64, CPU_ARM64]))).toEqual({ format: "macho_universal", architectures: ["x64", "arm64"], note: null });
    expect(parseExecutableHeader(fat([CPU_ARM64, CPU_X64], 0xcafebabf)).architectures).toEqual(["arm64", "x64"]);
    expect(parseExecutableHeader(javaClass())).toMatchObject({ format: "unknown", note: expect.stringContaining("Java class file") });
    // A plausible count whose entries are cut off is not trusted.
    expect(parseExecutableHeader(fat([CPU_X64, CPU_ARM64]).subarray(0, 20)).format).toBe("unknown");
  });

  test("shebang scripts, empty and unrecognised files", () => {
    const script = new TextEncoder().encode("#!/usr/bin/env python3\r\nprint('x')\n");
    expect(parseExecutableHeader(script)).toEqual({ format: "script", architectures: [], note: "#!/usr/bin/env python3" });
    expect(parseExecutableHeader(new Uint8Array())).toMatchObject({ format: "unknown", note: "Empty file (0 bytes)" });
    expect(parseExecutableHeader(new TextEncoder().encode("plain text"))).toMatchObject({ format: "unknown" });
  });

  test("inspectBinary reads at most 64 KiB of real files, follows links and never executes them", async () => {
    const dir = tempDir("headers-");
    const write = (name: string, bytes: Uint8Array) => {
      const file = path.join(dir, name);
      fs.writeFileSync(file, bytes);
      return file;
    };
    const big = new Uint8Array(MAX_HEADER_BYTES * 3);
    big.set(elf(0xb7));
    const linuxArm: HostArch = { platform: "linux", nativeArch: "arm64" };
    expect(await inspectBinary(write("big-elf", big), linuxArm)).toEqual({ format: "elf", architectures: ["arm64"], compatibility: "native", note: null });
    expect(await inspectBinary(write("empty", new Uint8Array()), linuxArm)).toMatchObject({ format: "unknown", note: "Empty file (0 bytes)" });
    expect(await inspectBinary(write("java", javaClass()), linuxArm)).toMatchObject({ format: "unknown", compatibility: "unknown" });
    expect(await inspectBinary(write("tool", new TextEncoder().encode("#!/bin/sh\necho hi\n")), linuxArm)).toEqual({
      format: "script",
      architectures: [],
      compatibility: "script",
      note: "#!/bin/sh",
    });
    // Windows scripts are judged by extension (they would run through cmd.exe / PowerShell).
    const cmd = write("codeql.cmd", new TextEncoder().encode("@echo off\r\n"));
    expect(await inspectBinary(cmd, { platform: "win32", nativeArch: "x64" })).toMatchObject({ format: "script", compatibility: "script" });
    expect(await inspectBinary(path.join(dir, "missing"), linuxArm)).toMatchObject({ format: "unknown", note: "Not readable (ENOENT)" });
    // App Execution Aliases (WindowsApps reparse points) cannot be opened.
    expect(await inspectBinary("C:\\Users\\u\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe", { platform: "win32", nativeArch: "x64" })).toMatchObject({
      format: "unknown",
      note: "App Execution Alias (not readable)",
    });
    const target = write("real-tool", pe(0x8664));
    try {
      fs.symlinkSync(target, path.join(dir, "linked-tool"));
      expect(await inspectBinary(path.join(dir, "linked-tool"), { platform: "win32", nativeArch: "arm64" })).toMatchObject({ format: "pe", compatibility: "emulated" });
    } catch (error) {
      // Creating symlinks needs Developer Mode or elevation on Windows; the rest is still covered.
      if (!["EPERM", "EACCES"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
    }
  });
});

// ───────────────────────────── compatibility ─────────────────────────────

describe("binary compatibility against the native architecture", () => {
  const header = (format: ParsedHeader["format"], ...architectures: CpuArch[]): ParsedHeader => ({ format, architectures, note: null });
  const compat = (h: ParsedHeader, platform: NodeJS.Platform, nativeArch: CpuArch | null) => binaryCompatibility(h, { platform, nativeArch }).compatibility;

  test("Windows x64", () => {
    expect(compat(header("pe", "x64"), "win32", "x64")).toBe("native");
    expect(compat(header("pe", "ia32"), "win32", "x64")).toBe("compatible_32bit");
    expect(compat(header("pe", "arm64"), "win32", "x64")).toBe("incompatible");
    expect(compat(header("elf", "x64"), "win32", "x64")).toBe("incompatible");
  });

  test("Windows on Arm (an x64 Bun runs emulated there)", () => {
    expect(binaryCompatibility(header("pe", "x64"), { platform: "win32", nativeArch: "arm64" })).toEqual({
      compatibility: "emulated",
      note: "x64 binary runs under Windows on Arm emulation",
    });
    expect(compat(header("pe", "arm64"), "win32", "arm64")).toBe("native");
    expect(compat(header("pe", "ia32"), "win32", "arm64")).toBe("compatible_32bit");
    expect(compat(header("pe", "arm"), "win32", "arm64")).toBe("incompatible");
    expect(isArchEmulated("win32", "x64", "arm64")).toBe(true);
    expect(isArchEmulated("win32", "ia32", "x64")).toBe(false);
    expect(resolveNativeArch({ platform: "win32", processArch: "x64", windowsRegistryArch: "ARM64", env: { PROCESSOR_ARCHITECTURE: "AMD64" } })).toBe("arm64");
    // Without the registry: WOW64 processes see PROCESSOR_ARCHITEW6432.
    expect(resolveNativeArch({ platform: "win32", processArch: "ia32", env: { PROCESSOR_ARCHITECTURE: "x86", PROCESSOR_ARCHITEW6432: "AMD64" } })).toBe("x64");
    expect(resolveNativeArch({ platform: "win32", processArch: "x64", env: { processor_architecture: "AMD64" } })).toBe("x64");
  });

  test("macOS on Apple silicon (Rosetta 2) and Intel", () => {
    expect(compat(header("macho", "arm64"), "darwin", "arm64")).toBe("native");
    expect(binaryCompatibility(header("macho", "x64"), { platform: "darwin", nativeArch: "arm64" }).compatibility).toBe("emulated");
    expect(compat(header("macho_universal", "x64", "arm64"), "darwin", "arm64")).toBe("native");
    expect(compat(header("elf", "arm64"), "darwin", "arm64")).toBe("incompatible");
    expect(compat(header("macho", "arm64"), "darwin", "x64")).toBe("incompatible");
    expect(compat(header("macho_universal", "x64", "arm64"), "darwin", "x64")).toBe("native");
    expect(resolveNativeArch({ platform: "darwin", processArch: "x64", darwinProcTranslated: "1", darwinArm64: null })).toBe("arm64");
    expect(resolveNativeArch({ platform: "darwin", processArch: "arm64", darwinProcTranslated: "0", darwinArm64: "1" })).toBe("arm64");
    expect(resolveNativeArch({ platform: "darwin", processArch: "x64", darwinProcTranslated: "0", darwinArm64: null })).toBe("x64");
    expect(isArchEmulated("darwin", "x64", "arm64")).toBe(true);
    expect(isArchEmulated("darwin", "arm64", "arm64")).toBe(false);
  });

  test("Linux x64 and arm64", () => {
    expect(compat(header("elf", "x64"), "linux", "x64")).toBe("native");
    expect(compat(header("elf", "ia32"), "linux", "x64")).toBe("compatible_32bit");
    expect(binaryCompatibility(header("elf", "arm64"), { platform: "linux", nativeArch: "x64" }).note).toContain("binfmt_misc/qemu-user");
    expect(compat(header("pe", "x64"), "linux", "x64")).toBe("incompatible");
    expect(compat(header("elf", "arm64"), "linux", "arm64")).toBe("native");
    expect(compat(header("elf", "x64"), "linux", "arm64")).toBe("incompatible");
    expect(resolveNativeArch({ platform: "linux", processArch: "x64", machine: "aarch64" })).toBe("arm64");
    expect(machineToCpuArch("armv7l")).toBe("arm");
    expect(machineToCpuArch("ppc64le")).toBe("ppc64");
    expect(isArchEmulated("linux", "x64", "arm64")).toBe(true);
    expect(isArchEmulated("linux", "ia32", "x64")).toBe(false);
  });

  test("32-bit code is judged consistently by the header check, process emulation and runnable architectures", () => {
    // Linux arm64 + ELF 32-bit Arm: AArch32 compatibility, not emulation; may run, so a presence candidate.
    const armOnArm64 = binaryCompatibility(header("elf", "arm"), { platform: "linux", nativeArch: "arm64" });
    expect(armOnArm64.compatibility).toBe("compatible_32bit");
    expect(armOnArm64.note).toContain("runs only if the CPU and kernel support AArch32 (many arm64 servers and boards do; some recent cores do not)");
    expect(isArchEmulated("linux", "arm", "arm64")).toBe(false);
    expect(runnableArchitectures("linux", "arm64")).toEqual(["arm64", "arm"]);

    // Linux x64 + ELF ia32: IA-32 compatibility, not emulation; runnable.
    expect(compat(header("elf", "ia32"), "linux", "x64")).toBe("compatible_32bit");
    expect(isArchEmulated("linux", "ia32", "x64")).toBe(false);
    expect(runnableArchitectures("linux", "x64")).toEqual(["x64", "ia32"]);

    // The reverse directions need a foreign CPU: incompatible, emulated as a process, not runnable.
    expect(compat(header("elf", "arm64"), "linux", "x64")).toBe("incompatible");
    expect(isArchEmulated("linux", "arm64", "x64")).toBe(true);
    expect(runnableArchitectures("linux", "x64")).not.toContain("arm64");
    expect(compat(header("elf", "arm"), "linux", "x64")).toBe("incompatible");

    // Windows on Arm: 32-bit Arm apps are not supported on Windows 11 24H2 and later.
    const arm32OnWindows = binaryCompatibility(header("pe", "arm"), { platform: "win32", nativeArch: "arm64" });
    expect(arm32OnWindows.compatibility).toBe("incompatible");
    expect(arm32OnWindows.note).toContain("24H2");
    expect(runnableArchitectures("win32", "arm64")).toEqual(["arm64", "x64", "ia32"]);

    // macOS on Apple silicon: no 32-bit code at all.
    const arm32OnMac = binaryCompatibility(header("macho", "arm"), { platform: "darwin", nativeArch: "arm64" });
    expect(arm32OnMac.compatibility).toBe("incompatible");
    expect(arm32OnMac.note).toContain("32-bit");
    expect(compat(header("macho", "ia32"), "darwin", "x64")).toBe("incompatible");
    expect(runnableArchitectures("darwin", "arm64")).toEqual(["arm64", "x64"]);
  });

  test("scripts and unknown hosts", () => {
    expect(compat(header("script"), "linux", "x64")).toBe("script");
    expect(compat(header("pe", "x64"), "win32", null)).toBe("unknown");
    expect(compat(header("unknown"), "win32", "x64")).toBe("unknown");
    expect(isArchEmulated("linux", "x64", null)).toBeNull();
  });
});

// ───────────────────────────── search directories ─────────────────────────────

function searchEnv(overrides: Partial<SearchEnvironment> & Pick<SearchEnvironment, "platform">, existing: string[] = [], listings: Record<string, string[]> = {}): SearchEnvironment {
  return {
    env: {},
    homedir: overrides.platform === "win32" ? "C:\\Users\\dev" : "/home/dev",
    persisted: null,
    isDirectory: (dir) => existing.includes(dir),
    listDirectory: (dir) => {
      const names = listings[dir];
      if (!names) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      return names;
    },
    ...overrides,
  };
}

const sources = (dirs: SearchDirectory[]) => dirs.map((entry) => `${entry.source}:${entry.dir}`);

describe("search directories", () => {
  test("Windows: process PATH first, then machine and user PATH, then existing well-known dirs", () => {
    const env = {
      Path: [
        "C:\\Users\\dev\\AppData\\Local\\Temp\\bun-node-38afee6c8",
        "C:\\Tools\\",
        "c:/tools",
        '"C:\\Program Files\\Quoted"',
        "relative\\bin",
        "C:drive-relative",
        "\\\\server\\share\\bin",
        "",
      ].join(";"),
      LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local",
      ProgramFiles: "C:\\Program Files",
      "ProgramFiles(x86)": "C:\\Program Files (x86)",
      ProgramW6432: "C:\\Program Files",
      ProgramData: "C:\\ProgramData",
      APPDATA: "C:\\Users\\dev\\AppData\\Roaming",
    };
    const persisted = {
      system: ["%SystemRoot%\\system32", "D:\\CodeQL", "C:\\Tools", "%NOT_DEFINED%\\bin"],
      user: ["%LOCALAPPDATA%\\agy\\bin", "D:\\CodeQL\\", "C:\\Users\\dev\\.bun\\bin"],
    };
    const existing = [
      "C:\\Program Files\\GitHub CLI",
      "C:\\Users\\dev\\.cargo\\bin",
      "C:\\Users\\dev\\AppData\\Local\\Programs\\Python\\Python312\\Scripts",
      "C:\\Users\\dev\\AppData\\Local\\Programs\\Python\\Python313\\Scripts",
      "C:\\Users\\dev\\.bun\\bin",
    ];
    const dirs = buildSearchDirectories(
      searchEnv({ platform: "win32", env: { ...env, SystemRoot: "C:\\Windows" }, persisted }, existing, {
        "C:\\Users\\dev\\AppData\\Local\\Programs\\Python": ["Python312", "Python313", "Launcher"],
      }),
    );
    expect(sources(dirs)).toEqual([
      "process_path:C:\\Tools",
      "process_path:C:\\Program Files\\Quoted",
      "persisted_system_path:C:\\Windows\\system32",
      "persisted_system_path:D:\\CodeQL",
      "persisted_user_path:C:\\Users\\dev\\AppData\\Local\\agy\\bin",
      "persisted_user_path:C:\\Users\\dev\\.bun\\bin",
      "well_known:C:\\Users\\dev\\.cargo\\bin",
      "well_known:C:\\Program Files\\GitHub CLI",
      "well_known:C:\\Users\\dev\\AppData\\Local\\Programs\\Python\\Python313\\Scripts",
      "well_known:C:\\Users\\dev\\AppData\\Local\\Programs\\Python\\Python312\\Scripts",
    ]);
    expect(expandWindowsVariables("%localappdata%\\x", env)).toBe("C:\\Users\\dev\\AppData\\Local\\x");
    expect(expandWindowsVariables("%NOPE%\\x", env)).toBeNull();
    expect(isBunShimDir("C:\\Users\\dev\\AppData\\Local\\Temp\\bun-node-38afee6c8\\", "win32")).toBe(true);
    expect(isBunShimDir("/tmp/bun-node-1a2b", "linux")).toBe(true);
    expect(isBunShimDir("/tmp/bun-node-cache", "linux")).toBe(false);
  });

  test("Windows: no %ProgramData%\\chocolatey fallback (any user can create it); ChocolateyInstall is honoured", () => {
    const base = { Path: "C:\\Windows\\System32", ProgramData: "C:\\ProgramData" };
    const planted = ["C:\\ProgramData\\chocolatey\\bin"];
    const withoutChoco = buildSearchDirectories(searchEnv({ platform: "win32", env: base }, planted)).map((entry) => entry.dir);
    expect(withoutChoco).not.toContain("C:\\ProgramData\\chocolatey\\bin");
    const withChoco = buildSearchDirectories(searchEnv({ platform: "win32", env: { ...base, ChocolateyInstall: "C:\\ProgramData\\chocolatey" } }, planted));
    expect(sources(withChoco)).toContain("well_known:C:\\ProgramData\\chocolatey\\bin");
  });

  test("Windows: UNC and device PATH entries are skipped on purpose and counted", () => {
    const plan = buildSearchPlan(
      searchEnv({
        platform: "win32",
        env: { Path: "\\\\fileserver\\tools\\codeql;C:\\Windows\\System32;\\\\?\\C:\\dev;relative", HOMESHARE: "\\\\home\\u" },
        persisted: { system: ["//other/share"], user: ["%HOMESHARE%\\bin"] },
      }),
    );
    expect(plan.directories.map((entry) => entry.dir)).toEqual(["C:\\Windows\\System32"]);
    expect(plan.skippedNetworkEntries).toBe(4);
    const posix = buildSearchPlan(searchEnv({ platform: "linux", env: { PATH: "//usr/bin:relative" } }));
    expect(posix.skippedNetworkEntries).toBe(0);
    expect(posix.directories.map((entry) => entry.dir)).toEqual(["/usr/bin"]);
  });

  test("Windows: a UNC or device install location (AppData redirected to a share) is never listed or checked", () => {
    const touched: string[] = [];
    const env = {
      Path: "C:\\Windows\\System32",
      // Folder Redirection of AppData\Roaming to a file server, and a device-namespace LOCALAPPDATA.
      APPDATA: "\\\\fileserver\\profiles$\\u\\AppData\\Roaming",
      LOCALAPPDATA: "\\\\?\\C:\\Users\\u\\AppData\\Local",
      SCOOP: "\\\\fileserver\\scoop",
      CARGO_HOME: "//fileserver/cargo",
    };
    const plan = buildSearchPlan({
      platform: "win32",
      env,
      homedir: "C:\\Users\\u",
      persisted: null,
      isDirectory: (dir) => {
        touched.push(dir);
        return false;
      },
      listDirectory: (dir) => {
        touched.push(dir);
        return [];
      },
    });
    expect(touched.length).toBeGreaterThan(0);
    expect(touched.filter((dir) => /^[\\/]{2}/.test(dir))).toEqual([]);
    expect(plan.directories.map((entry) => entry.dir)).toEqual(["C:\\Windows\\System32"]);
    // Not PATH entries, so not counted as skipped PATH entries.
    expect(plan.skippedNetworkEntries).toBe(0);
    expect(pythonInstallBases({ platform: "win32", env, homedir: "C:\\Users\\u" })).toEqual([]);

    // A local (drive-rooted) AppData is still listed for Python version directories.
    const local = { ...env, APPDATA: "C:\\Users\\u\\AppData\\Roaming\\", LOCALAPPDATA: "relative\\Local" };
    expect(pythonInstallBases({ platform: "win32", env: local, homedir: "C:\\Users\\u" }).map((base) => base.dir)).toEqual(["C:\\Users\\u\\AppData\\Roaming\\Python"]);
  });

  test("the locator's refresh checks and lists directories asynchronously only, and never on a UNC path", async () => {
    const syncCalls: string[] = [];
    const asyncCalls: string[] = [];
    const scripts = "D:\\Users\\u\\AppData\\Local\\Programs\\Python\\Python313\\Scripts";
    const locator = new ExecutableLocator({
      platform: "win32",
      env: {
        Path: "C:\\Windows\\System32",
        APPDATA: "\\\\fileserver\\profiles$\\u\\AppData\\Roaming",
        LOCALAPPDATA: "D:\\Users\\u\\AppData\\Local",
        PATHEXT: ".EXE",
      },
      homedir: "C:\\Users\\u",
      isDirectory: (dir) => {
        syncCalls.push(dir);
        return false;
      },
      listDirectory: (dir) => {
        syncCalls.push(dir);
        return [];
      },
      isDirectoryAsync: async (dir) => {
        asyncCalls.push(dir);
        return dir === scripts;
      },
      listDirectoryAsync: async (dir) => {
        asyncCalls.push(dir);
        if (dir === "D:\\Users\\u\\AppData\\Local\\Programs\\Python") return ["Python313", "Launcher"];
        return dir === scripts ? ["semgrep.exe"] : [];
      },
      isExecutableFile: () => true,
      fileIdentity: () => null,
      loadPersisted: async () => ({ entries: { system: [], user: [] }, read: true, error: null }),
    });
    // With a persisted loader the constructor probes no well-known directory.
    expect(syncCalls).toEqual([]);
    const snapshot = await locator.refresh();
    expect(syncCalls).toEqual([]);
    expect(asyncCalls).toContain("D:\\Users\\u\\AppData\\Local\\Programs\\Python");
    expect(asyncCalls.filter((dir) => /^[\\/]{2}/.test(dir))).toEqual([]);
    expect(locator.locate("semgrep", snapshot)).toMatchObject({ path: `${scripts}\\semgrep.exe`, source: "well_known" });
    expect(syncCalls).toEqual([]);
  });

  test("a well-known directory whose check never answers counts as missing instead of blocking the refresh", async () => {
    const locator = new ExecutableLocator({
      platform: "linux",
      env: { PATH: "/usr/bin" },
      homedir: "/home/dev",
      isDirectoryAsync: (dir) => (dir === "/snap/bin" ? new Promise<boolean>(() => undefined) : Promise.resolve(dir === "/home/dev/.local/bin")),
      listDirectoryAsync: async () => [],
      listDirectory: () => [],
      loadPersisted: async () => ({ entries: { system: [], user: [] }, read: true, error: null }),
      listTimeoutMs: 50,
    });
    const started = performance.now();
    const snapshot = await locator.refresh();
    expect(performance.now() - started).toBeLessThan(2_000);
    expect(sources([...snapshot.directories])).toEqual(["process_path:/usr/bin", "well_known:/home/dev/.local/bin"]);
  });

  test("macOS: launchd PATH, /etc/paths entries and Homebrew/MacPorts/pip --user dirs", () => {
    const existing = ["/opt/homebrew/bin", "/usr/local/bin", "/Users/dev/Library/Python/3.12/bin", "/usr/bin", "/bin"];
    const dirs = buildSearchDirectories(
      searchEnv(
        {
          platform: "darwin",
          homedir: "/Users/dev",
          env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin:~/bin:./node_modules/.bin" },
          persisted: { system: [...parseEtcPaths("/usr/local/bin\n/usr/bin\n# comment\n\n/bin\n"), "/Library/Apple/usr/bin"], user: [] },
        },
        existing,
        { "/Users/dev/Library/Python": ["3.9", "3.12", "README"] },
      ),
    );
    expect(sources(dirs)).toEqual([
      "process_path:/usr/bin",
      "process_path:/bin",
      "process_path:/usr/sbin",
      "process_path:/sbin",
      "persisted_system_path:/usr/local/bin",
      "persisted_system_path:/Library/Apple/usr/bin",
      "well_known:/opt/homebrew/bin",
      "well_known:/Users/dev/Library/Python/3.12/bin",
    ]);
  });

  test("Linux: systemd-style PATH plus /etc/environment, snap, linuxbrew and ~ only for well-known dirs", () => {
    const existing = ["/snap/bin", "/home/dev/.local/bin", "/home/linuxbrew/.linuxbrew/bin", "/home/dev/.bun-custom/bin", "/usr/bin"];
    const dirs = buildSearchDirectories(
      searchEnv(
        {
          platform: "linux",
          env: { PATH: "/usr/bin:/bin:~/bin::relative", BUN_INSTALL: "~/.bun-custom" },
          persisted: { system: parseEtcEnvironmentPath('LANG=C\nPATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"\n'), user: [] },
        },
        existing,
      ),
    );
    expect(sources(dirs)).toEqual([
      "process_path:/usr/bin",
      "process_path:/bin",
      "persisted_system_path:/usr/local/sbin",
      "persisted_system_path:/usr/local/bin",
      "persisted_system_path:/usr/sbin",
      "well_known:/home/dev/.bun-custom/bin",
      "well_known:/home/dev/.local/bin",
      "well_known:/snap/bin",
      "well_known:/home/linuxbrew/.linuxbrew/bin",
    ]);
  });
});

// ───────────────────────────── locating ─────────────────────────────

function probes(platform: NodeJS.Platform, files: Record<string, string[]>, nativeArch: CpuArch = "x64", env: Record<string, string> = {}) {
  return {
    platform,
    env,
    nativeArch,
    directoryIndex: (dir: string) => {
      const names = files[dir];
      if (!names) return new Map<string, string>();
      return new Map(names.map((name) => [platform === "win32" ? name.toLowerCase() : name, name] as [string, string]));
    },
    isExecutableFile: () => true,
  };
}

describe("locating executables", () => {
  test("Windows PATHEXT semantics never return the extension-less codeql launcher", () => {
    const dirs: SearchDirectory[] = [
      { dir: "C:\\Old", source: "process_path" },
      { dir: "D:\\CodeQL", source: "persisted_system_path" },
      { dir: "E:\\Other", source: "persisted_user_path" },
    ];
    const files = { "C:\\Old": ["codeql"], "D:\\CodeQL": ["codeql", "codeql.cmd", "CodeQL.EXE"], "E:\\Other": ["codeql.bat"] };
    const located = locateExecutable("codeql", dirs, probes("win32", files));
    expect(located.path).toBe("D:\\CodeQL\\CodeQL.EXE");
    expect(located.source).toBe("persisted_system_path");
    expect(located.onProcessPath).toBe(false);
    expect(located.shadowed).toEqual(["D:\\CodeQL\\codeql.cmd", "E:\\Other\\codeql.bat"]);
    expect(locateExecutable("codeql", dirs.slice(0, 1), probes("win32", files)).path).toBeNull();

    expect(executableFileNames("gh", "win32", {}, "x64")).toEqual(["gh.com", "gh.exe", "gh.bat", "gh.cmd"]);
    expect(executableFileNames("gh.exe", "win32", {}, "x64")).toEqual(["gh.exe"]);
    expect(executableFileNames("tool", "win32", { PATHEXT: ".EXE;.PS1;bogus" }, "x64")).toEqual(["tool.exe", "tool.ps1"]);
    expect(executableFileNames("gh", "linux", {}, "x64")).toEqual(["gh"]);
  });

  test("POSIX: the bare name, first match on the process PATH, at most four shadowed matches", () => {
    const dirs: SearchDirectory[] = ["/a", "/b", "/c", "/d", "/e", "/f"].map((dir) => ({ dir, source: "process_path" as const }));
    const files = Object.fromEntries(dirs.map((entry) => [entry.dir, ["semgrep"]]));
    const located = locateExecutable("semgrep", dirs, probes("linux", files));
    expect(located.path).toBe("/a/semgrep");
    expect(located.onProcessPath).toBe(true);
    expect(located.shadowed).toEqual(["/b/semgrep", "/c/semgrep", "/d/semgrep", "/e/semgrep"]);
    const notExecutable = locateExecutable("semgrep", dirs, { ...probes("linux", files), isExecutableFile: (file: string) => file === "/c/semgrep" });
    expect(notExecutable.path).toBe("/c/semgrep");
  });

  test("osv-scanner release-asset names for the host OS and runnable architectures", () => {
    expect(releaseAssetNames("osv-scanner", "win32", "arm64")).toEqual(["osv-scanner_windows_arm64", "osv-scanner_windows_amd64", "osv-scanner_windows_386"]);
    expect(releaseAssetNames("osv-scanner", "darwin", "arm64")).toEqual(["osv-scanner_darwin_arm64", "osv-scanner_darwin_amd64"]);
    // 32-bit Arm may run on Linux arm64 (AArch32), so its asset name is a presence candidate there.
    expect(releaseAssetNames("osv-scanner", "linux", "arm64")).toEqual(["osv-scanner_linux_arm64", "osv-scanner_linux_arm"]);
    expect(releaseAssetNames("semgrep", "linux", "x64")).toEqual([]);

    const win = locateExecutable("osv-scanner", [{ dir: "C:\\bin", source: "well_known" }], probes("win32", { "C:\\bin": ["osv-scanner_linux_amd64", "osv-scanner_windows_amd64.exe"] }));
    expect(win.path).toBe("C:\\bin\\osv-scanner_windows_amd64.exe");
    const linux = locateExecutable("osv-scanner", [{ dir: "/opt/bin", source: "well_known" }], probes("linux", { "/opt/bin": ["osv-scanner_linux_amd64"] }));
    expect(linux.path).toBe("/opt/bin/osv-scanner_linux_amd64");
    const darwin = locateExecutable("osv-scanner", [{ dir: "/usr/local/bin", source: "well_known" }], probes("darwin", { "/usr/local/bin": ["osv-scanner_linux_arm64"] }, "arm64"));
    expect(darwin.path).toBeNull();
  });

  test("Linux merged /usr: the same file reached through symlinked directories is not a later match", () => {
    // Arch/Fedora: /bin -> usr/bin, /sbin -> usr/sbin -> bin. The systemd PATH plus /bin and /sbin.
    const dirs: SearchDirectory[] = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"].map((dir) => ({
      dir,
      source: "process_path" as const,
    }));
    const files = Object.fromEntries(["/usr/sbin", "/usr/bin", "/sbin", "/bin"].map((dir) => [dir, ["git"]]));
    const sameInode = { ...probes("linux", files), fileIdentity: (file: string) => (file.endsWith("/git") ? "2049:1234" : null) };
    expect(locateExecutable("git", dirs, sameInode)).toMatchObject({ path: "/usr/sbin/git", shadowed: [] });
    // Without identities (unreadable), nothing is merged.
    expect(locateExecutable("git", dirs, probes("linux", files)).shadowed).toHaveLength(3);
  });

  test("merged directories on the real file system (symlink, or a junction on Windows)", () => {
    const root = tempDir("merged-");
    const usrBin = path.join(root, "usr", "bin");
    fs.mkdirSync(usrBin, { recursive: true });
    const name = process.platform === "win32" ? "git.exe" : "git";
    fs.writeFileSync(path.join(usrBin, name), elf(0x3e), { mode: 0o755 });
    const bin = path.join(root, "bin");
    fs.symlinkSync(usrBin, bin, process.platform === "win32" ? "junction" : "dir");
    const locator = new ExecutableLocator({ env: { PATH: [usrBin, bin].join(path.delimiter), PATHEXT: ".EXE" }, homedir: path.join(root, "home"), isDirectory: () => false });
    expect(locator.locate("git")).toMatchObject({ path: path.join(usrBin, name), shadowed: [] });
  });

  test("the locator waits for the first persisted read, then serves the cache and revalidates in the background", async () => {
    let clock = 0;
    let loads = 0;
    let release: (value: PersistedPathResult) => void = () => undefined;
    const locator = new ExecutableLocator({
      platform: "linux",
      env: { PATH: "/usr/bin" },
      homedir: "/home/dev",
      isDirectory: () => false,
      listDirectory: (dir) => (dir === "/opt/tools" ? ["semgrep"] : []),
      isExecutableFile: () => true,
      now: () => clock,
      ttlMs: 1000,
      loadPersisted: () => {
        loads += 1;
        return new Promise((resolve) => {
          release = resolve;
        });
      },
    });
    expect(locator.snapshot().persistedPathRead).toBe(false);
    expect(locator.locate("semgrep").path).toBeNull();
    const first = locator.current();
    const second = locator.current();
    release({ entries: { system: ["/opt/tools"], user: [] }, read: true, error: null });
    const snapshot = await first;
    expect(await second).toBe(snapshot);
    expect(loads).toBe(1);
    expect(locator.locate("semgrep", snapshot)).toMatchObject({ path: "/opt/tools/semgrep", source: "persisted_system_path", onProcessPath: false });
    expect(locator.status(snapshot)).toMatchObject({ persistedPathRead: true, persistedPathError: null, searchedDirectories: 2 });

    clock = 5000;
    expect(await locator.current()).toBe(snapshot);
    expect(loads).toBe(2);
    release({ entries: { system: [], user: [] }, read: false, error: "powershell.exe exited with code 1" });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(locator.snapshot()).not.toBe(snapshot);
    expect(locator.status()).toMatchObject({ persistedPathRead: false, persistedPathError: "powershell.exe exited with code 1" });
  });
});

// ───────────────────────────── execution policy ─────────────────────────────

describe("choosing a file to run", () => {
  const trusted = () => null;

  test("standard install locations are never run, only reported", () => {
    // The reviewer's scenario: a planted C:\ProgramData\chocolatey\bin\gh.exe, with ChocolateyInstall set or not.
    const planted = [{ path: "C:\\ProgramData\\chocolatey\\bin\\gh.exe", source: "well_known" as const }];
    expect(chooseForExecution(planted, "win32", trusted)).toMatchObject({ path: null, skipped: [{ path: planted[0].path }] });
    const locator = new ExecutableLocator({
      platform: "win32",
      env: { Path: "C:\\Windows\\System32", ChocolateyInstall: "C:\\ProgramData\\chocolatey", PATHEXT: ".EXE" },
      homedir: "C:\\Users\\u",
      isDirectory: (dir) => dir === "C:\\ProgramData\\chocolatey\\bin",
      listDirectory: (dir) => (dir === "C:\\ProgramData\\chocolatey\\bin" ? ["gh.exe", "sentra.exe"] : []),
      isExecutableFile: () => true,
    });
    expect(locator.locate("gh").path).toBe("C:\\ProgramData\\chocolatey\\bin\\gh.exe");
    expect(locator.locateForExecution("gh")).toEqual({ path: null, source: null, skipped: [] });
  });

  test("Windows: a .cmd/.bat earlier on PATH is skipped and the later gh.exe is run", () => {
    const matches = [
      { path: "C:\\Users\\u\\bin\\gh.cmd", source: "process_path" as const },
      { path: "C:\\Program Files\\GitHub CLI\\gh.exe", source: "persisted_system_path" as const },
    ];
    const choice = chooseForExecution(matches, "win32", trusted);
    expect(choice).toMatchObject({ path: "C:\\Program Files\\GitHub CLI\\gh.exe", source: "persisted_system_path" });
    expect(choice.skipped).toEqual([{ path: "C:\\Users\\u\\bin\\gh.cmd", reason: expect.stringContaining("not a .exe or .com") }]);
    expect(chooseForExecution([{ path: "C:\\x\\gh.COM", source: "persisted_user_path" }], "win32", trusted).path).toBe("C:\\x\\gh.COM");
  });

  test("macOS/Linux: persisted-PATH matches must pass the ownership check; process-PATH matches are not checked", () => {
    // Intel Homebrew: /usr/local/bin is in /etc/paths and group-writable by admin.
    const homebrewReason = "the directory /usr/local/bin is writable by group admin (gid 80), which is not root";
    const untrusted = (file: string) => (file.startsWith("/usr/local/") ? homebrewReason : null);
    const persisted = [
      { path: "/usr/local/bin/gh", source: "persisted_system_path" as const },
      { path: "/usr/bin/gh", source: "persisted_system_path" as const },
    ];
    const choice = chooseForExecution(persisted, "darwin", untrusted);
    expect(choice.path).toBe("/usr/bin/gh");
    expect(choice.skipped).toEqual([{ path: "/usr/local/bin/gh", reason: `found through the persisted PATH, but ${homebrewReason}` }]);
    expect(chooseForExecution([{ path: "/usr/local/bin/gh", source: "process_path" }], "linux", untrusted).path).toBe("/usr/local/bin/gh");

    // Owner root or the bridge user; never writable by others; group-writable only for group root.
    expect(isTrustedOwnership({ uid: 0, gid: 0, mode: 0o100755 }, 501)).toBe(true);
    expect(isTrustedOwnership({ uid: 501, gid: 20, mode: 0o100755 }, 501)).toBe(true);
    expect(isTrustedOwnership({ uid: 501, gid: 20, mode: 0o100755 }, 0)).toBe(false); // root bridge, Homebrew user's file
    expect(isTrustedOwnership({ uid: 0, gid: 0, mode: 0o100777 }, 0)).toBe(false);
    expect(isTrustedOwnership({ uid: 0, gid: 80, mode: 0o040775 }, 0)).toBe(false);
    expect(isTrustedOwnership({ uid: 0, gid: 0, mode: 0o040775 }, 0)).toBe(true);
  });

  test("ownership problems are named precisely: owner, others, or a non-root group (Homebrew's admin group)", () => {
    const groups = (gid: number) => parseEtcGroup("# comment\nwheel:*:0:root\nstaff:*:20:root\nadmin:*:80:root\n").get(gid) ?? null;
    expect(ownershipProblem({ uid: 501, gid: 20, mode: 0o040755 }, 0, groups)).toBe("owned by uid 501, which is neither root nor the bridge user (uid 0)");
    expect(ownershipProblem({ uid: 0, gid: 0, mode: 0o040777 }, 0, groups)).toBe("writable by others");
    // Apple-silicon Homebrew: /opt/homebrew/bin is drwxrwxr-x, owned by the installing user, group admin.
    expect(ownershipProblem({ uid: 501, gid: 80, mode: 0o040775 }, 501, groups)).toBe("writable by group admin (gid 80), which is not root");
    expect(ownershipProblem({ uid: 501, gid: 4242, mode: 0o040775 }, 501, groups)).toBe("writable by group gid 4242, which is not root");
    expect(ownershipProblem({ uid: 0, gid: 0, mode: 0o040775 }, 501, groups)).toBeNull();
    expect(parseEtcGroup("broken\nnogid:x::\nadm:x:4:syslog\n")).toEqual(new Map([[4, "adm"]]));

    // The check names which of the three paths failed (injected stat/realpath, so this runs anywhere).
    const modes: Record<string, { uid: number; gid: number; mode: number }> = {
      "/etc/paths.d-dir": { uid: 0, gid: 0, mode: 0o040755 },
      "/opt/homebrew/bin": { uid: 501, gid: 80, mode: 0o040775 },
      "/opt/homebrew/Cellar/gh/2.60.0/bin/gh": { uid: 501, gid: 80, mode: 0o100755 },
      "/opt/homebrew/Cellar/gh/2.60.0/bin": { uid: 501, gid: 80, mode: 0o040755 },
    };
    const check = defaultExecutionTrustCheck("darwin", {
      euid: 501,
      groupName: groups,
      stat: (file) => {
        const facts = modes[file];
        if (!facts) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
        return facts;
      },
      realpath: (file) => (file === "/opt/homebrew/bin/gh" ? "/opt/homebrew/Cellar/gh/2.60.0/bin/gh" : file),
    });
    expect(check("/opt/homebrew/bin/gh")).toBe("the directory /opt/homebrew/bin is writable by group admin (gid 80), which is not root");
    expect(check("/nowhere/gh")).toBe("the directory /nowhere could not be checked (ENOENT)");
  });

  test("Windows: the ownership check accepts every file (ACLs are not read), so only source and file type decide", () => {
    const check = defaultExecutionTrustCheck("win32");
    expect(check("C:\\Users\\Public\\gh.exe")).toBeNull();
    expect(check("D:\\anything\\at\\all.exe")).toBeNull();
    // What still applies on Windows: never a standard install location, never a script.
    const choice = chooseForExecution(
      [
        { path: "C:\\ProgramData\\chocolatey\\bin\\gh.exe", source: "well_known" },
        { path: "C:\\Tools\\gh.cmd", source: "persisted_user_path" },
        { path: "C:\\Program Files\\GitHub CLI\\gh.exe", source: "persisted_system_path" },
      ],
      "win32",
      check,
    );
    expect(choice.path).toBe("C:\\Program Files\\GitHub CLI\\gh.exe");
    expect(choice.skipped.map((entry) => entry.path)).toEqual(["C:\\ProgramData\\chocolatey\\bin\\gh.exe", "C:\\Tools\\gh.cmd"]);
  });

  test.skipIf(process.platform === "win32")("POSIX: the real ownership check rejects a directory writable by others or by a non-root group", () => {
    const dir = tempDir("trust-");
    const file = path.join(dir, "gh");
    fs.writeFileSync(file, "#!/bin/sh\nexit 0\n");
    fs.chmodSync(file, 0o755);
    const linkDir = tempDir("trust-link-");
    fs.chmodSync(linkDir, 0o755);
    const link = path.join(linkDir, "gh");
    fs.symlinkSync(file, link);
    const check = defaultExecutionTrustCheck(process.platform);
    const realDir = fs.realpathSync(dir);
    try {
      // Owned by the user running the tests (the bridge user here), not writable by others.
      fs.chmodSync(dir, 0o755);
      expect(check(file)).toBeNull();
      expect(check(link)).toBeNull();

      fs.chmodSync(dir, 0o757);
      expect(check(file)).toBe(`the directory ${dir} is writable by others`);
      // Through a symlink in a safe directory, the target's directory is still checked.
      expect(check(link)).toBe(`the directory ${realDir} is writable by others`);

      fs.chmodSync(dir, 0o755);
      fs.chmodSync(file, 0o757);
      expect(check(file)).toBe(`the file ${fs.realpathSync(file)} is writable by others`);
      fs.chmodSync(file, 0o755);

      fs.chmodSync(dir, 0o775);
      const gid = fs.statSync(dir).gid;
      // Group-writable is accepted only for group root (a root-run test leaves the directory in group 0).
      if (gid === 0) expect(check(file)).toBeNull();
      else expect(check(file)).toStartWith(`the directory ${dir} is writable by group `);
      expect(check(path.join(dir, "missing"))).toStartWith("its target could not be resolved (ENOENT)");
    } finally {
      fs.chmodSync(dir, 0o700);
    }
  });

  test("sentra and the default gh lookup use the process PATH only, and only .exe/.com on Windows", () => {
    // The reviewer's reproduction: a temp ProgramData with chocolatey\bin\sentra.exe must not be chosen.
    const listings: Record<string, string[]> = {
      "C:\\Windows\\System32": ["cmd.exe"],
      "C:\\ProgramData\\chocolatey\\bin": ["sentra.exe", "gh.exe"],
      "C:\\Tools": ["sentra.cmd", "gh.bat"],
      "D:\\Sentra": ["sentra.exe"],
    };
    const options = (pathValue: string) => ({
      platform: "win32" as const,
      env: { PATH: pathValue, ProgramData: "C:\\ProgramData", PATHEXT: ".COM;.EXE;.BAT;.CMD" },
      listDirectory: (dir: string) => listings[dir] ?? [],
      isExecutableFile: () => true,
      fileIdentity: () => null,
    });
    expect(findOnProcessPathForExecution("sentra", options("C:\\Windows\\System32"))).toBeNull();
    expect(findOnProcessPathForExecution("gh", options("C:\\Windows\\System32"))).toBeNull();
    expect(findOnProcessPathForExecution("sentra", options("C:\\Tools"))).toBeNull();
    expect(findOnProcessPathForExecution("sentra", options("C:\\Tools;D:\\Sentra"))).toBe("D:\\Sentra\\sentra.exe");
    expect(findOnProcessPathForExecution("sentra", options("relative;\\\\server\\share"))).toBeNull();
  });

  test("the gh usage note names the file that is actually run", () => {
    const located = (paths: [string, "process_path" | "persisted_system_path" | "well_known"][]) => ({
      path: paths[0]?.[0] ?? null,
      source: paths[0]?.[1] ?? null,
      onProcessPath: paths[0]?.[1] === "process_path",
      shadowed: paths.slice(1).map(([file]) => file),
      matches: paths.map(([file, source]) => ({ path: file, source })),
    });
    const same = located([["C:\\gh\\gh.exe", "process_path"]]);
    expect(ghExecutionNote(same, chooseForExecution(same.matches, "win32", trusted), "win32")).toBe("The file shown is the one run.");
    const script = located([
      ["C:\\Users\\u\\bin\\gh.cmd", "process_path"],
      ["C:\\Program Files\\GitHub CLI\\gh.exe", "persisted_system_path"],
    ]);
    expect(ghExecutionNote(script, chooseForExecution(script.matches, "win32", trusted), "win32")).toBe(
      "The file run is C:\\Program Files\\GitHub CLI\\gh.exe; C:\\Users\\u\\bin\\gh.cmd is not run: not a .exe or .com (a script would run through its interpreter, such as cmd.exe).",
    );
    const wellKnownOnly = located([["/opt/homebrew/bin/gh", "well_known"]]);
    expect(ghExecutionNote(wellKnownOnly, { path: null, source: null, skipped: [] }, "darwin")).toBe(
      "Nothing is run on this host: /opt/homebrew/bin/gh is not run: found only in a standard install location, which is never used to run a program.",
    );
    expect(ghExecutionNote(located([]), { path: null, source: null, skipped: [] }, "linux")).toBeNull();
  });

  test("gh auth token gets an allow-listed environment without the bridge's secrets", () => {
    const env = ghEnvironment(
      {
        PATH: "/usr/bin",
        HOME: "/home/u",
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
        GH_CONFIG_DIR: "/home/u/.config/gh",
        SENTRA_WEB_SECRET_KEY: "k",
        SENTRA_WEB_TOKENS: "admin:t",
        SENTRA_GITHUB_WEBHOOK_SECRET: "s",
        SENTRA_GITLAB_WEBHOOK_TOKEN: "g",
        GITHUB_TOKEN: "ghp_x",
        AWS_SECRET_ACCESS_KEY: "a",
      },
      "linux",
    );
    expect(env).toEqual({
      GH_PROMPT_DISABLED: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
      NO_COLOR: "1",
      PATH: "/usr/bin",
      HOME: "/home/u",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
      GH_CONFIG_DIR: "/home/u/.config/gh",
    });
    // Windows variable names are matched case-insensitively.
    expect(ghEnvironment({ Path: "C:\\Windows", SystemRoot: "C:\\Windows", AppData: "C:\\Users\\u\\AppData\\Roaming" }, "win32")).toMatchObject({
      PATH: "C:\\Windows",
      SYSTEMROOT: "C:\\Windows",
      APPDATA: "C:\\Users\\u\\AppData\\Roaming",
    });
  });
});

// ───────────────────────────── host platform ─────────────────────────────

const VM_STAT = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                3000.
Pages active:                            200000.
Pages inactive:                          190000.
Pages speculative:                        10000.
Pages throttled:                              0.
Pages wired down:                        100000.
Pages purgeable:                          20000.
"Translation faults":                 123456789.
Pages copy-on-write:                    1234567.
File-backed pages:                       150000.
Anonymous pages:                         250000.
Pages stored in compressor:              300000.
Pages occupied by compressor:             50000.
`;

describe("host platform facts", () => {
  test("parsers for registry, /etc, os-release, sw_vers, meminfo and vm_stat", () => {
    expect(parseWindowsRegistryJson('\uFEFF{"userPath":"%LOCALAPPDATA%\\\\x;D:\\\\Ünïcode","systemPath":null,"processorArchitecture":"ARM64"}')).toEqual({
      userPath: "%LOCALAPPDATA%\\x;D:\\Ünïcode",
      systemPath: null,
      processorArchitecture: "ARM64",
    });
    expect(() => parseWindowsRegistryJson("not json")).toThrow();
    expect(parseEtcEnvironmentPath("PATH=/a:/b\nexport PATH='/c:/d'\n")).toEqual(["/c", "/d"]);
    expect(parseEtcEnvironmentPath("LANG=C\n")).toEqual([]);
    expect(parseOsRelease('NAME="Ubuntu"\nVERSION="24.04 LTS (Noble Numbat)"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n')).toBe("Ubuntu 24.04.1 LTS");
    expect(parseOsRelease("NAME=Alpine\nVERSION_ID=3.20.0\n")).toBe("Alpine 3.20.0");
    expect(parseSwVers("ProductName:\t\tmacOS\nProductVersion:\t\t15.1\nBuildVersion:\t\t24B83\n")).toBe("macOS 15.1");
    expect(windowsOsName("Windows 10 Pro", "10.0.26100")).toBe("Windows 11 Pro");
    expect(windowsOsName("Windows 10 Pro", "10.0.19045")).toBe("Windows 10 Pro");
    expect(windowsOsName("Windows 11 Education", "10.0.26300")).toBe("Windows 11 Education");
    expect(windowsOsName("", "10.0.26300")).toBeNull();
    expect(parseProcMeminfo("MemTotal:       16000000 kB\nMemFree:          500000 kB\nMemAvailable:    8000000 kB\n")).toBe(8_000_000 * 1024);
    expect(parseProcMeminfo("MemTotal: 1 kB\n")).toBeNull();
    // used = (active + inactive + speculative - file-backed - purgeable) + wired + compressor = 230000 + 150000 pages
    const total = 1_000_000 * 16384;
    expect(parseVmStat(VM_STAT, total)).toBe(total - 380_000 * 16384);
    // Far above os.freemem(), which only counts the 3000 free pages.
    expect(parseVmStat(VM_STAT, total)!).toBeGreaterThan(3000 * 16384 * 100);
    expect(parseVmStat("Pages free: 10.\n", total)).toBeNull();
  });

  test("Windows: one allow-listed PowerShell call yields both PATHs and the native architecture", async () => {
    const calls: { file: string; args: string[]; input: string | undefined }[] = [];
    const host = new HostPlatform({
      platform: "win32",
      processArch: "x64",
      env: { SystemRoot: "C:\\Windows", PROCESSOR_ARCHITECTURE: "AMD64" },
      run: async (file, args, input): Promise<SystemProgramResult> => {
        calls.push({ file, args, input });
        return { code: 0, timedOut: false, stdout: JSON.stringify({ userPath: "%USERPROFILE%\\bin;D:\\CodeQL;", systemPath: "C:\\Windows\\system32;D:\\CodeQL", processorArchitecture: "ARM64" }) };
      },
      osVersion: () => "Windows 11 Pro",
      osRelease: () => "10.0.26100",
      freemem: () => 123,
    });
    const persisted = await host.persistedPaths();
    expect(persisted).toEqual({ entries: { system: ["C:\\Windows\\system32", "D:\\CodeQL"], user: ["%USERPROFILE%\\bin", "D:\\CodeQL", ""] }, read: true, error: null });
    expect(await host.nativeArch()).toBe("arm64");
    expect(await host.archEmulated()).toBe(true);
    expect(await host.osName()).toBe("Windows 11 Pro");
    expect(await host.availableMemory(1000)).toEqual({ availableBytes: 123, source: "os" });
    expect(calls).toHaveLength(1);
    expect(calls[0].file).toBe(windowsPowerShellPath({ SystemRoot: "C:\\Windows" }));
    // The fixed script goes to standard input: no encoded payload, no execution-policy override.
    expect(calls[0].args).toEqual(["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", "-"]);
    expect([...WINDOWS_POWERSHELL_ARGS]).toEqual(calls[0].args);
    expect(calls[0].args.join(" ")).not.toMatch(/EncodedCommand|ExecutionPolicy|Bypass/i);
    expect(calls[0].input).toBe(`${WINDOWS_REGISTRY_SCRIPT}\r\n`);
    // `-Command -` runs standard input line by line, so the script must be a single line.
    expect(WINDOWS_REGISTRY_SCRIPT).not.toMatch(/[\r\n]/);
  });

  test("Windows: the registry is read at most once per TTL window, not on every snapshot refresh", async () => {
    let clock = 0;
    let calls = 0;
    const host = new HostPlatform({
      platform: "win32",
      processArch: "x64",
      env: { SystemRoot: "C:\\Windows" },
      now: () => clock,
      run: async () => {
        calls += 1;
        return { code: 0, timedOut: false, stdout: JSON.stringify({ userPath: null, systemPath: "D:\\CodeQL", processorArchitecture: "AMD64" }) };
      },
    });
    // The executable search refreshes every 60 s while the host page polls every 10 s.
    for (clock = 0; clock < WINDOWS_REGISTRY_TTL_MS; clock += 10_000) await host.persistedPaths();
    expect(calls).toBe(1);
    clock = WINDOWS_REGISTRY_TTL_MS + 1;
    await host.persistedPaths();
    expect(calls).toBe(2);
    expect(WINDOWS_REGISTRY_TTL_MS).toBeGreaterThanOrEqual(10 * 60_000);
  });

  test.if(process.platform === "win32")("Windows: the real registry read through stdin works on this host", async () => {
    // Starts only the allow-listed %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe.
    const host = new HostPlatform();
    const persisted = await host.persistedPaths();
    expect(persisted.error).toBeNull();
    expect(persisted.read).toBe(true);
    expect(persisted.entries.system.length).toBeGreaterThan(0);
    expect(["x64", "arm64", "ia32", "arm"]).toContain((await host.nativeArch()) as string);
  });

  test("Windows: a failed PowerShell call is reported, not thrown, and the env fallback gives the arch", async () => {
    const host = new HostPlatform({
      platform: "win32",
      processArch: "x64",
      env: { SystemRoot: "C:\\Windows", PROCESSOR_ARCHITECTURE: "AMD64" },
      run: async () => ({ code: null, stdout: "", timedOut: true }),
    });
    const persisted = await host.persistedPaths();
    expect(persisted.read).toBe(false);
    expect(persisted.error).toContain("did not answer");
    expect(await host.nativeArch()).toBe("x64");
  });

  test("Windows: a PowerShell that keeps failing is started again after 1, 2, 4, 8, then every 10 minutes", async () => {
    expect([0, 1, 2, 3, 4, 5, 6, 50].map(registryRetryDelayMs)).toEqual([0, 60_000, 120_000, 240_000, 480_000, 600_000, 600_000, 600_000]);
    let clock = 0;
    const starts: number[] = [];
    let outcome: () => SystemProgramResult = () => ({ code: 1, stdout: "", timedOut: false });
    const host = new HostPlatform({
      platform: "win32",
      processArch: "x64",
      env: { SystemRoot: "C:\\Windows", PROCESSOR_ARCHITECTURE: "AMD64" },
      now: () => clock,
      run: async () => {
        starts.push(clock);
        return outcome();
      },
    });
    // The search refreshes about every minute while the page is open (it polls every 10 s); simulate
    // 40 minutes of that against a powershell.exe that always exits with code 1 (for example a
    // Constrained Language Mode policy that blocks the script).
    for (clock = 0; clock <= 40 * 60_000; clock += 10_000) {
      const result = await host.persistedPaths();
      expect(result).toMatchObject({ read: false, entries: { system: [], user: [] } });
      expect(result.error).toStartWith("powershell.exe exited with code 1 (next attempt in about ");
    }
    // 0, then +1, +2, +4, +8 minutes, then every 10 minutes: 0, 1, 3, 7, 15, 25, 35 (minutes).
    expect(starts.map((at) => at / 60_000)).toEqual([0, 1, 3, 7, 15, 25, 35]);
    // The cached failure is reused: the native architecture falls back to the environment without a new start.
    expect(await host.nativeArch()).toBe("x64");
    expect(starts).toHaveLength(7);

    // Once PowerShell answers again, the read is cached for the full window and the backoff resets.
    outcome = () => ({ code: 0, timedOut: false, stdout: JSON.stringify({ userPath: null, systemPath: "D:\\CodeQL", processorArchitecture: "AMD64" }) });
    clock = 45 * 60_000;
    expect(await host.persistedPaths()).toMatchObject({ read: true, error: null, entries: { system: ["D:\\CodeQL"] } });
    const afterRecovery = starts.length;
    clock += WINDOWS_REGISTRY_TTL_MS - 1;
    await host.persistedPaths();
    expect(starts.length).toBe(afterRecovery);
    outcome = () => ({ code: null, stdout: "", timedOut: true });
    clock += 2;
    expect((await host.persistedPaths()).error).toContain("(next attempt in about 1 min)");
    expect(starts.length).toBe(afterRecovery + 1);
    const thrown = new HostPlatform({
      platform: "win32",
      processArch: "x64",
      env: { SystemRoot: "C:\\Windows" },
      run: async () => {
        throw new Error("spawn EACCES");
      },
    });
    expect((await thrown.persistedPaths()).error).toStartWith("powershell.exe could not be started: spawn EACCES");
  });

  test("macOS: sysctl detects Rosetta, sw_vers names the OS, vm_stat gives available memory", async () => {
    const calls: string[] = [];
    const host = new HostPlatform({
      platform: "darwin",
      processArch: "x64",
      run: async (file, args) => {
        calls.push([file, ...args].join(" "));
        if (file === "/usr/sbin/sysctl" && args[1] === "sysctl.proc_translated") return { code: 0, stdout: "1\n", timedOut: false };
        if (file === "/usr/sbin/sysctl") return { code: 1, stdout: "", timedOut: false };
        if (file === "/usr/bin/sw_vers") return { code: 0, stdout: "ProductName:\tmacOS\nProductVersion:\t14.5\n", timedOut: false };
        if (file === "/usr/bin/vm_stat") return { code: 0, stdout: VM_STAT, timedOut: false };
        throw new Error(`unexpected ${file}`);
      },
      readTextFile: async (file) => (file === "/etc/paths" ? "/usr/local/bin\n/usr/bin\n" : file === "/etc/paths.d/10-cryptex" ? "/System/Cryptexes/App/usr/bin\n" : null),
      listDirectory: async (dir) => (dir === "/etc/paths.d" ? ["10-cryptex", ".hidden"] : null),
    });
    expect(await host.nativeArch()).toBe("arm64");
    expect(await host.archEmulated()).toBe(true);
    expect(await host.osName()).toBe("macOS 14.5");
    const total = 1_000_000 * 16384;
    expect(await host.availableMemory(total)).toEqual({ availableBytes: total - 380_000 * 16384, source: "vm_stat" });
    expect(await host.persistedPaths()).toEqual({ entries: { system: ["/usr/local/bin", "/usr/bin", "/System/Cryptexes/App/usr/bin"], user: [] }, read: true, error: null });
    expect(calls.every((call) => ["/usr/sbin/sysctl", "/usr/bin/sw_vers", "/usr/bin/vm_stat"].includes(call.split(" ")[0]))).toBe(true);
  });

  test("macOS: one unreadable /etc/paths.d file is a partial read, not a failed one", async () => {
    const eacces = () => Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    const partial = new HostPlatform({
      platform: "darwin",
      processArch: "arm64",
      run: async () => ({ code: 1, stdout: "", timedOut: false }),
      readTextFile: async (file) => {
        if (file === "/etc/paths") return "/usr/local/bin\n/usr/bin\n";
        throw eacces();
      },
      listDirectory: async () => ["corp-tools"],
    });
    const result = await partial.persistedPaths();
    expect(result.entries.system).toEqual(["/usr/local/bin", "/usr/bin"]);
    expect(result.read).toBe(true);
    expect(result.error).toContain("/etc/paths.d/corp-tools");
    expect(describeSearchScope({ persistedPathRead: result.read, persistedPathError: result.error }, "darwin")).toBe(
      "the bridge process PATH, the persisted PATH (/etc/paths and /etc/paths.d) (only partly read: /etc/paths.d/corp-tools: EACCES: permission denied) and standard install locations",
    );

    const failed = new HostPlatform({
      platform: "darwin",
      processArch: "arm64",
      run: async () => ({ code: 1, stdout: "", timedOut: false }),
      readTextFile: async () => {
        throw eacces();
      },
      listDirectory: async () => {
        throw eacces();
      },
    });
    const none = await failed.persistedPaths();
    expect(none).toMatchObject({ entries: { system: [], user: [] }, read: false });
    expect(describeSearchScope({ persistedPathRead: none.read, persistedPathError: none.error }, "darwin")).toStartWith(
      "the bridge process PATH and standard install locations; the persisted PATH (/etc/paths and /etc/paths.d) could not be read (",
    );
  });

  test("Linux: os.machine, os-release, MemAvailable and /etc/environment are read from files only", async () => {
    const files: Record<string, string> = {
      "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
      "/proc/meminfo": "MemTotal: 2000 kB\nMemAvailable: 1500 kB\n",
      "/etc/environment": 'PATH="/usr/local/bin:/usr/bin"\n',
    };
    const host = new HostPlatform({
      platform: "linux",
      processArch: "x64",
      machine: () => "aarch64",
      run: async () => {
        throw new Error("no program may be started on Linux");
      },
      readTextFile: async (file) => files[file] ?? null,
      freemem: () => 1,
    });
    expect(await host.nativeArch()).toBe("arm64");
    expect(await host.archEmulated()).toBe(true);
    expect(await host.osName()).toBe("Debian GNU/Linux 12 (bookworm)");
    expect(await host.availableMemory(10 * 1024 * 1024)).toEqual({ availableBytes: 1500 * 1024, source: "proc_meminfo" });
    expect(await host.persistedPaths()).toEqual({ entries: { system: ["/usr/local/bin", "/usr/bin"], user: [] }, read: true, error: null });
  });

  test("the system program runner refuses anything that is not allow-listed", async () => {
    await expect(createSystemProgramRunner("linux", {})("/usr/bin/gh", ["auth", "token"])).rejects.toThrow("not an allow-listed system program");
    await expect(createSystemProgramRunner("darwin", {})("/opt/homebrew/bin/codeql", [])).rejects.toThrow("not an allow-listed");
    await expect(createSystemProgramRunner("win32", { SystemRoot: "C:\\Windows" })("D:\\CodeQL\\codeql.exe", [])).rejects.toThrow("not an allow-listed");
  });
});

// ───────────────────────────── tools + runtime ─────────────────────────────

describe("reported tools", () => {
  test("every reported tool has an explicit usage", () => {
    expect(Object.keys(TOOL_USAGE).sort()).toEqual([...TOOL_NAMES].sort());
    expect(TOOL_USAGE.gh.usage).toBe("executed");
    expect(TOOL_USAGE.bun.usage).toBe("runtime");
    expect(TOOL_USAGE.codeql.usage).toBe("presence_only");
    for (const name of ["git", "cargo", "semgrep", "osv-scanner", "docker"] as const) expect(TOOL_USAGE[name].usage).toBe("not_used");
  });

  test("the Bun runtime is tied to a located install by file identity only, never by guessing", async () => {
    const root = tempDir("runtime-");
    const realDir = path.join(root, "real", "bin");
    const otherDir = path.join(root, "other");
    const shimDir = path.join(root, "bun-node-38afee6c8");
    const copiedShimDir = path.join(root, "bun-node-0badc0de");
    const portableDir = path.join(root, "portable");
    for (const dir of [realDir, otherDir, shimDir, copiedShimDir, portableDir]) fs.mkdirSync(dir, { recursive: true });
    const real = path.join(realDir, "bun.exe");
    const other = path.join(otherDir, "bun.exe");
    fs.writeFileSync(real, pe(0x8664));
    fs.writeFileSync(other, pe(0x8664));
    const shim = path.join(shimDir, "bun.exe");
    fs.linkSync(real, shim);
    const platform = process.platform;
    const matches = [
      { path: other, source: "process_path" as const },
      { path: real, source: "persisted_user_path" as const },
    ];
    // Windows `bun run`: process.execPath is a hard link of the install in a bun-node-<hex> dir.
    expect(await resolveBunRuntime(shim, platform, matches)).toMatchObject({ path: real, match: matches[1], note: null });
    expect(await resolveBunRuntime(real, platform, matches)).toMatchObject({ path: real, match: matches[1], note: null });
    // A shim that is a copy (TEMP on another volume) matches nothing: another Bun is NOT reported as the runtime.
    const copiedShim = path.join(copiedShimDir, "bun.exe");
    fs.copyFileSync(real, copiedShim);
    expect(await resolveBunRuntime(copiedShim, platform, matches)).toEqual({
      path: copiedShim,
      match: null,
      identity: expect.any(String),
      note: UNMATCHED_SHIM_NOTE,
    });
    expect(await resolveBunRuntime(path.join(shimDir, "gone.exe"), platform, matches)).toMatchObject({ path: path.join(shimDir, "gone.exe"), match: null, note: UNMATCHED_SHIM_NOTE });
    // Started from a directory outside the search (e.g. a portable copy): that file is the runtime.
    const portable = path.join(portableDir, "bun.exe");
    fs.copyFileSync(real, portable);
    expect(await resolveBunRuntime(portable, platform, matches)).toMatchObject({ path: portable, match: null, note: null });
  });

  test("the bun usage note says how its path was chosen, without contradicting itself", async () => {
    const root = tempDir("bun-note-");
    const win = process.platform === "win32";
    const exe = win ? "bun.exe" : "bun";
    const installDir = path.join(root, "install");
    const shimDir = path.join(root, "bun-node-feedf00d");
    const portableDir = path.join(root, "portable");
    for (const dir of [installDir, shimDir, portableDir]) fs.mkdirSync(dir);
    const header = win ? pe(0x8664) : process.platform === "darwin" ? macho(CPU_ARM64) : elf(0x3e);
    const install = path.join(installDir, exe);
    fs.writeFileSync(install, header, { mode: 0o755 });
    // A copied bun-node shim (TEMP on another volume) and a Bun started from outside the search.
    const copiedShim = path.join(shimDir, exe);
    fs.copyFileSync(install, copiedShim);
    const portable = path.join(portableDir, exe);
    fs.copyFileSync(install, portable);
    const locator = new ExecutableLocator({ env: { PATH: installDir, PATHEXT: ".EXE" }, homedir: path.join(root, "home"), isDirectory: () => false });
    const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }) });
    const bunRow = async (execPath: string) => (await describeTools({ executables: locator, hostPlatform }, { execPath })).find((tool) => tool.name === "bun")!;

    expect((await bunRow(install)).usageNote).toBe(`${TOOL_USAGE.bun.note} ${BUN_MATCHED_NOTE}`);
    const shim = await bunRow(copiedShim);
    expect(shim).toMatchObject({ path: copiedShim, usageNote: `${TOOL_USAGE.bun.note} ${UNMATCHED_SHIM_NOTE}` });
    // The note must not also claim that the path is a matched install and not the shim.
    expect(shim.usageNote).not.toContain("matched by file identity");
    expect(shim.usageNote).not.toContain("not the temporary bun-node shim");
    const outside = await bunRow(portable);
    expect(outside).toMatchObject({ path: portable, source: null, usageNote: `${TOOL_USAGE.bun.note} ${BUN_UNMATCHED_NOTE}` });
    expect(outside.usageNote).not.toContain("matched by file identity");
    expect(bunRuntimeNote({ match: { path: install, source: "process_path" }, note: null })).toBe(BUN_MATCHED_NOTE);
    expect(bunRuntimeNote({ match: null, note: null })).toBe(BUN_UNMATCHED_NOTE);
    expect(bunRuntimeNote({ match: null, note: UNMATCHED_SHIM_NOTE })).toBe(UNMATCHED_SHIM_NOTE);
  });

  test("a resolved target is reported only through a link, not for 8.3 short names, mapped drives or letter case", async () => {
    const enoent = () => Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    const fake = (real: Record<string, string>, links: string[]): LinkProbes => ({
      realpath: async (file) => {
        const value = real[file];
        if (value === undefined) throw enoent();
        return value;
      },
      readlink: async () => {
        throw Object.assign(new Error("EINVAL"), { code: "EINVAL" });
      },
      lstat: async (file) => ({ isSymbolicLink: () => links.includes(file) }),
    });
    // Windows expands an 8.3 short name in the canonical path; no component is a link.
    const short = "C:\\PROGRA~1\\GitHub CLI\\gh.exe";
    expect(await resolvedTarget(short, "win32", fake({ [short]: "C:\\Program Files\\GitHub CLI\\gh.exe" }, []))).toBeNull();
    // subst and mapped drives resolve to another drive or a UNC path; still not a link.
    const subst = "S:\\tools\\codeql.exe";
    expect(await resolvedTarget(subst, "win32", fake({ [subst]: "C:\\very\\long\\tools\\codeql.exe" }, []))).toBeNull();
    expect(await resolvedTarget("Z:\\bin\\gh.exe", "win32", fake({ "Z:\\bin\\gh.exe": "\\\\server\\share\\bin\\gh.exe" }, []))).toBeNull();
    // A junction among the parent directories is a link.
    const links = "C:\\Users\\u\\AppData\\Local\\Microsoft\\WinGet\\Links";
    expect(await resolvedTarget(`${links}\\gh.exe`, "win32", fake({ [`${links}\\gh.exe`]: "C:\\Program Files\\GitHub CLI\\gh.exe" }, [links]))).toBe(
      "C:\\Program Files\\GitHub CLI\\gh.exe",
    );
    // A component that cannot be checked is not assumed to be a plain directory.
    const unreadable: LinkProbes = { ...fake({ [short]: "C:\\Program Files\\GitHub CLI\\gh.exe" }, []), lstat: async () => Promise.reject(enoent()) };
    expect(await resolvedTarget(short, "win32", unreadable)).toBe("C:\\Program Files\\GitHub CLI\\gh.exe");
    // App Execution Aliases cannot be opened; their link target is read instead.
    const alias = "C:\\Users\\u\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe";
    const aliasTarget = "C:\\Program Files\\WindowsApps\\PythonSoftwareFoundation.Python.3.13\\python.exe";
    expect(await resolvedTarget(alias, "win32", { ...fake({}, []), readlink: async () => aliasTarget })).toBe(aliasTarget);
    // POSIX: a symlinked file (Homebrew) or parent directory (merged /usr) is a link; letter case alone is not.
    const brew = "/opt/homebrew/bin/gh";
    expect(await resolvedTarget(brew, "darwin", fake({ [brew]: "/opt/homebrew/Cellar/gh/2.80.0/bin/gh" }, [brew]))).toBe("/opt/homebrew/Cellar/gh/2.80.0/bin/gh");
    expect(await resolvedTarget("/bin/git", "linux", fake({ "/bin/git": "/usr/bin/git" }, ["/bin"]))).toBe("/usr/bin/git");
    expect(await resolvedTarget("/USR/local/bin/gh", "darwin", fake({ "/USR/local/bin/gh": "/usr/local/bin/gh" }, []))).toBeNull();
  });

  test.if(process.platform === "win32")("on this host, a real 8.3 short-name path is not reported as a link", async () => {
    const short = "C:\\PROGRA~1";
    let long: string;
    try {
      long = fs.realpathSync.native(short);
    } catch {
      return; // 8.3 names are disabled on this volume
    }
    if (long.toLowerCase() === short.toLowerCase()) return;
    expect(await resolvedTarget(short, "win32")).toBeNull();
    // A junction still is one, also when it is reached through the long name.
    const root = tempDir("short-name-");
    fs.mkdirSync(path.join(root, "real"));
    fs.symlinkSync(path.join(root, "real"), path.join(root, "junction"), "junction");
    expect(await resolvedTarget(path.join(root, "junction"), "win32")).toBe(path.join(root, "real"));
  });

  test("a Bun reached through a symlink or junction (Homebrew's bin links, WinGet Links) is reported on the process PATH", async () => {
    const root = tempDir("bun-link-");
    const win = process.platform === "win32";
    const exe = win ? "bun.exe" : "bun";
    const cellar = path.join(root, "Cellar", "bun", "1.2.19", "bin");
    const otherDir = path.join(root, "other");
    const linkDir = path.join(root, "homebrew-bin");
    fs.mkdirSync(cellar, { recursive: true });
    fs.mkdirSync(otherDir);
    const header = win ? pe(0x8664) : process.platform === "darwin" ? macho(CPU_ARM64) : elf(0x3e);
    fs.writeFileSync(path.join(cellar, exe), header, { mode: 0o755 });
    fs.writeFileSync(path.join(otherDir, exe), header, { mode: 0o755 });
    if (win) {
      // Homebrew and WinGet link the executable itself; a file symlink needs a privilege on Windows,
      // so a directory junction (which does not) stands in for it there.
      fs.symlinkSync(cellar, linkDir, "junction");
    } else {
      // brew: /opt/homebrew/bin/bun -> ../Cellar/bun/<version>/bin/bun
      fs.mkdirSync(linkDir);
      fs.symlinkSync(path.join(cellar, exe), path.join(linkDir, exe));
    }
    // process.execPath is already resolved by Bun on macOS and Linux (and through junctions on Windows).
    const execPath = fs.realpathSync(path.join(cellar, exe));
    const locator = new ExecutableLocator({
      env: { PATH: [linkDir, cellar, otherDir].join(path.delimiter), PATHEXT: ".EXE" },
      homedir: path.join(root, "home"),
      isDirectory: () => false,
    });
    const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }) });
    const tools = await describeTools({ executables: locator, hostPlatform }, { execPath });
    const bun = tools.find((tool) => tool.name === "bun")!;
    expect(bun).toMatchObject({
      path: path.join(linkDir, exe),
      resolvedPath: execPath,
      resolvedVia: "link",
      source: "process_path",
      onProcessPath: true,
      // The cellar entry is the same file; only the genuinely different install is listed.
      shadowed: [path.join(otherDir, exe)],
      usageNote: `${TOOL_USAGE.bun.note} ${BUN_MATCHED_NOTE}`,
    });
  });

  test("Scoop shim files: the path line is parsed with or without quotes; only absolute drive paths count", () => {
    expect(parseScoopShim('path = "C:\\Users\\x\\scoop\\apps\\bun\\current\\bun.exe"\r\nargs = --smol\r\n')).toBe("C:\\Users\\x\\scoop\\apps\\bun\\current\\bun.exe");
    // Older Scoop releases wrote the value unquoted; whitespace, a BOM and forward slashes are tolerated.
    expect(parseScoopShim("\uFEFF  PATH=C:/Users/x/scoop/apps/gh/current/bin/gh.exe  \n")).toBe("C:\\Users\\x\\scoop\\apps\\gh\\current\\bin\\gh.exe");
    expect(parseScoopShim("args = x\npath = 'D:\\scoop\\apps\\git\\current\\cmd\\git.exe'\n")).toBe("D:\\scoop\\apps\\git\\current\\cmd\\git.exe");
    for (const rejected of ['path = "bun.exe"', 'path = "\\\\server\\share\\bun.exe"', 'path = "\\\\?\\C:\\bun.exe"', 'path = ""', "args = only", "", 'path = "C:\\a"b.exe"']) {
      expect(parseScoopShim(rejected)).toBeNull();
    }
    expect(scoopShimFile("C:\\Users\\x\\scoop\\shims\\bun.EXE", "win32")).toBe("C:\\Users\\x\\scoop\\shims\\bun.shim");
    expect(scoopShimFile("C:\\Users\\x\\scoop\\shims\\bun.cmd", "win32")).toBeNull();
    expect(scoopShimFile("/home/x/bin/bun", "linux")).toBeNull();
    // Chocolatey shimgen shims embed the target; they are only recognised by location.
    const choco = { ChocolateyInstall: "C:\\ProgramData\\chocolatey" };
    expect(isChocolateyShim("C:\\ProgramData\\chocolatey\\bin\\gh.exe", choco, "win32")).toBe(true);
    expect(isChocolateyShim("C:\\ProgramData\\chocolatey\\lib\\gh\\tools\\gh.exe", choco, "win32")).toBe(false);
    expect(isChocolateyShim("C:\\ProgramData\\chocolatey\\bin\\gh.exe", {}, "win32")).toBe(false);
  });

  test.if(process.platform === "win32")("a Scoop shim is resolved through its .shim file: header, resolved path and Bun runtime match", async () => {
    // ~\scoop: shims\bun.exe is a copy of Scoop's generic shim.exe (here a 32-bit x86 PE, so the
    // test can tell which file was inspected) and shims\bun.shim names apps\bun\current\bun.exe.
    const scoop = tempDir("scoop-");
    const shims = path.join(scoop, "shims");
    const current = path.join(scoop, "apps", "bun", "current");
    fs.mkdirSync(shims, { recursive: true });
    fs.mkdirSync(current, { recursive: true });
    const target = path.join(current, "bun.exe");
    fs.writeFileSync(target, pe(0x8664));
    fs.writeFileSync(path.join(shims, "bun.exe"), pe(0x14c));
    fs.writeFileSync(path.join(shims, "bun.shim"), `path = "${target}"\r\nargs = \r\n`);
    // gh through a Scoop shim whose app was uninstalled: the target is reported, and is unreadable.
    fs.writeFileSync(path.join(shims, "gh.exe"), pe(0x14c));
    fs.writeFileSync(path.join(shims, "gh.shim"), `path = ${path.join(scoop, "apps", "gh", "current", "gh.exe")}\n`);
    // Under `bun run`, process.execPath is a hard link of the real bun.exe in a bun-node-<hex> directory.
    const bunRunDir = path.join(scoop, "bun-node-5c00b");
    fs.mkdirSync(bunRunDir);
    const execPath = path.join(bunRunDir, "bun.exe");
    fs.linkSync(target, execPath);

    const locator = new ExecutableLocator({
      env: { PATH: shims, PATHEXT: ".COM;.EXE;.BAT;.CMD" },
      homedir: path.join(scoop, "home"),
      isDirectory: () => false,
    });
    const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }) });
    const tools = await describeTools({ executables: locator, hostPlatform }, { execPath });
    const bun = tools.find((tool) => tool.name === "bun")!;
    expect(bun).toMatchObject({
      path: path.join(shims, "bun.exe"),
      resolvedPath: target,
      resolvedVia: "scoop_shim",
      source: "process_path",
      onProcessPath: true,
      shadowed: [],
      usageNote: `${TOOL_USAGE.bun.note} ${BUN_MATCHED_NOTE}`,
    });
    // The architecture is the target's (x64), not the shim's (x86).
    expect(bun.binary).toMatchObject({ format: "pe", architectures: ["x64"] });
    expect(bun.binary?.note).toContain(`Scoop shim for ${target}`);
    // The runtime identity check goes through the shim's target, so the bun-node link is resolved away.
    expect(await resolveBunRuntime(execPath, "win32", [{ path: path.join(shims, "bun.exe"), source: "process_path" }])).toMatchObject({
      path: path.join(shims, "bun.exe"),
      note: null,
    });
    const gh = tools.find((tool) => tool.name === "gh")!;
    expect(gh).toMatchObject({ path: path.join(shims, "gh.exe"), resolvedVia: "scoop_shim", resolvedPath: path.join(scoop, "apps", "gh", "current", "gh.exe") });
    expect(gh.binary).toMatchObject({ format: "unknown", note: expect.stringContaining("Not readable (ENOENT)") });
    // The shim itself is what the bridge would run (a .exe on the process PATH), as Scoop intends.
    expect(gh.usageNote).toEndWith("The file shown is the one run.");
  });

  test.if(process.platform === "win32")("a Chocolatey shimgen shim is reported as the shim, with a note that its target is not resolved", async () => {
    const choco = tempDir("choco-");
    const bin = path.join(choco, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "codeql.exe"), pe(0x8664));
    const locator = new ExecutableLocator({
      env: { PATH: "", PATHEXT: ".EXE", ChocolateyInstall: choco },
      homedir: path.join(choco, "home"),
      isDirectory: (dir) => dir.toLowerCase() === bin.toLowerCase(),
    });
    const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }) });
    const codeql = (await describeTools({ executables: locator, hostPlatform })).find((tool) => tool.name === "codeql")!;
    expect(codeql).toMatchObject({ path: path.join(bin, "codeql.exe"), source: "well_known", resolvedPath: null, resolvedVia: null });
    expect(codeql.binary?.note).toBe(CHOCOLATEY_SHIM_NOTE);
  });

  test("describeTools reports source, process-PATH visibility, headers and shadowed copies without executing anything", async () => {
    const root = tempDir("describe-");
    const processDir = path.join(root, "process");
    const persistedDir = path.join(root, "persisted");
    fs.mkdirSync(processDir);
    fs.mkdirSync(persistedDir);
    const win = process.platform === "win32";
    const exe = (name: string) => (win ? `${name}.exe` : name);
    const writeTool = (dir: string, name: string, bytes: Uint8Array) => {
      const file = path.join(dir, name);
      fs.writeFileSync(file, bytes, { mode: 0o755 });
      return file;
    };
    // Headers of the host's native format; nothing here could run anyway.
    const nativeHeader = win ? pe(0x8664) : process.platform === "darwin" ? macho(CPU_ARM64) : elf(0x3e);
    const gh = writeTool(processDir, exe("gh"), nativeHeader);
    const codeql = writeTool(persistedDir, exe("codeql"), nativeHeader);
    const codeqlLauncher = writeTool(persistedDir, "codeql", new TextEncoder().encode("#!/bin/sh\nexit 0\n"));
    const shadowGh = writeTool(persistedDir, exe("gh"), nativeHeader);
    // The bridge started through `bun run`: process.execPath is a hard link in a bun-node-<hex> dir.
    const realBun = writeTool(processDir, exe("bun"), nativeHeader);
    const shimDir = path.join(root, "bun-node-0123abcd");
    fs.mkdirSync(shimDir);
    const shimBun = path.join(shimDir, exe("bun"));
    fs.linkSync(realBun, shimBun);

    const locator = new ExecutableLocator({
      env: { PATH: processDir, PATHEXT: ".EXE;.CMD" },
      homedir: path.join(root, "home"),
      isDirectory: () => false,
      loadPersisted: async () => ({ entries: { system: [persistedDir], user: [] }, read: true, error: null }),
    });
    const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }) });
    const tools = await describeTools({ executables: locator, hostPlatform }, { execPath: shimBun });
    const byName = new Map(tools.map((tool) => [tool.name, tool] as [string, ToolAvailability]));
    expect(byName.get("gh")).toMatchObject({ available: true, path: gh, source: "process_path", onProcessPath: true, shadowed: [shadowGh], usage: "executed" });
    expect(byName.get("gh")?.usageNote).toBe(`${TOOL_USAGE.gh.note} The file shown is the one run.`);
    expect(byName.get("gh")?.binary?.format).toBe(win ? "pe" : process.platform === "darwin" ? "macho" : "elf");
    const codeqlRow = byName.get("codeql")!;
    expect(codeqlRow).toMatchObject({ available: true, source: "persisted_system_path", onProcessPath: false, usage: "presence_only" });
    // On Windows the extension-less launcher is never the match; on POSIX it is the bare name.
    expect(codeqlRow.path).toBe(win ? codeql : codeqlLauncher);
    expect(byName.get("semgrep")).toMatchObject({ available: false, path: null, source: null, binary: null, shadowed: [], usage: "not_used" });
    expect(byName.get("bun")).toMatchObject({ available: true, path: realBun, source: "process_path", onProcessPath: true, usage: "runtime", shadowed: [] });
    // Cached per snapshot.
    expect(await describeTools({ executables: locator, hostPlatform }, { execPath: shimBun })).toBe(tools);
  });

  test("tool rows of older topology reports are upgraded when read back", () => {
    const db = openWebDb(path.join(tempDir("legacy-topo-"), "web.db"));
    openDbs.push(db);
    const legacy = {
      reportId: "legacy-1",
      tenantId: "t1",
      workspace: "/w",
      createdAt: "2026-01-01T00:00:00.000Z",
      createdBy: "alice",
      languages: [],
      primaryLanguage: null,
      manifests: [],
      frameworks: [],
      subsystems: [],
      entrypoints: [],
      lockfiles: [],
      packagesTotal: 0,
      tools: [{ name: "codeql", available: true, path: "D:\\CodeQL\\codeql.exe" }, { bogus: true }],
      notes: [],
    } as unknown as TopologyReportView;
    saveTopologyReport(db, legacy);
    expect(latestTopologyReport(db, "t1")?.tools).toEqual([
      {
        name: "codeql",
        available: true,
        path: "D:\\CodeQL\\codeql.exe",
        resolvedPath: null,
        resolvedVia: null,
        source: null,
        onProcessPath: false,
        binary: null,
        usage: "presence_only",
        usageNote: TOOL_USAGE.codeql.note,
        shadowed: [],
      },
    ]);
    expect(normalizeStoredTool(null)).toBeNull();
  });

  test.if(process.platform === "win32")("gh is only started when it is a Windows executable", () => {
    const db = openWebDb(path.join(tempDir("gh-"), "web.db"));
    openDbs.push(db);
    const secrets = new SecretStore(db, crypto.randomBytes(32));
    const located: (string | null)[] = [];
    const github = new GitHubService(secrets, null, os.tmpdir(), {
      locateGh: () => {
        const value = located.length === 0 ? "C:\\nowhere\\gh.cmd" : null;
        located.push(value);
        return value;
      },
    });
    expect(github.resolveAuth()).toBeNull();
    // A different located gh invalidates the cached answer.
    expect(github.resolveAuth()).toBeNull();
    expect(located).toEqual(["C:\\nowhere\\gh.cmd", null]);
  });

  test.if(process.platform !== "win32")("gh runs without the bridge's secrets and is stopped at the timeout", () => {
    const dir = tempDir("gh-run-");
    const db = openWebDb(path.join(dir, "web.db"));
    openDbs.push(db);
    const secrets = new SecretStore(db, crypto.randomBytes(32));
    const token = "ghp_abcdefghijklmnopqrstuvwxyz012345";
    const leaky = path.join(dir, "gh-env");
    // Prints a token only when the bridge's secret variables are absent from its environment.
    fs.writeFileSync(leaky, `#!/bin/sh\nif [ -n "$SENTRA_WEB_SECRET_KEY$SENTRA_WEB_TOKENS" ]; then exit 3; fi\necho ${token}\n`, { mode: 0o755 });
    const slow = path.join(dir, "gh-slow");
    fs.writeFileSync(slow, "#!/bin/sh\nexec sleep 30\n", { mode: 0o755 });
    const saved = { key: process.env.SENTRA_WEB_SECRET_KEY, tokens: process.env.SENTRA_WEB_TOKENS };
    process.env.SENTRA_WEB_SECRET_KEY = "secret";
    process.env.SENTRA_WEB_TOKENS = "admin:x";
    try {
      expect(new GitHubService(secrets, null, dir, { locateGh: () => leaky }).resolveAuth()).toEqual({ source: "gh_cli", token });
      const started = performance.now();
      expect(new GitHubService(secrets, null, dir, { locateGh: () => slow, ghTimeoutMs: 300 }).resolveAuth()).toBeNull();
      expect(performance.now() - started).toBeLessThan(10_000);
    } finally {
      if (saved.key === undefined) delete process.env.SENTRA_WEB_SECRET_KEY;
      else process.env.SENTRA_WEB_SECRET_KEY = saved.key;
      if (saved.tokens === undefined) delete process.env.SENTRA_WEB_TOKENS;
      else process.env.SENTRA_WEB_TOKENS = saved.tokens;
    }
  });
});

// ───────────────────────────── /api/system ─────────────────────────────

const ENV_KEYS = ["SENTRA_WEB_TOKENS", "SENTRA_WEB_DATA_DIR", "SENTRA_REPO_ROOT", "SENTRA_WEB_HOST", "SENTRA_BIN", "SENTRA_PLUGIN_DIR", "SENTRA_WEB_WORKSPACE_ROOTS"];

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

describe("configured grants", () => {
  test("the generated local admin token is not counted as a configured grant", () => {
    const repo = tempDir("cfg-repo-");
    const generated = withEnv({ SENTRA_REPO_ROOT: repo, SENTRA_WEB_DATA_DIR: tempDir("cfg-data-"), SENTRA_BIN: process.execPath }, () => loadConfig());
    expect(generated.generatedAdminToken).not.toBeNull();
    expect(generated.tokenGrants).toHaveLength(1);
    expect(configuredGrantCount(generated)).toBe(0);

    const configured = withEnv(
      { SENTRA_REPO_ROOT: repo, SENTRA_WEB_DATA_DIR: tempDir("cfg-data-"), SENTRA_BIN: process.execPath, SENTRA_WEB_TOKENS: `admin:${"a".repeat(32)}` },
      () => loadConfig(),
    );
    expect(configured.generatedAdminToken).toBeNull();
    expect(configuredGrantCount(configured)).toBe(1);
  });

  test("/api/system reports grants, the search snapshot and host facts from injected host services", async () => {
    const dataDir = tempDir("system-data-");
    fs.mkdirSync(path.join(dataDir, "tmp"));
    const token = "z".repeat(40);
    const config = {
      repoRoot: tempDir("system-repo-"),
      webRoot: TEST_ROOT,
      host: "127.0.0.1",
      port: 3998,
      isLoopbackBind: true,
      production: false,
      staticDir: null,
      sentraBin: path.join(dataDir, "missing-sentra-binary"),
      dataDir,
      registryDbPath: path.join(dataDir, "sentra.db"),
      webDbPath: path.join(dataDir, "sentra-web.db"),
      backupDir: path.join(dataDir, "backups"),
      allowedOrigins: new Set(["http://127.0.0.1:3998"]),
      allowedHosts: new Set(["127.0.0.1:3998"]),
      tokenGrants: [{ role: "admin", label: "local-admin", digest: sha256(token), generated: true }, ...parseTokenGrants(`viewer:${"v".repeat(40)}`)],
      generatedAdminToken: token,
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
      tmpDir: path.join(dataDir, "tmp"),
    } satisfies ServerConfig;
    const hostPlatform = new HostPlatform({ run: async () => ({ code: 1, stdout: "", timedOut: false }), readTextFile: async () => null });
    const executables = new ExecutableLocator({
      env: { PATH: path.join(dataDir, "no-tools-here") },
      homedir: path.join(dataDir, "home"),
      isDirectory: () => false,
      loadPersisted: async () => ({ entries: { system: [], user: [] }, read: false, error: "registry unavailable in this test" }),
    });
    const { app, router } = createApp(config, { executables, hostPlatform });
    openDbs.push(app.db);
    const server = { requestIP: () => ({ address: "127.0.0.1", family: "IPv4" as const, port: 1 }), timeout: () => undefined };
    const response = await handleRequest(
      new Request("http://127.0.0.1:3998/api/system", { headers: { host: "127.0.0.1:3998", authorization: `Bearer ${token}` } }),
      server,
      app as AppContext,
      router as Router,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as SystemStatus;
    expect(body.apiContractVersion).toBe(API_CONTRACT_VERSION);
    expect(body.auth).toMatchObject({ configuredGrants: 1, generatedLocalToken: true });
    expect(body.toolSearch).toMatchObject({
      persistedPathRead: false,
      persistedPathError: "registry unavailable in this test",
      searchedDirectories: 1,
      skippedNetworkEntries: 0,
    });
    expect(body.host).toHaveProperty("runtimePathNote");
    expect(body.core).toMatchObject({ present: false, binary: null });
    expect(body.tools.map((tool) => tool.name)).toEqual([...TOOL_NAMES]);
    expect(body.tools.find((tool) => tool.name === "gh")).toMatchObject({ available: false, usage: "executed" });
    expect(body.host.availableMemoryBytes).toBeGreaterThan(0);
    expect(body.host).not.toHaveProperty("freeMemoryBytes");
    expect(["os", "proc_meminfo", "vm_stat"]).toContain(body.host.memorySource);
    expect(body.host.runtimePath.length).toBeGreaterThan(0);
    expect(body.host).toHaveProperty("nativeArch");
    expect(body.host).toHaveProperty("osName");

    // /api/health is public and reports the contract version, so a console can detect a stale bridge.
    const health = await handleRequest(new Request("http://127.0.0.1:3998/api/health", { headers: { host: "127.0.0.1:3998" } }), server, app as AppContext, router as Router);
    expect(health.status).toBe(200);
    expect((await health.json()) as HealthResponse).toEqual({ status: "ok", coreAvailable: false, apiContractVersion: API_CONTRACT_VERSION });
  });
});

// ───────────────────────────── bridge / console contract ─────────────────────────────

describe("API contract version", () => {
  test("is a positive integer above the unversioned contract", () => {
    expect(Number.isInteger(API_CONTRACT_VERSION)).toBe(true);
    expect(API_CONTRACT_VERSION).toBeGreaterThanOrEqual(2);
  });

  test("the console names a stale or newer bridge, and a bridge that reports no version as version 1", () => {
    expect(reportedContractVersion({ status: "ok", coreAvailable: true })).toBe(1);
    expect(reportedContractVersion({ apiContractVersion: "2" })).toBe(1);
    expect(reportedContractVersion({ apiContractVersion: 3 })).toBe(3);
    expect(reportedContractVersion(null)).toBe(1);
    expect(contractMismatch(API_CONTRACT_VERSION)).toBeNull();
    const older = contractMismatch(1, 2);
    expect(older).toMatchObject({ bridgeVersion: 1, expectedVersion: 2, bridgeIs: "older" });
    expect(older?.message).toStartWith(
      "The bridge is running older code than this console (contract v1, console expects v2). Restart the bridge (stop it and rerun `bun run dev`, or `bun run start` in production).",
    );
    const newer = contractMismatch(3, 2);
    // (Bun's toMatchObject replaces matched properties with asymmetric matchers, so the message is checked separately.)
    expect(newer?.bridgeIs).toBe("newer");
    expect(newer?.message).toContain("contract v3, console expects v2");
    // In production a reload serves the same prebuilt web/dist again: the advice must name the rebuild.
    expect(newer?.message).toContain("Reload this page");
    expect(newer?.message).toContain("in production (`bun run start`), the console is the prebuilt web/dist, so rebuild it with `bun run build`");
    expect(older?.message).not.toContain("bun run build");
  });

  test("stale-PATH advice is specific to the bridge host's OS and to where the tool was found", () => {
    expect(stalePathAdvice("win32", "persisted")).toContain("a process copies PATH when it starts");
    expect(stalePathAdvice("darwin", "persisted")).toContain("launchd");
    expect(stalePathAdvice("darwin", "persisted")).not.toContain("registry");
    expect(stalePathAdvice("linux", "persisted")).toContain("Environment=PATH=");
    expect(stalePathAdvice("linux", "persisted")).toContain("pam_env");
    expect(stalePathAdvice("darwin", "well_known")).toContain("~/.zprofile");
    expect(stalePathAdvice("linux", "well_known")).toContain("~/.profile");
    expect(stalePathAdvice("win32", "well_known")).toContain("Environment Variables");
    expect(toolSearchLocations("linux")).toBe("the bridge process PATH, the persisted PATH (/etc/environment) and standard install locations");
    expect(toolSearchLocations("darwin")).not.toContain("user PATH");
  });

  test("Windows restart advice covers terminals hosted by a running application and services, not only a new terminal", () => {
    for (const advice of [stalePathAdvice("win32", "persisted"), stalePathAdvice("win32", "well_known")]) {
      expect(advice).not.toContain("Open a new terminal");
      expect(advice).toContain("a terminal opened from the Start menu or Explorer");
      expect(advice).toContain("such as VS Code, inherits that application’s old PATH, so restart the application first");
      expect(advice).toContain("A bridge run as a Windows service gets PATH changes only after a reboot, unless its service configuration sets PATH");
    }
  });

  test("Linux advice does not attribute /snap/bin to shell profiles", () => {
    const advice = stalePathAdvice("linux", "well_known");
    const profileSentence = advice.split(". ").find((sentence) => sentence.includes("shell profiles (~/.profile, ~/.bashrc)"));
    expect(profileSentence).toBeDefined();
    expect(profileSentence).not.toContain("/snap/bin");
    expect(advice).toContain("/snap/bin is not added by a shell profile: snapd adds it for login shells (/etc/profile.d/apps-bin-path.sh)");
    expect(advice).toContain("systemd environment generator");
  });

  test("standard-install-location advice does not claim the persisted PATH lacks the directory when it was not read", () => {
    expect(persistedPathReadState({ persistedPathRead: true, persistedPathError: null })).toBe("read");
    expect(persistedPathReadState({ persistedPathRead: true, persistedPathError: "/etc/paths.d/x: EACCES" })).toBe("partial");
    expect(persistedPathReadState({ persistedPathRead: false, persistedPathError: "powershell.exe timed out" })).toBe("unread");
    expect(persistedPathReadState({ persistedPathRead: false, persistedPathError: null })).toBe("unread");

    // Read: the directory is on no persisted PATH, which the advice may say.
    expect(stalePathAdvice("win32", "well_known", "read")).toContain("on neither the process PATH nor the persisted PATH: the installer did not add it");
    // Not read: the registry may well list it (the GitHub CLI installer adds itself to the system Path).
    const unread = stalePathAdvice("win32", "well_known", "unread");
    expect(unread).not.toContain("neither the process PATH nor the persisted PATH");
    expect(unread).not.toContain("the installer did not add it");
    expect(unread).toStartWith("Whether the persisted system and user PATH (registry) lists their directory is unknown, because it could not be read.");
    expect(unread).toContain("If an installer added the directory there, the bridge started before that change: restart the bridge");
    expect(unread).toContain("Environment Variables");
    expect(stalePathAdvice("darwin", "well_known", "partial")).toStartWith(
      "Whether the persisted PATH (/etc/paths and /etc/paths.d) lists their directory is unknown, because it was only partly read.",
    );
    expect(stalePathAdvice("linux", "well_known", "unread")).toStartWith("Whether the persisted PATH (/etc/environment) lists their directory is unknown");
    // The persisted-PATH banner is only shown for tools found there, so the read state does not change it.
    expect(stalePathAdvice("win32", "persisted", "unread")).toBe(stalePathAdvice("win32", "persisted"));
  });
});
