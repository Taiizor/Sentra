import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { CpuArch, HostInfo } from "../src/types/api.ts";
import { envValue, nodeArchToCpuArch, splitPathList, type PersistedPathResult } from "./executables.ts";

/**
 * Host OS facts the Node `os` module gets wrong or does not provide: native hardware architecture
 * (os.arch() is the process architecture), a friendly OS name, available (not just free) memory,
 * and the persisted PATH. Detection never executes a discovered tool: the only programs spawned are
 * fixed system binaries addressed by absolute path (Windows PowerShell 5.1 for registry reads,
 * macOS sw_vers/sysctl/vm_stat), asynchronously, with a minimal environment and a short timeout.
 * Everything else is read from files with bounded reads.
 */

export const SYSTEM_PROGRAM_TIMEOUT_MS = 5_000;
const MAX_PROGRAM_OUTPUT_BYTES = 256 * 1024;
const MAX_TEXT_FILE_BYTES = 64 * 1024;
/**
 * The persisted PATH changes rarely, and every read starts powershell.exe, so the registry is read
 * at most once per window. Directory contents are still re-listed with every search snapshot.
 */
export const WINDOWS_REGISTRY_TTL_MS = 10 * 60_000;
/** First wait after a failed registry read; doubled after each further failure, up to the TTL. */
export const WINDOWS_REGISTRY_RETRY_MS = 60_000;
const VM_STAT_TTL_MS = 2_000;

/**
 * How long a failed registry read is reused before powershell.exe is started again: 1, 2, 4 and 8
 * minutes, then every 10 minutes. A host where PowerShell always fails (blocked by policy, Constrained
 * Language Mode under WDAC/AppLocker, a broken installation) therefore starts it at most once per
 * 10 minutes after the first quarter hour, not on every one-minute search refresh.
 */
export function registryRetryDelayMs(consecutiveFailures: number): number {
  if (consecutiveFailures <= 0) return 0;
  return Math.min(WINDOWS_REGISTRY_RETRY_MS * 2 ** Math.min(consecutiveFailures - 1, 30), WINDOWS_REGISTRY_TTL_MS);
}

export const DARWIN_SW_VERS = "/usr/bin/sw_vers";
export const DARWIN_SYSCTL = "/usr/sbin/sysctl";
export const DARWIN_VM_STAT = "/usr/bin/vm_stat";

export type MemorySource = HostInfo["memorySource"];

export interface SystemProgramResult {
  code: number | null;
  stdout: string;
  timedOut: boolean;
}

/** Starts an allow-listed program; `input`, when given, is written to its standard input. */
export type SystemProgramRunner = (file: string, args: string[], input?: string) => Promise<SystemProgramResult>;

// ───────────────────────────── pure parsers ─────────────────────────────

/** Maps os.machine()/uname -m values to CpuArch. */
export function machineToCpuArch(machine: string): CpuArch {
  const value = machine.trim().toLowerCase();
  if (value === "x86_64" || value === "amd64") return "x64";
  if (value === "aarch64" || value === "arm64" || value === "aarch64_be") return "arm64";
  if (/^i[3-6]86$/.test(value) || value === "x86") return "ia32";
  if (/^armv[5-8]/.test(value) || value === "arm") return "arm";
  if (value === "riscv64") return "riscv64";
  if (value === "ppc64" || value === "ppc64le") return "ppc64";
  if (value === "s390x") return "s390x";
  if (value === "loongarch64" || value === "loong64") return "loong64";
  return "unknown";
}

/** Maps a Windows PROCESSOR_ARCHITECTURE value (AMD64, ARM64, x86). */
export function windowsArchitecture(value: string | null | undefined): CpuArch | null {
  switch ((value ?? "").trim().toUpperCase()) {
    case "AMD64":
    case "EM64T":
      return "x64";
    case "ARM64":
      return "arm64";
    case "X86":
      return "ia32";
    case "ARM":
      return "arm";
    case "":
      return null;
    default:
      return "unknown";
  }
}

export interface NativeArchInput {
  platform: NodeJS.Platform;
  processArch: string;
  /** HKLM ...\Session Manager\Environment PROCESSOR_ARCHITECTURE (not translated for emulated processes). */
  windowsRegistryArch?: string | null;
  env?: Readonly<Record<string, string | undefined>>;
  /** `sysctl -n sysctl.proc_translated`: "1" when this process runs under Rosetta 2. */
  darwinProcTranslated?: string | null;
  /** `sysctl -n hw.optional.arm64`: "1" on Apple silicon. */
  darwinArm64?: string | null;
  /** os.machine() on Linux and other POSIX systems. */
  machine?: string | null;
}

export function resolveNativeArch(input: NativeArchInput): CpuArch | null {
  const processArch = nodeArchToCpuArch(input.processArch);
  if (input.platform === "win32") {
    const fromRegistry = windowsArchitecture(input.windowsRegistryArch);
    if (fromRegistry) return fromRegistry;
    // PROCESSOR_ARCHITEW6432 is set for WOW64 processes and names the native architecture. Under
    // x64 emulation on Arm the process variables report AMD64, hence the registry is preferred.
    const env = input.env ?? {};
    return (
      windowsArchitecture(envValue(env, "PROCESSOR_ARCHITEW6432", "win32")) ??
      windowsArchitecture(envValue(env, "PROCESSOR_ARCHITECTURE", "win32")) ??
      processArch
    );
  }
  if (input.platform === "darwin") {
    if (input.darwinProcTranslated?.trim() === "1") return "arm64";
    if (input.darwinArm64?.trim() === "1") return "arm64";
    return processArch;
  }
  if (input.machine) return machineToCpuArch(input.machine);
  return processArch;
}

/** True when the process architecture differs from the native one and runs under emulation. */
export function isArchEmulated(platform: NodeJS.Platform, processArch: CpuArch, nativeArch: CpuArch | null): boolean | null {
  if (!nativeArch || nativeArch === "unknown" || processArch === "unknown") return null;
  if (processArch === nativeArch) return false;
  if (platform === "win32") return nativeArch === "arm64" && (processArch === "x64" || processArch === "ia32");
  if (platform === "darwin") return nativeArch === "arm64" && processArch === "x64";
  // 32-bit compatibility modes execute natively (a 32-bit Arm process on arm64 runs in AArch32 state,
  // like binaryCompatibility's compatible_32bit); anything else needs qemu-user/binfmt_misc.
  if (nativeArch === "x64" && processArch === "ia32") return false;
  if (nativeArch === "arm64" && processArch === "arm") return false;
  return true;
}

/**
 * Friendly Windows name from os.version() (the registry ProductName, e.g. "Windows 11 Education").
 * Windows 11 still writes "Windows 10" into ProductName, so builds 22000 and later are renamed. The
 * build number is not appended: HostInfo.release ("10.0.<build>") already carries it.
 */
export function windowsOsName(version: string, release: string): string | null {
  const name = version.trim();
  if (!name) return null;
  const build = Number(release.split(".")[2]);
  return Number.isFinite(build) && build >= 22000 && /^Windows 10\b/.test(name) ? name.replace(/^Windows 10\b/, "Windows 11") : name;
}

/** `sw_vers` output ("ProductName:\tmacOS\nProductVersion:\t14.5\n..."). */
export function parseSwVers(text: string): string | null {
  const fields = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z]+):\s*(.*?)\s*$/.exec(line);
    if (match) fields.set(match[1], match[2]);
  }
  const name = fields.get("ProductName");
  const version = fields.get("ProductVersion");
  if (!name) return null;
  return version ? `${name} ${version}` : name;
}

/** Shell-style value of an os-release / environment assignment. */
function unquoteShellValue(raw: string): string {
  const value = raw.trim();
  if (value.length >= 2 && (value.startsWith('"') || value.startsWith("'")) && value.endsWith(value[0])) {
    const inner = value.slice(1, -1);
    return value[0] === '"' ? inner.replace(/\\(["\\$`])/g, "$1") : inner;
  }
  return value;
}

/** PRETTY_NAME of /etc/os-release, falling back to NAME + VERSION. */
export function parseOsRelease(text: string): string | null {
  const fields = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)=(.*)$/.exec(line);
    if (match) fields.set(match[1], unquoteShellValue(match[2]));
  }
  const pretty = fields.get("PRETTY_NAME");
  if (pretty) return pretty;
  const name = fields.get("NAME");
  if (!name) return null;
  const version = fields.get("VERSION") ?? fields.get("VERSION_ID");
  return version ? `${name} ${version}` : name;
}

/** MemAvailable of /proc/meminfo in bytes (kernel 3.14+), or null. */
export function parseProcMeminfo(text: string): number | null {
  const match = /^MemAvailable:\s+(\d+)\s*kB/m.exec(text);
  return match ? Number(match[1]) * 1024 : null;
}

/**
 * Available memory from `vm_stat`, consistent with Activity Monitor: used = app memory (anonymous
 * pages minus purgeable) + wired + compressed, so file cache, purgeable and free pages count as
 * available. Falls back to free + speculative + inactive when fields are missing.
 */
export function parseVmStat(text: string, totalBytes: number): number | null {
  const pageSizeMatch = /page size of (\d+) bytes/.exec(text);
  if (!pageSizeMatch) return null;
  const pageSize = Number(pageSizeMatch[1]);
  const pages = new Map<string, number>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*"?([^":]+)"?:\s+(\d+)\.?\s*$/.exec(line);
    if (match) pages.set(match[1].trim().toLowerCase(), Number(match[2]));
  }
  const get = (name: string) => pages.get(name);
  const clamp = (value: number) => Math.max(0, Math.min(totalBytes, Math.round(value)));
  const active = get("pages active");
  const inactive = get("pages inactive");
  const speculative = get("pages speculative");
  const wired = get("pages wired down");
  const compressed = get("pages occupied by compressor");
  const purgeable = get("pages purgeable") ?? 0;
  const fileBacked = get("file-backed pages");
  if ([active, inactive, speculative, wired, compressed, fileBacked].every((value) => value !== undefined)) {
    const appPages = active! + inactive! + speculative! - fileBacked! - purgeable;
    const usedPages = Math.max(0, appPages) + wired! + compressed!;
    return clamp(totalBytes - usedPages * pageSize);
  }
  const free = get("pages free");
  if (free === undefined) return null;
  return clamp((free + (speculative ?? 0) + (inactive ?? 0)) * pageSize);
}

/** Entries of /etc/paths and /etc/paths.d/* files (one directory per line). */
export function parseEtcPaths(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

/** PATH entries of /etc/environment (pam_env KEY=VALUE format), or [] when PATH is absent. */
export function parseEtcEnvironmentPath(text: string): string[] {
  let value: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?PATH\s*=(.*)$/.exec(line);
    if (match) value = unquoteShellValue(match[1]);
  }
  return value === null ? [] : splitPathList(value, "linux").filter((entry) => entry.trim().length > 0);
}

export interface WindowsRegistryEnvironment {
  userPath: string | null;
  systemPath: string | null;
  processorArchitecture: string | null;
}

/** JSON printed by WINDOWS_REGISTRY_SCRIPT. Throws on malformed output. */
export function parseWindowsRegistryJson(text: string): WindowsRegistryEnvironment {
  const trimmed = text.replace(/^\uFEFF/, "").trim();
  const parsed = JSON.parse(trimmed) as Record<string, unknown>;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("registry output is not a JSON object");
  const field = (name: string) => (typeof parsed[name] === "string" ? (parsed[name] as string) : null);
  return { userPath: field("userPath"), systemPath: field("systemPath"), processorArchitecture: field("processorArchitecture") };
}

// ───────────────────────────── system programs ─────────────────────────────

/**
 * Reads the persisted user and machine PATH unexpanded (REG_EXPAND_SZ kept as written) plus the
 * native PROCESSOR_ARCHITECTURE, and prints them as one UTF-8 JSON object. Fixed text with no
 * external input. It is a single line because `-Command -` executes standard input line by line.
 */
export const WINDOWS_REGISTRY_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
  "$opt = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames",
  "function Read-Value($root, $subKey, $name) { $key = $root.OpenSubKey($subKey); if ($null -eq $key) { return $null }; try { return $key.GetValue($name, $null, $opt) } finally { $key.Close() } }",
  "$machineKey = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'",
  "$result = [ordered]@{ userPath = (Read-Value ([Microsoft.Win32.Registry]::CurrentUser) 'Environment' 'Path'); systemPath = (Read-Value ([Microsoft.Win32.Registry]::LocalMachine) $machineKey 'Path'); processorArchitecture = (Read-Value ([Microsoft.Win32.Registry]::LocalMachine) $machineKey 'PROCESSOR_ARCHITECTURE') }",
  "[Console]::Out.Write(($result | ConvertTo-Json -Compress))",
].join("; ");

/**
 * powershell.exe arguments. The script is piped on standard input (`-Command -`), so the command
 * line carries no encoded payload, and no execution-policy override is passed: execution policy
 * applies to script files, not to commands read this way.
 */
export const WINDOWS_POWERSHELL_ARGS: readonly string[] = ["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", "-"];

function windowsSystemRoot(env: Readonly<Record<string, string | undefined>>): string {
  const candidate = (envValue(env, "SystemRoot", "win32") ?? envValue(env, "windir", "win32") ?? "").trim();
  return /^[A-Za-z]:\\[^%"]*$/.test(candidate) ? candidate.replace(/\\+$/, "") : "C:\\Windows";
}

export function windowsPowerShellPath(env: Readonly<Record<string, string | undefined>>): string {
  return path.win32.join(windowsSystemRoot(env), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/** The only programs host detection may start, by absolute path. */
export function allowedSystemPrograms(platform: NodeJS.Platform, env: Readonly<Record<string, string | undefined>>): string[] {
  if (platform === "win32") return [windowsPowerShellPath(env)];
  if (platform === "darwin") return [DARWIN_SW_VERS, DARWIN_SYSCTL, DARWIN_VM_STAT];
  return [];
}

function minimalEnvironment(platform: NodeJS.Platform, env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  if (platform === "win32") {
    const systemRoot = windowsSystemRoot(env);
    const out: Record<string, string> = {
      SystemRoot: systemRoot,
      windir: systemRoot,
      PATH: `${systemRoot}\\System32;${systemRoot}`,
    };
    // PowerShell needs a profile-less user context (temp and app-data folders) to start.
    for (const name of ["SystemDrive", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData"]) {
      const value = envValue(env, name, "win32");
      if (value) out[name] = value;
    }
    return out;
  }
  return { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" };
}

async function readBounded(stream: ReadableStream<Uint8Array>, limit: number): Promise<{ text: string; truncated: boolean }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > limit) {
        chunks.push(value.subarray(0, limit - size));
        truncated = true;
        await reader.cancel().catch(() => undefined);
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return { text: Buffer.concat(chunks).toString("utf8"), truncated };
}

/**
 * Starts one allow-listed system program asynchronously (never spawnSync), without a shell, with a
 * minimal environment, a system working directory and a timeout.
 */
export function createSystemProgramRunner(
  platform: NodeJS.Platform = process.platform,
  env: Readonly<Record<string, string | undefined>> = process.env,
  timeoutMs = SYSTEM_PROGRAM_TIMEOUT_MS,
): SystemProgramRunner {
  const allowed = new Set(allowedSystemPrograms(platform, env));
  return async (file, args, input) => {
    if (!allowed.has(file)) throw new Error(`Refusing to start ${file}: not an allow-listed system program`);
    const cwd = platform === "win32" ? path.win32.join(windowsSystemRoot(env), "System32") : "/";
    const proc = Bun.spawn([file, ...args], {
      cwd,
      env: minimalEnvironment(platform, env),
      stdin: input === undefined ? "ignore" : Buffer.from(input, "utf8"),
      stdout: "pipe",
      stderr: "ignore",
      windowsHide: true,
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      proc.kill();
    }, timeoutMs);
    try {
      const output = await readBounded(proc.stdout, MAX_PROGRAM_OUTPUT_BYTES);
      if (output.truncated) proc.kill();
      const code = await proc.exited;
      return { code: timedOut ? null : code, stdout: output.text, timedOut };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Bounded UTF-8 read; null when the file does not exist. Other errors are thrown. */
export async function readTextFileBounded(file: string, limit = MAX_TEXT_FILE_BYTES): Promise<string | null> {
  let handle: fs.promises.FileHandle | null = null;
  try {
    handle = await fs.promises.open(file, "r");
    const stat = await handle.stat();
    if (!stat.isFile()) throw Object.assign(new Error(`${file} is not a regular file`), { code: "EISDIR" });
    // procfs files report size 0, so read up to the limit regardless of the reported size.
    const buffer = Buffer.alloc(limit);
    let offset = 0;
    while (offset < limit) {
      const { bytesRead } = await handle.read(buffer, offset, limit - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return buffer.subarray(0, offset).toString("utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" || (error as NodeJS.ErrnoException).code === "ENOTDIR") return null;
    throw error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ───────────────────────────── service ─────────────────────────────

export interface HostPlatformOptions {
  platform?: NodeJS.Platform;
  processArch?: string;
  env?: Readonly<Record<string, string | undefined>>;
  run?: SystemProgramRunner;
  readTextFile?: (file: string) => Promise<string | null>;
  listDirectory?: (dir: string) => Promise<string[] | null>;
  freemem?: () => number;
  machine?: () => string;
  osVersion?: () => string;
  osRelease?: () => string;
  now?: () => number;
}

export interface AvailableMemory {
  availableBytes: number;
  source: MemorySource;
}

export class HostPlatform {
  readonly platform: NodeJS.Platform;
  readonly processArch: CpuArch;
  private readonly rawProcessArch: string;
  private readonly env: Readonly<Record<string, string | undefined>>;
  private readonly run: SystemProgramRunner;
  private readonly readTextFile: (file: string) => Promise<string | null>;
  private readonly listDirectory: (dir: string) => Promise<string[] | null>;
  private readonly freemem: () => number;
  private readonly machine: () => string;
  private readonly osVersion: () => string;
  private readonly osRelease: () => string;
  private readonly now: () => number;
  /** Cached registry read: reused while `now - at < ttl` (ttl is the retry delay after a failure). */
  private registry: { at: number; ttl: number; promise: Promise<WindowsRegistryEnvironment> } | null = null;
  private registryFailures = 0;
  private nativeArchValue: CpuArch | null | undefined;
  private nativeArchPromise: Promise<CpuArch | null> | null = null;
  private osNamePromise: Promise<string | null> | null = null;
  private vmStat: { at: number; promise: Promise<string | null> } | null = null;

  constructor(options: HostPlatformOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.rawProcessArch = options.processArch ?? process.arch;
    this.processArch = nodeArchToCpuArch(this.rawProcessArch);
    this.env = options.env ?? process.env;
    this.run = options.run ?? createSystemProgramRunner(this.platform, this.env);
    this.readTextFile = options.readTextFile ?? ((file) => readTextFileBounded(file));
    this.listDirectory =
      options.listDirectory ??
      (async (dir) => {
        try {
          return await fs.promises.readdir(dir);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
          throw error;
        }
      });
    this.freemem = options.freemem ?? (() => os.freemem());
    this.machine = options.machine ?? (() => os.machine());
    this.osVersion = options.osVersion ?? (() => os.version());
    this.osRelease = options.osRelease ?? (() => os.release());
    this.now = options.now ?? (() => performance.now());
  }

  /**
   * One PowerShell call per TTL window: persisted PATHs and native architecture together. A failed
   * call is reused too, for registryRetryDelayMs(consecutive failures), so a PowerShell that always
   * fails is not started again on every search refresh.
   */
  private windowsRegistry(): Promise<WindowsRegistryEnvironment> {
    if (this.registry && this.now() - this.registry.at < this.registry.ttl) return this.registry.promise;
    const promise = (async () => {
      let result: SystemProgramResult;
      try {
        result = await this.run(windowsPowerShellPath(this.env), [...WINDOWS_POWERSHELL_ARGS], `${WINDOWS_REGISTRY_SCRIPT}\r\n`);
      } catch (error) {
        throw new Error(`powershell.exe could not be started: ${errorText(error)}`);
      }
      if (result.timedOut) throw new Error(`powershell.exe did not answer within ${SYSTEM_PROGRAM_TIMEOUT_MS} ms`);
      if (result.code !== 0) throw new Error(`powershell.exe exited with code ${result.code}`);
      try {
        return parseWindowsRegistryJson(result.stdout);
      } catch (error) {
        throw new Error(`Could not parse the registry read: ${errorText(error)}`);
      }
    })();
    const entry = { at: this.now(), ttl: WINDOWS_REGISTRY_TTL_MS, promise };
    this.registry = entry;
    promise.then(
      () => {
        this.registryFailures = 0;
      },
      () => {
        this.registryFailures += 1;
        // The retry delay counts from the failure, not from the start of the attempt.
        entry.at = this.now();
        entry.ttl = registryRetryDelayMs(this.registryFailures);
      },
    );
    return promise;
  }

  /** Milliseconds until a failed registry read is attempted again; null when the last read did not fail. */
  registryRetryInMs(): number | null {
    if (this.registryFailures === 0 || !this.registry) return null;
    return Math.max(0, this.registry.at + this.registry.ttl - this.now());
  }

  /** Persisted PATH entries for the executable search. Never throws. */
  async persistedPaths(): Promise<PersistedPathResult> {
    const empty = { system: [] as string[], user: [] as string[] };
    try {
      if (this.platform === "win32") {
        let registry: WindowsRegistryEnvironment;
        try {
          registry = await this.windowsRegistry();
        } catch (error) {
          const retryMs = this.registryRetryInMs();
          const retry = retryMs === null ? "" : ` (next attempt in about ${Math.max(1, Math.round(retryMs / 60_000))} min)`;
          return { entries: empty, read: false, error: `${errorText(error)}${retry}` };
        }
        this.rememberNativeArch(resolveNativeArch({ platform: "win32", processArch: this.rawProcessArch, windowsRegistryArch: registry.processorArchitecture, env: this.env }));
        return {
          entries: {
            system: registry.systemPath ? splitPathList(registry.systemPath, "win32") : [],
            user: registry.userPath ? splitPathList(registry.userPath, "win32") : [],
          },
          read: true,
          error: null,
        };
      }
      if (this.platform === "darwin") {
        const system: string[] = [];
        const errors: string[] = [];
        try {
          system.push(...parseEtcPaths((await this.readTextFile("/etc/paths")) ?? ""));
        } catch (error) {
          errors.push(`/etc/paths: ${errorText(error)}`);
        }
        try {
          const names = ((await this.listDirectory("/etc/paths.d")) ?? []).filter((name) => !name.startsWith(".")).sort();
          for (const name of names.slice(0, 200)) {
            try {
              system.push(...parseEtcPaths((await this.readTextFile(path.posix.join("/etc/paths.d", name))) ?? ""));
            } catch (error) {
              errors.push(`/etc/paths.d/${name}: ${errorText(error)}`);
            }
          }
        } catch (error) {
          errors.push(`/etc/paths.d: ${errorText(error)}`);
        }
        // Entries that were read are searched even when another file failed, so that counts as a
        // (partial) read; the failures are kept as the error.
        return { entries: { system, user: [] }, read: errors.length === 0 || system.length > 0, error: errors.length > 0 ? errors.join("; ") : null };
      }
      if (this.platform === "linux") {
        const text = await this.readTextFile("/etc/environment");
        return { entries: { system: text === null ? [] : parseEtcEnvironmentPath(text), user: [] }, read: true, error: null };
      }
      return { entries: empty, read: false, error: `The persisted PATH is not read on ${this.platform}` };
    } catch (error) {
      return { entries: empty, read: false, error: errorText(error) };
    }
  }

  private rememberNativeArch(value: CpuArch | null): void {
    if (value) this.nativeArchValue = value;
  }

  /** Native architecture if already determined, without waiting; null before detection. */
  knownNativeArch(): CpuArch | null {
    return this.nativeArchValue ?? null;
  }

  async nativeArch(): Promise<CpuArch | null> {
    if (this.nativeArchValue !== undefined) return this.nativeArchValue;
    if (!this.nativeArchPromise) {
      this.nativeArchPromise = this.detectNativeArch().then((value) => {
        this.nativeArchValue = value;
        return value;
      });
    }
    return this.nativeArchPromise;
  }

  private async detectNativeArch(): Promise<CpuArch | null> {
    if (this.platform === "win32") {
      let registryArch: string | null = null;
      try {
        registryArch = (await this.windowsRegistry()).processorArchitecture;
      } catch {
        // Environment fallback below.
      }
      return resolveNativeArch({ platform: "win32", processArch: this.rawProcessArch, windowsRegistryArch: registryArch, env: this.env });
    }
    if (this.platform === "darwin") {
      const read = async (name: string) => {
        try {
          const result = await this.run(DARWIN_SYSCTL, ["-n", name]);
          return result.code === 0 ? result.stdout.trim() : null;
        } catch {
          return null;
        }
      };
      const [translated, arm64] = await Promise.all([read("sysctl.proc_translated"), read("hw.optional.arm64")]);
      return resolveNativeArch({ platform: "darwin", processArch: this.rawProcessArch, darwinProcTranslated: translated, darwinArm64: arm64 });
    }
    let machine: string | null = null;
    try {
      machine = this.machine();
    } catch {
      machine = null;
    }
    return resolveNativeArch({ platform: this.platform, processArch: this.rawProcessArch, machine });
  }

  async archEmulated(): Promise<boolean | null> {
    return isArchEmulated(this.platform, this.processArch, await this.nativeArch());
  }

  osName(): Promise<string | null> {
    if (!this.osNamePromise) this.osNamePromise = this.detectOsName();
    return this.osNamePromise;
  }

  private async detectOsName(): Promise<string | null> {
    try {
      if (this.platform === "win32") return windowsOsName(this.osVersion(), this.osRelease());
      if (this.platform === "darwin") {
        const result = await this.run(DARWIN_SW_VERS, []);
        return result.code === 0 ? parseSwVers(result.stdout) : null;
      }
      if (this.platform === "linux") {
        for (const file of ["/etc/os-release", "/usr/lib/os-release"]) {
          const text = await this.readTextFile(file);
          if (text !== null) return parseOsRelease(text);
        }
        return null;
      }
      return this.osVersion() || null;
    } catch {
      return null;
    }
  }

  private vmStatText(): Promise<string | null> {
    if (this.vmStat && this.now() - this.vmStat.at < VM_STAT_TTL_MS) return this.vmStat.promise;
    const promise = this.run(DARWIN_VM_STAT, []).then(
      (result) => (result.code === 0 ? result.stdout : null),
      () => null,
    );
    this.vmStat = { at: this.now(), promise };
    return promise;
  }

  /** Memory available to new work: MemAvailable on Linux, vm_stat on macOS, os.freemem() elsewhere. */
  async availableMemory(totalBytes: number): Promise<AvailableMemory> {
    if (this.platform === "linux") {
      try {
        const text = await this.readTextFile("/proc/meminfo");
        const available = text === null ? null : parseProcMeminfo(text);
        if (available !== null) return { availableBytes: Math.min(available, totalBytes), source: "proc_meminfo" };
      } catch {
        // Fallback below.
      }
    } else if (this.platform === "darwin") {
      const text = await this.vmStatText();
      const available = text === null ? null : parseVmStat(text, totalBytes);
      if (available !== null) return { availableBytes: available, source: "vm_stat" };
    }
    // Windows: os.freemem() is the available physical memory (ullAvailPhys), which is correct.
    return { availableBytes: this.freemem(), source: "os" };
  }
}
