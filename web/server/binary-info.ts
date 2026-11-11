import fs from "node:fs";
import path from "node:path";
import type { BinaryCompatibility, BinaryFormat, BinaryInfo, CpuArch } from "../src/types/api.ts";

/**
 * Executable header inspection. The file is opened read-only and at most MAX_HEADER_BYTES are
 * read; nothing is ever executed. Compatibility is judged against the NATIVE architecture of the
 * host OS (not the bridge process architecture, which differs under emulation).
 */

export const MAX_HEADER_BYTES = 64 * 1024;
const MAX_FAT_ARCHS = 30;
const MAX_SHEBANG_CHARS = 200;

export interface HostArch {
  platform: NodeJS.Platform;
  nativeArch: CpuArch | null;
}

export interface ParsedHeader {
  format: BinaryFormat;
  architectures: CpuArch[];
  note: string | null;
}

const PE_MACHINES: Record<number, CpuArch> = {
  0x8664: "x64",
  0xaa64: "arm64",
  0x014c: "ia32",
  0x01c4: "arm",
  0x01c0: "arm",
  0x5064: "riscv64",
  0x6264: "loong64",
};

const MACHO_CPU_TYPES: Record<number, CpuArch> = {
  0x01000007: "x64",
  0x0100000c: "arm64",
  0x00000007: "ia32",
  0x0000000c: "arm",
  0x01000012: "ppc64",
};

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

function unknown(note: string | null): ParsedHeader {
  return { format: "unknown", architectures: [], note };
}

function elfArch(machine: number, is64: boolean): CpuArch | null {
  switch (machine) {
    case 0x3e:
      return "x64";
    case 0xb7:
      return "arm64";
    case 0x03:
      return "ia32";
    case 0x28:
      return "arm";
    case 0xf3:
      return is64 ? "riscv64" : null;
    case 0x15:
      return "ppc64";
    case 0x16:
      return is64 ? "s390x" : null;
    case 0x102:
      return is64 ? "loong64" : null;
    default:
      return null;
  }
}

function parsePe(bytes: Uint8Array, view: DataView): ParsedHeader {
  if (bytes.length < 0x40) return unknown("Truncated MZ header");
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset < 0x40 || peOffset + 6 > bytes.length) {
    return unknown(peOffset + 6 > MAX_HEADER_BYTES ? "PE header offset is beyond the 64 KiB read limit" : "MZ header without a readable PE header");
  }
  if (bytes[peOffset] !== 0x50 || bytes[peOffset + 1] !== 0x45 || bytes[peOffset + 2] !== 0 || bytes[peOffset + 3] !== 0) {
    return unknown("MZ (DOS) executable without a PE signature");
  }
  const machine = view.getUint16(peOffset + 4, true);
  const arch = PE_MACHINES[machine];
  if (!arch) return { format: "pe", architectures: ["unknown"], note: `Unrecognised PE machine type ${hex(machine)}` };
  return { format: "pe", architectures: [arch], note: null };
}

function parseElf(bytes: Uint8Array, view: DataView): ParsedHeader {
  if (bytes.length < 20) return unknown("Truncated ELF header");
  const elfClass = bytes[4];
  const data = bytes[5];
  if ((elfClass !== 1 && elfClass !== 2) || (data !== 1 && data !== 2)) return unknown("ELF header with an invalid class or byte order");
  const machine = view.getUint16(18, data === 1);
  const arch = elfArch(machine, elfClass === 2);
  if (!arch) return { format: "elf", architectures: ["unknown"], note: `Unrecognised ELF machine ${hex(machine)} (${elfClass === 2 ? "64" : "32"}-bit)` };
  return { format: "elf", architectures: [arch], note: null };
}

function machoArch(cpuType: number): CpuArch {
  return MACHO_CPU_TYPES[cpuType >>> 0] ?? "unknown";
}

function parseFat(bytes: Uint8Array, view: DataView, magic: number): ParsedHeader {
  const count = view.getUint32(4, false);
  if (count < 1 || count > MAX_FAT_ARCHS) {
    // 0xCAFEBABE is shared with Java class files, whose next word is the class-file version.
    return unknown(magic === 0xcafebabe ? "Java class file (0xCAFEBABE header), not a universal binary" : "0xCAFEBABF header without a plausible architecture count");
  }
  const entrySize = magic === 0xcafebabf ? 32 : 20;
  if (8 + count * entrySize > bytes.length) return unknown("Truncated universal binary header");
  const architectures: CpuArch[] = [];
  for (let index = 0; index < count; index += 1) {
    const arch = machoArch(view.getUint32(8 + index * entrySize, false));
    if (!architectures.includes(arch)) architectures.push(arch);
  }
  return { format: "macho_universal", architectures, note: null };
}

/** Classifies the leading bytes of a file (PE, ELF, Mach-O, universal, shebang script). */
export function parseExecutableHeader(bytes: Uint8Array): ParsedHeader {
  if (bytes.length === 0) return unknown("Empty file (0 bytes)");
  if (bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x21) {
    const end = bytes.indexOf(0x0a);
    const line = Buffer.from(bytes.subarray(0, end === -1 ? Math.min(bytes.length, 512) : Math.min(end, 512)))
      .toString("utf8")
      .replace(/\r$/, "")
      .trim();
    return { format: "script", architectures: [], note: line.slice(0, MAX_SHEBANG_CHARS) };
  }
  if (bytes.length < 4) return unknown("File too short to identify");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return parsePe(bytes, view);
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return parseElf(bytes, view);
  const magic = view.getUint32(0, false);
  if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) {
    if (bytes.length < 8) return unknown("Truncated Mach-O header");
    const littleEndian = magic === 0xcefaedfe || magic === 0xcffaedfe;
    const cpuType = view.getUint32(4, littleEndian);
    const arch = machoArch(cpuType);
    return { format: "macho", architectures: [arch], note: arch === "unknown" ? `Unrecognised Mach-O CPU type ${hex(cpuType)}` : null };
  }
  if (magic === 0xcafebabe || magic === 0xcafebabf) {
    if (bytes.length < 8) return unknown("Truncated universal binary header");
    return parseFat(bytes, view, magic);
  }
  return unknown("Not a recognised executable format");
}

const WINDOWS_SCRIPT_EXTENSIONS: Record<string, string> = {
  ".cmd": "Windows batch script (runs through cmd.exe)",
  ".bat": "Windows batch script (runs through cmd.exe)",
  ".ps1": "PowerShell script",
  ".vbs": "Windows Script Host script",
  ".vbe": "Windows Script Host script",
  ".js": "Windows Script Host script",
  ".jse": "Windows Script Host script",
  ".wsf": "Windows Script Host script",
  ".wsh": "Windows Script Host settings file",
};

/** Note for a Windows script judged by extension, or null when the file is not one. */
export function windowsScriptNote(filePath: string, platform: NodeJS.Platform): string | null {
  if (platform !== "win32") return null;
  return WINDOWS_SCRIPT_EXTENSIONS[path.win32.extname(filePath).toLowerCase()] ?? null;
}

/** Display name of an OS for messages. */
export function osLabel(platform: NodeJS.Platform): string {
  return platform === "win32" ? "Windows" : platform === "darwin" ? "macOS" : platform === "linux" ? "Linux" : platform;
}

/** Executable formats each OS starts natively (anything else cannot run there). */
export const NATIVE_FORMATS: Partial<Record<NodeJS.Platform, readonly BinaryFormat[]>> = {
  win32: ["pe"],
  darwin: ["macho", "macho_universal"],
  linux: ["elf"],
};

const FORMAT_LABEL: Record<BinaryFormat, string> = {
  pe: "Windows (PE)",
  elf: "ELF",
  macho: "Mach-O",
  macho_universal: "Mach-O universal",
  script: "script",
  unknown: "unknown",
};

export function binaryCompatibility(header: ParsedHeader, host: HostArch): { compatibility: BinaryCompatibility; note: string | null } {
  if (header.format === "script") return { compatibility: "script", note: null };
  const architectures = header.architectures.filter((arch) => arch !== "unknown");
  if (header.format === "unknown" || architectures.length === 0) return { compatibility: "unknown", note: null };
  const native = host.nativeArch;
  if (!native || native === "unknown") return { compatibility: "unknown", note: "The native architecture of the host could not be determined" };
  const incompatible = (note: string) => ({ compatibility: "incompatible" as const, note });
  const archList = architectures.join(", ");

  switch (host.platform) {
    case "win32": {
      if (header.format !== "pe") return incompatible(`${FORMAT_LABEL[header.format]} binary cannot run on Windows`);
      const arch = architectures[0];
      if (arch === native) return { compatibility: "native", note: null };
      if (arch === "x64" && native === "arm64") return { compatibility: "emulated", note: "x64 binary runs under Windows on Arm emulation" };
      if (arch === "ia32" && native === "x64") return { compatibility: "compatible_32bit", note: "32-bit x86 binary runs under WOW64" };
      if (arch === "ia32" && native === "arm64") {
        return { compatibility: "compatible_32bit", note: "32-bit x86 binary runs under WOW64 emulation on Windows on Arm" };
      }
      if (arch === "arm" && native === "arm64") {
        return incompatible("32-bit Arm (ARM32) binary: Windows 11 24H2 and later do not run 32-bit Arm apps (earlier Windows on Arm releases did)");
      }
      return incompatible(`${arch} binary cannot run on ${native} Windows`);
    }
    case "darwin": {
      if (header.format !== "macho" && header.format !== "macho_universal") {
        return incompatible(`${FORMAT_LABEL[header.format]} binary cannot run on macOS`);
      }
      if (architectures.includes(native)) return { compatibility: "native", note: null };
      if (native === "arm64" && architectures.includes("x64")) {
        return { compatibility: "emulated", note: "x64 binary runs under Rosetta 2 translation (Rosetta must be installed)" };
      }
      if (architectures.every((arch) => arch === "arm" || arch === "ia32")) {
        return incompatible(`32-bit ${archList} binary: macOS has not run 32-bit apps since macOS 10.15`);
      }
      return incompatible(`${archList} binary cannot run on ${native} macOS`);
    }
    case "linux": {
      if (header.format !== "elf") return incompatible(`${FORMAT_LABEL[header.format]} binary cannot run on Linux`);
      const arch = architectures[0];
      if (arch === native) return { compatibility: "native", note: null };
      if (arch === "ia32" && native === "x64") {
        return { compatibility: "compatible_32bit", note: "32-bit x86 binary; needs 32-bit (i386) libraries and kernel IA-32 support" };
      }
      if (arch === "arm" && native === "arm64") {
        return {
          compatibility: "compatible_32bit",
          note: "32-bit Arm binary; runs only if the CPU and kernel support AArch32 (many arm64 servers and boards do; some recent cores do not), and needs 32-bit Arm (armhf) libraries when dynamically linked",
        };
      }
      return incompatible(`${arch} binary cannot run on ${native} Linux unless binfmt_misc/qemu-user is configured`);
    }
    default:
      return { compatibility: "unknown", note: `Compatibility is not assessed on ${osLabel(host.platform)}` };
  }
}

export function describeBinary(header: ParsedHeader, host: HostArch): BinaryInfo {
  const { compatibility, note } = binaryCompatibility(header, host);
  const notes = [header.note, note].filter((value): value is string => !!value);
  return { format: header.format, architectures: header.architectures, compatibility, note: notes.length > 0 ? notes.join("; ") : null };
}

function isWindowsAppsPath(filePath: string, platform: NodeJS.Platform): boolean {
  return platform === "win32" && /[\\/]WindowsApps[\\/]/i.test(filePath);
}

function unreadable(filePath: string, platform: NodeJS.Platform, error: unknown): BinaryInfo {
  const code = (error as NodeJS.ErrnoException | null)?.code ?? "error";
  const note = isWindowsAppsPath(filePath, platform) ? "App Execution Alias (not readable)" : `Not readable (${code})`;
  return { format: "unknown", architectures: [], compatibility: "unknown", note };
}

/**
 * Reads the header of an executable (links followed via realpath first, at most 64 KiB) and
 * judges compatibility with the host. Never throws; unreadable files are reported as unknown.
 */
export async function inspectBinary(filePath: string, host: HostArch): Promise<BinaryInfo> {
  const scriptNote = windowsScriptNote(filePath, host.platform);
  if (scriptNote) return { format: "script", architectures: [], compatibility: "script", note: scriptNote };
  let real: string;
  try {
    real = await fs.promises.realpath(filePath);
  } catch (error) {
    return unreadable(filePath, host.platform, error);
  }
  let bytes: Uint8Array;
  let handle: fs.promises.FileHandle | null = null;
  try {
    // Checked before opening: opening a FIFO or device for reading could block.
    if (!(await fs.promises.stat(real)).isFile()) {
      return { format: "unknown", architectures: [], compatibility: "unknown", note: "Not a regular file" };
    }
    handle = await fs.promises.open(real, "r");
    const stat = await handle.stat();
    if (!stat.isFile()) return { format: "unknown", architectures: [], compatibility: "unknown", note: "Not a regular file" };
    const buffer = Buffer.alloc(Math.min(stat.size, MAX_HEADER_BYTES));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    bytes = buffer.subarray(0, bytesRead);
  } catch (error) {
    return unreadable(filePath, host.platform, error);
  } finally {
    await handle?.close().catch(() => undefined);
  }
  if (bytes.length === 0 && isWindowsAppsPath(filePath, host.platform)) {
    return { format: "unknown", architectures: [], compatibility: "unknown", note: "App Execution Alias (not readable)" };
  }
  return describeBinary(parseExecutableHeader(bytes), host);
}
