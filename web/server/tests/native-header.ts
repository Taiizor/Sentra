/**
 * Synthetic executable headers for tests that write fake tools to disk. The bytes are only a
 * header: no file written from them can be started, and the code under test never tries to.
 */

/** PE header (MZ stub, e_lfanew, PE signature, machine). */
export function peHeader(machine: number, peOffset = 0x80): Uint8Array {
  const bytes = new Uint8Array(peOffset + 24);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  view.setUint32(0x3c, peOffset, true);
  bytes.set([0x50, 0x45, 0, 0], peOffset);
  view.setUint16(peOffset + 4, machine, true);
  return bytes;
}

/** ELF header with the given e_machine. */
export function elfHeader(machine: number, elfClass: 1 | 2 = 2, data: 1 | 2 = 1): Uint8Array {
  const bytes = new Uint8Array(64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, elfClass, data, 1]);
  new DataView(bytes.buffer).setUint16(18, machine, data === 1);
  return bytes;
}

/** Thin 64-bit Mach-O header with the given CPU type. */
export function machoHeader(cpuType: number, littleEndian = true, magic = 0xfeedfacf): Uint8Array {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, magic, littleEndian);
  view.setUint32(4, cpuType, littleEndian);
  return bytes;
}

export const PE_X64 = 0x8664;
export const PE_ARM64 = 0xaa64;
export const ELF_X64 = 0x3e;
export const ELF_ARM64 = 0xb7;
export const MACHO_X64 = 0x01000007;
export const MACHO_ARM64 = 0x0100000c;

/** A header in this host's native format and process architecture, so it is judged runnable here. */
export function hostNativeHeader(): Uint8Array {
  const arm64 = process.arch === "arm64";
  if (process.platform === "win32") return peHeader(arm64 ? PE_ARM64 : PE_X64);
  if (process.platform === "darwin") return machoHeader(arm64 ? MACHO_ARM64 : MACHO_X64);
  return elfHeader(arm64 ? ELF_ARM64 : ELF_X64);
}

/** File name of an executable on this host (`name.exe` on Windows). */
export function hostExecutableName(name: string): string {
  return process.platform === "win32" ? `${name}.exe` : name;
}
