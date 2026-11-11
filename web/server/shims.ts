import fs from "node:fs";
import path from "node:path";
import { envValue } from "./executables.ts";

/**
 * Package-manager shims on Windows, for presence reporting only (nothing here is executed).
 *
 * - Scoop: every app executable gets a copy of Scoop's generic shim.exe in `~\scoop\shims` named
 *   after the command (bun.exe), next to a `<name>.shim` text file whose `path = "..."` line names
 *   the real executable, usually under `~\scoop\apps\<app>\current` (a junction to the installed
 *   version), which is not on PATH and not searched. Older Scoop releases wrote the value without
 *   quotes; an `args = ...` line may follow. The shim's own header says nothing about the target, so
 *   the target is inspected instead, and Bun's runtime is matched against the target's file identity.
 * - Chocolatey: shimgen shims in `%ChocolateyInstall%\bin` embed the target path in the executable.
 *   They are not resolved; the header reported is the shim's, and a note says so.
 */

const MAX_SHIM_FILE_BYTES = 8 * 1024;

/**
 * Target executable of a Scoop `.shim` file: the first `path = ...` line, quotes removed. Only an
 * absolute drive-rooted path is accepted (no relative, UNC or device path), else null.
 */
export function parseScoopShim(text: string): string | null {
  for (const line of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const match = /^\s*path\s*=\s*(.*?)\s*$/i.exec(line);
    if (!match) continue;
    let value = match[1];
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.endsWith(value[0])) value = value.slice(1, -1).trim();
    if (!value || value.includes("\u0000") || value.includes('"')) return null;
    if (!/^[A-Za-z]:[\\/]/.test(value)) return null;
    return path.win32.normalize(value);
  }
  return null;
}

/** The `.shim` file Scoop writes next to a shim executable, or null when `file` cannot be a Scoop shim. */
export function scoopShimFile(file: string, platform: NodeJS.Platform): string | null {
  if (platform !== "win32") return null;
  const extension = path.win32.extname(file);
  if (extension.toLowerCase() !== ".exe") return null;
  return `${file.slice(0, -extension.length)}.shim`;
}

/** Bounded read of a small regular file; null when it is missing, not a regular file, or too large. */
async function readSmallTextFile(file: string, limit: number): Promise<string | null> {
  let handle: fs.promises.FileHandle | null = null;
  try {
    handle = await fs.promises.open(file, "r");
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) return null;
    const buffer = Buffer.alloc(Math.min(stat.size, limit));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).toString("utf8");
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Target named by the Scoop `.shim` file next to `file` (a located `<name>.exe`), or null when there
 * is none or it does not name an absolute path. The target is not required to exist.
 */
export async function readScoopShimTarget(file: string, platform: NodeJS.Platform): Promise<string | null> {
  const shimFile = scoopShimFile(file, platform);
  if (!shimFile) return null;
  const text = await readSmallTextFile(shimFile, MAX_SHIM_FILE_BYTES);
  return text === null ? null : parseScoopShim(text);
}

export const CHOCOLATEY_SHIM_NOTE =
  "Chocolatey shim (shimgen): the target is embedded in this executable and is not resolved, so the header shown is the shim's";

/** True for a `.exe` directly in `%ChocolateyInstall%\bin`, where Chocolatey puts its shimgen shims. */
export function isChocolateyShim(file: string, env: Readonly<Record<string, string | undefined>>, platform: NodeJS.Platform): boolean {
  if (platform !== "win32" || !/\.exe$/i.test(file)) return false;
  const install = envValue(env, "ChocolateyInstall", "win32")?.trim();
  if (!install || !/^[A-Za-z]:[\\/]/.test(install)) return false;
  const bin = path.win32.join(install, "bin").replace(/\\+$/, "").toLowerCase();
  return path.win32.dirname(path.win32.normalize(file)).toLowerCase() === bin;
}
