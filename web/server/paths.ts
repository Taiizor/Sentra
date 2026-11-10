import fs from "node:fs";
import path from "node:path";
import { HttpError } from "./http-error.ts";

const CASE_INSENSITIVE_FS = process.platform === "win32" || process.platform === "darwin";

function comparable(value: string): string {
  return CASE_INSENSITIVE_FS ? value.toLowerCase() : value;
}

/**
 * Rejects device/UNC namespaces and NUL bytes before any filesystem access.
 *
 * Windows treats `\` and `/` as interchangeable, so a path is judged on its separator-normalised
 * form: any leading pair of separators (`\\server\share`, `\/server/share`, `/\server`, `\\?\`,
 * `\\.\`) and the NT object prefix `\??\` are refused. Touching such a path would make the bridge
 * open an SMB connection (and authenticate with the service account) or reach a raw device.
 */
export function assertPlainPath(candidate: string, field = "path", platform: NodeJS.Platform = process.platform): void {
  if (candidate.includes("\u0000")) {
    throw new HttpError(400, "invalid_path", `'${field}' contains a NUL byte`);
  }
  if (platform === "win32") {
    const normalized = candidate.replace(/\//g, "\\");
    if (normalized.startsWith("\\\\") || normalized.startsWith("\\??\\")) {
      throw new HttpError(400, "invalid_path", `'${field}' must not be a UNC network path or a device namespace`);
    }
    return;
  }
  if (/^\/\/[?.]\//.test(candidate)) {
    throw new HttpError(400, "invalid_path", `'${field}' must not use a device namespace`);
  }
}

/**
 * Lexical absolute form of a user-supplied directory, validated without touching the disk:
 * plain path, absolute, and on Windows rooted at a drive letter (`C:\...`).
 */
export function lexicalAbsolute(candidate: string, field = "path", platform: NodeJS.Platform = process.platform): string {
  assertPlainPath(candidate, field, platform);
  if (platform === "win32") {
    if (!/^[A-Za-z]:[\\/]/.test(candidate)) {
      throw new HttpError(400, "invalid_path", `'${field}' must be an absolute path that starts with a drive letter (for example C:\\work\\repo)`);
    }
    return path.win32.resolve(candidate);
  }
  if (!path.posix.isAbsolute(candidate)) {
    throw new HttpError(400, "invalid_path", `'${field}' must be an absolute path`);
  }
  return path.posix.resolve(candidate);
}

/** True when `child` equals `parent` or is located underneath it (both absolute, resolved). */
export function isWithin(parent: string, child: string): boolean {
  const p = comparable(path.resolve(parent));
  const c = comparable(path.resolve(child));
  if (p === c) return true;
  const prefix = p.endsWith(path.sep) ? p : p + path.sep;
  return c.startsWith(prefix);
}

/** Canonical absolute path of an existing directory, following symlinks. */
export function realDirectory(candidate: string, field = "workspace"): string {
  const lexical = lexicalAbsolute(candidate, field);
  let resolved: string;
  try {
    resolved = fs.realpathSync.native(lexical);
  } catch {
    throw new HttpError(404, "path_not_found", `'${field}' does not exist`);
  }
  // A link inside a local directory may still point at a network or device path.
  assertPlainPath(resolved, field);
  if (!fs.statSync(resolved).isDirectory()) {
    throw new HttpError(400, "invalid_path", `'${field}' is not a directory`);
  }
  return resolved;
}

/**
 * Resolves `relative` inside `root` and verifies — after following symlinks — that the
 * target stays inside the root. Used for every file read/patch target in a workspace.
 */
export function resolveInside(root: string, relative: string, field = "path"): { absolute: string; relative: string } {
  assertPlainPath(relative, field);
  const rootReal = fs.realpathSync.native(root);
  // No diff-prefix stripping here: a real directory named "a" or "b" must resolve as written.
  // Patch callers normalise `a/` / `b/` headers themselves.
  const joined = path.resolve(rootReal, relative);
  if (!isWithin(rootReal, joined)) {
    throw new HttpError(403, "path_outside_workspace", `'${field}' resolves outside the workspace`);
  }
  let finalPath = joined;
  if (fs.existsSync(joined)) {
    finalPath = fs.realpathSync.native(joined);
    if (!isWithin(rootReal, finalPath)) {
      throw new HttpError(403, "path_outside_workspace", `'${field}' resolves outside the workspace through a link`);
    }
  }
  return { absolute: finalPath, relative: path.relative(rootReal, finalPath).split(path.sep).join("/") };
}
