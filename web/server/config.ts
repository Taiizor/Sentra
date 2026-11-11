import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { MAX_HEADER_BYTES, NATIVE_FORMATS, osLabel, parseExecutableHeader } from "./binary-info.ts";
import { findOnProcessPathForExecution, pathApi } from "./executables.ts";

/** Server-side roles. The UI labels them Viewer / Operator / SecurityAdmin. */
export type Role = "viewer" | "operator" | "admin";

export const ROLES: readonly Role[] = ["viewer", "operator", "admin"];

export interface TokenGrant {
  role: Role;
  label: string;
  /** SHA-256 digest of the token; the raw token is never kept in memory after load. */
  digest: Buffer;
  /** Set on the loopback-only admin grant generated when SENTRA_WEB_TOKENS is empty. */
  generated?: true;
}

/** Number of grants configured through SENTRA_WEB_TOKENS (the generated local admin token excluded). */
export function configuredGrantCount(config: Pick<ServerConfig, "tokenGrants">): number {
  return config.tokenGrants.filter((grant) => !grant.generated).length;
}

export interface ServerConfig {
  repoRoot: string;
  webRoot: string;
  host: string;
  port: number;
  isLoopbackBind: boolean;
  production: boolean;
  /** Directory with the Vite production build, served from the same origin when present. */
  staticDir: string | null;
  sentraBin: string;
  /**
   * gh executable pinned by the host operator (SENTRA_GH_BIN); null to locate gh automatically.
   * Validated once at startup (resolveGhBinary). It is the only way to choose the gh the bridge
   * runs: a gh path cannot be set in the web console.
   */
  ghBin: string | null;
  dataDir: string;
  /** Core-owned SQLite store that holds the tenant/workspace registry. */
  registryDbPath: string;
  /** Web-bridge-owned SQLite store (sessions, audit chain, scan history, settings). */
  webDbPath: string;
  backupDir: string;
  allowedOrigins: Set<string>;
  allowedHosts: Set<string>;
  tokenGrants: TokenGrant[];
  /** Admin token generated for loopback-only operation when no tokens are configured. */
  generatedAdminToken: string | null;
  sessionTtlMs: number;
  cookieSecure: boolean;
  githubWebhookSecret: string | null;
  gitlabWebhookToken: string | null;
  githubTokenFromEnv: string | null;
  secretKey: Buffer;
  maxBodyBytes: number;
  cliTimeoutMs: number;
  cliLongTimeoutMs: number;
  cliMaxConcurrency: number;
  trustProxy: boolean;
  /** Optional allowlist of parent directories under which workspaces may be registered. */
  workspaceRoots: string[];
  /** Directory of plugin adapter manifests (SENTRA_PLUGIN_DIR); null disables plugin discovery. */
  pluginDir: string | null;
  /** Bridge-private scratch space (PR checkouts, temporary patch files). */
  tmpDir: string;
}

export class ConfigError extends Error {}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

function env(name: string): string | null {
  const value = process.env[name];
  if (value === undefined) return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function envInt(name: string, fallback: number, min: number, max: number): number {
  const raw = env(name);
  if (raw === null) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max || String(parsed) !== raw) {
    throw new ConfigError(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = env(name);
  if (raw === null) return fallback;
  if (["1", "true", "yes", "on"].includes(raw.toLowerCase())) return true;
  if (["0", "false", "no", "off"].includes(raw.toLowerCase())) return false;
  throw new ConfigError(`${name} must be a boolean (true/false)`);
}

export function sha256(value: string | Buffer): Buffer {
  return crypto.createHash("sha256").update(value).digest();
}

function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

/**
 * Parses SENTRA_WEB_TOKENS: comma-separated `role:token` or `role:label:token` entries.
 * Tokens shorter than 24 characters are rejected to avoid guessable credentials.
 */
export function parseTokenGrants(raw: string | null): TokenGrant[] {
  if (raw === null) return [];
  const grants: TokenGrant[] = [];
  const seen = new Set<string>();
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(":");
    if (parts.length !== 2 && parts.length !== 3) {
      throw new ConfigError("SENTRA_WEB_TOKENS entries must look like role:token or role:label:token");
    }
    const role = parts[0].trim().toLowerCase();
    const label = parts.length === 3 ? parts[1].trim() : role;
    const token = parts[parts.length - 1].trim();
    if (!isRole(role)) {
      throw new ConfigError(`SENTRA_WEB_TOKENS contains unknown role '${role}' (expected viewer, operator or admin)`);
    }
    if (!/^[A-Za-z0-9._~+/=-]{24,256}$/.test(token)) {
      throw new ConfigError("SENTRA_WEB_TOKENS tokens must be 24-256 URL-safe characters");
    }
    if (!/^[A-Za-z0-9._@-]{1,64}$/.test(label)) {
      throw new ConfigError("SENTRA_WEB_TOKENS labels must be 1-64 characters of [A-Za-z0-9._@-]");
    }
    const digestHex = sha256(token).toString("hex");
    if (seen.has(digestHex)) {
      throw new ConfigError("SENTRA_WEB_TOKENS contains a duplicated token");
    }
    seen.add(digestHex);
    grants.push({ role, label, digest: sha256(token) });
  }
  return grants;
}

function resolveSentraBinary(repoRoot: string): string {
  const explicit = env("SENTRA_BIN");
  if (explicit) {
    const resolved = path.resolve(explicit);
    if (!fs.existsSync(resolved)) {
      throw new ConfigError(`SENTRA_BIN points to a missing file: ${resolved}`);
    }
    return resolved;
  }
  const exe = process.platform === "win32" ? "sentra.exe" : "sentra";
  for (const profile of ["release", "debug"]) {
    const candidate = path.resolve(repoRoot, "target", profile, exe);
    if (fs.existsSync(candidate)) return candidate;
  }
  // The binary is executed for every core call, so it is taken from the bridge process PATH only,
  // never from standard install locations (some can be created by any local user). Relative and
  // UNC entries are skipped, and on Windows only sentra.exe/.com is accepted (no batch wrapper).
  const onPath = findOnProcessPathForExecution("sentra");
  if (onPath) return onPath;
  // Resolved lazily: health reports the binary as missing instead of crashing startup.
  return path.resolve(repoRoot, "target", "release", exe);
}

/** File-system access behind resolveGhBinary (injectable so every platform's rules are tested anywhere). */
export interface GhBinaryProbes {
  /** What the path leads to after following links; "missing" when nothing exists there. Throws on other errors. */
  kind(file: string): "file" | "directory" | "other" | "missing";
  /** Execute permission for the bridge user (macOS and Linux). */
  isExecutable(file: string): boolean;
  /** At most MAX_HEADER_BYTES from the start of the file. */
  readHeader(file: string): Uint8Array;
}

const HOST_GH_PROBES: GhBinaryProbes = {
  kind(file) {
    try {
      const stat = fs.statSync(file);
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
};

/**
 * Validates SENTRA_GH_BIN, the gh executable the host operator pins for `gh auth token`: an
 * absolute local path (no UNC or device path on Windows) to an existing regular file that is a
 * native executable of this OS, not a script: on Windows a .exe or .com with a PE header (a .cmd
 * or .bat would run through cmd.exe), on macOS a Mach-O and on Linux an ELF file with execute
 * permission. The file is only inspected here, never run. Ownership is not checked: like
 * SENTRA_BIN, the variable is set by whoever controls the bridge's environment.
 */
export function resolveGhBinary(input: string | null, platform: NodeJS.Platform = process.platform, probes: GhBinaryProbes = HOST_GH_PROBES): string | null {
  if (input === null) return null;
  // One pair of surrounding quotes, as Windows "Copy as path" adds, is not part of the path.
  const raw = /^"[^"]+"$/.test(input) ? input.slice(1, -1).trim() : input;
  // oxlint-disable-next-line no-control-regex -- intentional: rejects control characters in SENTRA_GH_BIN
  if (/[\u0000-\u001f\u007f]/.test(raw)) throw new ConfigError("SENTRA_GH_BIN contains control characters");
  if (platform === "win32") {
    if (/^[\\/]{2}/.test(raw)) {
      throw new ConfigError("SENTRA_GH_BIN must be a path on a local drive; UNC (\\\\server\\share) and device (\\\\?\\, \\\\.\\) paths are not accepted");
    }
    if (!/^[A-Za-z]:[\\/]/.test(raw)) throw new ConfigError(`SENTRA_GH_BIN must be an absolute path such as C:\\Program Files\\GitHub CLI\\gh.exe: ${raw}`);
  } else if (!raw.startsWith("/")) {
    throw new ConfigError(`SENTRA_GH_BIN must be an absolute path such as /usr/bin/gh: ${raw}`);
  }
  const file = pathApi(platform).normalize(raw);
  let kind: ReturnType<GhBinaryProbes["kind"]>;
  try {
    kind = probes.kind(file);
  } catch (error) {
    throw new ConfigError(`SENTRA_GH_BIN could not be checked (${(error as NodeJS.ErrnoException).code ?? "error"}): ${file}`);
  }
  if (kind === "missing") throw new ConfigError(`SENTRA_GH_BIN points to a missing file: ${file}`);
  if (kind !== "file") throw new ConfigError(`SENTRA_GH_BIN is not a regular file: ${file}`);
  if (platform === "win32") {
    if (!/\.(exe|com)$/i.test(file)) {
      throw new ConfigError(`SENTRA_GH_BIN must name a .exe or .com file (a script such as .cmd would run through cmd.exe): ${file}`);
    }
  } else if (!probes.isExecutable(file)) {
    throw new ConfigError(`SENTRA_GH_BIN is not executable by the bridge user: ${file}`);
  }
  let header: ReturnType<typeof parseExecutableHeader>;
  try {
    header = parseExecutableHeader(probes.readHeader(file));
  } catch (error) {
    throw new ConfigError(`SENTRA_GH_BIN could not be read (${(error as NodeJS.ErrnoException).code ?? "error"}): ${file}`);
  }
  if (header.format === "script") throw new ConfigError(`SENTRA_GH_BIN must be a native executable, not a script (${header.note}): ${file}`);
  const expected = NATIVE_FORMATS[platform];
  if (expected && !expected.includes(header.format)) {
    throw new ConfigError(`SENTRA_GH_BIN is not a native ${osLabel(platform)} executable (${header.note ?? `${header.format} file`}): ${file}`);
  }
  return file;
}

function loadSecretKey(dataDir: string): Buffer {
  const raw = env("SENTRA_WEB_SECRET_KEY");
  if (raw) {
    const decoded = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
    if (decoded.length !== 32) {
      throw new ConfigError("SENTRA_WEB_SECRET_KEY must encode exactly 32 bytes (64 hex chars or base64)");
    }
    return decoded;
  }
  const keyFile = path.join(dataDir, "web-secret.key");
  if (fs.existsSync(keyFile)) {
    const decoded = Buffer.from(fs.readFileSync(keyFile, "utf8").trim(), "hex");
    if (decoded.length !== 32) {
      throw new ConfigError(`Secret key file is corrupt: ${keyFile}`);
    }
    return decoded;
  }
  const generated = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, generated.toString("hex"), { encoding: "utf8", mode: 0o600, flag: "wx" });
  return generated;
}

function loadOrCreateLocalAdminToken(dataDir: string): string {
  const tokenFile = path.join(dataDir, "web-admin.token");
  if (fs.existsSync(tokenFile)) {
    const existing = fs.readFileSync(tokenFile, "utf8").trim();
    if (/^[A-Za-z0-9_-]{32,256}$/.test(existing)) return existing;
  }
  const generated = crypto.randomBytes(32).toString("base64url");
  fs.writeFileSync(tokenFile, generated, { encoding: "utf8", mode: 0o600 });
  return generated;
}

/** Real path of an existing location; the resolved input when it does not exist (yet). */
export function canonicalPath(value: string): string {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return path.resolve(value);
  }
}

function normalizeOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigError(`Invalid origin in SENTRA_WEB_ALLOWED_ORIGINS: ${value}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ConfigError(`Origins must use http or https: ${value}`);
  }
  return parsed.origin;
}

export function loadConfig(): ServerConfig {
  const webRoot = path.resolve(import.meta.dir, "..");
  const repoRoot = path.resolve(env("SENTRA_REPO_ROOT") ?? path.resolve(webRoot, ".."));
  const host = env("SENTRA_WEB_HOST") ?? "127.0.0.1";
  const port = envInt("SENTRA_WEB_PORT", 3001, 1, 65535);
  const isLoopbackBind = LOOPBACK_HOSTS.has(host);
  const production =
    process.argv.includes("--production") ||
    (env("SENTRA_WEB_MODE") ?? (process.env.NODE_ENV === "production" ? "production" : "development")) === "production";

  const requestedDataDir = path.resolve(env("SENTRA_WEB_DATA_DIR") ?? path.resolve(repoRoot, "..", "sentra_web_storage"));
  fs.mkdirSync(requestedDataDir, { recursive: true, mode: 0o700 });
  // Canonical form (links and junctions resolved): workspace roots and file targets are compared
  // as canonical paths, so the data directory must be too or containment checks can miss it.
  const dataDir = canonicalPath(requestedDataDir);
  const backupDir = path.join(dataDir, "backups");
  fs.mkdirSync(backupDir, { recursive: true });

  const normalizedData = dataDir.toLowerCase() + path.sep;
  const normalizedRepo = canonicalPath(repoRoot).toLowerCase() + path.sep;
  if (normalizedData.startsWith(normalizedRepo)) {
    throw new ConfigError(
      "SENTRA_WEB_DATA_DIR must be outside the repository checkout (the core requires storage outside every workspace)",
    );
  }

  const tokenGrants = parseTokenGrants(env("SENTRA_WEB_TOKENS"));
  let generatedAdminToken: string | null = null;
  if (tokenGrants.length === 0) {
    if (!isLoopbackBind) {
      throw new ConfigError(
        "Refusing to bind to a non-loopback address without SENTRA_WEB_TOKENS. Configure role tokens or bind to 127.0.0.1.",
      );
    }
    generatedAdminToken = loadOrCreateLocalAdminToken(dataDir);
    tokenGrants.push({ role: "admin", label: "local-admin", digest: sha256(generatedAdminToken), generated: true });
  }

  const allowedOrigins = new Set<string>();
  const allowedHosts = new Set<string>();
  for (const loopback of ["localhost", "127.0.0.1", "[::1]"]) {
    allowedHosts.add(`${loopback}:${port}`);
    allowedOrigins.add(`http://${loopback}:${port}`);
    if (!production) {
      // Vite dev server proxies /api to this bridge and forwards its own origin.
      allowedOrigins.add(`http://${loopback}:5173`);
      allowedHosts.add(`${loopback}:5173`);
    }
  }
  for (const origin of (env("SENTRA_WEB_ALLOWED_ORIGINS") ?? "").split(",")) {
    if (origin.trim()) {
      const normalized = normalizeOrigin(origin.trim());
      allowedOrigins.add(normalized);
      allowedHosts.add(new URL(normalized).host);
    }
  }
  for (const extraHost of (env("SENTRA_WEB_ALLOWED_HOSTS") ?? "").split(",")) {
    if (extraHost.trim()) allowedHosts.add(extraHost.trim().toLowerCase());
  }

  const staticCandidate = path.join(webRoot, "dist");
  const staticDir = production && fs.existsSync(path.join(staticCandidate, "index.html")) ? staticCandidate : null;

  const workspaceRoots = (env("SENTRA_WEB_WORKSPACE_ROOTS") ?? "")
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => canonicalPath(path.resolve(entry)));

  const pluginDirRaw = env("SENTRA_PLUGIN_DIR");
  let pluginDir: string | null = null;
  if (pluginDirRaw) {
    pluginDir = path.resolve(pluginDirRaw);
    if (!fs.existsSync(pluginDir) || !fs.statSync(pluginDir).isDirectory()) {
      throw new ConfigError(`SENTRA_PLUGIN_DIR is not a directory: ${pluginDir}`);
    }
  }

  const tmpDir = path.join(dataDir, "tmp");
  fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });

  return {
    repoRoot,
    webRoot,
    host,
    port,
    isLoopbackBind,
    production,
    staticDir,
    sentraBin: resolveSentraBinary(repoRoot),
    ghBin: resolveGhBinary(env("SENTRA_GH_BIN")),
    dataDir,
    registryDbPath: path.join(dataDir, "sentra.db"),
    webDbPath: path.join(dataDir, "sentra-web.db"),
    backupDir,
    allowedOrigins,
    allowedHosts,
    tokenGrants,
    generatedAdminToken,
    sessionTtlMs: envInt("SENTRA_WEB_SESSION_TTL_MINUTES", 12 * 60, 5, 7 * 24 * 60) * 60_000,
    cookieSecure: envBool("SENTRA_WEB_COOKIE_SECURE", false),
    githubWebhookSecret: env("SENTRA_GITHUB_WEBHOOK_SECRET"),
    gitlabWebhookToken: env("SENTRA_GITLAB_WEBHOOK_TOKEN"),
    githubTokenFromEnv: env("GITHUB_TOKEN") ?? env("GH_TOKEN"),
    secretKey: loadSecretKey(dataDir),
    maxBodyBytes: envInt("SENTRA_WEB_MAX_BODY_BYTES", 2 * 1024 * 1024, 1024, 64 * 1024 * 1024),
    cliTimeoutMs: envInt("SENTRA_CLI_TIMEOUT_SECONDS", 120, 5, 3600) * 1000,
    cliLongTimeoutMs: envInt("SENTRA_CLI_LONG_TIMEOUT_SECONDS", 900, 30, 7200) * 1000,
    cliMaxConcurrency: envInt("SENTRA_CLI_MAX_CONCURRENCY", 2, 1, 16),
    trustProxy: envBool("SENTRA_WEB_TRUST_PROXY", false),
    workspaceRoots,
    pluginDir,
    tmpDir,
  };
}
