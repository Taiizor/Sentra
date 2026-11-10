import type { Database } from "bun:sqlite";
import fs from "node:fs";
import path from "node:path";
import type { LockfileView, ToolAvailability, TopologyReportView } from "../../src/types/api.ts";
import { parseJsonColumn } from "../db.ts";
import { isWithin } from "../paths.ts";

/**
 * Deterministic, read-only workspace topology. Everything in a report is derived from files
 * that exist in the workspace (bounded walk, bounded reads) or from core CLI probes; nothing
 * is executed in, or written to, the workspace. Entry points are explicitly heuristic.
 */

// ───────────────────────────── limits ─────────────────────────────

/** Directories never descended into (vendored, generated or tool-state trees). */
export const TOPOLOGY_SKIP_DIRS: ReadonlySet<string> = new Set([
  ".git",
  "node_modules",
  "target",
  "vendor",
  "dist",
  "build",
  "out",
  ".venv",
  "venv",
  "__pycache__",
  ".next",
  ".nuxt",
  ".gradle",
  ".idea",
  ".vscode",
  "bin",
  "obj",
]);

export interface WalkLimits {
  /** Deepest directory level that is listed; the workspace root is level 0. */
  maxDepth: number;
  /** Maximum number of directory entries examined across the whole walk. */
  maxEntries: number;
}

export const DEFAULT_WALK_LIMITS: WalkLimits = { maxDepth: 6, maxEntries: 20_000 };

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_ENTRY_READ_BYTES = 256 * 1024;
const MAX_ENTRY_CANDIDATES_READ = 400;
const MAX_ENTRY_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_CANDIDATE_FILES = 2_000;
export const MAX_DECLARED_DEPENDENCIES = 300;
const MAX_SUBSYSTEMS = 500;
const MAX_ENTRYPOINTS = 300;

// ───────────────────────────── manifest classification ─────────────────────────────

export interface ManifestClass {
  kind: string;
  /** OSV ecosystem name, or null for files that are not package manifests. */
  ecosystem: string | null;
  /** True for manifests that declare a package/module (used for subsystems). */
  packageManifest: boolean;
}

/** Classifies a file by its name and workspace-relative directory (forward slashes). */
export function classifyManifest(relativeDir: string, name: string): ManifestClass | null {
  switch (name) {
    case "package.json":
      return { kind: "package.json", ecosystem: "npm", packageManifest: true };
    case "Cargo.toml":
      return { kind: "Cargo.toml", ecosystem: "crates.io", packageManifest: true };
    case "go.mod":
      return { kind: "go.mod", ecosystem: "Go", packageManifest: true };
    case "pyproject.toml":
      return { kind: "pyproject.toml", ecosystem: "PyPI", packageManifest: true };
    case "composer.json":
      return { kind: "composer.json", ecosystem: "Packagist", packageManifest: true };
    case "Gemfile":
      return { kind: "Gemfile", ecosystem: "RubyGems", packageManifest: true };
    case "pom.xml":
      return { kind: "pom.xml", ecosystem: "Maven", packageManifest: true };
    case "build.gradle":
    case "build.gradle.kts":
      return { kind: name, ecosystem: "Maven", packageManifest: true };
    case "docker-compose.yml":
    case "docker-compose.yaml":
    case "compose.yml":
    case "compose.yaml":
      return { kind: "docker-compose", ecosystem: null, packageManifest: false };
    default:
      break;
  }
  if (/^requirements([._-][A-Za-z0-9._-]+)?\.txt$/.test(name)) {
    return { kind: "requirements.txt", ecosystem: "PyPI", packageManifest: false };
  }
  if (/\.csproj$/i.test(name)) return { kind: "csproj", ecosystem: "NuGet", packageManifest: true };
  if (name === "Dockerfile" || /^Dockerfile\.[A-Za-z0-9._-]+$/.test(name) || /\.dockerfile$/i.test(name)) {
    return { kind: "Dockerfile", ecosystem: null, packageManifest: false };
  }
  if (/\.ya?ml$/i.test(name) && (relativeDir === ".github/workflows" || relativeDir.endsWith("/.github/workflows"))) {
    return { kind: "github-workflow", ecosystem: null, packageManifest: false };
  }
  return null;
}

/** File names that make a file an entry-point candidate anywhere in the walk. */
const ENTRY_NAMES_ANYWHERE = new Set([
  "main.rs",
  "main.go",
  "server.ts",
  "server.js",
  "server.mjs",
  "app.py",
  "manage.py",
  "main.py",
  "wsgi.py",
  "asgi.py",
  "__main__.py",
  "Program.cs",
]);

/** File names that are only candidates at a package.json root (or its src/ directory). */
const ENTRY_NAMES_AT_PACKAGE_ROOT = new Set(["index.ts", "index.js", "index.mjs", "main.ts", "main.js", "app.ts", "app.js"]);

// ───────────────────────────── walk ─────────────────────────────

export interface ManifestHit extends ManifestClass {
  /** Workspace-relative path with forward slashes. */
  path: string;
  /** Workspace-relative directory ("." for the root). */
  dir: string;
  name: string;
}

export interface WorkspaceWalk {
  manifests: ManifestHit[];
  /** Workspace-relative paths of files whose name makes them entry-point candidates. */
  candidateFiles: string[];
  entriesVisited: number;
  entryLimitReached: boolean;
  depthLimitReached: boolean;
  symlinksSkipped: number;
  skippedDirectories: number;
  unreadableDirectories: number;
  candidateLimitReached: boolean;
}

function joinRel(dir: string, name: string): string {
  return dir === "." ? name : `${dir}/${name}`;
}

function isLink(absolute: string): boolean {
  try {
    return fs.lstatSync(absolute).isSymbolicLink();
  } catch {
    return true;
  }
}

/**
 * Breadth-first walk bounded by depth and entry count. Symbolic links and junctions are never
 * followed, and the skip list is applied case-insensitively.
 */
export function walkWorkspace(root: string, limits: WalkLimits = DEFAULT_WALK_LIMITS): WorkspaceWalk {
  const result: WorkspaceWalk = {
    manifests: [],
    candidateFiles: [],
    entriesVisited: 0,
    entryLimitReached: false,
    depthLimitReached: false,
    symlinksSkipped: 0,
    skippedDirectories: 0,
    unreadableDirectories: 0,
    candidateLimitReached: false,
  };
  const queue: { absolute: string; rel: string; depth: number }[] = [{ absolute: root, rel: ".", depth: 0 }];
  for (let index = 0; index < queue.length && !result.entryLimitReached; index += 1) {
    const current = queue[index];
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current.absolute, { withFileTypes: true });
    } catch {
      result.unreadableDirectories += 1;
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (result.entriesVisited >= limits.maxEntries) {
        result.entryLimitReached = true;
        break;
      }
      result.entriesVisited += 1;
      if (entry.isSymbolicLink()) {
        result.symlinksSkipped += 1;
        continue;
      }
      const absolute = path.join(current.absolute, entry.name);
      const rel = joinRel(current.rel, entry.name);
      if (entry.isDirectory()) {
        if (TOPOLOGY_SKIP_DIRS.has(entry.name.toLowerCase())) {
          result.skippedDirectories += 1;
          continue;
        }
        // Junctions and other reparse points can surface as directories; lstat decides.
        if (isLink(absolute)) {
          result.symlinksSkipped += 1;
          continue;
        }
        if (current.depth + 1 > limits.maxDepth) {
          result.depthLimitReached = true;
          continue;
        }
        queue.push({ absolute, rel, depth: current.depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      const manifest = classifyManifest(current.rel, entry.name);
      if (manifest) result.manifests.push({ ...manifest, path: rel, dir: current.rel, name: entry.name });
      if (ENTRY_NAMES_ANYWHERE.has(entry.name) || ENTRY_NAMES_AT_PACKAGE_ROOT.has(entry.name)) {
        if (result.candidateFiles.length < MAX_CANDIDATE_FILES) result.candidateFiles.push(rel);
        else result.candidateLimitReached = true;
      }
    }
  }
  return result;
}

/** Reads at most `maxBytes` of a regular file; links and non-files are refused (null). */
export function readBounded(absolute: string, maxBytes: number): { text: string; truncated: boolean } | null {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(absolute);
  } catch {
    return null;
  }
  if (!stat.isFile()) return null;
  const size = Math.min(stat.size, maxBytes);
  const buffer = Buffer.alloc(size);
  let fd: number | null = null;
  try {
    fd = fs.openSync(absolute, "r");
    let offset = 0;
    while (offset < size) {
      const read = fs.readSync(fd, buffer, offset, size - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    return { text: buffer.subarray(0, offset).toString("utf8"), truncated: stat.size > maxBytes };
  } catch {
    return null;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

// ───────────────────────────── manifest parsers ─────────────────────────────

export interface DeclaredDependency {
  name: string;
  /** Version requirement exactly as declared; null when the manifest declares none. */
  version: string | null;
}

export interface ParsedManifest {
  packageName: string | null;
  dependencies: DeclaredDependency[];
  /** Workspace member patterns (Cargo `[workspace].members`, package.json `workspaces`). */
  workspaceMembers: string[];
}

const EMPTY_MANIFEST: ParsedManifest = { packageName: null, dependencies: [], workspaceMembers: [] };

function stringRecordEntries(value: unknown): DeclaredDependency[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>)
    .filter(([name]) => name.length > 0 && name.length <= 214)
    .map(([name, version]) => ({ name, version: typeof version === "string" && version.length > 0 ? version.slice(0, 200) : null }));
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function parsePackageJson(text: string): ParsedManifest {
  const parsed: unknown = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("package.json is not a JSON object");
  const doc = parsed as Record<string, unknown>;
  const workspacesField = doc.workspaces;
  const workspaceMembers = Array.isArray(workspacesField)
    ? stringArray(workspacesField)
    : workspacesField && typeof workspacesField === "object"
      ? stringArray((workspacesField as Record<string, unknown>).packages)
      : [];
  return {
    packageName: typeof doc.name === "string" && doc.name ? doc.name : null,
    dependencies: [...stringRecordEntries(doc.dependencies), ...stringRecordEntries(doc.devDependencies)],
    workspaceMembers,
  };
}

export function parseComposerJson(text: string): ParsedManifest {
  const parsed: unknown = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("composer.json is not a JSON object");
  const doc = parsed as Record<string, unknown>;
  // Platform requirements (php, ext-*, lib-*) are not packages.
  const packages = (value: unknown) => stringRecordEntries(value).filter((dep) => dep.name.includes("/"));
  return {
    packageName: typeof doc.name === "string" && doc.name ? doc.name : null,
    dependencies: [...packages(doc.require), ...packages(doc["require-dev"])],
    workspaceMembers: [],
  };
}

interface TomlEntry {
  /** Table header with quotes removed, e.g. "dependencies" or "dependencies.serde". */
  section: string;
  key: string;
  value: string;
}

/** Removes a trailing `#` comment while respecting basic and literal strings. */
function stripTomlComment(line: string): string {
  let quote: string | null = null;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (char === "\\" && quote === '"') {
        index += 1;
      } else if (char === quote) {
        quote = null;
      }
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "#") {
      return line.slice(0, index);
    }
  }
  return line;
}

function bracketBalance(text: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (char === "\\" && quote === '"') index += 1;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "[" || char === "{") {
      depth += 1;
    } else if (char === "]" || char === "}") {
      depth -= 1;
    }
  }
  return depth;
}

function unquoteKey(key: string): string {
  return key
    .split(".")
    .map((part) => part.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1"))
    .join(".");
}

/**
 * Line-oriented reader for the subset of TOML used by Cargo.toml and pyproject.toml
 * dependency declarations: table headers, `key = value` pairs, multi-line arrays, and
 * skipping of multi-line strings. It is not a general TOML parser.
 */
export function readTomlEntries(text: string): TomlEntry[] {
  const entries: TomlEntry[] = [];
  const lines = text.split(/\r?\n/);
  let section = "";
  for (let index = 0; index < lines.length; index += 1) {
    const line = stripTomlComment(lines[index]).trim();
    if (!line) continue;
    if (line.startsWith("[[")) {
      section = `[[${unquoteKey(line.replace(/^\[\[|\]\]$/g, ""))}]]`;
      continue;
    }
    if (line.startsWith("[")) {
      section = unquoteKey(line.replace(/^\[|\]$/g, ""));
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = unquoteKey(line.slice(0, eq));
    let value = line.slice(eq + 1).trim();
    if (value.startsWith('"""') || value.startsWith("'''")) {
      const fence = value.slice(0, 3);
      if (value.length < 6 || !value.slice(3).includes(fence)) {
        // Skip the body of a multi-line string so its content is never read as TOML.
        while (index + 1 < lines.length && !lines[index + 1].includes(fence)) index += 1;
        index += 1;
      }
      continue;
    }
    while (bracketBalance(value) > 0 && index + 1 < lines.length) {
      index += 1;
      value += ` ${stripTomlComment(lines[index]).trim()}`;
    }
    entries.push({ section, key, value });
  }
  return entries;
}

function tomlString(value: string): string | null {
  const match = value.match(/^"((?:[^"\\]|\\.)*)"$/) ?? value.match(/^'([^']*)'$/);
  return match ? match[1] : null;
}

function tomlStringArray(value: string): string[] {
  if (!value.startsWith("[")) return [];
  const items: string[] = [];
  const pattern = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
  for (let match = pattern.exec(value); match; match = pattern.exec(value)) items.push(match[1] ?? match[2]);
  return items;
}

function inlineTableVersion(value: string): string | null {
  const match = value.match(/\bversion\s*=\s*"([^"]*)"/) ?? value.match(/\bversion\s*=\s*'([^']*)'/);
  return match ? match[1] : null;
}

export function parseCargoToml(text: string): ParsedManifest {
  const entries = readTomlEntries(text);
  const order: string[] = [];
  const versions = new Map<string, string | null>();
  const note = (name: string, version: string | null) => {
    if (!versions.has(name)) order.push(name);
    if (version !== null || !versions.has(name)) versions.set(name, version);
  };
  let packageName: string | null = null;
  const workspaceMembers: string[] = [];
  for (const entry of entries) {
    if (entry.section === "package" && entry.key === "name") packageName = tomlString(entry.value);
    if (entry.section === "workspace" && entry.key === "members") workspaceMembers.push(...tomlStringArray(entry.value));
    for (const table of ["dependencies", "workspace.dependencies"]) {
      if (entry.section === table) {
        const [name, ...rest] = entry.key.split(".");
        if (!name) continue;
        if (rest.length > 0) {
          // `serde.workspace = true` / `serde.version = "1"`
          note(name, rest.join(".") === "version" ? tomlString(entry.value) : null);
        } else {
          note(name, tomlString(entry.value) ?? inlineTableVersion(entry.value));
        }
      } else if (entry.section.startsWith(`${table}.`) && !entry.section.slice(table.length + 1).includes(".")) {
        // [dependencies.serde] with `version = "1"`
        const name = entry.section.slice(table.length + 1);
        note(name, entry.key === "version" ? tomlString(entry.value) : null);
      }
    }
  }
  return {
    packageName,
    dependencies: order.map((name) => ({ name, version: versions.get(name) ?? null })),
    workspaceMembers,
  };
}

/** Parses a PEP 508 requirement into its project name and version specifier. */
export function parsePep508(requirement: string): DeclaredDependency | null {
  const match = requirement.trim().match(/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(\([^)]*\)|[<>=!~][^;@]*)?/);
  if (!match) return null;
  const spec = (match[3] ?? "").replace(/^\(|\)$/g, "").trim();
  return { name: match[1], version: spec ? spec.slice(0, 200) : null };
}

export function parsePyproject(text: string): ParsedManifest {
  const entries = readTomlEntries(text);
  let packageName: string | null = null;
  const dependencies: DeclaredDependency[] = [];
  for (const entry of entries) {
    if (entry.section !== "project") continue;
    if (entry.key === "name") packageName = tomlString(entry.value);
    if (entry.key === "dependencies") {
      for (const requirement of tomlStringArray(entry.value)) {
        const parsed = parsePep508(requirement);
        if (parsed) dependencies.push(parsed);
      }
    }
  }
  return { packageName, dependencies, workspaceMembers: [] };
}

export function parseRequirementsTxt(text: string): ParsedManifest {
  const dependencies: DeclaredDependency[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-") || /^[a-z]+:\/\//i.test(line)) continue;
    const parsed = parsePep508(line);
    if (parsed) dependencies.push(parsed);
  }
  return { packageName: null, dependencies, workspaceMembers: [] };
}

export function parseGoMod(text: string): ParsedManifest {
  let packageName: string | null = null;
  const dependencies: DeclaredDependency[] = [];
  let inRequireBlock = false;
  const requireLine = (line: string) => {
    if (/\/\/\s*indirect\b/.test(line)) return;
    const [modulePath, version] = line.replace(/\/\/.*$/, "").trim().split(/\s+/);
    if (modulePath) dependencies.push({ name: modulePath, version: version ?? null });
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("//")) continue;
    if (inRequireBlock) {
      if (line.startsWith(")")) inRequireBlock = false;
      else requireLine(line);
      continue;
    }
    const moduleMatch = line.match(/^module\s+(\S+)/);
    if (moduleMatch) {
      packageName = moduleMatch[1].replace(/^"|"$/g, "");
      continue;
    }
    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    const single = line.match(/^require\s+(.+)$/);
    if (single) requireLine(single[1]);
  }
  return { packageName, dependencies, workspaceMembers: [] };
}

/** Kinds whose declared direct dependencies are extracted. */
const DEPENDENCY_PARSERS: Record<string, (text: string) => ParsedManifest> = {
  "package.json": parsePackageJson,
  "Cargo.toml": parseCargoToml,
  "go.mod": parseGoMod,
  "pyproject.toml": parsePyproject,
  "requirements.txt": parseRequirementsTxt,
  "composer.json": parseComposerJson,
};

// ───────────────────────────── subsystems ─────────────────────────────

type Subsystem = TopologyReportView["subsystems"][number];

/**
 * Expands a workspace member pattern relative to the manifest directory. Exact paths and a
 * single trailing `/*` are supported; other glob forms are reported as unsupported.
 */
export function expandMemberPattern(
  root: string,
  baseDir: string,
  pattern: string,
  marker: string,
): { dirs: string[]; problem: string | null } {
  const cleaned = pattern.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
  if (!cleaned || cleaned.split("/").includes("..") || path.isAbsolute(cleaned)) {
    return { dirs: [], problem: `member pattern '${pattern}' leaves the workspace or is empty` };
  }
  const resolveRel = (rel: string) => path.join(root, ...rel.split("/").filter((part) => part !== "."));
  const prefix = baseDir === "." ? "" : `${baseDir}/`;
  if (cleaned.endsWith("/*") && !/[*?[\]{}]/.test(cleaned.slice(0, -2))) {
    const parentRel = `${prefix}${cleaned.slice(0, -2)}`;
    const parentAbs = resolveRel(parentRel);
    if (!isWithin(root, parentAbs) || !isPlainDirectoryPath(root, parentRel)) {
      return { dirs: [], problem: `member pattern '${pattern}' is not a plain directory` };
    }
    let children: fs.Dirent[];
    try {
      children = fs.readdirSync(parentAbs, { withFileTypes: true });
    } catch {
      return { dirs: [], problem: `member pattern '${pattern}': directory not readable` };
    }
    const dirs = children
      .filter((child) => child.isDirectory() && !child.isSymbolicLink())
      .map((child) => `${parentRel}/${child.name}`)
      .filter((rel) => !isLink(resolveRel(rel)) && isPlainFile(path.join(resolveRel(rel), marker)))
      .sort();
    return { dirs, problem: null };
  }
  if (/[*?[\]{}]/.test(cleaned)) return { dirs: [], problem: `member pattern '${pattern}' uses a glob form that is not expanded` };
  const rel = `${prefix}${cleaned}`;
  const absolute = resolveRel(rel);
  if (!isWithin(root, absolute)) return { dirs: [], problem: `member pattern '${pattern}' leaves the workspace` };
  if (!isPlainDirectoryPath(root, rel)) {
    return { dirs: [], problem: `declared member '${rel}' does not exist as a directory (links and junctions are not followed)` };
  }
  return { dirs: [rel], problem: null };
}

/**
 * True when every component of `rel` below `root` exists and is a real directory: no
 * symbolic link or junction anywhere on the path, so nothing outside the workspace is listed.
 */
export function isPlainDirectoryPath(root: string, rel: string): boolean {
  let current = root;
  for (const part of rel.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") return false;
    current = path.join(current, part);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch {
      return false;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) return false;
  }
  return true;
}

/** A regular file that is not reached through a link at its last component. */
function isPlainFile(absolute: string): boolean {
  try {
    const stat = fs.lstatSync(absolute);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

// ───────────────────────────── entry points ─────────────────────────────

type Entrypoint = TopologyReportView["entrypoints"][number];

const ENTRY_TOKENS: { token: string; kind: string }[] = [
  { token: "Bun.serve(", kind: "http-server" },
  { token: "app.listen(", kind: "http-server" },
  { token: "http.createServer(", kind: "http-server" },
  { token: "https.createServer(", kind: "http-server" },
  { token: "http.ListenAndServe(", kind: "http-server" },
  { token: "uvicorn.run(", kind: "http-server" },
  { token: "#[tokio::main]", kind: "async-runtime-main" },
  { token: "fn main(", kind: "program-main" },
  { token: "func main(", kind: "program-main" },
  { token: "static void Main(", kind: "program-main" },
  { token: "static async Task Main(", kind: "program-main" },
  { token: "execute_from_command_line(", kind: "django-management" },
  { token: 'if __name__ == "__main__"', kind: "script-main" },
  { token: "if __name__ == '__main__'", kind: "script-main" },
];

const KIND_PRIORITY = ["http-server", "async-runtime-main", "program-main", "django-management", "script-main"];

export interface EntrypointScan {
  entrypoints: Entrypoint[];
  filesRead: number;
  bytesRead: number;
  readLimitReached: boolean;
  unreadable: number;
}

/** Returns the first line (1-based) on which each listed token occurs. */
export function findEntryTokens(text: string): { token: string; kind: string; line: number }[] {
  const hits: { token: string; kind: string; line: number }[] = [];
  const lines = text.split("\n");
  for (const { token, kind } of ENTRY_TOKENS) {
    const line = lines.findIndex((candidate) => candidate.includes(token));
    if (line >= 0) hits.push({ token, kind, line: line + 1 });
  }
  return hits.sort((a, b) => a.line - b.line);
}

export function detectEntrypoints(root: string, walk: WorkspaceWalk): EntrypointScan {
  const scan: EntrypointScan = { entrypoints: [], filesRead: 0, bytesRead: 0, readLimitReached: false, unreadable: 0 };
  const packageDirs = new Set(walk.manifests.filter((manifest) => manifest.kind === "package.json").map((manifest) => manifest.dir));
  const absoluteOf = (rel: string) => path.join(root, ...rel.split("/"));

  const read = (rel: string): string | null => {
    if (scan.filesRead >= MAX_ENTRY_CANDIDATES_READ || scan.bytesRead >= MAX_ENTRY_TOTAL_BYTES) {
      scan.readLimitReached = true;
      return null;
    }
    const content = readBounded(absoluteOf(rel), MAX_ENTRY_READ_BYTES);
    if (!content) {
      scan.unreadable += 1;
      return null;
    }
    scan.filesRead += 1;
    scan.bytesRead += Buffer.byteLength(content.text);
    return content.text;
  };

  for (const rel of walk.candidateFiles) {
    if (scan.entrypoints.length >= MAX_ENTRYPOINTS) break;
    const slash = rel.lastIndexOf("/");
    const dir = slash < 0 ? "." : rel.slice(0, slash);
    const name = rel.slice(slash + 1);
    if (!ENTRY_NAMES_ANYWHERE.has(name)) {
      const parent = dir.endsWith("/src") ? dir.slice(0, -4) : dir === "src" ? "." : null;
      if (!packageDirs.has(dir) && !(parent !== null && packageDirs.has(parent))) continue;
    }
    const text = read(rel);
    const scope = ENTRY_NAMES_ANYWHERE.has(name) ? "matches an entry-point file name" : "is an entry-point file name at a package.json root";
    if (text === null) {
      if (scan.readLimitReached) {
        scan.entrypoints.push({ path: rel, kind: "name-match", evidence: `file name '${name}' ${scope}; content not read (read budget exhausted)` });
      }
      continue;
    }
    const hits = findEntryTokens(text);
    const kind = KIND_PRIORITY.find((candidate) => hits.some((hit) => hit.kind === candidate)) ?? "name-match";
    const tokens = hits
      .slice(0, 4)
      .map((hit) => `'${hit.token}' at line ${hit.line}`)
      .join(", ");
    const evidence = hits.length
      ? `file name '${name}' ${scope}; matched ${tokens}`
      : `file name '${name}' ${scope}; no listed entry-point token in the first ${MAX_ENTRY_READ_BYTES / 1024} KiB`;
    scan.entrypoints.push({ path: rel, kind, evidence });
  }

  for (const manifest of walk.manifests) {
    if (manifest.kind !== "github-workflow" || scan.entrypoints.length >= MAX_ENTRYPOINTS) continue;
    const text = read(manifest.path);
    const lines = text?.split("\n") ?? [];
    const targetLine = lines.findIndex((line) => /\bpull_request_target\b/.test(line));
    const evidence =
      targetLine >= 0
        ? `GitHub Actions workflow file; mentions 'pull_request_target' at line ${targetLine + 1}`
        : "GitHub Actions workflow file (triggers are not parsed)";
    scan.entrypoints.push({ path: manifest.path, kind: "ci-workflow", evidence });
  }
  return scan;
}

// ───────────────────────────── report assembly ─────────────────────────────

export type TopologyContent = Omit<TopologyReportView, "reportId" | "tenantId" | "createdAt" | "createdBy">;

export interface LanguageProbe {
  primaryLanguage: string | null;
  languages: { language: string; filesCount: number }[];
}

export interface LockfileInventory {
  lockfiles: LockfileView[];
  totalPackages: number;
}

/** Real data sources injected by the route (core CLI probes, PATH lookups). */
export interface TopologySources {
  languageProbe(): Promise<LanguageProbe>;
  lockfileInventory(): Promise<LockfileInventory>;
  tools(): ToolAvailability[];
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Maps `sentra codeql --workspace <dir> --json` (probe mode) to language counts. Throws when
 * the document does not have the probe shape, so a malformed result is reported, not guessed.
 */
export function parseCodeqlProbe(document: unknown): LanguageProbe {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("sentra codeql did not return a JSON object");
  }
  const doc = document as Record<string, unknown>;
  if (!Array.isArray(doc.detected_languages)) {
    throw new Error("sentra codeql output has no detected_languages array");
  }
  const languages: LanguageProbe["languages"] = [];
  for (const item of doc.detected_languages) {
    if (!item || typeof item !== "object") continue;
    const entry = item as Record<string, unknown>;
    if (typeof entry.language !== "string" || typeof entry.files_count !== "number" || !Number.isFinite(entry.files_count)) continue;
    languages.push({ language: entry.language, filesCount: entry.files_count });
  }
  languages.sort((a, b) => b.filesCount - a.filesCount || a.language.localeCompare(b.language));
  return {
    primaryLanguage: typeof doc.primary_language === "string" && doc.primary_language ? doc.primary_language : null,
    languages,
  };
}

export async function computeTopology(root: string, sources: TopologySources, limits: WalkLimits = DEFAULT_WALK_LIMITS): Promise<TopologyContent> {
  const started = performance.now();
  const notes: string[] = [];
  // Start the core probes first; the walk below runs while they execute.
  const languagesPromise = sources.languageProbe().then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error: errorText(error) }),
  );
  const inventoryPromise = sources.lockfileInventory().then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error: errorText(error) }),
  );

  const walk = walkWorkspace(root, limits);

  // Manifests and declared dependencies.
  const parsedByPath = new Map<string, ParsedManifest>();
  const frameworks: TopologyReportView["frameworks"] = [];
  let dependenciesOmitted = 0;
  const parseFailures: string[] = [];
  for (const manifest of walk.manifests) {
    const parser = DEPENDENCY_PARSERS[manifest.kind];
    if (!parser) continue;
    const content = readBounded(path.join(root, ...manifest.path.split("/")), MAX_MANIFEST_BYTES);
    if (!content) {
      parseFailures.push(`${manifest.path}: not readable`);
      continue;
    }
    if (content.truncated) {
      parseFailures.push(`${manifest.path}: larger than ${MAX_MANIFEST_BYTES / 1024} KiB, not parsed`);
      continue;
    }
    let parsed: ParsedManifest = EMPTY_MANIFEST;
    try {
      parsed = parser(content.text.replace(/^\uFEFF/, ""));
    } catch (error) {
      parseFailures.push(`${manifest.path}: ${errorText(error).slice(0, 200)}`);
      continue;
    }
    parsedByPath.set(manifest.path, parsed);
    for (const dependency of parsed.dependencies) {
      if (frameworks.length >= MAX_DECLARED_DEPENDENCIES) {
        dependenciesOmitted += 1;
        continue;
      }
      frameworks.push({ name: dependency.name, version: dependency.version, manifest: manifest.path });
    }
  }

  // Subsystems: declared workspace members first, then every directory with a package manifest.
  const subsystems: Subsystem[] = [];
  const seenSubsystemPaths = new Set<string>();
  const memberProblems: string[] = [];
  const packageNameAt = (dir: string, kind: string): string | null =>
    parsedByPath.get(dir === "." ? kind : `${dir}/${kind}`)?.packageName ?? null;
  const baseName = (dir: string) => (dir === "." ? path.basename(root) : dir.slice(dir.lastIndexOf("/") + 1));
  const addSubsystem = (subsystem: Subsystem) => {
    if (seenSubsystemPaths.has(subsystem.path) || subsystems.length >= MAX_SUBSYSTEMS) return;
    seenSubsystemPaths.add(subsystem.path);
    subsystems.push(subsystem);
  };
  for (const manifest of walk.manifests) {
    const parsed = parsedByPath.get(manifest.path);
    if (!parsed || parsed.workspaceMembers.length === 0) continue;
    const isCargo = manifest.kind === "Cargo.toml";
    for (const pattern of parsed.workspaceMembers.slice(0, 200)) {
      const expanded = expandMemberPattern(root, manifest.dir, pattern, manifest.kind);
      if (expanded.problem) memberProblems.push(`${manifest.path}: ${expanded.problem}`);
      for (const dir of expanded.dirs) {
        addSubsystem({
          name: packageNameAt(dir, manifest.kind) ?? baseName(dir),
          path: dir,
          kind: isCargo ? "cargo-workspace-member" : "package-json-workspace-member",
        });
      }
    }
  }
  for (const manifest of walk.manifests) {
    if (!manifest.packageManifest) continue;
    addSubsystem({
      name: parsedByPath.get(manifest.path)?.packageName ?? baseName(manifest.dir),
      path: manifest.dir,
      kind: `${manifest.kind} directory`,
    });
  }

  const entryScan = detectEntrypoints(root, walk);

  const languageResult = await languagesPromise;
  const inventoryResult = await inventoryPromise;
  const walkMs = Math.round(performance.now() - started);

  // Notes: every limitation that applies to this report.
  if (languageResult.ok) {
    notes.push("Languages are file counts by extension reported by the core `sentra codeql` probe; no code was parsed and CodeQL was not run.");
  } else {
    notes.push(`Language probe failed (sentra codeql): ${languageResult.error}`);
  }
  notes.push(
    `Workspace walk: up to depth ${limits.maxDepth} and ${limits.maxEntries} directory entries; ${walk.entriesVisited} entries examined. ` +
      `Skipped directory names: ${[...TOPOLOGY_SKIP_DIRS].join(", ")} (${walk.skippedDirectories} skipped). Symbolic links and junctions are not followed (${walk.symlinksSkipped} skipped).`,
  );
  if (walk.entryLimitReached) notes.push(`The entry limit (${limits.maxEntries}) was reached; manifests and entry points beyond it are missing from this report.`);
  if (walk.depthLimitReached) notes.push(`Directories deeper than ${limits.maxDepth} levels were not listed.`);
  if (walk.unreadableDirectories > 0) notes.push(`${walk.unreadableDirectories} directories could not be read.`);
  notes.push(
    "Frameworks are declared direct dependencies read from manifests (package.json dependencies/devDependencies, Cargo.toml [dependencies]/[workspace.dependencies], go.mod require without '// indirect', pyproject.toml [project].dependencies, requirements*.txt, composer.json require/require-dev). Versions are requirements as declared, not resolved versions, and a declaration does not prove use.",
  );
  if (dependenciesOmitted > 0) notes.push(`${dependenciesOmitted} further declared dependencies were omitted (cap ${MAX_DECLARED_DEPENDENCIES}).`);
  for (const failure of parseFailures.slice(0, 20)) notes.push(`Manifest not parsed: ${failure}`);
  if (parseFailures.length > 20) notes.push(`${parseFailures.length - 20} more manifests could not be parsed.`);
  notes.push("Subsystems are Cargo workspace members, package.json workspaces and directories containing a package manifest; only exact paths and a trailing '/*' are expanded.");
  for (const problem of memberProblems.slice(0, 20)) notes.push(`Workspace member: ${problem}`);
  notes.push(
    `Entry points are heuristic: entry-point file names, GitHub Actions workflow files and token matches (for example 'Bun.serve(', 'app.listen(', 'fn main(') in the first ${MAX_ENTRY_READ_BYTES / 1024} KiB of candidate files. They are not a complete or verified list of attack surfaces.`,
  );
  if (entryScan.readLimitReached) notes.push("The entry-point read budget was exhausted; some candidates were listed by file name only.");
  if (walk.candidateLimitReached) notes.push(`More than ${MAX_CANDIDATE_FILES} entry-point candidate files exist; the rest were not considered.`);
  if (inventoryResult.ok) {
    notes.push("Lockfiles and the package total come from the core `sentra inventory` lockfile parsers.");
  } else {
    notes.push(`Lockfile inventory unavailable (sentra inventory): ${inventoryResult.error}. Lockfiles and the package total are empty in this report.`);
  }
  notes.push("Tool availability is a PATH lookup on the Sentra host; no tool was executed.");
  notes.push(`The bridge only read files; no project code was executed and nothing was written to the workspace. Computed in ${walkMs} ms.`);

  return {
    workspace: root,
    languages: languageResult.ok ? languageResult.value.languages : [],
    primaryLanguage: languageResult.ok ? languageResult.value.primaryLanguage : null,
    manifests: walk.manifests.map((manifest) => ({ path: manifest.path, kind: manifest.kind, ecosystem: manifest.ecosystem })),
    frameworks,
    subsystems,
    entrypoints: entryScan.entrypoints,
    lockfiles: inventoryResult.ok ? inventoryResult.value.lockfiles : [],
    packagesTotal: inventoryResult.ok ? inventoryResult.value.totalPackages : 0,
    tools: sources.tools(),
    notes,
  };
}

// ───────────────────────────── persistence ─────────────────────────────

export function saveTopologyReport(db: Database, report: TopologyReportView): void {
  db.query(
    `INSERT INTO recon_reports (report_id, tenant_id, workspace, kind, created_at, created_by, provider, model, content_json)
     VALUES (?, ?, ?, 'topology', ?, ?, NULL, NULL, ?)`,
  ).run(report.reportId, report.tenantId, report.workspace, report.createdAt, report.createdBy, JSON.stringify(report));
}

export function latestTopologyReport(db: Database, tenantId: string): TopologyReportView | null {
  const row = db
    .query(
      "SELECT content_json FROM recon_reports WHERE tenant_id = ? AND kind = 'topology' ORDER BY created_at DESC, rowid DESC LIMIT 1",
    )
    .get(tenantId) as { content_json: string } | null;
  if (!row) return null;
  const parsed = parseJsonColumn<TopologyReportView | null>(row.content_json, null);
  return parsed && typeof parsed.reportId === "string" ? parsed : null;
}

// ───────────────────────────── model grounding ─────────────────────────────

function capList<T>(items: readonly T[], max: number, render: (item: T) => string): string[] {
  const lines = items.slice(0, max).map(render);
  if (items.length > max) lines.push(`- (${items.length - max} more not shown)`);
  return lines.length ? lines : ["- (none found)"];
}

/**
 * Renders a topology report as plain text for a model prompt. Only report fields are used,
 * so every line is traceable to the persisted report.
 */
export function renderGroundedContext(report: TopologyReportView): string {
  const lines: string[] = [
    "Grounded workspace context (computed by Sentra)",
    `Source: topology report ${report.reportId}, computed ${report.createdAt} by reading workspace files (nothing was executed).`,
    "Generic architecture descriptions in the prompt above are template defaults and were not derived from this workspace; prefer the facts below.",
    "Entry points below are heuristic file-name/token matches, not confirmed attack surfaces.",
    "",
    `Primary language: ${report.primaryLanguage ?? "unknown"}`,
    "Languages (files by extension):",
    ...capList(report.languages, 20, (item) => `- ${item.language}: ${item.filesCount}`),
    "",
    "Manifests:",
    ...capList(report.manifests, 60, (item) => `- ${item.path} (${item.kind}${item.ecosystem ? `, ${item.ecosystem}` : ""})`),
    "",
    "Subsystems:",
    ...capList(report.subsystems, 60, (item) => `- ${item.name} at ${item.path} (${item.kind})`),
    "",
    "Heuristic entry points:",
    ...capList(report.entrypoints, 60, (item) => `- ${item.path} [${item.kind}]: ${item.evidence}`),
    "",
    "Declared direct dependencies:",
    ...capList(report.frameworks, 150, (item) => `- ${item.name}${item.version ? ` ${item.version}` : ""} (${item.manifest})`),
    "",
    `Lockfiles (${report.packagesTotal} packages in total):`,
    ...capList(
      report.lockfiles,
      30,
      (item) => `- ${item.path} (${item.kind}, ${item.packages} packages${item.parseError ? `, parse error: ${item.parseError}` : ""})`,
    ),
    "",
    "Limitations of this context:",
    ...report.notes.map((note) => `- ${note}`),
  ];
  const text = lines.join("\n");
  const maxChars = 48 * 1024;
  return text.length > maxChars ? `${text.slice(0, maxChars)}\n(context truncated at ${maxChars} characters)` : text;
}
