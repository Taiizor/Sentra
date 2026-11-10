import fs from "node:fs";
import path from "node:path";

/**
 * Reads git metadata directly from the `.git` directory without executing git. Running git
 * inside an untrusted workspace can trigger repository-controlled programs (fsmonitor,
 * hooks, filters), so the bridge only parses the small text files it needs.
 */

const MAX_META_BYTES = 256 * 1024;

function readSmall(file: string): string | null {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > MAX_META_BYTES) return null;
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/** Resolves the git directory for a work tree (supports `.git` files used by worktrees). */
export function findGitDir(workspace: string): string | null {
  const dotGit = path.join(workspace, ".git");
  let stat: fs.Stats;
  try {
    stat = fs.statSync(dotGit);
  } catch {
    return null;
  }
  if (stat.isDirectory()) return dotGit;
  const pointer = readSmall(dotGit);
  const match = pointer?.match(/^gitdir:\s*(.+)\s*$/m);
  if (!match) return null;
  const resolved = path.resolve(workspace, match[1].trim());
  return fs.existsSync(resolved) ? resolved : null;
}

function commonDir(gitDir: string): string {
  const pointer = readSmall(path.join(gitDir, "commondir"));
  return pointer ? path.resolve(gitDir, pointer.trim()) : gitDir;
}

export interface GitHeadInfo {
  branch: string | null;
  sha: string | null;
  detached: boolean;
}

function resolveRef(gitDir: string, ref: string): string | null {
  if (!/^refs\/[A-Za-z0-9._/-]+$/.test(ref) || ref.includes("..")) return null;
  for (const dir of [gitDir, commonDir(gitDir)]) {
    const loose = readSmall(path.join(dir, ...ref.split("/")));
    if (loose && /^[0-9a-f]{40,64}\s*$/.test(loose)) return loose.trim();
  }
  const packed = readSmall(path.join(commonDir(gitDir), "packed-refs"));
  if (packed) {
    for (const line of packed.split(/\r?\n/)) {
      const [sha, name] = line.split(" ");
      if (name === ref && /^[0-9a-f]{40,64}$/.test(sha)) return sha;
    }
  }
  return null;
}

export function readHead(workspace: string): GitHeadInfo | null {
  const gitDir = findGitDir(workspace);
  if (!gitDir) return null;
  const head = readSmall(path.join(gitDir, "HEAD"))?.trim();
  if (!head) return null;
  if (/^[0-9a-f]{40,64}$/.test(head)) return { branch: null, sha: head, detached: true };
  const match = head.match(/^ref:\s*(refs\/heads\/.+)$/);
  if (!match) return null;
  return { branch: match[1].slice("refs/heads/".length), sha: resolveRef(gitDir, match[1]), detached: false };
}

/** Returns the URL of a named remote from `.git/config`. */
export function readRemoteUrl(workspace: string, remote = "origin"): string | null {
  const gitDir = findGitDir(workspace);
  if (!gitDir) return null;
  const config = readSmall(path.join(commonDir(gitDir), "config"));
  if (!config) return null;
  let inSection = false;
  for (const rawLine of config.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("[")) {
      const section = line.match(/^\[remote\s+"([^"]+)"\]$/);
      inSection = !!section && section[1] === remote;
      continue;
    }
    if (!inSection) continue;
    const kv = line.match(/^url\s*=\s*(.+)$/);
    if (kv) return kv[1].trim();
  }
  return null;
}

export interface GitHubRepoRef {
  owner: string;
  repo: string;
}

const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

export function isValidRepoRef(ref: GitHubRepoRef): boolean {
  return OWNER_PATTERN.test(ref.owner) && REPO_PATTERN.test(ref.repo) && ref.repo !== "." && ref.repo !== "..";
}

/** Parses https/ssh GitHub remote URLs (github.com or a configured enterprise host). */
export function parseGitHubRemote(url: string, host = "github.com"): GitHubRepoRef | null {
  const escaped = host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [
    new RegExp(`^https?://(?:[^@/]+@)?${escaped}/([^/]+)/([^/]+?)(?:\\.git)?/?$`, "i"),
    new RegExp(`^ssh://git@${escaped}(?::\\d+)?/([^/]+)/([^/]+?)(?:\\.git)?/?$`, "i"),
    new RegExp(`^git@${escaped}:([^/]+)/([^/]+?)(?:\\.git)?$`, "i"),
  ];
  for (const pattern of patterns) {
    const match = url.trim().match(pattern);
    if (match) {
      const ref = { owner: match[1], repo: match[2] };
      return isValidRepoRef(ref) ? ref : null;
    }
  }
  return null;
}
