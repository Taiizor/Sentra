import type { Database } from "bun:sqlite";
import fs from "node:fs";
import path from "node:path";
import type {
  PrScanResultView,
  PrSecurityView,
  PrStatusRequest,
  SastMatchView,
  Severity,
} from "../../src/types/api.ts";
import { nowIso, parseJsonColumn } from "../db.ts";
import type { GitHubRepoRef } from "../git-meta.ts";
import type { GitHubService, PullRequestFile } from "../github.ts";
import { HttpError } from "../http-error.ts";
import { log } from "../logger.ts";
import { resolveInside } from "../paths.ts";
import { cliFailure, cliValue, type SentraCli } from "../sentra-cli.ts";
import type { ActorRef } from "./types.ts";

/**
 * Pull request SAST scans. The bridge never checks out or executes pull request code: it
 * downloads the full content of each changed file at the PR head commit through the GitHub
 * contents API, writes those files into a private temporary directory and runs the core's
 * line-based `sentra scan` over that directory only. Results are unverified candidates and
 * are stored per (repository, pr_number, head_sha) in the bridge database.
 */

export const PR_SCAN_LIMITS = {
  /** Changed files listed from GitHub per pull request. */
  maxListedFiles: 300,
  /** Files downloaded and written for one scan. */
  maxFiles: 200,
  maxFileBytes: 1024 * 1024,
  maxTotalBytes: 20 * 1024 * 1024,
  fetchConcurrency: 4,
} as const;

export type PrScanStatus = PrScanResultView["status"];
export type CommitState = PrStatusRequest["state"];

export interface SkippedFile {
  path: string;
  reason: string;
}

// ───────────────────────────── pure helpers ─────────────────────────────

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])$/i;

/**
 * Validates a repository-relative path reported by GitHub before it is written to disk.
 * Returns the reason it is unsafe, or null when it may be materialized. The rules are
 * conservative on every host (also Windows device names and reserved characters).
 */
export function prFilePathProblem(raw: string): string | null {
  if (typeof raw !== "string" || raw.length === 0) return "empty path";
  if (raw.length > 1024) return "path longer than 1024 characters";
  // oxlint-disable-next-line no-control-regex -- intentional: rejects changed-file paths that contain control characters
  if (/[\u0000-\u001f\u007f]/.test(raw)) return "path contains NUL or control characters";
  if (raw.startsWith("/") || raw.startsWith("\\")) return "absolute path";
  if (/^[A-Za-z]:/.test(raw)) return "drive-letter path";
  if (raw.includes("\\")) return "path contains a backslash";
  for (const segment of raw.split("/")) {
    if (segment.length === 0) return "path contains an empty segment";
    if (segment === "." || segment === "..") return "path contains a '.' or '..' segment";
    if (segment.length > 255) return "path segment longer than 255 characters";
    if (segment.toLowerCase() === ".git") return "path inside a .git directory";
    if (/[<>:"|?*]/.test(segment)) return "path segment contains characters reserved on Windows";
    if (/[. ]$/.test(segment)) return "path segment ends with a dot or space";
    if (WINDOWS_RESERVED.test(segment.split(".")[0])) return "path segment is a reserved device name";
  }
  return null;
}

/**
 * Splits the PR file list into files to download and files skipped up front (removed files,
 * unsafe paths, paths that would collide with another file on this host's filesystem).
 * `uncovered` counts the skipped files that still have content at the head commit, i.e. the
 * skips that leave part of the change unscanned (removed files do not).
 */
export function planPrFiles(
  files: readonly PullRequestFile[],
  caseInsensitive: boolean,
): { candidates: PullRequestFile[]; skipped: SkippedFile[]; nonRemoved: number; uncovered: number } {
  const candidates: PullRequestFile[] = [];
  const skipped: SkippedFile[] = [];
  const fileKeys = new Set<string>();
  const dirKeys = new Set<string>();
  let nonRemoved = 0;
  let uncovered = 0;
  const keyOf = (value: string) => (caseInsensitive ? value.toLowerCase() : value);
  for (const file of files) {
    if (file.status === "removed") {
      skipped.push({ path: file.filename, reason: "removed in this pull request (no content at the head commit)" });
      continue;
    }
    nonRemoved += 1;
    const problem = prFilePathProblem(file.filename);
    if (problem) {
      skipped.push({ path: file.filename, reason: `unsafe path: ${problem}` });
      uncovered += 1;
      continue;
    }
    const key = keyOf(file.filename);
    const parents: string[] = [];
    const segments = key.split("/");
    for (let index = 1; index < segments.length; index += 1) parents.push(segments.slice(0, index).join("/"));
    if (fileKeys.has(key) || dirKeys.has(key) || parents.some((parent) => fileKeys.has(parent))) {
      skipped.push({
        path: file.filename,
        reason: caseInsensitive
          ? "collides with another changed path on this host's case-insensitive filesystem"
          : "collides with another changed path",
      });
      uncovered += 1;
      continue;
    }
    fileKeys.add(key);
    for (const parent of parents) dirKeys.add(parent);
    candidates.push(file);
  }
  return { candidates, skipped, nonRemoved, uncovered };
}

/** Returns why downloaded content cannot be scanned as text, or null. */
export function contentProblem(text: string): string | null {
  if (text.includes("\u0000")) return "binary content (contains NUL bytes)";
  return null;
}

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFORMATIONAL: "Informational",
  INFO: "Informational",
};

export function mapCoreSeverity(value: unknown): Severity {
  return typeof value === "string" ? (SEVERITY_MAP[value.toUpperCase()] ?? "Unknown") : "Unknown";
}

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Maps the `matches` array of `sentra scan --json` (keys as emitted by the core). */
export function mapScanMatches(raw: unknown): SastMatchView[] {
  if (!Array.isArray(raw)) return [];
  const matches: SastMatchView[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const match = item as Record<string, unknown>;
    const filePath = str(match.file_path);
    const line = typeof match.line_number === "number" && Number.isInteger(match.line_number) ? match.line_number : null;
    if (!filePath || line === null) continue;
    matches.push({
      ruleId: str(match.rule_id) ?? "unknown",
      ruleName: str(match.rule_name) ?? "unknown",
      cwe: str(match.cwe),
      severity: mapCoreSeverity(match.severity),
      category: str(match.category),
      filePath,
      line,
      snippet: typeof match.snippet === "string" ? match.snippet : null,
      rationale: str(match.rationale),
    });
  }
  return matches;
}

/**
 * Outcome of a PR scan. A scan only reads as clean or warnings (the states that can back a
 * `success` commit status) when every changed file with content at the head commit was handed
 * to the core scanner. A file left out by the bridge (download failure, size or file-count
 * limit, more changed files than are listed, unsafe or colliding path, write failure) makes the
 * result failed with the reason; a critical signal is still reported as critical. Files the core
 * scanner's own scope rules skip (vendored or build directories, binary formats) are treated as
 * they are in a workspace scan and do not count as gaps, unless the scanner evaluated nothing.
 */
export function derivePrScanStatus(input: {
  cliFailed: boolean;
  criticalCount: number;
  signalsFound: number;
  fetchFailures: number;
  filesScanned: number;
  eligibleFiles: number;
  /** Changed files with content at the head commit that the bridge did not hand to the scanner. */
  uncoveredFiles: number;
}): PrScanStatus {
  if (input.cliFailed) return "failed";
  if (input.criticalCount > 0) return "critical";
  if (input.fetchFailures > 0) return "failed";
  if (input.uncoveredFiles > 0) return "failed";
  if (input.eligibleFiles > 0 && input.filesScanned === 0) return "failed";
  if (input.signalsFound > 0) return "warnings";
  return "clean";
}

/**
 * Security state of a pull request from its stored scans: the scan of the current head when
 * one exists, otherwise the latest scan of an older head ('stale'), otherwise 'not_scanned'.
 */
export function prSecurityView(headSha: string, scans: readonly PrScanResultView[]): PrSecurityView {
  const exact = scans.find((scan) => scan.headSha === headSha) ?? null;
  const latest = exact ?? [...scans].sort((a, b) => b.scannedAt.localeCompare(a.scannedAt))[0] ?? null;
  if (!latest) {
    return {
      status: "not_scanned",
      scannedHeadSha: null,
      scannedAt: null,
      scannedBy: null,
      signalsFound: null,
      criticalCount: null,
      highCount: null,
      filesScanned: null,
      filesConsidered: null,
    };
  }
  return {
    status: exact ? exact.status : "stale",
    scannedHeadSha: latest.headSha,
    scannedAt: latest.scannedAt,
    scannedBy: latest.scannedBy,
    signalsFound: latest.signalsFound,
    criticalCount: latest.criticalCount,
    highCount: latest.highCount,
    filesScanned: latest.filesScanned,
    filesConsidered: latest.filesConsidered,
  };
}

/**
 * Commit states that the stored scan of the current head commit can back. The status is
 * published under the `sentra/security-scan` context, so it must not claim more than the
 * scan showed: success needs a clean (or admin-accepted warnings) scan of that exact commit.
 */
export function allowedCommitStates(scanAtHead: Pick<PrScanResultView, "status"> | null): CommitState[] {
  if (!scanAtHead) return ["pending"];
  switch (scanAtHead.status) {
    case "clean":
      return ["success", "pending"];
    case "warnings":
      return ["success", "failure", "pending"];
    case "critical":
      return ["failure", "pending"];
    case "failed":
      return ["error", "pending"];
  }
}

export function repositoryKey(ref: GitHubRepoRef): string {
  return `${ref.owner}/${ref.repo}`.toLowerCase();
}

// ───────────────────────────── persistence ─────────────────────────────

interface PrScanRow {
  repository: string;
  pr_number: number;
  head_sha: string;
  scanned_at: string;
  scanned_by: string;
  files_considered: number;
  files_scanned: number;
  signals_found: number;
  critical_count: number;
  high_count: number;
  status: PrScanStatus;
  matches_json: string;
  skipped_json: string;
  error: string | null;
}

function fromRow(row: PrScanRow): PrScanResultView {
  return {
    prNumber: row.pr_number,
    headSha: row.head_sha,
    status: row.status,
    filesConsidered: row.files_considered,
    filesScanned: row.files_scanned,
    skipped: parseJsonColumn<SkippedFile[]>(row.skipped_json, []),
    matches: parseJsonColumn<SastMatchView[]>(row.matches_json, []),
    signalsFound: row.signals_found,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    scannedAt: row.scanned_at,
    scannedBy: row.scanned_by,
    error: row.error,
  };
}

export function savePrScan(db: Database, repoKey: string, scan: PrScanResultView): void {
  db.query(
    `INSERT OR REPLACE INTO pr_scans (repository, pr_number, head_sha, scanned_at, scanned_by, files_considered, files_scanned,
       signals_found, critical_count, high_count, status, matches_json, skipped_json, error)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    repoKey,
    scan.prNumber,
    scan.headSha,
    scan.scannedAt,
    scan.scannedBy,
    scan.filesConsidered,
    scan.filesScanned,
    scan.signalsFound,
    scan.criticalCount,
    scan.highCount,
    scan.status,
    JSON.stringify(scan.matches),
    JSON.stringify(scan.skipped),
    scan.error,
  );
}

export function latestPrScan(db: Database, repoKey: string, prNumber: number): PrScanResultView | null {
  const row = db
    .query("SELECT * FROM pr_scans WHERE repository = ? AND pr_number = ? ORDER BY scanned_at DESC LIMIT 1")
    .get(repoKey, prNumber) as PrScanRow | null;
  return row ? fromRow(row) : null;
}

export function prScanAtHead(db: Database, repoKey: string, prNumber: number, headSha: string): PrScanResultView | null {
  const row = db
    .query("SELECT * FROM pr_scans WHERE repository = ? AND pr_number = ? AND head_sha = ?")
    .get(repoKey, prNumber, headSha) as PrScanRow | null;
  return row ? fromRow(row) : null;
}

/** Stored scans (without match/skip payloads) for the given pull requests, grouped by number. */
export function scansForPulls(db: Database, repoKey: string, prNumbers: readonly number[]): Map<number, PrScanResultView[]> {
  const grouped = new Map<number, PrScanResultView[]>();
  if (prNumbers.length === 0) return grouped;
  const wanted = new Set(prNumbers);
  const rows = db
    .query(
      `SELECT repository, pr_number, head_sha, scanned_at, scanned_by, files_considered, files_scanned, signals_found,
              critical_count, high_count, status, '[]' AS matches_json, '[]' AS skipped_json, error
       FROM pr_scans WHERE repository = ? ORDER BY scanned_at DESC`,
    )
    .all(repoKey) as PrScanRow[];
  for (const row of rows) {
    if (!wanted.has(row.pr_number)) continue;
    const list = grouped.get(row.pr_number) ?? [];
    list.push(fromRow(row));
    grouped.set(row.pr_number, list);
  }
  return grouped;
}

// ───────────────────────────── scan execution ─────────────────────────────

export interface PrScanDeps {
  github: Pick<GitHubService, "getPullRequest" | "listPullRequestFiles" | "fileAtRef">;
  cli: Pick<SentraCli, "run">;
  db: Database;
  /** Bridge-private scratch directory (config.tmpDir). */
  tmpDir: string;
  scanTimeoutMs: number;
  /** Defaults to the host filesystem's behaviour (Windows / macOS are case-insensitive). */
  caseInsensitiveFs?: boolean;
}

export interface PrScanInput {
  ref: GitHubRepoRef;
  prNumber: number;
  actor: ActorRef;
  signal?: AbortSignal;
}

const runningScans = new Set<string>();

function describeError(error: unknown): string {
  if (error instanceof HttpError) return `${error.code}: ${error.message}`;
  return error instanceof Error ? error.message : String(error);
}

/**
 * Downloads the changed files of a pull request at its head commit, scans them with the core
 * and persists the result. The temporary directory is always removed.
 */
export async function runPrScan(deps: PrScanDeps, input: PrScanInput): Promise<PrScanResultView> {
  const repoKey = repositoryKey(input.ref);
  const lockKey = `${repoKey}#${input.prNumber}`;
  if (runningScans.has(lockKey)) {
    throw new HttpError(409, "pr_scan_running", `A scan of pull request #${input.prNumber} is already running`);
  }
  runningScans.add(lockKey);
  try {
    return await scanPullRequest(deps, input, repoKey);
  } finally {
    runningScans.delete(lockKey);
  }
}

async function scanPullRequest(deps: PrScanDeps, input: PrScanInput, repoKey: string): Promise<PrScanResultView> {
  const { ref, prNumber } = input;
  const pr = await deps.github.getPullRequest(ref, prNumber);
  if (!/^[0-9a-f]{40}$/.test(pr.headSha)) {
    throw new HttpError(502, "github_request_failed", "GitHub returned an invalid head commit sha");
  }
  const files = await deps.github.listPullRequestFiles(ref, prNumber, PR_SCAN_LIMITS.maxListedFiles);
  const caseInsensitive = deps.caseInsensitiveFs ?? (process.platform === "win32" || process.platform === "darwin");
  const plan = planPrFiles(files, caseInsensitive);
  const skipped: SkippedFile[] = [...plan.skipped];
  let uncovered = plan.uncovered;
  if (pr.changedFiles !== null && pr.changedFiles > files.length) {
    skipped.push({
      path: `(${pr.changedFiles - files.length} further changed files)`,
      reason: `not listed: the bridge considers at most ${PR_SCAN_LIMITS.maxListedFiles} changed files per pull request`,
    });
    uncovered += pr.changedFiles - files.length;
  }

  fs.mkdirSync(deps.tmpDir, { recursive: true, mode: 0o700 });
  const workDir = fs.mkdtempSync(path.join(deps.tmpDir, "pr-scan-"));
  let materialized = 0;
  let totalBytes = 0;
  let fetchFailures = 0;
  try {
    const queue = [...plan.candidates];
    while (queue.length > 0) {
      if (input.signal?.aborted) throw new HttpError(499, "aborted", "The pull request scan was cancelled");
      if (materialized >= PR_SCAN_LIMITS.maxFiles || totalBytes >= PR_SCAN_LIMITS.maxTotalBytes) break;
      const batch = queue.splice(0, PR_SCAN_LIMITS.fetchConcurrency);
      const results = await Promise.all(
        batch.map(async (file) => {
          try {
            const content = await deps.github.fileAtRef(ref, file.filename, pr.headSha, { maxBytes: PR_SCAN_LIMITS.maxFileBytes });
            return { file, content, error: null as unknown };
          } catch (error) {
            return { file, content: null, error };
          }
        }),
      );
      for (const { file, content, error } of results) {
        if (error) {
          if (error instanceof HttpError && error.code === "upstream_too_large") {
            skipped.push({ path: file.filename, reason: `larger than ${PR_SCAN_LIMITS.maxFileBytes / (1024 * 1024)} MiB` });
            uncovered += 1;
          } else if (error instanceof HttpError && error.status === 412) {
            throw error;
          } else {
            fetchFailures += 1;
            skipped.push({ path: file.filename, reason: `could not be downloaded from GitHub (${describeError(error)})` });
          }
          continue;
        }
        if (content === null) {
          skipped.push({ path: file.filename, reason: "not present at the head commit (for example a submodule entry)" });
          continue;
        }
        const problem = contentProblem(content);
        if (problem) {
          skipped.push({ path: file.filename, reason: problem });
          continue;
        }
        const size = Buffer.byteLength(content, "utf8");
        if (materialized >= PR_SCAN_LIMITS.maxFiles) {
          skipped.push({ path: file.filename, reason: `file limit reached (${PR_SCAN_LIMITS.maxFiles} files per scan)` });
          uncovered += 1;
          continue;
        }
        if (totalBytes + size > PR_SCAN_LIMITS.maxTotalBytes) {
          skipped.push({
            path: file.filename,
            reason: `total size limit reached (${PR_SCAN_LIMITS.maxTotalBytes / (1024 * 1024)} MiB per scan)`,
          });
          uncovered += 1;
          continue;
        }
        try {
          // "./" keeps resolveInside from treating a leading "a/" or "b/" directory as a diff prefix.
          const target = resolveInside(workDir, `./${file.filename}`, "file");
          if (target.relative !== file.filename) {
            skipped.push({ path: file.filename, reason: "path does not round-trip on this host's filesystem" });
            uncovered += 1;
            continue;
          }
          fs.mkdirSync(path.dirname(target.absolute), { recursive: true, mode: 0o700 });
          fs.writeFileSync(target.absolute, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
          materialized += 1;
          totalBytes += size;
        } catch (writeError) {
          skipped.push({ path: file.filename, reason: `could not be written on this host (${describeError(writeError)})` });
          uncovered += 1;
        }
      }
    }
    uncovered += queue.length;
    for (const file of queue) {
      skipped.push({
        path: file.filename,
        reason:
          materialized >= PR_SCAN_LIMITS.maxFiles
            ? `file limit reached (${PR_SCAN_LIMITS.maxFiles} files per scan)`
            : `total size limit reached (${PR_SCAN_LIMITS.maxTotalBytes / (1024 * 1024)} MiB per scan)`,
      });
    }

    let matches: SastMatchView[] = [];
    let filesScanned = 0;
    let signalsFound = 0;
    let cliError: string | null = null;
    if (materialized > 0) {
      const result = await deps.cli.run(["scan", "--workspace", cliValue(workDir, "workspace"), "--json"], {
        timeoutMs: deps.scanTimeoutMs,
        signal: input.signal,
      });
      const doc = result.json as Record<string, unknown> | undefined;
      if (result.timedOut) {
        cliError = "sentra scan timed out";
      } else if (result.code !== 0 || !doc || doc.command !== "scan" || typeof doc.files_scanned !== "number") {
        cliError = cliFailure("scan", result).message;
      } else {
        matches = mapScanMatches(doc.matches);
        filesScanned = doc.files_scanned;
        signalsFound = typeof doc.signals_found === "number" ? doc.signals_found : matches.length;
      }
    }

    const criticalCount = matches.filter((match) => match.severity === "Critical").length;
    const highCount = matches.filter((match) => match.severity === "High").length;
    const eligibleFiles = plan.nonRemoved;
    const status = derivePrScanStatus({
      cliFailed: cliError !== null,
      criticalCount,
      signalsFound,
      fetchFailures,
      filesScanned,
      eligibleFiles,
      uncoveredFiles: uncovered,
    });
    let error: string | null = cliError;
    if (!error && status === "failed") {
      error =
        fetchFailures > 0
          ? `${fetchFailures} changed file(s) could not be downloaded from GitHub; the result does not cover them`
          : uncovered > 0
            ? `Incomplete coverage: ${uncovered} changed file(s) with content at the head commit were not scanned (see the skipped list). A partial scan cannot read as clean or warnings; ${signalsFound} candidate signal(s) were found in the ${filesScanned} scanned file(s).`
            : materialized === 0
            ? "No changed file could be scanned: every file was skipped (see the skipped list)"
            : `The core scanner evaluated none of the ${materialized} downloaded file(s) (it ignores some directories, extensions and non-UTF-8 content)`;
    }
    const view: PrScanResultView = {
      prNumber,
      headSha: pr.headSha,
      status,
      filesConsidered: files.length,
      filesScanned,
      skipped,
      matches,
      signalsFound,
      criticalCount,
      highCount,
      scannedAt: nowIso(),
      scannedBy: input.actor.label,
      error,
    };
    savePrScan(deps.db, repoKey, view);
    return view;
  } finally {
    try {
      fs.rmSync(workDir, { recursive: true, force: true, maxRetries: 3 });
    } catch (cleanupError) {
      log.warn("failed to remove pull request scan directory", { dir: workDir, error: String(cleanupError) });
    }
  }
}
