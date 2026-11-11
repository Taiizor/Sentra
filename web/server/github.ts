import crypto from "node:crypto";
import { HttpError } from "./http-error.ts";
import { log } from "./logger.ts";
import { fetchWithLimits } from "./net-guard.ts";
import type { SecretStore } from "./secrets.ts";
import { envValue, findOnProcessPathForExecution } from "./executables.ts";
import { isValidRepoRef, type GitHubRepoRef } from "./git-meta.ts";

/**
 * Real GitHub access through the REST and GraphQL APIs. Credentials are resolved from, in
 * order: a PAT stored (encrypted) by an admin in the console, GITHUB_TOKEN/GH_TOKEN, or the
 * local GitHub CLI session (`gh auth token`). There is no simulated fallback: without a
 * credential every GitHub feature reports "not configured".
 */

export type GitHubAuthSource = "stored_pat" | "env_token" | "gh_cli";

export interface GitHubAuth {
  source: GitHubAuthSource;
  token: string;
}

export const GITHUB_PAT_SECRET = "github.pat";

const API_BASE = (process.env.SENTRA_GITHUB_API_URL ?? "https://api.github.com").replace(/\/+$/, "");
const GRAPHQL_URL = API_BASE.endsWith("/api/v3") ? `${API_BASE.slice(0, -3)}graphql` : `${API_BASE}/graphql`;
export const GITHUB_WEB_HOST = API_BASE === "https://api.github.com" ? "github.com" : new URL(API_BASE).host;

/** Time `gh auth token` may take before it is killed; it only reads local config or the OS credential store. */
export const GH_TOKEN_TIMEOUT_MS = 5_000;

/**
 * Variables `gh auth token` may see: what it needs to find its configuration and the OS credential
 * store (Windows Credential Manager, macOS Keychain, the Secret Service over D-Bus on Linux).
 * The bridge's own secrets (SENTRA_WEB_SECRET_KEY, SENTRA_WEB_TOKENS, webhook secrets) are never
 * passed.
 */
const GH_ENV_ALLOWLIST = [
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "WINDIR",
  "TEMP",
  "TMP",
  "TMPDIR",
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "USER",
  "LOGNAME",
  "LANG",
  "LC_ALL",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_STATE_HOME",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "GH_CONFIG_DIR",
];

/** Allow-listed environment for `gh auth token` (prompts, colour and update checks disabled). */
export function ghEnvironment(
  source: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  const env: Record<string, string> = { GH_PROMPT_DISABLED: "1", GH_NO_UPDATE_NOTIFIER: "1", NO_COLOR: "1" };
  for (const name of GH_ENV_ALLOWLIST) {
    const value = envValue(source, name, platform);
    if (value !== undefined) env[name] = value;
  }
  return env;
}

/** Default cap for REST/GraphQL response bodies. */
const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
/** Upper bound of open pull requests read per listing (10 GraphQL pages of 100). */
const MAX_PULL_PAGES = 10;
const VIEWER_CACHE_MS = 60_000;
const PULL_CACHE_MS = 30_000;

/** Signature of the outbound HTTP helper; injectable so tests never touch the network. */
export type GitHubFetcher = (
  input: string,
  init: RequestInit & { timeoutMs?: number; maxResponseBytes?: number },
) => Promise<{ status: number; ok: boolean; headers: Headers; text: string }>;

export interface GitHubServiceOptions {
  fetcher?: GitHubFetcher;
  /** Replaces `gh auth token` discovery (tests, or hosts where gh must not be consulted). */
  ghTokenReader?: () => string | null;
  /**
   * gh executable pinned by the host operator (SENTRA_GH_BIN, validated by loadConfig). When set it
   * is the only gh ever run: locateGh is not consulted, so there is no silent fallback to another
   * gh. Paths set in the web console are never passed here.
   */
  ghBin?: string | null;
  /**
   * Absolute path of the gh executable to run, or null when none qualifies. Defaults to the bridge
   * process PATH only; the app passes the locator's execution lookup (process PATH and persisted
   * PATH, never standard install locations).
   */
  locateGh?: () => string | null;
  /** Timeout for `gh auth token` (default GH_TOKEN_TIMEOUT_MS). */
  ghTimeoutMs?: number;
}

export interface GitHubViewer {
  login: string;
  /** Classic-token scopes from `X-OAuth-Scopes`; null for fine-grained or app tokens. */
  scopes: string | null;
}

export interface PullRequestSummary {
  number: number;
  title: string;
  state: "open";
  isDraft: boolean;
  author: { login: string; avatarUrl: string | null };
  headRef: string;
  headSha: string;
  baseRef: string;
  htmlUrl: string;
  createdAt: string;
  updatedAt: string;
  filesCount: number;
  additions: number;
  deletions: number;
  checks: { total: number; successful: number; failed: number; inProgress: number; rollupState: string | null };
}

export interface PullRequestDetails {
  number: number;
  state: string;
  title: string;
  htmlUrl: string;
  headSha: string;
  headRef: string;
  headRepoFullName: string | null;
  baseRef: string;
  isFork: boolean;
  changedFiles: number | null;
}

export interface WorkflowStepView {
  number: number;
  name: string;
  status: string;
  conclusion: string | null;
  startedAt: string | null;
  completedAt: string | null;
  durationSeconds: number | null;
}

export interface WorkflowJobView {
  id: number;
  name: string;
  status: string;
  conclusion: string | null;
  htmlUrl: string | null;
  startedAt: string | null;
  completedAt: string | null;
  steps: WorkflowStepView[];
}

export interface WorkflowRunView {
  id: number;
  name: string;
  workflowPath: string;
  event: string;
  status: string;
  conclusion: string | null;
  htmlUrl: string;
  headSha: string;
  headBranch: string | null;
  runNumber: number;
  runAttempt: number;
  createdAt: string;
  runStartedAt: string | null;
  updatedAt: string;
  jobs: WorkflowJobView[];
}

export interface PullRequestFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  previousFilename: string | null;
}

function seconds(start: string | null, end: string | null): number | null {
  if (!start || !end) return null;
  const delta = (Date.parse(end) - Date.parse(start)) / 1000;
  return Number.isFinite(delta) && delta >= 0 ? Math.round(delta) : null;
}

const TOKEN_PREFIXES = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] as const;

/**
 * Checks that a value looks like a GitHub token before it is sent anywhere. Returns a
 * human-readable reason when it does not, or null when the shape is acceptable. The shape
 * check is not a validity check: the token is verified against GitHub before it is stored.
 */
export function githubTokenShapeError(token: string): string | null {
  if (token.length === 0) return "The token is empty";
  if (token.length > 255) return "The token is longer than 255 characters";
  if (/\s/.test(token)) return "The token must not contain whitespace";
  const prefix = TOKEN_PREFIXES.find((candidate) => token.startsWith(candidate));
  if (!prefix) return `The token must start with one of: ${TOKEN_PREFIXES.join(", ")}`;
  const rest = token.slice(prefix.length);
  if (rest.length < 16) return "The token is too short to be a GitHub token";
  if (!/^[A-Za-z0-9_]+$/.test(rest)) return "The token contains characters GitHub tokens never use";
  return null;
}

/** Maps a non-2xx GitHub response to an HttpError that cannot be confused with a console 401. */
function githubError(status: number, message: string): HttpError {
  const [httpStatus, code] =
    status === 401
      ? [502, "github_auth_failed"]
      : status === 403
        ? [403, "github_forbidden"]
        : status === 404
          ? [404, "github_not_found"]
          : status === 409 || status === 422
            ? [409, "github_conflict"]
            : [502, "github_request_failed"];
  return new HttpError(httpStatus, code, message, { githubStatus: status });
}

function errorMessageFrom(text: string): string | null {
  try {
    const parsed = JSON.parse(text) as { message?: unknown };
    return typeof parsed.message === "string" ? parsed.message.slice(0, 300) : null;
  } catch {
    return null;
  }
}

export class GitHubService {
  private ghCache: { token: string | null; at: number; ghPath: string | null } | null = null;
  private readonly pullCache = new Map<string, { at: number; data: PullRequestSummary[] }>();
  private readonly viewerCache = new Map<string, { at: number; viewer: GitHubViewer }>();
  private readonly secrets: SecretStore;
  private readonly envToken: string | null;
  private readonly ghCwd: string;
  private readonly fetcher: GitHubFetcher;
  private readonly ghTokenReader: (() => string | null) | null;
  private readonly ghBin: string | null;
  private readonly locateGh: () => string | null;
  private readonly ghTimeoutMs: number;

  constructor(secrets: SecretStore, envToken: string | null, ghCwd: string, options: GitHubServiceOptions = {}) {
    this.secrets = secrets;
    this.envToken = envToken;
    this.ghCwd = ghCwd;
    this.fetcher = options.fetcher ?? fetchWithLimits;
    this.ghTokenReader = options.ghTokenReader ?? null;
    this.ghBin = options.ghBin ?? null;
    this.locateGh = options.locateGh ?? (() => findOnProcessPathForExecution("gh"));
    this.ghTimeoutMs = options.ghTimeoutMs ?? GH_TOKEN_TIMEOUT_MS;
  }

  /**
   * Reads `gh auth token` (cached for five minutes, and read again when a different gh is
   * located). Runs outside any workspace, with an allow-listed environment and a timeout. On
   * Windows only a .exe/.com is started, never a batch script (which would run through cmd.exe).
   * The gh run is SENTRA_GH_BIN when set, else the locator's execution choice.
   */
  private ghCliToken(): string | null {
    const now = Date.now();
    const gh = this.ghTokenReader ? null : (this.ghBin ?? this.locateGh());
    if (this.ghCache && now - this.ghCache.at < 5 * 60_000 && this.ghCache.ghPath === gh) return this.ghCache.token;
    let token: string | null = null;
    if (this.ghTokenReader) {
      token = this.ghTokenReader();
    } else if (gh && process.platform === "win32" && !/\.(exe|com)$/i.test(gh)) {
      log.warn("the located gh is not a Windows executable; it is not started", { path: gh });
    } else {
      if (gh) {
        try {
          const proc = Bun.spawnSync([gh, "auth", "token", "--hostname", GITHUB_WEB_HOST], {
            cwd: this.ghCwd,
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
            windowsHide: true,
            env: ghEnvironment(),
            timeout: this.ghTimeoutMs,
            killSignal: "SIGKILL",
            maxBuffer: 64 * 1024,
          });
          if (proc.exitedDueToTimeout) {
            log.warn("gh auth token did not finish in time and was stopped", { path: gh, timeoutMs: this.ghTimeoutMs });
          } else {
            const out = proc.stdout.toString().trim();
            if (proc.exitCode === 0 && /^[A-Za-z0-9_]{20,255}$/.test(out)) token = out;
          }
        } catch (error) {
          log.warn("gh auth token failed", { error: String(error) });
        }
      }
    }
    this.ghCache = { token, at: now, ghPath: gh };
    return token;
  }

  resolveAuth(): GitHubAuth | null {
    const stored = this.secrets.get(GITHUB_PAT_SECRET);
    if (stored) return { source: "stored_pat", token: stored };
    if (this.envToken) return { source: "env_token", token: this.envToken };
    const gh = this.ghCliToken();
    if (gh) return { source: "gh_cli", token: gh };
    return null;
  }

  invalidateCaches(): void {
    this.ghCache = null;
    this.pullCache.clear();
    this.viewerCache.clear();
  }

  private requireAuth(): GitHubAuth {
    const auth = this.resolveAuth();
    if (!auth) {
      throw new HttpError(
        412,
        "github_not_configured",
        "No GitHub credential is available. Sign in with `gh auth login`, set GITHUB_TOKEN, or store a token in Settings.",
      );
    }
    return auth;
  }

  async rest<T = unknown>(
    method: string,
    apiPath: string,
    body?: unknown,
    options: { auth?: GitHubAuth; accept?: string; allow404?: boolean; maxResponseBytes?: number } = {},
  ): Promise<T | null> {
    const auth = options.auth ?? this.requireAuth();
    const response = await this.fetcher(`${API_BASE}${apiPath}`, {
      method,
      redirect: "follow",
      timeoutMs: 30_000,
      maxResponseBytes: options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      headers: {
        Authorization: `Bearer ${auth.token}`,
        Accept: options.accept ?? "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sentra-web-bridge",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (response.status === 404 && options.allow404) return null;
    if (!response.ok) {
      const detail = errorMessageFrom(response.text);
      const base = `GitHub API ${method} ${apiPath.split("?")[0]} failed with HTTP ${response.status}`;
      throw githubError(response.status, detail ? `${base}: ${detail}` : base);
    }
    // Raw media types return file bytes; an empty file is an empty string, not "missing".
    if (options.accept && !options.accept.includes("json")) return response.text as T;
    if (!response.text) return null;
    return JSON.parse(response.text) as T;
  }

  async graphql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    const auth = this.requireAuth();
    const response = await this.fetcher(GRAPHQL_URL, {
      method: "POST",
      redirect: "follow",
      timeoutMs: 30_000,
      maxResponseBytes: 16 * 1024 * 1024,
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
        "User-Agent": "sentra-web-bridge",
      },
      body: JSON.stringify({ query, variables }),
    });
    let parsed: { data?: T; errors?: { message: string }[] };
    try {
      parsed = JSON.parse(response.text);
    } catch {
      throw githubError(response.ok ? 502 : response.status, `GitHub GraphQL returned HTTP ${response.status}`);
    }
    if (!response.ok) {
      const detail = errorMessageFrom(response.text);
      throw githubError(response.status, `GitHub GraphQL failed with HTTP ${response.status}${detail ? `: ${detail}` : ""}`);
    }
    if (parsed.errors?.length || !parsed.data) {
      const message = parsed.errors?.map((error) => error.message).join("; ") ?? "empty response";
      throw new HttpError(502, "github_request_failed", `GitHub GraphQL error: ${message}`);
    }
    return parsed.data;
  }

  /**
   * The account behind a credential (`GET /user`). With an explicit `auth` the call verifies
   * that specific token and bypasses the cache; otherwise the resolved credential is used.
   */
  async viewer(auth?: GitHubAuth): Promise<GitHubViewer> {
    const effective = auth ?? this.requireAuth();
    const cacheKey = crypto.createHash("sha256").update(effective.token).digest("hex");
    if (!auth) {
      const cached = this.viewerCache.get(cacheKey);
      if (cached && Date.now() - cached.at < VIEWER_CACHE_MS) return cached.viewer;
    }
    const response = await this.fetcher(`${API_BASE}/user`, {
      method: "GET",
      redirect: "follow",
      timeoutMs: 15_000,
      maxResponseBytes: 1024 * 1024,
      headers: {
        Authorization: `Bearer ${effective.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sentra-web-bridge",
      },
    });
    if (!response.ok) {
      const detail = errorMessageFrom(response.text);
      throw githubError(response.status, `GitHub rejected the credential (HTTP ${response.status}${detail ? `: ${detail}` : ""})`);
    }
    let login: unknown;
    try {
      login = (JSON.parse(response.text) as { login?: unknown }).login;
    } catch {
      login = undefined;
    }
    if (typeof login !== "string" || login.length === 0) {
      throw new HttpError(502, "github_request_failed", "GitHub returned a /user response without a login");
    }
    const viewer: GitHubViewer = { login, scopes: response.headers.get("x-oauth-scopes") };
    this.viewerCache.set(cacheKey, { at: Date.now(), viewer });
    return viewer;
  }

  async repository(ref: GitHubRepoRef): Promise<{
    fullName: string;
    private: boolean;
    defaultBranch: string;
    htmlUrl: string;
    permissions: Record<string, boolean> | null;
  }> {
    assertRepo(ref);
    const repo = await this.rest<{
      full_name: string;
      private: boolean;
      default_branch: string;
      html_url: string;
      permissions?: Record<string, boolean>;
    }>("GET", `/repos/${ref.owner}/${ref.repo}`);
    if (!repo) throw new HttpError(404, "github_repo_not_found", "Repository not found");
    return {
      fullName: repo.full_name,
      private: repo.private,
      defaultBranch: repo.default_branch,
      htmlUrl: repo.html_url,
      permissions: repo.permissions ?? null,
    };
  }

  async listOpenPullRequests(ref: GitHubRepoRef, useCache = true): Promise<PullRequestSummary[]> {
    return (await this.listOpenPullRequestsWithMeta(ref, useCache)).pulls;
  }

  /** Open pull requests plus the time they were actually fetched from GitHub (cache aware). */
  async listOpenPullRequestsWithMeta(
    ref: GitHubRepoRef,
    useCache = true,
  ): Promise<{ pulls: PullRequestSummary[]; fetchedAt: string }> {
    assertRepo(ref);
    const key = `${ref.owner}/${ref.repo}`.toLowerCase();
    const cached = this.pullCache.get(key);
    if (useCache && cached && Date.now() - cached.at < PULL_CACHE_MS) {
      return { pulls: cached.data, fetchedAt: new Date(cached.at).toISOString() };
    }
    type CheckNode =
      | { __typename: "CheckRun"; status: string; conclusion: string | null }
      | { __typename: "StatusContext"; state: string };
    type PullNode = {
      number: number;
      title: string;
      isDraft: boolean;
      url: string;
      createdAt: string;
      updatedAt: string;
      additions: number;
      deletions: number;
      changedFiles: number;
      headRefName: string;
      headRefOid: string;
      baseRefName: string;
      author: { login: string; avatarUrl: string } | null;
      commits: {
        nodes: { commit: { statusCheckRollup: { state: string; contexts: { nodes: CheckNode[] } } | null } }[];
      };
    };
    const nodes: PullNode[] = [];
    let after: string | null = null;
    for (let page = 0; page < MAX_PULL_PAGES; page += 1) {
      const data: {
        repository: {
          pullRequests: { pageInfo: { hasNextPage: boolean; endCursor: string | null }; nodes: PullNode[] };
        } | null;
      } = await this.graphql(
        `query($owner: String!, $name: String!, $after: String) {
          repository(owner: $owner, name: $name) {
            pullRequests(states: OPEN, first: 100, after: $after, orderBy: { field: UPDATED_AT, direction: DESC }) {
              pageInfo { hasNextPage endCursor }
              nodes {
                number title isDraft url createdAt updatedAt additions deletions changedFiles
                headRefName headRefOid baseRefName
                author { login avatarUrl }
                commits(last: 1) { nodes { commit { statusCheckRollup { state contexts(first: 100) { nodes {
                  __typename
                  ... on CheckRun { status conclusion }
                  ... on StatusContext { state }
                } } } } } }
              }
            }
          }
        }`,
        { owner: ref.owner, name: ref.repo, after },
      );
      if (!data.repository) throw new HttpError(404, "github_repo_not_found", `Repository ${key} not found or not accessible`);
      nodes.push(...data.repository.pullRequests.nodes);
      const info = data.repository.pullRequests.pageInfo;
      if (!info.hasNextPage || !info.endCursor) break;
      if (page === MAX_PULL_PAGES - 1) {
        log.warn("open pull request listing truncated", { repository: key, listed: nodes.length });
      }
      after = info.endCursor;
    }
    const pulls = nodes.map((pr): PullRequestSummary => {
      const rollup = pr.commits.nodes[0]?.commit.statusCheckRollup ?? null;
      const checks = { total: 0, successful: 0, failed: 0, inProgress: 0, rollupState: rollup?.state ?? null };
      for (const node of rollup?.contexts.nodes ?? []) {
        checks.total += 1;
        if (node.__typename === "CheckRun") {
          if (node.status !== "COMPLETED") checks.inProgress += 1;
          else if (["SUCCESS", "NEUTRAL", "SKIPPED"].includes(node.conclusion ?? "")) checks.successful += 1;
          else checks.failed += 1;
        } else if (node.state === "SUCCESS") checks.successful += 1;
        else if (node.state === "FAILURE" || node.state === "ERROR") checks.failed += 1;
        else checks.inProgress += 1;
      }
      return {
        number: pr.number,
        title: pr.title,
        state: "open",
        isDraft: pr.isDraft,
        author: { login: pr.author?.login ?? "ghost", avatarUrl: pr.author?.avatarUrl ?? null },
        headRef: pr.headRefName,
        headSha: pr.headRefOid,
        baseRef: pr.baseRefName,
        htmlUrl: pr.url,
        createdAt: pr.createdAt,
        updatedAt: pr.updatedAt,
        filesCount: pr.changedFiles,
        additions: pr.additions,
        deletions: pr.deletions,
        checks,
      };
    });
    const at = Date.now();
    this.pullCache.set(key, { at, data: pulls });
    return { pulls, fetchedAt: new Date(at).toISOString() };
  }

  async getPullRequest(ref: GitHubRepoRef, number: number): Promise<PullRequestDetails> {
    assertRepo(ref);
    assertPullNumber(number);
    const pr = await this.rest<{
      number: number;
      state: string;
      title: string;
      html_url: string;
      changed_files?: number;
      head: { sha: string; ref: string; repo: { full_name: string } | null };
      base: { ref: string; repo: { full_name: string } };
    }>("GET", `/repos/${ref.owner}/${ref.repo}/pulls/${number}`, undefined, { allow404: true });
    if (!pr) throw new HttpError(404, "github_pr_not_found", `Pull request #${number} was not found in ${ref.owner}/${ref.repo}`);
    const headRepo = pr.head.repo?.full_name ?? null;
    return {
      number: pr.number,
      state: pr.state,
      title: pr.title,
      htmlUrl: pr.html_url,
      headSha: pr.head.sha,
      headRef: pr.head.ref,
      headRepoFullName: headRepo,
      baseRef: pr.base.ref,
      isFork: headRepo !== null && headRepo.toLowerCase() !== pr.base.repo.full_name.toLowerCase(),
      changedFiles: typeof pr.changed_files === "number" ? pr.changed_files : null,
    };
  }

  async listPullRequestFiles(ref: GitHubRepoRef, number: number, maxFiles = 300): Promise<PullRequestFile[]> {
    assertRepo(ref);
    assertPullNumber(number);
    const files: PullRequestFile[] = [];
    for (let page = 1; files.length < maxFiles && page <= 30; page += 1) {
      const batch = await this.rest<
        { filename: string; status: string; additions: number; deletions: number; changes: number; previous_filename?: string }[]
      >("GET", `/repos/${ref.owner}/${ref.repo}/pulls/${number}/files?per_page=100&page=${page}`);
      if (!batch || batch.length === 0) break;
      for (const file of batch) {
        files.push({
          filename: file.filename,
          status: file.status,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes,
          previousFilename: file.previous_filename ?? null,
        });
      }
      if (batch.length < 100) break;
    }
    return files.slice(0, maxFiles);
  }

  /**
   * Raw file content at a commit, or null when the path does not exist at that ref. With
   * `maxBytes`, larger files fail with HttpError code `upstream_too_large`.
   */
  async fileAtRef(ref: GitHubRepoRef, filePath: string, gitRef: string, options: { maxBytes?: number } = {}): Promise<string | null> {
    assertRepo(ref);
    const encoded = filePath.split("/").map(encodeURIComponent).join("/");
    return this.rest<string>("GET", `/repos/${ref.owner}/${ref.repo}/contents/${encoded}?ref=${encodeURIComponent(gitRef)}`, undefined, {
      accept: "application/vnd.github.raw",
      allow404: true,
      maxResponseBytes: options.maxBytes,
    });
  }

  async workflowRunsForCommit(ref: GitHubRepoRef, sha: string, maxRuns = 10): Promise<WorkflowRunView[]> {
    assertRepo(ref);
    if (!/^[0-9a-f]{40}$/.test(sha)) throw new HttpError(400, "invalid_request", "head sha must be a 40-character hex digest");
    const runs = await this.rest<{
      workflow_runs: {
        id: number;
        name: string | null;
        path: string;
        event: string;
        status: string;
        conclusion: string | null;
        html_url: string;
        head_sha: string;
        head_branch: string | null;
        run_number: number;
        run_attempt: number;
        created_at: string;
        run_started_at: string | null;
        updated_at: string;
      }[];
    }>("GET", `/repos/${ref.owner}/${ref.repo}/actions/runs?head_sha=${sha}&per_page=${maxRuns}`);
    const result: WorkflowRunView[] = [];
    for (const run of runs?.workflow_runs ?? []) {
      const jobs = await this.rest<{
        jobs: {
          id: number;
          name: string;
          status: string;
          conclusion: string | null;
          html_url: string | null;
          started_at: string | null;
          completed_at: string | null;
          steps?: { number: number; name: string; status: string; conclusion: string | null; started_at: string | null; completed_at: string | null }[];
        }[];
      }>("GET", `/repos/${ref.owner}/${ref.repo}/actions/runs/${run.id}/jobs?per_page=100`);
      result.push({
        id: run.id,
        name: run.name ?? run.path,
        workflowPath: run.path,
        event: run.event,
        status: run.status,
        conclusion: run.conclusion,
        htmlUrl: run.html_url,
        headSha: run.head_sha,
        headBranch: run.head_branch,
        runNumber: run.run_number,
        runAttempt: run.run_attempt,
        createdAt: run.created_at,
        runStartedAt: run.run_started_at,
        updatedAt: run.updated_at,
        jobs: (jobs?.jobs ?? []).map((job) => ({
          id: job.id,
          name: job.name,
          status: job.status,
          conclusion: job.conclusion,
          htmlUrl: job.html_url,
          startedAt: job.started_at,
          completedAt: job.completed_at,
          steps: (job.steps ?? []).map((step) => ({
            number: step.number,
            name: step.name,
            status: step.status,
            conclusion: step.conclusion,
            startedAt: step.started_at,
            completedAt: step.completed_at,
            durationSeconds: seconds(step.started_at, step.completed_at),
          })),
        })),
      });
    }
    return result;
  }

  async postIssueComment(ref: GitHubRepoRef, number: number, body: string): Promise<{ id: number; htmlUrl: string }> {
    assertRepo(ref);
    assertPullNumber(number);
    const comment = await this.rest<{ id: number; html_url: string }>(
      "POST",
      `/repos/${ref.owner}/${ref.repo}/issues/${number}/comments`,
      { body },
    );
    if (!comment || typeof comment.id !== "number" || typeof comment.html_url !== "string") {
      throw new HttpError(502, "github_request_failed", "GitHub returned an unexpected comment response");
    }
    return { id: comment.id, htmlUrl: comment.html_url };
  }

  async createCommitStatus(
    ref: GitHubRepoRef,
    sha: string,
    state: "success" | "failure" | "pending" | "error",
    description: string,
    targetUrl?: string,
  ): Promise<void> {
    assertRepo(ref);
    if (!/^[0-9a-f]{40}$/.test(sha)) throw new HttpError(400, "invalid_request", "commit sha must be a 40-character hex digest");
    await this.rest("POST", `/repos/${ref.owner}/${ref.repo}/statuses/${sha}`, {
      state,
      context: "sentra/security-scan",
      description: description.slice(0, 140),
      ...(targetUrl ? { target_url: targetUrl } : {}),
    });
  }

  /**
   * Publishes a single-file change as a new branch plus draft pull request. The caller supplies
   * the full patched content computed against `baseSha`; nothing is force-pushed and an
   * existing branch is never overwritten. The branch is deleted again if PR creation fails.
   */
  async createSingleFilePullRequest(
    ref: GitHubRepoRef,
    input: {
      baseBranch: string;
      baseSha: string;
      branchName: string;
      filePath: string;
      blobSha: string;
      newContent: string;
      commitMessage: string;
      title: string;
      body: string;
    },
  ): Promise<{ number: number; htmlUrl: string; commitSha: string }> {
    assertRepo(ref);
    const auth = this.requireAuth();
    const encodedPath = input.filePath.split("/").map(encodeURIComponent).join("/");
    const encodedBranch = input.branchName.split("/").map(encodeURIComponent).join("/");
    await this.rest("POST", `/repos/${ref.owner}/${ref.repo}/git/refs`, { ref: `refs/heads/${input.branchName}`, sha: input.baseSha }, { auth });
    try {
      const commit = await this.rest<{ commit: { sha: string } }>(
        "PUT",
        `/repos/${ref.owner}/${ref.repo}/contents/${encodedPath}`,
        {
          message: input.commitMessage,
          content: Buffer.from(input.newContent, "utf8").toString("base64"),
          sha: input.blobSha,
          branch: input.branchName,
        },
        { auth },
      );
      const pr = await this.rest<{ number: number; html_url: string }>(
        "POST",
        `/repos/${ref.owner}/${ref.repo}/pulls`,
        { title: input.title, head: input.branchName, base: input.baseBranch, body: input.body, draft: true },
        { auth },
      );
      if (!pr || !commit) throw new HttpError(502, "github_request_failed", "GitHub returned an empty response");
      this.pullCache.clear();
      return { number: pr.number, htmlUrl: pr.html_url, commitSha: commit.commit.sha };
    } catch (error) {
      await this.rest("DELETE", `/repos/${ref.owner}/${ref.repo}/git/refs/heads/${encodedBranch}`, undefined, { auth, allow404: true }).catch(
        (cleanupError) => log.warn("failed to delete branch after PR creation error", { error: String(cleanupError) }),
      );
      throw error;
    }
  }

  /** Blob metadata and content of a file on a branch, used as the base for PR patches. */
  async fileForPatch(
    ref: GitHubRepoRef,
    filePath: string,
    branch: string,
  ): Promise<{ baseSha: string; blobSha: string; content: string }> {
    assertRepo(ref);
    const branchRef = await this.rest<{ object: { sha: string } }>(
      "GET",
      `/repos/${ref.owner}/${ref.repo}/git/ref/heads/${branch.split("/").map(encodeURIComponent).join("/")}`,
      undefined,
      { allow404: true },
    );
    if (!branchRef) throw new HttpError(404, "github_branch_not_found", `Branch ${branch} not found`);
    const encodedPath = filePath.split("/").map(encodeURIComponent).join("/");
    const file = await this.rest<{ sha: string; content?: string; encoding?: string; size: number; type: string }>(
      "GET",
      `/repos/${ref.owner}/${ref.repo}/contents/${encodedPath}?ref=${branchRef.object.sha}`,
      undefined,
      { allow404: true },
    );
    if (!file || file.type !== "file") {
      throw new HttpError(404, "github_file_not_found", `${filePath} does not exist on ${branch}`);
    }
    if (file.encoding !== "base64" || file.content === undefined) {
      throw new HttpError(413, "github_file_too_large", `${filePath} is too large to patch through the GitHub contents API`);
    }
    return {
      baseSha: branchRef.object.sha,
      blobSha: file.sha,
      content: Buffer.from(file.content.replace(/\n/g, ""), "base64").toString("utf8"),
    };
  }
}

export function assertRepo(ref: GitHubRepoRef): void {
  if (!isValidRepoRef(ref)) throw new HttpError(400, "invalid_repository", "Invalid GitHub owner/repository name");
}

function assertPullNumber(number: number): void {
  if (!Number.isSafeInteger(number) || number < 1) {
    throw new HttpError(400, "invalid_request", "Pull request number must be a positive integer");
  }
}
