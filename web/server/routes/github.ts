import type {
  GitHubCredentialSource,
  GitHubCredentialView,
  GitHubStatusView,
  PrCommentResponse,
  PrScanResultView,
  PrStatusResponse,
  PullRequestListView,
  PullRequestWorkflowsView,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import type { GitHubRepoRef } from "../git-meta.ts";
import { GITHUB_PAT_SECRET, githubTokenShapeError, type GitHubViewer } from "../github.ts";
import { HttpError, json, type AuthedContext, type Router } from "../http.ts";
import {
  allowedCommitStates,
  latestPrScan,
  prScanAtHead,
  prSecurityView,
  repositoryKey,
  runPrScan,
  scansForPulls,
} from "../services/pr-scan.ts";
import type { TenantRecord } from "../services/workspaces.ts";
import { oneOf, requiredString } from "../validate.ts";
import { actorOf, audited, tenantParam } from "./helpers.ts";

const COMMIT_STATES = ["success", "failure", "pending", "error"] as const;
const MAX_COMMENT_CHARS = 65_536;

function describe(error: unknown): string {
  if (error instanceof HttpError) return error.message;
  return error instanceof Error ? error.message : String(error);
}

/** Resolves the credential source without throwing (a corrupt stored secret is reported). */
function credentialSource(app: AppContext): { source: GitHubCredentialSource | null; error: string | null } {
  try {
    return { source: app.github.resolveAuth()?.source ?? null, error: null };
  } catch (error) {
    return { source: null, error: `The stored GitHub token could not be decrypted: ${describe(error)}` };
  }
}

function credentialView(app: AppContext): GitHubCredentialView {
  const { source } = credentialSource(app);
  const meta = app.secrets.meta(GITHUB_PAT_SECRET);
  return { source, storedTokenConfigured: meta !== null, storedTokenUpdatedAt: meta?.updatedAt ?? null };
}

const NO_CREDENTIAL =
  "No GitHub credential is available. Sign in with `gh auth login` on the bridge host, set GITHUB_TOKEN, or store a token in Settings.";

function requireCredential(app: AppContext): void {
  const { source, error } = credentialSource(app);
  if (error) throw new HttpError(500, "github_credential_unreadable", error);
  if (!source) throw new HttpError(412, "github_not_configured", NO_CREDENTIAL);
}

function requireRepository(app: AppContext, tenant: TenantRecord): GitHubRepoRef {
  const repository = app.workspaces.repository(tenant);
  if (!repository) {
    throw new HttpError(
      412,
      "repository_not_resolved",
      `No GitHub repository is configured for '${tenant.tenantId}' and none was detected from the workspace's origin remote. Set one in the GitHub settings of this tenant.`,
    );
  }
  return { owner: repository.owner, repo: repository.repo };
}

/** `:number` must be a positive integer pull request number. */
export function pullNumberParam(raw: string | undefined): number {
  if (!raw || !/^[1-9][0-9]{0,9}$/.test(raw) || Number(raw) > 2_147_483_647) {
    throw new HttpError(400, "invalid_request", "Pull request number must be a positive integer");
  }
  return Number(raw);
}

async function statusView(app: AppContext, tenant: TenantRecord): Promise<GitHubStatusView> {
  const { source, error } = credentialSource(app);
  const credential = credentialView(app);
  const repository = app.workspaces.repository(tenant);
  if (!source) {
    return {
      credential,
      viewer: null,
      viewerError: error ?? NO_CREDENTIAL,
      viewerErrorKind: error ? "credential_unreadable" : "no_credential",
      repository,
      repositoryInfo: null,
      repositoryError: repository ? "Repository details require a GitHub credential." : "No GitHub repository is configured or detected for this tenant.",
    };
  }
  const [viewer, repositoryInfo] = await Promise.allSettled([
    app.github.viewer(),
    repository ? app.github.repository({ owner: repository.owner, repo: repository.repo }) : Promise.resolve(null),
  ]);
  return {
    credential,
    viewer: viewer.status === "fulfilled" ? viewer.value : null,
    viewerError: viewer.status === "rejected" ? describe(viewer.reason) : null,
    viewerErrorKind: viewer.status === "rejected" ? "check_failed" : null,
    repository,
    repositoryInfo: repositoryInfo.status === "fulfilled" ? repositoryInfo.value : null,
    repositoryError:
      repositoryInfo.status === "rejected"
        ? describe(repositoryInfo.reason)
        : repository
          ? null
          : "No GitHub repository is configured for this tenant and none was detected from the workspace's origin remote.",
  };
}

function pullTarget(ref: GitHubRepoRef, prNumber: number): string {
  return `${ref.owner}/${ref.repo}#${prNumber}`;
}

export function registerGitHubRoutes(router: Router, app: AppContext): void {
  // ── connection status & settings ────────────────────────────────────────
  router.get("/api/tenants/:tenantId/github", { auth: "session", permission: "github:read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json(await statusView(app, tenant));
  });

  router.put("/api/tenants/:tenantId/github/repository", { auth: "session", permission: "settings:write" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = await ctx.readJson();
    if (body.repository !== null && typeof body.repository !== "string") {
      throw new HttpError(400, "invalid_request", "'repository' must be 'owner/repo' or null");
    }
    const repository = body.repository === null ? null : requiredString(body, "repository", { max: 200 });
    const updated = await audited(
      app,
      ctx.principal,
      {
        action: "github_repository_set",
        tenantId: tenant.tenantId,
        target: repository ?? "(git remote detection)",
        details: { previous: tenant.githubOwner && tenant.githubRepo ? `${tenant.githubOwner}/${tenant.githubRepo}` : null },
      },
      () => app.workspaces.update(tenant.tenantId, { githubRepository: repository }),
    );
    return json(await statusView(app, updated));
  });

  router.put("/api/settings/github/token", { auth: "session", permission: "settings:write", maxBodyBytes: 4096 }, async (ctx) => {
    const body = await ctx.readJson();
    const token = requiredString(body, "token", { max: 255, trim: false });
    const shapeError = githubTokenShapeError(token);
    if (shapeError) throw new HttpError(400, "invalid_token", shapeError);
    await audited(
      app,
      ctx.principal,
      { action: "github_token_stored", target: GITHUB_PAT_SECRET, details: {} },
      async () => {
        let viewer: GitHubViewer;
        try {
          // Verify this exact token before it replaces anything.
          viewer = await app.github.viewer({ source: "stored_pat", token });
        } catch (error) {
          const githubStatus = error instanceof HttpError ? (error.details as { githubStatus?: number } | undefined)?.githubStatus : undefined;
          if (githubStatus === 401 || githubStatus === 403) {
            throw new HttpError(422, "github_token_rejected", describe(error));
          }
          throw error;
        }
        app.secrets.set(GITHUB_PAT_SECRET, token, ctx.principal.label);
        app.github.invalidateCaches();
        return viewer;
      },
      (viewer) => ({ login: viewer.login, scopes: viewer.scopes }),
    );
    return json(credentialView(app));
  });

  router.delete("/api/settings/github/token", { auth: "session", permission: "settings:write" }, async (ctx) => {
    const wasConfigured = app.secrets.has(GITHUB_PAT_SECRET);
    await audited(app, ctx.principal, { action: "github_token_removed", target: GITHUB_PAT_SECRET, details: { wasConfigured } }, () => {
      app.secrets.delete(GITHUB_PAT_SECRET);
      app.github.invalidateCaches();
    });
    return json(credentialView(app));
  });

  // ── pull requests ───────────────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/github/pulls", { auth: "session", permission: "github:read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    requireCredential(app);
    const ref = requireRepository(app, tenant);
    const { pulls, fetchedAt } = await app.github.listOpenPullRequestsWithMeta(ref, ctx.url.searchParams.get("refresh") !== "1");
    const scans = scansForPulls(
      app.db,
      repositoryKey(ref),
      pulls.map((pr) => pr.number),
    );
    const view: PullRequestListView = {
      repository: { owner: ref.owner, repo: ref.repo },
      pulls: pulls.map((pr) => ({
        ...pr,
        isSentraBranch: pr.headRef.startsWith("sentra/"),
        security: prSecurityView(pr.headSha, scans.get(pr.number) ?? []),
      })),
      fetchedAt,
    };
    return json(view);
  });

  router.get("/api/tenants/:tenantId/github/pulls/:number/workflows", { auth: "session", permission: "github:read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const prNumber = pullNumberParam(ctx.params.number);
    requireCredential(app);
    const ref = requireRepository(app, tenant);
    const pr = await app.github.getPullRequest(ref, prNumber);
    const view: PullRequestWorkflowsView = {
      prNumber,
      headSha: pr.headSha,
      runs: await app.github.workflowRunsForCommit(ref, pr.headSha),
    };
    return json(view);
  });

  router.get("/api/tenants/:tenantId/github/pulls/:number/scan", { auth: "session", permission: "github:read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const prNumber = pullNumberParam(ctx.params.number);
    const ref = requireRepository(app, tenant);
    const scan: PrScanResultView | null = latestPrScan(app.db, repositoryKey(ref), prNumber);
    return json({ scan });
  });

  router.post("/api/tenants/:tenantId/github/pulls/:number/scan", { auth: "session", permission: "github:scan" }, async (ctx: AuthedContext) => {
    const tenant = tenantParam(app, ctx);
    const prNumber = pullNumberParam(ctx.params.number);
    requireCredential(app);
    const ref = requireRepository(app, tenant);
    if (!app.cli.available()) {
      throw new HttpError(503, "core_unavailable", "The sentra core binary was not found; pull request scans need it.");
    }
    const result = await audited(
      app,
      ctx.principal,
      { action: "github_pr_scanned", tenantId: tenant.tenantId, target: pullTarget(ref, prNumber), details: { prNumber } },
      () =>
        runPrScan(
          {
            github: app.github,
            cli: app.cli,
            db: app.db,
            tmpDir: app.config.tmpDir,
            scanTimeoutMs: app.config.cliLongTimeoutMs,
          },
          { ref, prNumber, actor: actorOf(ctx.principal) },
        ),
      (scan) => ({
        headSha: scan.headSha,
        status: scan.status,
        filesConsidered: scan.filesConsidered,
        filesScanned: scan.filesScanned,
        skippedFiles: scan.skipped.length,
        signalsFound: scan.signalsFound,
        criticalCount: scan.criticalCount,
      }),
    );
    return json(result);
  });

  router.post("/api/tenants/:tenantId/github/pulls/:number/comment", { auth: "session", permission: "github:comment" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const prNumber = pullNumberParam(ctx.params.number);
    const body = await ctx.readJson();
    const text = requiredString(body, "body", { max: MAX_COMMENT_CHARS, trim: false });
    if (!text.trim()) throw new HttpError(400, "invalid_request", "'body' must not be blank");
    requireCredential(app);
    const ref = requireRepository(app, tenant);
    const comment = await audited(
      app,
      ctx.principal,
      {
        action: "github_pr_comment_posted",
        tenantId: tenant.tenantId,
        target: pullTarget(ref, prNumber),
        details: { prNumber, bodyLength: text.length, disclosure: "public" },
      },
      async () => {
        // The issues endpoint also accepts plain issue numbers; confirm this is a pull request.
        await app.github.getPullRequest(ref, prNumber);
        return app.github.postIssueComment(ref, prNumber, text);
      },
      (posted) => ({ commentId: posted.id, url: posted.htmlUrl }),
    );
    const response: PrCommentResponse = { id: comment.id, url: comment.htmlUrl };
    return json(response, 201);
  });

  router.post("/api/tenants/:tenantId/github/pulls/:number/status", { auth: "session", permission: "github:status" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const prNumber = pullNumberParam(ctx.params.number);
    const body = await ctx.readJson();
    const state = oneOf(body.state, "state", COMMIT_STATES);
    const description = requiredString(body, "description", { max: 140 });
    requireCredential(app);
    const ref = requireRepository(app, tenant);
    const response = await audited(
      app,
      ctx.principal,
      {
        action: "github_commit_status_set",
        tenantId: tenant.tenantId,
        target: pullTarget(ref, prNumber),
        details: { prNumber, state, descriptionLength: description.length, disclosure: "public" },
      },
      async (): Promise<PrStatusResponse> => {
        const pr = await app.github.getPullRequest(ref, prNumber);
        const scan = prScanAtHead(app.db, repositoryKey(ref), prNumber, pr.headSha);
        const allowed = allowedCommitStates(scan);
        if (!allowed.includes(state)) {
          throw new HttpError(
            409,
            "status_not_backed_by_scan",
            scan
              ? `The stored scan of head ${pr.headSha.slice(0, 12)} is '${scan.status}', which only supports: ${allowed.join(", ")}`
              : `Head ${pr.headSha.slice(0, 12)} has not been scanned by Sentra; only 'pending' can be published until it is`,
            { allowed, scanStatus: scan?.status ?? null, headSha: pr.headSha },
          );
        }
        await app.github.createCommitStatus(ref, pr.headSha, state, description);
        return { sha: pr.headSha, state };
      },
      (result) => ({ sha: result.sha }),
    );
    return json(response, 201);
  });
}
