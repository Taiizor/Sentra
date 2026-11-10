import type { CreatePullRequestResponse, PatchBundleView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { HttpError, json, type Router } from "../http.ts";
import { PROVIDER_IDS } from "../llm.ts";
import { isValidGitBranchName, PatchService, type GenerationAuditMeta } from "../services/patches.ts";
import { oneOf, optionalString } from "../validate.ts";
import { actorOf, audited, tenantParam } from "./helpers.ts";

const FINDING_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const BUNDLE_ID_RE = /^[A-Za-z0-9-]{1,64}$/;

function idParam(value: string | undefined, field: string, pattern: RegExp): string {
  if (!value || !pattern.test(value)) throw new HttpError(400, "invalid_request", `Invalid ${field}`);
  return value;
}

/**
 * Model-generated patch candidates: generation (ai:generate), local apply/rollback through the
 * core patch engine (patch:apply) and draft pull requests (github:create-pr). Every
 * state-changing call is recorded on the operator audit chain without file contents, prompts
 * or model output.
 */
export function registerPatchRoutes(router: Router, app: AppContext): void {
  const service = new PatchService(app);

  router.post("/api/tenants/:tenantId/findings/:findingId/patches", { auth: "session", permission: "ai:generate" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const findingId = idParam(ctx.params.findingId, "finding id", FINDING_ID_RE);
    const body = await ctx.readJson();
    const provider = body.provider === undefined || body.provider === null ? undefined : oneOf(body.provider, "provider", PROVIDER_IDS);
    // Filled in by the service as it progresses so failures are audited with provider usage too.
    const details: Record<string, unknown> & GenerationAuditMeta = { findingId, requestedProvider: provider ?? null };
    const view: PatchBundleView = await audited(
      app,
      ctx.principal,
      { action: "ai_patch_generated", tenantId: tenant.tenantId, target: findingId, details },
      () => service.generate(tenant, findingId, provider, actorOf(ctx.principal), (meta) => Object.assign(details, meta)),
      (bundle) => ({ bundleId: bundle.bundleId, targetPath: bundle.targetPath, applyCheckDetail: bundle.applyCheckDetail }),
    );
    return json(view, 201);
  });

  router.get("/api/tenants/:tenantId/patches", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body: { patches: PatchBundleView[] } = { patches: service.list(tenant.tenantId) };
    return json(body);
  });

  router.post("/api/tenants/:tenantId/patches/:bundleId/apply", { auth: "session", permission: "patch:apply" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const bundleId = idParam(ctx.params.bundleId, "patch bundle id", BUNDLE_ID_RE);
    const current = service.get(tenant.tenantId, bundleId);
    const result = await audited(
      app,
      ctx.principal,
      {
        action: "patch_applied",
        tenantId: tenant.tenantId,
        target: current.targetPath,
        details: { bundleId, findingId: current.findingId, fromState: current.state },
      },
      () => service.apply(tenant, bundleId, actorOf(ctx.principal)),
      (outcome) => ({ backupFile: outcome.backupFile, coreAuditRecorded: outcome.coreAuditRecorded }),
    );
    return json(result.view);
  });

  router.post("/api/tenants/:tenantId/patches/:bundleId/rollback", { auth: "session", permission: "patch:apply" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const bundleId = idParam(ctx.params.bundleId, "patch bundle id", BUNDLE_ID_RE);
    const current = service.get(tenant.tenantId, bundleId);
    const result = await audited(
      app,
      ctx.principal,
      {
        action: "patch_rolled_back",
        tenantId: tenant.tenantId,
        target: current.targetPath,
        details: { bundleId, findingId: current.findingId, fromState: current.state },
      },
      () => service.rollback(tenant, bundleId, actorOf(ctx.principal)),
      (outcome) => ({ coreAuditRecorded: outcome.coreAuditRecorded }),
    );
    return json(result.view);
  });

  router.post("/api/tenants/:tenantId/patches/:bundleId/pull-request", { auth: "session", permission: "github:create-pr" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const bundleId = idParam(ctx.params.bundleId, "patch bundle id", BUNDLE_ID_RE);
    const body = await ctx.readJson();
    const baseBranch = optionalString(body, "baseBranch", { max: 200 });
    if (baseBranch !== undefined && !isValidGitBranchName(baseBranch)) {
      throw new HttpError(400, "invalid_request", "'baseBranch' is not a valid branch name");
    }
    const current = service.get(tenant.tenantId, bundleId);
    const repository = app.workspaces.repository(tenant);
    const response: CreatePullRequestResponse = await audited(
      app,
      ctx.principal,
      {
        action: "pull_request_created",
        tenantId: tenant.tenantId,
        target: current.targetPath,
        details: {
          bundleId,
          findingId: current.findingId,
          repository: repository ? `${repository.owner}/${repository.repo}` : null,
          requestedBaseBranch: baseBranch ?? null,
          draft: true,
        },
      },
      () => service.createPullRequest(tenant, bundleId, baseBranch),
      (created) => ({
        prNumber: created.number,
        prUrl: created.url,
        branch: created.branch,
        baseBranch: created.baseBranch,
        baseSha: created.baseSha,
        commitSha: created.commitSha,
      }),
    );
    return json(response, 201);
  });
}
