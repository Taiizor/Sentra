import type { CodeqlIngestView, CodeqlSettingsView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { HttpError, json, type Router } from "../http.ts";
import {
  CODEQL_IMPORT_MAX_BYTES,
  codeqlSettingsView,
  importCodeqlSarif,
  parseCodeqlSettingsUpdate,
  syncGithubCodeScanning,
  type CodeqlSettingsUpdate,
} from "../services/codeql.ts";

export const IMPORT_BUSY_MESSAGE =
  "Another CodeQL SARIF import is being processed on this bridge; imports run one at a time so that large files cannot exhaust memory. Try again when it has finished.";
import { asObject } from "../validate.ts";
import { requireCredential, requireRepository } from "./github.ts";
import { audited, tenantParam } from "./helpers.ts";

/**
 * CodeQL routes (ADR-0011):
 * - GET /api/settings/codeql (read) and PUT (settings:write): host analysis settings. Enabling
 *   requires acceptTerms: true in the same request; every change is audited.
 * - POST /api/tenants/:tenantId/codeql/import (scan:run): a CodeQL SARIF document as the JSON body
 *   (up to 64 MiB on this route only), streamed into a private file and parsed by
 *   `sentra codeql import`. One import is processed at a time (429 codeql_import_busy otherwise).
 * - POST /api/tenants/:tenantId/codeql/github-sync (scan:run): open GitHub code scanning alerts of
 *   tool CodeQL for the tenant's repository, read-only.
 */

/** Fields of a settings change recorded on the audit chain (no secrets exist in these settings). */
function auditedChanges(update: CodeqlSettingsUpdate): Record<string, unknown> {
  return Object.fromEntries(Object.entries(update).filter(([, value]) => value !== undefined));
}

export function registerCodeqlRoutes(router: Router, app: AppContext): void {
  router.get("/api/settings/codeql", { auth: "session", permission: "read" }, async () => {
    const view: CodeqlSettingsView = await codeqlSettingsView(app);
    return json(view);
  });

  router.put("/api/settings/codeql", { auth: "session", permission: "settings:write", maxBodyBytes: 8 * 1024 }, async (ctx) => {
    const body = asObject(await ctx.readJson());
    const previous = app.codeql.settings();
    const raw = Object.fromEntries(Object.entries(body).slice(0, 16).map(([key, value]) => [key.slice(0, 40), typeof value === "string" ? value.slice(0, 80) : value]));
    await audited(
      app,
      ctx.principal,
      { action: "codeql_settings_updated", target: "codeql_analysis", details: { requested: raw, previousEnabled: previous.enabled } },
      () => {
        const update = parseCodeqlSettingsUpdate(body, app.codeql.limits);
        const next = app.codeql.update(update, ctx.principal.label);
        return { update, next };
      },
      ({ update, next }) => ({
        changes: auditedChanges(update),
        enabled: next.enabled,
        termsAccepted: update.acceptTerms === true,
        termsAcceptedBy: next.termsAcceptedBy,
        termsAcceptedAt: next.termsAcceptedAt,
      }),
    );
    return json(await codeqlSettingsView(app));
  });

  router.post(
    "/api/tenants/:tenantId/codeql/import",
    { auth: "session", permission: "scan:run", maxBodyBytes: CODEQL_IMPORT_MAX_BYTES },
    async (ctx) => {
      const tenant = tenantParam(app, ctx);
      const declared = Number(ctx.req.headers.get("content-length") ?? "NaN");
      const view = await audited(
        app,
        ctx.principal,
        { action: "codeql_sarif_imported", tenantId: tenant.tenantId, details: { declaredBytes: Number.isFinite(declared) ? declared : null } },
        async (): Promise<CodeqlIngestView> => {
          const contentType = (ctx.req.headers.get("content-type") ?? "").toLowerCase();
          if (!contentType.startsWith("application/json")) {
            throw new HttpError(415, "unsupported_media_type", "Send the SARIF document as the request body with Content-Type: application/json");
          }
          // Taken before the body is read: a second upload is refused without receiving it.
          const release = app.codeql.importLock.tryAcquire(tenant.tenantId);
          if (!release) throw new HttpError(429, "codeql_import_busy", IMPORT_BUSY_MESSAGE);
          try {
            const workspace = app.workspaces.workspaceRoot(tenant);
            return await importCodeqlSarif(app, tenant, workspace, ctx.req, ctx.req.signal);
          } finally {
            release();
          }
        },
        (result) => ({
          resultsTotal: result.resultsTotal,
          resultsOutsideWorkspace: result.resultsOutsideWorkspace,
          truncated: result.truncated,
          sourceTool: result.sourceTool,
          ...result.findings,
        }),
      );
      return json(view);
    },
  );

  router.post("/api/tenants/:tenantId/codeql/github-sync", { auth: "session", permission: "scan:run", maxBodyBytes: 1024 }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const view = await audited(
      app,
      ctx.principal,
      { action: "codeql_github_synced", tenantId: tenant.tenantId },
      async (): Promise<CodeqlIngestView> => {
        requireCredential(app);
        const repo = requireRepository(app, tenant);
        return syncGithubCodeScanning(app, app.github, tenant, repo);
      },
      (result) => ({ repository: result.repository, alerts: result.resultsTotal, truncated: result.truncated, ...result.findings }),
    );
    return json(view);
  });
}
