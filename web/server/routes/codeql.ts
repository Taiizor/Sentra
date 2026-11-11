import type { CodeqlIngestView, CodeqlPacksDownloadView, CodeqlPacksStreamEvent, CodeqlSettingsView } from "../../src/types/api.ts";
import { markAuditHandled } from "../audit-log.ts";
import type { AppContext } from "../app-context.ts";
import { nowIso } from "../db.ts";
import { HttpError, json, sseResponse, type AuthedContext, type Router } from "../http.ts";
import {
  CODEQL_IMPORT_MAX_BYTES,
  codeqlSettingsView,
  describeRunning,
  importCodeqlSarif,
  parseCodeqlSettingsUpdate,
  syncGithubCodeScanning,
  type CodeqlSettingsUpdate,
} from "../services/codeql.ts";
import { downloadPacks, PACKS_DISABLED_MESSAGE, parsePackLanguages, readPacks } from "../services/codeql-packs.ts";
import { asObject } from "../validate.ts";
import { requireCredential, requireRepository } from "./github.ts";
import { audited, tenantParam } from "./helpers.ts";

export const IMPORT_BUSY_MESSAGE =
  "Another CodeQL SARIF import is being processed on this bridge; imports run one at a time so that large files cannot exhaust memory. Try again when it has finished.";

/**
 * CodeQL routes (ADR-0011):
 * - GET /api/settings/codeql (read) and PUT (settings:write): host analysis settings. Enabling
 *   requires acceptTerms: true in the same request; every change is audited.
 * - GET /api/settings/codeql/packs (read): the query packs of the configured suite per language
 *   (`sentra codeql packs --json`, never a download), shared and reused for 30 s; ?refresh=1 reads
 *   them again.
 * - POST /api/settings/codeql/packs/download (settings:write): downloads missing query packs
 *   (`sentra codeql packs --download`), as JSON or, with `Accept: text/event-stream`, as a stream
 *   of progress events like a scan. Only while host analysis is enabled with accepted terms (409
 *   codeql_disabled), because it runs the CodeQL CLI. Holds the bridge-wide CodeQL lock shared
 *   with host analysis (409 codeql_busy otherwise); closing the stream cancels the download.
 *   Audited as codeql_packs_downloaded, refusals included.
 * - POST /api/tenants/:tenantId/codeql/import (scan:run): a CodeQL SARIF document as the JSON body
 *   (up to 64 MiB on this route only), streamed into a private file and parsed by
 *   `sentra codeql import`. One import is processed at a time (429 codeql_import_busy otherwise).
 * - POST /api/tenants/:tenantId/codeql/github-sync (scan:run): open GitHub code scanning alerts of
 *   tool CodeQL for the tenant's repository, read-only.
 */

const PACKS_AUDIT_ACTION = "codeql_packs_downloaded";

/**
 * Runs one pack download for the route: takes the bridge-wide CodeQL lock, runs the download and
 * records the outcome on the audit chain (refusals included). `emit` receives the stream events.
 */
async function runPackDownload(
  app: AppContext,
  ctx: AuthedContext,
  languages: string[] | undefined,
  signal: AbortSignal,
  emit: (event: CodeqlPacksStreamEvent) => void,
): Promise<CodeqlPacksDownloadView> {
  const requested = { languages: languages ?? "all missing", suite: app.codeql.settings().suite };
  const fail = (error: unknown): never => {
    app.audit.append(ctx.principal, {
      action: PACKS_AUDIT_ACTION,
      outcome: "failure",
      target: "codeql_packs",
      details: { ...requested, error: error instanceof HttpError ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : String(error) },
    });
    throw markAuditHandled(error);
  };
  if (!app.codeql.analysisEnabled()) return fail(new HttpError(409, "codeql_disabled", PACKS_DISABLED_MESSAGE));
  const release = app.codeql.lock.tryAcquire(null, "pack_download", ctx.principal.label);
  if (!release) {
    const running = app.codeql.lock.current;
    return fail(
      new HttpError(409, "codeql_busy", `${running ? describeRunning(running) : "Another CodeQL operation is running on this bridge"}; CodeQL runs one operation at a time, so the download did not start. Try again when it has finished.`),
    );
  }
  try {
    const result = await downloadPacks(app, {
      languages,
      signal,
      onProgress: (progress) => emit({ type: "progress", progress, ts: nowIso() }),
      onLog: (stream, text) => emit({ type: "log", stream, text, ts: nowIso() }),
      // CodeQL has stopped: release before the result's pack listing is read, so that it does not
      // report this download as still running (release is idempotent; `finally` calls it again).
      onCoreExited: release,
    });
    app.audit.append(ctx.principal, {
      action: PACKS_AUDIT_ACTION,
      outcome: result.outcome === "completed" || result.outcome === "nothing_to_do" ? "success" : "failure",
      target: "codeql_packs",
      details: {
        ...requested,
        outcome: result.outcome,
        downloaded: result.downloaded,
        failed: result.failed.map((entry) => ({ language: entry.language, message: entry.message.slice(0, 300) })),
        durationMs: result.durationMs,
      },
    });
    return result;
  } catch (error) {
    return fail(error);
  } finally {
    release();
  }
}

/** Fields of a settings change recorded on the audit chain (no secrets exist in these settings). */
function auditedChanges(update: CodeqlSettingsUpdate): Record<string, unknown> {
  return Object.fromEntries(Object.entries(update).filter(([, value]) => value !== undefined));
}

export function registerCodeqlRoutes(router: Router, app: AppContext): void {
  router.get("/api/settings/codeql", { auth: "session", permission: "read" }, async () => {
    const view: CodeqlSettingsView = await codeqlSettingsView(app);
    return json(view);
  });

  router.get("/api/settings/codeql/packs", { auth: "session", permission: "read" }, async (ctx) => {
    return json(await readPacks(app, { fresh: ctx.url.searchParams.get("refresh") === "1", signal: ctx.req.signal }));
  });

  router.post("/api/settings/codeql/packs/download", { auth: "session", permission: "settings:write", maxBodyBytes: 4 * 1024 }, async (ctx) => {
    const languages = parsePackLanguages(await ctx.readJson());
    const wantsStream = (ctx.req.headers.get("accept") ?? "").toLowerCase().includes("text/event-stream");
    if (!wantsStream) return json(await runPackDownload(app, ctx, languages, ctx.req.signal, () => {}));
    return sseResponse(ctx.req, async (channel, signal) => {
      // Cancel the download (the core kills CodeQL's process tree) when the client goes away.
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener("abort", abort, { once: true });
      const poll = setInterval(() => {
        if (channel.closed) abort();
      }, 1000);
      try {
        const result = await runPackDownload(app, ctx, languages, controller.signal, (event) => channel.send(event.type, event));
        const complete: CodeqlPacksStreamEvent = { type: "complete", result };
        channel.send(complete.type, complete);
      } catch (error) {
        const event: CodeqlPacksStreamEvent =
          error instanceof HttpError
            ? { type: "error", status: error.status, code: error.code, message: error.message }
            : { type: "error", status: 500, code: "codeql_packs_failed", message: "The pack download failed unexpectedly; see the bridge log." };
        channel.send(event.type, event);
      } finally {
        clearInterval(poll);
        signal.removeEventListener("abort", abort);
      }
    });
  });

  router.put("/api/settings/codeql", { auth: "session", permission: "settings:write", maxBodyBytes: 16 * 1024 }, async (ctx) => {
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
          const release = app.codeql.importLock.tryAcquire(tenant.tenantId, "sarif_import");
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
