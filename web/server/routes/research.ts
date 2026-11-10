import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import type { ModelReconReportView, ProviderId, ReconWorkflow, TopologyReportView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { nowIso, parseJsonColumn } from "../db.ts";
import { HttpError, json, type Principal, type Router } from "../http.ts";
import { isProviderId } from "../llm.ts";
import { hasPermission } from "../permissions.ts";
import { cliValue } from "../sentra-cli.ts";
import {
  CoverageLedger,
  parseCoverageId,
  parseUpsertRequest,
  tenantFindingLookup,
  validateCoverageUnits,
} from "../services/coverage.ts";
import { computeTopology, latestTopologyReport, parseCodeqlProbe, renderGroundedContext, saveTopologyReport } from "../services/topology.ts";
import type { TenantRecord } from "../services/workspaces.ts";
import { oneOf } from "../validate.ts";
import { toolAvailability } from "./core-routes.ts";
import { audited, intParam, tenantParam } from "./helpers.ts";

/**
 * Research routes: the operator-maintained coverage ledger, the deterministic workspace
 * topology, and model-generated reconnaissance. Model output is persisted and always returned
 * with the unverified-output disclaimer; nothing here is written into the workspace.
 */

export const RECON_WORKFLOWS: readonly ReconWorkflow[] = ["scout", "threat-model"];

export const MODEL_RECON_DISCLAIMER = "Unverified model output. Every statement is a hypothesis; Sentra has not validated it.";

const MODEL_RECON_MAX_TOKENS = 4096;

/** Tenants with a topology computation or model recon in flight (one of each at a time). */
const topologyInFlight = new Set<string>();
const modelReconInFlight = new Set<string>();

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function runTopology(app: AppContext, tenant: TenantRecord, principal: Principal): Promise<TopologyReportView> {
  if (topologyInFlight.has(tenant.tenantId)) {
    throw new HttpError(409, "topology_running", "A topology computation is already running for this tenant");
  }
  topologyInFlight.add(tenant.tenantId);
  try {
    return await audited(
      app,
      principal,
      { action: "recon_topology_computed", tenantId: tenant.tenantId, target: tenant.workspace },
      async () => {
        const root = app.workspaces.workspaceRoot(tenant);
        const content = await computeTopology(root, {
          languageProbe: async () => {
            const result = await app.cli.runJson(["codeql", "--workspace", cliValue(root, "workspace"), "--json"], {
              timeoutMs: app.config.cliLongTimeoutMs,
            });
            return parseCodeqlProbe(result);
          },
          lockfileInventory: async () => {
            const inventory = await app.osv.inventory(root);
            return { lockfiles: inventory.lockfiles, totalPackages: inventory.totalPackages };
          },
          tools: toolAvailability,
        });
        const report: TopologyReportView = {
          reportId: crypto.randomUUID(),
          tenantId: tenant.tenantId,
          createdAt: nowIso(),
          createdBy: principal.label,
          ...content,
        };
        saveTopologyReport(app.db, report);
        return report;
      },
      (report) => ({
        reportId: report.reportId,
        languages: report.languages.length,
        manifests: report.manifests.length,
        subsystems: report.subsystems.length,
        entrypoints: report.entrypoints.length,
      }),
    );
  } finally {
    topologyInFlight.delete(tenant.tenantId);
  }
}

interface ModelReportContent {
  workflow: ReconWorkflow;
  topologyReportId: string | null;
  output: string;
  inputTokens: number | null;
  outputTokens: number | null;
  latencyMs: number;
}

interface ModelReportRow {
  report_id: string;
  tenant_id: string;
  created_at: string;
  created_by: string;
  provider: string | null;
  model: string | null;
  content_json: string;
}

export function saveModelReport(db: Database, report: ModelReconReportView, workspace: string): void {
  const content: ModelReportContent = {
    workflow: report.workflow,
    topologyReportId: report.topologyReportId,
    output: report.output,
    inputTokens: report.inputTokens,
    outputTokens: report.outputTokens,
    latencyMs: report.latencyMs,
  };
  db.query(
    `INSERT INTO recon_reports (report_id, tenant_id, workspace, kind, created_at, created_by, provider, model, content_json)
     VALUES (?, ?, ?, 'model', ?, ?, ?, ?, ?)`,
  ).run(report.reportId, report.tenantId, workspace, report.createdAt, report.createdBy, report.provider, report.model, JSON.stringify(content));
}

export function listModelReports(db: Database, tenantId: string, limit: number): ModelReconReportView[] {
  const rows = db
    .query(
      `SELECT report_id, tenant_id, created_at, created_by, provider, model, content_json FROM recon_reports
       WHERE tenant_id = ? AND kind = 'model' ORDER BY created_at DESC, rowid DESC LIMIT ?`,
    )
    .all(tenantId, limit) as ModelReportRow[];
  const reports: ModelReconReportView[] = [];
  for (const row of rows) {
    const content = parseJsonColumn<Partial<ModelReportContent>>(row.content_json, {});
    if (!isProviderId(row.provider) || typeof content.output !== "string") continue;
    reports.push({
      reportId: row.report_id,
      tenantId: row.tenant_id,
      createdAt: row.created_at,
      createdBy: row.created_by,
      provider: row.provider,
      model: row.model ?? "unknown",
      workflow: content.workflow === "threat-model" ? "threat-model" : "scout",
      topologyReportId: typeof content.topologyReportId === "string" ? content.topologyReportId : null,
      output: content.output,
      inputTokens: typeof content.inputTokens === "number" ? content.inputTokens : null,
      outputTokens: typeof content.outputTokens === "number" ? content.outputTokens : null,
      latencyMs: typeof content.latencyMs === "number" ? content.latencyMs : 0,
      disclaimer: MODEL_RECON_DISCLAIMER,
    });
  }
  return reports;
}

/** Reads the core prompt template output (`sentra prompt <workflow> --json`). */
export function parsePromptOutput(document: unknown): { system: string; user: string } {
  const doc = document && typeof document === "object" && !Array.isArray(document) ? (document as Record<string, unknown>) : null;
  const system = doc?.system_prompt;
  const user = doc?.user_prompt;
  if (typeof system !== "string" || typeof user !== "string" || !system.trim() || !user.trim()) {
    throw new HttpError(502, "core_output_invalid", "sentra prompt did not return system_prompt and user_prompt");
  }
  return { system, user };
}

export function registerResearchRoutes(router: Router, app: AppContext): void {
  const ledger = new CoverageLedger(app.db);

  // ── coverage ledger ─────────────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/coverage", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json({ units: ledger.list(tenant.tenantId) });
  });

  // Registered before the `:coverageId` routes; ids always contain '/', so they never collide.
  router.post("/api/tenants/:tenantId/coverage/validate", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    let workspaceRoot: string | null = null;
    let workspaceError: string | null = null;
    try {
      workspaceRoot = app.workspaces.workspaceRoot(tenant);
    } catch (error) {
      workspaceError = errorMessage(error);
    }
    const result = validateCoverageUnits(ledger.list(tenant.tenantId), {
      workspaceRoot,
      workspaceError,
      findingExists: tenantFindingLookup(app.db, tenant.tenantId),
    });
    return json(result);
  });

  router.put(
    "/api/tenants/:tenantId/coverage/:coverageId",
    { auth: "session", permission: "research:write", maxBodyBytes: 512 * 1024 },
    async (ctx) => {
      const tenant = tenantParam(app, ctx);
      const coverageId = ctx.params.coverageId ?? "";
      parseCoverageId(coverageId);
      const input = parseUpsertRequest(coverageId, await ctx.readJson());
      const result = await audited(
        app,
        ctx.principal,
        {
          action: "coverage_unit_upserted",
          tenantId: tenant.tenantId,
          target: coverageId,
          details: { status: input.status, wave: input.wave },
        },
        () => ledger.upsert(tenant.tenantId, coverageId, input, ctx.principal.label),
        (outcome) => ({
          created: outcome.created,
          reviewedPaths: input.reviewedPaths.length,
          localChecks: input.localChecks.length,
          resultFingerprints: input.resultFingerprints.length,
        }),
      );
      return json(result.unit, result.created ? 201 : 200);
    },
  );

  router.delete("/api/tenants/:tenantId/coverage/:coverageId", { auth: "session", permission: "research:write" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const coverageId = ctx.params.coverageId ?? "";
    parseCoverageId(coverageId);
    await audited(app, ctx.principal, { action: "coverage_unit_deleted", tenantId: tenant.tenantId, target: coverageId }, () => {
      if (!ledger.delete(tenant.tenantId, coverageId)) {
        throw new HttpError(404, "coverage_unit_not_found", `Coverage unit '${coverageId}' does not exist`);
      }
    });
    return json({ ok: true });
  });

  // ── deterministic topology ──────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/recon/topology", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json({ report: latestTopologyReport(app.db, tenant.tenantId) });
  });

  router.post("/api/tenants/:tenantId/recon/topology", { auth: "session", permission: "research:run" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json(await runTopology(app, tenant, ctx.principal), 201);
  });

  // ── model reconnaissance ────────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/recon/model", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = tenantParam(app, ctx);
    const limit = intParam(ctx.url.searchParams.get("limit"), "limit", 1, 200, 50);
    return json({ reports: listModelReports(app.db, tenant.tenantId, limit) });
  });

  router.post("/api/tenants/:tenantId/recon/model", { auth: "session", permission: "ai:generate", maxBodyBytes: 4096 }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = await ctx.readJson();
    const workflow = oneOf(body.workflow, "workflow", RECON_WORKFLOWS);
    let requested: ProviderId | undefined;
    if (body.provider !== undefined && body.provider !== null) {
      if (!isProviderId(body.provider)) throw new HttpError(400, "invalid_request", "'provider' is not a known provider id");
      requested = body.provider;
    }
    // Fails with 412 before any work when no usable provider is configured.
    app.llm.resolve(requested);
    const root = app.workspaces.workspaceRoot(tenant);

    if (modelReconInFlight.has(tenant.tenantId)) {
      throw new HttpError(409, "model_recon_running", "A model reconnaissance request is already running for this tenant");
    }
    modelReconInFlight.add(tenant.tenantId);
    try {
      let topology = latestTopologyReport(app.db, tenant.tenantId);
      if (!topology) {
        if (!hasPermission(ctx.principal.role, "research:run")) {
          throw new HttpError(412, "topology_missing", "No topology report exists for this tenant; an operator must compute one first");
        }
        topology = await runTopology(app, tenant, ctx.principal);
      }
      const grounding = topology;
      const report = await audited(
        app,
        ctx.principal,
        {
          action: "recon_model_generated",
          tenantId: tenant.tenantId,
          target: workflow,
          details: { workflow, requestedProvider: requested ?? null, topologyReportId: grounding.reportId },
        },
        async () => {
          const promptDoc = await app.cli.runJson(["prompt", workflow, "--scope", cliValue(root, "workspace"), "--json"]);
          const prompt = parsePromptOutput(promptDoc);
          const completion = await app.llm.complete(
            {
              system: prompt.system,
              user: `${prompt.user}\n\n---\n${renderGroundedContext(grounding)}`,
              maxTokens: MODEL_RECON_MAX_TOKENS,
              expectJson: false,
            },
            requested,
          );
          const view: ModelReconReportView = {
            reportId: crypto.randomUUID(),
            tenantId: tenant.tenantId,
            createdAt: nowIso(),
            createdBy: ctx.principal.label,
            provider: completion.provider,
            model: completion.model,
            workflow,
            topologyReportId: grounding.reportId,
            output: completion.text,
            inputTokens: completion.inputTokens,
            outputTokens: completion.outputTokens,
            latencyMs: completion.latencyMs,
            disclaimer: MODEL_RECON_DISCLAIMER,
          };
          saveModelReport(app.db, view, root);
          return view;
        },
        (view) => ({
          reportId: view.reportId,
          provider: view.provider,
          model: view.model,
          latencyMs: view.latencyMs,
          inputTokens: view.inputTokens,
          outputTokens: view.outputTokens,
        }),
      );
      return json(report, 201);
    } finally {
      modelReconInFlight.delete(tenant.tenantId);
    }
  });
}
