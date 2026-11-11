import {
  API_CONTRACT_VERSION,
  type AuditLogPage,
  type AuditVerificationView,
  type HealthResponse,
  type HostInfo,
  type SessionInfo,
  type SetToolPathResponse,
  type SystemStatus,
  type TenantView,
  type ToolAvailability,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { markAuditHandled } from "../audit-log.ts";
import { AttemptLimiter } from "../auth.ts";
import { inspectBinary } from "../binary-info.ts";
import { configuredGrantCount } from "../config.ts";
import { collectHostInfo, describeTools, hostArch, hostToolsDeps, isToolName, toolPathProbesFor, type ToolName } from "../host-tools.ts";
import { HttpError, json, type AuthedContext, type Router } from "../http.ts";
import { permissionsFor, ROLE_LABEL } from "../permissions.ts";
import { checkToolPath, isConfigurableTool, MAX_TOOL_PATH_LENGTH, notConfigurableReason } from "../tool-paths.ts";
import { asObject, oneOf, optionalString, requiredString, TENANT_ID_PATTERN } from "../validate.ts";
import { actorOf, audited, intParam, tenantParam } from "./helpers.ts";

export const AUDIT_VERIFICATIONS_PER_MINUTE = 6;

let cachedCoreVersion: { value: string | null; error: string | null; at: number } | null = null;

async function coreVersion(app: AppContext): Promise<{ value: string | null; error: string | null }> {
  if (cachedCoreVersion && Date.now() - cachedCoreVersion.at < 60_000) return cachedCoreVersion;
  let value: string | null = null;
  let error: string | null = null;
  try {
    const result = await app.cli.runShared(["--version", "--json"], { ttlMs: 60_000, timeoutMs: 10_000 });
    const parsed = result.json as { version?: string } | undefined;
    if (result.code === 0 && parsed?.version) value = parsed.version;
    else error = `sentra --version exited with code ${result.code}`;
  } catch (failure) {
    error = failure instanceof Error ? failure.message : String(failure);
  }
  cachedCoreVersion = { value, error, at: Date.now() };
  return cachedCoreVersion;
}

/** Host facts for the system page (native architecture, OS name, available memory, real runtime). */
export function hostInfo(app: Pick<AppContext, "executables" | "hostPlatform" | "cli">): Promise<HostInfo> {
  return collectHostInfo(app, app.cli.queued);
}

/**
 * Reported tools: located through the executable search snapshot, or at the path an admin set in
 * the console (SENTRA_GH_BIN for gh); nothing is executed.
 */
export function toolAvailability(app: Pick<AppContext, "executables" | "hostPlatform" | "toolPaths" | "config">): Promise<ToolAvailability[]> {
  return describeTools(hostToolsDeps(app));
}

/** One tool's row as GET /api/system reports it. */
async function toolRow(app: AppContext, name: ToolName): Promise<ToolAvailability> {
  const row = (await toolAvailability(app)).find((tool) => tool.name === name);
  if (!row) throw new HttpError(500, "internal_error", `No row for tool ${name}`);
  return row;
}

/** `:name` of the tool routes: one of the reported tools (404 otherwise). */
function toolParam(ctx: AuthedContext): ToolName {
  const name = ctx.params.name ?? "";
  if (!isToolName(name)) throw new HttpError(404, "tool_not_found", "Unknown tool. Paths can be set for the tools listed on the Host & workers page.");
  return name;
}

/** Bound on the raw path recorded on the audit chain for a refused request. */
const AUDITED_PATH_CHARS = MAX_TOOL_PATH_LENGTH + 16;

function sessionInfo(principal: { role: SessionInfo["role"]; label: string; via: SessionInfo["via"] }, expiresAt: string | null): SessionInfo {
  return {
    authenticated: true,
    role: principal.role,
    roleLabel: ROLE_LABEL[principal.role],
    principal: principal.label,
    via: principal.via,
    permissions: permissionsFor(principal.role),
    expiresAt,
  };
}

export function registerCoreRoutes(router: Router, app: AppContext): void {
  // ── health (public, minimal) ────────────────────────────────────────────
  router.get("/api/health", { auth: "public" }, () => {
    // The contract version lets a console loaded from newer (or older) code detect the mismatch.
    const body: HealthResponse = { status: "ok", coreAvailable: app.cli.available(), apiContractVersion: API_CONTRACT_VERSION };
    return json(body);
  });

  // ── authentication ──────────────────────────────────────────────────────
  router.post("/api/auth/login", { auth: "public", maxBodyBytes: 4096 }, async (ctx) => {
    const body = await ctx.readJson();
    const token = requiredString(body, "token", { min: 8, max: 512 });
    const { principal, sessionId, expiresAt } = app.auth.login(token, ctx.ip);
    app.audit.append(principal, { action: "console_login", outcome: "success", details: { ip: ctx.ip } });
    return json(sessionInfo(principal, expiresAt), 200, {
      "Set-Cookie": app.auth.sessionCookie(sessionId, expiresAt, app.config.cookieSecure),
    });
  });

  router.post("/api/auth/logout", { auth: "session", permission: "read" }, (ctx) => {
    app.auth.logout(ctx.principal);
    app.audit.append(ctx.principal, { action: "console_logout", outcome: "success" });
    return json({ ok: true }, 200, { "Set-Cookie": app.auth.clearedCookie(app.config.cookieSecure) });
  });

  router.get("/api/auth/session", { auth: "session", permission: "read" }, (ctx) => {
    let expiresAt: string | null = null;
    if (ctx.principal.sessionIdHash) {
      const row = app.db.query("SELECT expires_at FROM web_sessions WHERE id_hash = ?").get(ctx.principal.sessionIdHash) as {
        expires_at: string;
      } | null;
      expiresAt = row?.expires_at ?? null;
    }
    return json(sessionInfo(ctx.principal, expiresAt));
  });

  // ── system ──────────────────────────────────────────────────────────────
  router.get("/api/system", { auth: "session", permission: "read" }, async () => {
    // The first response waits for the persisted PATH read; later ones use the cached snapshot.
    const snapshot = await app.executables.current();
    const corePresent = app.cli.available();
    const [version, host, tools, coreBinary] = await Promise.all([
      coreVersion(app),
      hostInfo(app),
      describeTools(hostToolsDeps(app), { snapshot }),
      corePresent ? hostArch(app).then((arch) => inspectBinary(app.config.sentraBin, arch)) : Promise.resolve(null),
    ]);
    const ai = app.llm.status();
    const body: SystemStatus = {
      apiContractVersion: API_CONTRACT_VERSION,
      mode: app.config.production ? "production" : "development",
      core: { binaryPath: app.config.sentraBin, present: corePresent, version: version.value, error: version.error, binary: coreBinary },
      dataDir: app.config.dataDir,
      host,
      tools,
      toolSearch: app.executables.status(snapshot),
      integrations: {
        githubCredentialSource: app.github.resolveAuth()?.source ?? null,
        osvEnabled: app.osv.enabled(),
        aiDefaultProvider: ai.defaultProvider,
        aiReadyProviders: ai.providers.filter((provider) => provider.ready).map((provider) => provider.id),
        githubWebhookSecretConfigured: !!app.config.githubWebhookSecret,
        gitlabWebhookTokenConfigured: !!app.config.gitlabWebhookToken,
      },
      auth: {
        configuredGrants: configuredGrantCount(app.config),
        generatedLocalToken: !!app.config.generatedAdminToken,
        bindHost: app.config.host,
        loopbackOnly: app.config.isLoopbackBind,
      },
      remoteWorkers: {
        registry: "not_available",
        note:
          "The Sentra core has no persisted remote-worker registry, so no remote workers exist. Scans parse workspace files without executing them; plugin adapters from SENTRA_PLUGIN_DIR, when configured, run as unsandboxed subprocesses on this host.",
      },
    };
    return json(body);
  });

  router.get("/api/system/host", { auth: "session", permission: "read" }, async () => json(await hostInfo(app)));

  // ── tool paths (reporting only) ─────────────────────────────────────────
  // An admin may tell the bridge where a tool lives when automatic detection cannot find it. The
  // path is only checked (exists, can run on this host, header read) and used for reporting; it is
  // never passed to anything that starts a program. gh (run by the bridge) and bun (runs the
  // bridge) are refused: a path entered in the web console must never become a program the bridge
  // runs, the "command execution through client-supplied paths" issue of the legacy bridge.
  router.put("/api/system/tools/:name", { auth: "session", permission: "settings:write", maxBodyBytes: 8 * 1024 }, async (ctx) => {
    const tool = toolParam(ctx);
    const body = asObject(await ctx.readJson());
    const raw = body.path;
    const check = await audited(
      app,
      ctx.principal,
      { action: "tool_path_configured", target: tool, details: { tool, path: typeof raw === "string" ? raw.slice(0, AUDITED_PATH_CHARS) : null } },
      async () => {
        if (!isConfigurableTool(tool)) throw new HttpError(409, "tool_path_not_configurable", notConfigurableReason(tool));
        if (typeof raw !== "string") throw new HttpError(400, "invalid_request", "'path' is required and must be a string");
        const deps = hostToolsDeps(app);
        const result = await checkToolPath(tool, raw, toolPathProbesFor(deps, await hostArch(deps)));
        if (!result.ok) throw new HttpError(400, "invalid_tool_path", result.problem);
        app.toolPaths.set(tool, result.input, ctx.principal.label);
        return result;
      },
      (result) => ({ path: result.input }),
    );
    const response: SetToolPathResponse = { tool: await toolRow(app, tool), warning: check.warning };
    return json(response);
  });

  router.delete("/api/system/tools/:name", { auth: "session", permission: "settings:write" }, async (ctx) => {
    const tool = toolParam(ctx);
    const previous = isConfigurableTool(tool) ? (app.toolPaths.list()[tool]?.path ?? null) : null;
    await audited(app, ctx.principal, { action: "tool_path_cleared", target: tool, details: { tool, path: previous } }, () => {
      if (!isConfigurableTool(tool)) throw new HttpError(409, "tool_path_not_configurable", notConfigurableReason(tool));
      app.toolPaths.clear(tool, ctx.principal.label);
    });
    const response: SetToolPathResponse = { tool: await toolRow(app, tool), warning: null };
    return json(response);
  });

  // ── tenants ─────────────────────────────────────────────────────────────
  router.get("/api/tenants", { auth: "session", permission: "read" }, async () => {
    const tenants: TenantView[] = [];
    for (const tenant of app.workspaces.list()) tenants.push(await app.workspaces.view(tenant));
    return json({ tenants });
  });

  router.get("/api/tenants/:tenantId", { auth: "session", permission: "read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json(await app.workspaces.view(tenant, ctx.url.searchParams.get("refresh") === "1"));
  });

  router.post("/api/tenants", { auth: "session", permission: "tenant:create" }, async (ctx) => {
    const body = await ctx.readJson();
    const tenantId = requiredString(body, "tenantId", { pattern: TENANT_ID_PATTERN, max: 64 }).toLowerCase();
    const input = {
      tenantId,
      name: requiredString(body, "name", { max: 120 }),
      description: optionalString(body, "description", { max: 500 }) ?? "",
      workspace: requiredString(body, "workspace", { max: 1024 }),
      isolationLevel: oneOf(body.isolationLevel ?? "single_operator", "isolationLevel", ["single_operator", "multi_tenant_isolated"] as const),
      githubRepository: optionalString(body, "githubRepository", { max: 200 }) ?? null,
    };
    const created = await audited(
      app,
      ctx.principal,
      { action: "tenant_registered", tenantId, target: input.workspace, details: { isolationLevel: input.isolationLevel } },
      () => app.workspaces.create(input, actorOf(ctx.principal)),
      (record) => ({ workspace: record.workspace, coreStore: app.workspaces.coreStorePath(record.tenantId) }),
    );
    return json(await app.workspaces.view(created, true), 201);
  });

  router.put("/api/tenants/:tenantId", { auth: "session", permission: "tenant:create" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = asObject(await ctx.readJson());
    const update = {
      name: optionalString(body, "name", { max: 120 }),
      description: body.description === "" ? "" : optionalString(body, "description", { max: 500 }),
      githubRepository: body.githubRepository === null ? null : optionalString(body, "githubRepository", { max: 200 }),
    };
    const updated = await audited(
      app,
      ctx.principal,
      { action: "tenant_updated", tenantId: tenant.tenantId, details: { fields: Object.keys(body) } },
      () => app.workspaces.update(tenant.tenantId, update),
    );
    return json(await app.workspaces.view(updated));
  });

  router.delete("/api/tenants/:tenantId", { auth: "session", permission: "tenant:create" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    await audited(
      app,
      ctx.principal,
      { action: "tenant_unregistered", tenantId: tenant.tenantId, target: tenant.workspace },
      () => app.workspaces.remove(tenant.tenantId),
    );
    return json({ ok: true, coreStoreRetained: app.workspaces.coreStorePath(tenant.tenantId) });
  });

  // ── core store read models ──────────────────────────────────────────────
  router.get("/api/tenants/:tenantId/core", { auth: "session", permission: "read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const limit = intParam(ctx.url.searchParams.get("limit"), "limit", 1, 1000, 200);
    return json(await app.coreStore.audit(tenant, limit, ctx.req.signal));
  });

  router.get("/api/tenants/:tenantId/research/sessions", { auth: "session", permission: "read" }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    return json(await app.coreStore.research(tenant, ctx.req.signal));
  });

  // ── operator audit chain ────────────────────────────────────────────────
  router.get("/api/audit-log", { auth: "session", permission: "read" }, (ctx) => {
    const tenant = ctx.url.searchParams.get("tenant");
    if (tenant !== null && !TENANT_ID_PATTERN.test(tenant)) throw new HttpError(400, "invalid_request", "Invalid tenant id");
    const limit = intParam(ctx.url.searchParams.get("limit"), "limit", 1, 500, 100);
    const beforeRaw = ctx.url.searchParams.get("before");
    const before = beforeRaw ? intParam(beforeRaw, "before", 1, Number.MAX_SAFE_INTEGER, 0) : undefined;
    const entries = app.audit.list({ tenantId: tenant, limit, beforeSeq: before });
    const page: AuditLogPage = {
      entries,
      total: app.audit.count(tenant),
      nextBefore: entries.length === limit ? entries[entries.length - 1].seq : null,
    };
    return json(page);
  });

  // Verification recomputes the whole chain and appends an entry, so it is rate limited per principal.
  const verifyLimiter = new AttemptLimiter(AUDIT_VERIFICATIONS_PER_MINUTE, 60_000);
  router.post("/api/audit-log/verify", { auth: "session", permission: "audit:verify" }, (ctx) => {
    if (!verifyLimiter.hit(`${ctx.principal.role}\u0000${ctx.principal.label}`)) {
      throw markAuditHandled(
        new HttpError(429, "too_many_requests", `The audit chain can be verified at most ${AUDIT_VERIFICATIONS_PER_MINUTE} times a minute per principal.`),
      );
    }
    const result: AuditVerificationView = app.audit.verify();
    app.audit.append(ctx.principal, {
      action: "audit_chain_verified",
      outcome: result.valid ? "success" : "failure",
      details: { checkedEntries: result.checkedEntries, firstInvalidSeq: result.firstInvalidSeq, reason: result.reason },
    });
    return json(result);
  });
}
