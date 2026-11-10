import os from "node:os";
import type {
  AuditLogPage,
  AuditVerificationView,
  HealthResponse,
  HostInfo,
  SessionInfo,
  SystemStatus,
  TenantView,
  ToolAvailability,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { markAuditHandled } from "../audit-log.ts";
import { AttemptLimiter } from "../auth.ts";
import { HttpError, json, type Router } from "../http.ts";
import { permissionsFor, ROLE_LABEL } from "../permissions.ts";
import { asObject, oneOf, optionalString, requiredString, TENANT_ID_PATTERN } from "../validate.ts";
import { actorOf, audited, intParam, tenantParam } from "./helpers.ts";

const TOOL_NAMES = ["git", "gh", "cargo", "bun", "codeql", "semgrep", "osv-scanner", "docker"];
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

export function hostInfo(app: AppContext): HostInfo {
  const cpus = os.cpus();
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpuModel: cpus[0]?.model ?? null,
    cpuCount: cpus.length,
    loadAverage: process.platform === "win32" ? null : os.loadavg(),
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    uptimeSeconds: Math.round(os.uptime()),
    processRssBytes: process.memoryUsage().rss,
    bunVersion: Bun.version,
    cliQueued: app.cli.queued,
    sampledAt: new Date().toISOString(),
  };
}

export function toolAvailability(): ToolAvailability[] {
  return TOOL_NAMES.map((name) => {
    const found = Bun.which(name);
    return { name, available: !!found, path: found ?? null };
  });
}

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
    const body: HealthResponse = { status: "ok", coreAvailable: app.cli.available() };
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
    const version = await coreVersion(app);
    const ai = app.llm.status();
    const body: SystemStatus = {
      mode: app.config.production ? "production" : "development",
      core: { binaryPath: app.config.sentraBin, present: app.cli.available(), version: version.value, error: version.error },
      dataDir: app.config.dataDir,
      host: hostInfo(app),
      tools: toolAvailability(),
      integrations: {
        githubCredentialSource: app.github.resolveAuth()?.source ?? null,
        osvEnabled: app.osv.enabled(),
        aiDefaultProvider: ai.defaultProvider,
        aiReadyProviders: ai.providers.filter((provider) => provider.ready).map((provider) => provider.id),
        githubWebhookSecretConfigured: !!app.config.githubWebhookSecret,
        gitlabWebhookTokenConfigured: !!app.config.gitlabWebhookToken,
      },
      auth: {
        configuredGrants: app.config.tokenGrants.length,
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

  router.get("/api/system/host", { auth: "session", permission: "read" }, () => json(hostInfo(app)));

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
