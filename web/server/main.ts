import fs from "node:fs";
import path from "node:path";
import type { Server } from "bun";
import { AuditLog, isAuditHandled, markAuditHandled } from "./audit-log.ts";
import { AttemptLimiter, AuthService, checkHost, checkOrigin } from "./auth.ts";
import { ConfigError, loadConfig, type ServerConfig } from "./config.ts";
import { openWebDb } from "./db.ts";
import {
  API_SECURITY_HEADERS,
  errorResponse,
  HttpError,
  json,
  readBodyJson,
  readBodyText,
  Router,
  withHeaders,
  type Principal,
  type RouteContext,
  type RouteDefinition,
} from "./http.ts";
import { log } from "./logger.ts";
import { hasPermission } from "./permissions.ts";
import type { AppContext } from "./app-context.ts";
import { registerRoutes } from "./routes/index.ts";
import { SecretStore } from "./secrets.ts";
import { SentraCli } from "./sentra-cli.ts";
import { isWithin } from "./paths.ts";
import { GitHubService } from "./github.ts";
import { LlmGateway } from "./llm.ts";
import { CoreStoreReader } from "./services/core-store.ts";
import { createOsvService } from "./services/osv.ts";
import { createScanService } from "./services/scans.ts";
import { ExecutableLocator } from "./executables.ts";
import { HostPlatform } from "./host-platform.ts";
import { SettingsStore } from "./services/settings-store.ts";
import { TENANT_ID_RE, WorkspaceService } from "./services/workspaces.ts";

const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
export const CSRF_HEADER = "x-sentra-client";
export const CSRF_HEADER_VALUE = "console";

const HTML_SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https://avatars.githubusercontent.com",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; "),
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
};

/**
 * Client address used for login rate limiting and recorded on login audit entries. Behind a
 * trusted reverse proxy it is the right-most `X-Forwarded-For` entry: the address the proxy
 * itself appended for its peer. Entries to the left are whatever the client sent and are
 * never trusted.
 */
export function clientIp(req: Request, server: Pick<Server<unknown>, "requestIP">, config: Pick<ServerConfig, "trustProxy">): string {
  if (config.trustProxy) {
    const forwarded = req.headers.get("x-forwarded-for");
    const last = forwarded
      ?.split(",")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .pop();
    if (last) return last.slice(0, 64);
  }
  return server.requestIP(req)?.address ?? "unknown";
}

/** State-changing requests one principal may send per minute (bounds audit growth and core load). */
export const MUTATIONS_PER_MINUTE = 300;
/** Unauthenticated connections are closed after this many idle seconds (session requests are exempt). */
export const IDLE_TIMEOUT_SECONDS = 30;

const mutationLimiters = new WeakMap<AppContext, AttemptLimiter>();

function mutationLimiter(app: AppContext): AttemptLimiter {
  let limiter = mutationLimiters.get(app);
  if (!limiter) {
    limiter = new AttemptLimiter(MUTATIONS_PER_MINUTE, 60_000);
    mutationLimiters.set(app, limiter);
  }
  return limiter;
}

/**
 * Records a rejected state-changing request of an authenticated principal (origin/CSRF
 * rejections, validation errors, failures outside an audited operation) so every attempted
 * change leaves an entry. Errors whose entry was already written are skipped.
 */
function recordRejection(app: AppContext, principal: Principal, req: Request, route: RouteDefinition | null, params: Record<string, string>, error: unknown): void {
  if (isAuditHandled(error)) return;
  const status = error instanceof HttpError ? error.status : 500;
  const tenantId = params.tenantId && TENANT_ID_RE.test(params.tenantId) ? params.tenantId : null;
  try {
    app.audit.append(principal, {
      action: "request_rejected",
      outcome: status === 401 || status === 403 ? "denied" : "failure",
      tenantId,
      target: `${req.method} ${route?.path ?? new URL(req.url).pathname.slice(0, 200)}`,
      details: {
        status,
        code: error instanceof HttpError ? error.code : "internal_error",
        message: error instanceof HttpError ? error.message.slice(0, 300) : "Internal server error",
      },
    });
  } catch (auditError) {
    log.error("could not record a rejected request", { error: auditError instanceof Error ? auditError.message : String(auditError) });
  }
}

function serveStatic(config: ServerConfig, pathname: string): Response | null {
  if (!config.staticDir) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return new Response("Bad Request", { status: 400 });
  }
  const candidate = path.resolve(config.staticDir, `.${decoded}`);
  if (isWithin(config.staticDir, candidate) && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const file = Bun.file(candidate);
    const immutable = decoded.startsWith("/assets/");
    return withHeaders(new Response(file), {
      ...HTML_SECURITY_HEADERS,
      "Cache-Control": immutable ? "public, max-age=31536000, immutable" : "no-cache",
    });
  }
  // SPA fallback for client-side routes.
  return withHeaders(new Response(Bun.file(path.join(config.staticDir, "index.html"))), {
    ...HTML_SECURITY_HEADERS,
    "Cache-Control": "no-cache",
    "Content-Type": "text/html; charset=utf-8",
  });
}

/** Host services that tests may replace (they otherwise read the real host lazily). */
export type HostServices = Pick<AppContext, "executables" | "hostPlatform">;

export function createHostServices(): HostServices {
  const hostPlatform = new HostPlatform();
  const executables = new ExecutableLocator({
    loadPersisted: () => hostPlatform.persistedPaths(),
    nativeArch: () => hostPlatform.knownNativeArch() ?? hostPlatform.processArch,
  });
  return { executables, hostPlatform };
}

export function createApp(config: ServerConfig, hostServices: HostServices = createHostServices()): { app: AppContext; router: Router } {
  const { executables, hostPlatform } = hostServices;
  const db = openWebDb(config.webDbPath);
  const secrets = new SecretStore(db, config.secretKey);
  const settings = new SettingsStore(db);
  // The CLI always runs from the data directory so cwd-relative defaults (plugin search
  // paths, data/sentra.db) can never resolve into the repository or a workspace.
  const cli = new SentraCli(config.sentraBin, config.dataDir, config.cliTimeoutMs, config.cliMaxConcurrency);
  const workspaces = new WorkspaceService(db, cli, config);
  const partial = {
    config,
    db,
    auth: new AuthService(db, config),
    audit: new AuditLog(db, config.secretKey),
    secrets,
    settings,
    cli,
    llm: new LlmGateway(db, secrets),
    // gh is run only from the process PATH or the persisted PATH, never from a standard install
    // location; the system page reports this same choice in the gh row's usage note.
    github: new GitHubService(secrets, config.githubTokenFromEnv, config.dataDir, { locateGh: () => executables.locateForExecution("gh").path }),
    workspaces,
    coreStore: new CoreStoreReader(cli, workspaces),
    executables,
    hostPlatform,
  };
  const osv = createOsvService(partial);
  const app: AppContext = { ...partial, osv, scans: createScanService({ ...partial, osv }) };
  workspaces.importLegacyTenants(
    () => settings.get<unknown>("legacy_import.tenants", null) !== null,
    (summary) => settings.set("legacy_import.tenants", summary, "system"),
  );
  const router = new Router();
  registerRoutes(router, app);
  return { app, router };
}

export async function handleRequest(
  req: Request,
  server: Pick<Server<unknown>, "requestIP" | "timeout">,
  app: AppContext,
  router: Router,
): Promise<Response> {
  const { config } = app;
  const url = new URL(req.url);

  if (!checkHost(req, config)) {
    return withHeaders(errorResponse(new HttpError(421, "host_not_allowed", "Host header is not allowed")), API_SECURITY_HEADERS);
  }

  if (!url.pathname.startsWith("/api/")) {
    const staticResponse = req.method === "GET" || req.method === "HEAD" ? serveStatic(config, url.pathname) : null;
    return staticResponse ?? withHeaders(errorResponse(new HttpError(404, "not_found", "Not found")), API_SECURITY_HEADERS);
  }

  let principal: Principal | null = null;
  let matchedRoute: RouteDefinition | null = null;
  let routeParams: Record<string, string> = {};
  try {
    const matched = router.match(req.method, url.pathname);
    if (matched === null) throw new HttpError(404, "not_found", "Unknown API route");
    if (matched === "method_not_allowed") throw new HttpError(405, "method_not_allowed", "Method not allowed");
    const { route, params } = matched;
    matchedRoute = route;
    routeParams = params;
    const ip = clientIp(req, server, config);
    const maxBody = route.options.maxBodyBytes ?? config.maxBodyBytes;

    if (route.options.auth === "session") {
      principal = app.auth.authenticate(req);
      if (!principal) throw new HttpError(401, "unauthenticated", "Sign in to the Sentra console first");
      // Authenticated work (core runs, scans, SSE streams) may be silent for minutes; only
      // unauthenticated connections are subject to the idle timeout.
      server.timeout(req, 0);
      if (STATE_CHANGING.has(req.method)) {
        if (!mutationLimiter(app).hit(`${principal.role}\u0000${principal.label}`)) {
          // Not recorded: recording every refused request would defeat the limit.
          throw markAuditHandled(
            new HttpError(429, "too_many_requests", `More than ${MUTATIONS_PER_MINUTE} state-changing requests in a minute. Try again shortly.`),
          );
        }
      }
      if (STATE_CHANGING.has(req.method) && principal.via === "session") {
        if (!checkOrigin(req, config)) throw new HttpError(403, "origin_rejected", "Request origin is not allowed");
        // A custom header cannot be sent cross-site without a CORS preflight, which this
        // server never grants; this also covers state-changing requests without a JSON body.
        if (req.headers.get(CSRF_HEADER) !== CSRF_HEADER_VALUE) {
          throw new HttpError(403, "csrf_header_missing", `State-changing requests must send ${CSRF_HEADER}: ${CSRF_HEADER_VALUE}`);
        }
      }
      const permission = route.options.permission;
      if (!permission || !hasPermission(principal.role, permission)) {
        if (STATE_CHANGING.has(req.method)) {
          app.audit.append(principal, {
            action: "authorization_denied",
            outcome: "denied",
            target: `${req.method} ${route.path}`,
            details: { permission: permission ?? null },
          });
        }
        throw markAuditHandled(new HttpError(403, "forbidden", `Your role (${principal.role}) lacks the '${permission}' permission`));
      }
    } else if (route.options.auth === "public" && STATE_CHANGING.has(req.method) && !checkOrigin(req, config)) {
      throw new HttpError(403, "origin_rejected", "Request origin is not allowed");
    }

    const ctx: RouteContext = {
      req,
      url,
      params,
      principal,
      ip,
      readJson: (limit?: number) => readBodyJson(req, limit ?? maxBody),
      readText: (limit?: number) => readBodyText(req, limit ?? maxBody),
    };
    const response = await route.handler(ctx);
    return withHeaders(response, API_SECURITY_HEADERS);
  } catch (error) {
    if (principal && STATE_CHANGING.has(req.method)) recordRejection(app, principal, req, matchedRoute, routeParams, error);
    if (error instanceof HttpError) {
      if (error.status >= 500) log.warn("request failed", { path: url.pathname, code: error.code, message: error.message });
      return withHeaders(errorResponse(error), API_SECURITY_HEADERS);
    }
    log.error("unhandled request error", { path: url.pathname, error: error instanceof Error ? error.stack ?? error.message : String(error) });
    return withHeaders(json({ error: { code: "internal_error", message: "Internal server error" } }, 500), API_SECURITY_HEADERS);
  }
}

export function startServer(): Server<unknown> {
  let config: ServerConfig;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      log.error("invalid configuration", { error: error.message });
      process.exit(78);
    }
    throw error;
  }
  const { app, router } = createApp(config);
  // Warm the executable search (persisted PATH read) and host detection without blocking startup.
  // The first GitHub credential lookup may run before this finishes; it then sees the process PATH only.
  void app.executables.refresh();
  void app.hostPlatform.nativeArch();
  void app.hostPlatform.osName();

  const server = Bun.serve({
    hostname: config.host,
    port: config.port,
    // Webhook payloads can reach 25 MB; per-route limits are enforced while reading bodies.
    maxRequestBodySize: Math.max(config.maxBodyBytes, 26 * 1024 * 1024),
    // Slow or stalled unauthenticated senders (webhooks, login, static files) are disconnected;
    // handleRequest lifts the limit for authenticated requests.
    idleTimeout: IDLE_TIMEOUT_SECONDS,
    development: false,
    fetch(req, srv) {
      return handleRequest(req, srv, app, router);
    },
    error(error) {
      log.error("server error", { error: error.message });
      return json({ error: { code: "internal_error", message: "Internal server error" } }, 500);
    },
  });

  log.info("sentra web bridge listening", {
    url: `http://${config.host.includes(":") ? `[${config.host}]` : config.host}:${server.port}`,
    mode: config.production ? "production" : "development",
    staticAssets: config.staticDir ?? "disabled (use the Vite dev server)",
    sentraBinary: config.sentraBin,
    sentraBinaryPresent: app.cli.available(),
    dataDir: config.dataDir,
    tokenGrants: config.tokenGrants.map((grant) => `${grant.role}:${grant.label}`),
  });
  const labels = config.tokenGrants.map((grant) => grant.label);
  const sharedLabels = [...new Set(labels.filter((label, index) => labels.indexOf(label) !== index))];
  if (sharedLabels.length > 0) {
    log.warn("several token grants share a label; audit entries cannot tell those tokens apart (use role:label:token)", {
      labels: sharedLabels,
    });
  }
  if (config.generatedAdminToken) {
    // Printed directly (not through the redacting logger) so the local operator can sign in.
    // The token travels in the URL fragment, which browsers never send to the server.
    const consoleUrl = config.staticDir ? `http://127.0.0.1:${server.port}` : "http://localhost:5173";
    console.log(
      [
        "",
        "[sentra-web] No SENTRA_WEB_TOKENS configured: a loopback-only admin token is in use.",
        `  token file : ${path.join(config.dataDir, "web-admin.token")}`,
        `  sign in    : ${consoleUrl}/#token=${config.generatedAdminToken}`,
        "",
      ].join("\n"),
    );
  }

  const shutdown = (signal: string) => {
    log.info("shutting down", { signal });
    server.stop();
    try {
      app.db.close();
    } catch {
      // already closed
    }
    process.exit(0);
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  return server;
}
