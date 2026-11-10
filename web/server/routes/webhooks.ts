import type { WebhookConfigView, WebhookDeliveryView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { readHead, readRemoteUrl } from "../git-meta.ts";
import { json, type Router } from "../http.ts";
import { WEBHOOK_MAX_BODY_BYTES, WebhookIntake, type WebhookResult } from "../services/webhooks.ts";
import { intParam } from "./helpers.ts";

function respond(result: WebhookResult): Response {
  return json(result.body, result.httpStatus);
}

export function registerWebhookRoutes(router: Router, app: AppContext): void {
  const intake = new WebhookIntake({
    db: app.db,
    githubSecret: app.config.githubWebhookSecret,
    gitlabToken: app.config.gitlabWebhookToken,
    bindHost: app.config.host,
    tenants: () => app.workspaces.list(),
    githubRepositoryOf: (tenant) => app.workspaces.repository(tenant),
    originUrlOf: (tenant) => readRemoteUrl(tenant.workspace),
    headOf: (tenant) => readHead(tenant.workspace),
    scans: app.scans,
    audit: (actor, entry) => app.audit.append(actor, entry),
  });

  // ── intake (authenticated by HMAC / shared token inside the handler, never by cookies) ──
  router.post("/api/webhook/github", { auth: "webhook", maxBodyBytes: WEBHOOK_MAX_BODY_BYTES }, async (ctx) =>
    respond(await intake.receiveGitHub(ctx.req.headers, () => ctx.readText(WEBHOOK_MAX_BODY_BYTES))),
  );

  router.post("/api/webhook/gitlab", { auth: "webhook", maxBodyBytes: WEBHOOK_MAX_BODY_BYTES }, async (ctx) =>
    respond(await intake.receiveGitLab(ctx.req.headers, () => ctx.readText(WEBHOOK_MAX_BODY_BYTES))),
  );

  // ── console views ───────────────────────────────────────────────────────
  router.get("/api/webhooks/deliveries", { auth: "session", permission: "read" }, (ctx) => {
    const limit = intParam(ctx.url.searchParams.get("limit"), "limit", 1, 500, 100);
    const deliveries: WebhookDeliveryView[] = intake.deliveries(limit);
    return json({ deliveries });
  });

  router.get("/api/webhooks/config", { auth: "session", permission: "read" }, () => {
    const view: WebhookConfigView = intake.config();
    return json(view);
  });
}
