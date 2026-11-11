import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import type { RepositoryRef, ScanRunView, WebhookConfigView, WebhookDeliveryStatus, WebhookDeliveryView } from "../../src/types/api.ts";
import { nowIso } from "../db.ts";
import type { GitHeadInfo } from "../git-meta.ts";
import { HttpError } from "../http-error.ts";
import { log } from "../logger.ts";
import { normalizeDeliveryId, verifyGitHubSignature, verifyGitLabToken } from "../webhook-verify.ts";
import type { TenantRecord } from "./workspaces.ts";
import { SYSTEM_ACTOR, type ActorRef, type ScanService } from "./types.ts";

/**
 * Authenticated webhook intake for GitHub (HMAC-SHA256 over the raw body) and GitLab (shared
 * token). Unauthenticated requests are only counted in memory; authenticated deliveries are
 * persisted once per (provider, delivery id). A push to a repository bound to a registered
 * tenant triggers a SAST scan of that tenant's LOCAL checkout: the bridge never fetches or
 * pulls, so each delivery records whether the checkout HEAD equals the pushed commit.
 */

export const WEBHOOK_MAX_BODY_BYTES = 25 * 1024 * 1024;

/**
 * GitHub deliveries can only be authenticated after the whole body was read (the HMAC covers
 * it), so at most this many such reads run at once; further senders get 429 instead of making
 * the bridge buffer many large unauthenticated bodies in parallel.
 */
export const MAX_UNVERIFIED_BODY_READS = 4;

const GITHUB_SIGNATURE_SHAPE = /^sha256=[0-9a-f]{64}$/i;

export type WebhookProvider = "github" | "gitlab";

export interface WebhookResult {
  httpStatus: number;
  body: { status: WebhookDeliveryStatus; deliveryId: string; detail: string | null; tenants?: string[] };
  /** Resolves when background scans finished (tests await it; the route does not). */
  background: Promise<void> | null;
}

export interface WebhookIntakeDeps {
  db: Database;
  githubSecret: string | null;
  gitlabToken: string | null;
  bindHost: string;
  tenants: () => TenantRecord[];
  /** Configured or git-remote-detected GitHub repository of a tenant. */
  githubRepositoryOf: (tenant: TenantRecord) => RepositoryRef | null;
  /** URL of the tenant workspace's `origin` remote, read from `.git/config`. */
  originUrlOf: (tenant: TenantRecord) => string | null;
  /** HEAD of the tenant workspace, read from `.git` without executing git. */
  headOf: (tenant: TenantRecord) => GitHeadInfo | null;
  scans: ScanService;
  audit: (actor: ActorRef, entry: { action: string; outcome: "success" | "failure"; tenantId: string | null; target: string | null; details: Record<string, unknown> }) => void;
}

interface DeliveryRecord {
  provider: WebhookProvider;
  deliveryId: string;
  eventType: string;
  repository: string | null;
  ref: string | null;
  afterSha: string | null;
  sender: string | null;
  payloadSha256: string;
}

interface DeliveryRow {
  provider: WebhookProvider;
  delivery_id: string;
  event_type: string;
  received_at: string;
  repository: string | null;
  ref: string | null;
  after_sha: string | null;
  sender: string | null;
  signature_valid: number;
  status: WebhookDeliveryStatus;
  detail: string | null;
  tenant_id: string | null;
  run_id: string | null;
}

// ───────────────────────────── pure helpers ─────────────────────────────

const ZERO_SHA = /^0+$/;
const MAX_DETAIL = 4000;

function text(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  // oxlint-disable-next-line no-control-regex -- intentional: rejects header values that contain control characters
  if (!trimmed || /[\u0000-\u001f\u007f]/.test(trimmed)) return null;
  return trimmed.slice(0, max);
}

function sha(value: unknown): string | null {
  return typeof value === "string" && /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(value) ? value : null;
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

/**
 * Parses a webhook body. GitHub can deliver `application/x-www-form-urlencoded` with the JSON
 * in a `payload` field; the signature always covers the raw body as received.
 */
export function parseWebhookPayload(rawBody: string, contentType: string | null): Record<string, unknown> {
  let jsonText = rawBody;
  if ((contentType ?? "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    const payload = new URLSearchParams(rawBody).get("payload");
    if (payload === null) throw new HttpError(400, "invalid_payload", "Form-encoded delivery without a 'payload' field");
    jsonText = payload;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new HttpError(400, "invalid_payload", "Webhook payload is not valid JSON");
  }
  const result = object(parsed);
  if (!result) throw new HttpError(400, "invalid_payload", "Webhook payload must be a JSON object");
  return result;
}

/** Host and path of a git remote URL (https, ssh:// or scp-like), lower-cased, without `.git`. */
export function parseRemoteHostPath(url: string): { host: string; path: string } | null {
  const trimmed = url.trim();
  let host: string | null = null;
  let rawPath: string | null = null;
  const scp = trimmed.match(/^(?:[^@/\s]+@)?([^:/\s]+):(?!\/\/)(.+)$/);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      if (!["https:", "http:", "ssh:", "git:"].includes(parsed.protocol)) return null;
      host = parsed.hostname;
      rawPath = decodeURIComponent(parsed.pathname);
    } catch {
      return null;
    }
  } else if (scp && !/^[A-Za-z]$/.test(scp[1])) {
    host = scp[1];
    rawPath = scp[2];
  }
  if (!host || rawPath === null) return null;
  const normalizedPath = rawPath.replace(/^\/+/, "").replace(/\/+$/, "").replace(/\.git$/i, "").toLowerCase();
  if (!normalizedPath || normalizedPath.split("/").some((segment) => !segment || segment === "." || segment === "..")) return null;
  return { host: host.toLowerCase().replace(/^\[|\]$/g, ""), path: normalizedPath };
}

/** Tenants whose GitHub repository (configured or from the origin remote) equals `fullName`. */
export function matchGitHubTenants(
  fullName: string,
  tenants: readonly TenantRecord[],
  repositoryOf: (tenant: TenantRecord) => RepositoryRef | null,
): TenantRecord[] {
  const wanted = fullName.toLowerCase();
  return tenants.filter((tenant) => {
    try {
      const repo = repositoryOf(tenant);
      return !!repo && `${repo.owner}/${repo.repo}`.toLowerCase() === wanted;
    } catch {
      return false;
    }
  });
}

/** Tenants whose origin remote points at the GitLab project (same host and namespace path). */
export function matchGitLabTenants(
  project: { pathWithNamespace: string; webUrl: string },
  tenants: readonly TenantRecord[],
  originUrlOf: (tenant: TenantRecord) => string | null,
): TenantRecord[] {
  let host: string;
  try {
    host = new URL(project.webUrl).hostname.toLowerCase();
  } catch {
    return [];
  }
  const wantedPath = project.pathWithNamespace.toLowerCase().replace(/^\/+|\/+$/g, "");
  return tenants.filter((tenant) => {
    try {
      const origin = originUrlOf(tenant);
      const parsed = origin ? parseRemoteHostPath(origin) : null;
      return !!parsed && parsed.host === host && parsed.path === wantedPath;
    } catch {
      return false;
    }
  });
}

/**
 * States whether a scan of the local checkout corresponds to the pushed commit.
 * `matchesPush` is null when either side is unknown.
 */
export function checkoutComparison(
  head: GitHeadInfo | null,
  afterSha: string | null,
  ref: string | null,
): { matchesPush: boolean | null; detail: string } {
  const pushedBranch = ref?.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : null;
  if (!head || !head.sha) {
    return {
      matchesPush: null,
      detail: "local checkout HEAD could not be read; the scan reflects the files on disk, which may not match the pushed commit",
    };
  }
  const local = `${head.sha.slice(0, 12)}${head.branch ? ` on branch ${head.branch}` : " (detached)"}`;
  if (!afterSha) {
    return { matchesPush: null, detail: `the delivery carried no pushed commit sha; the scan reflects the local checkout HEAD ${local}` };
  }
  if (head.sha === afterSha) {
    return { matchesPush: true, detail: `local checkout HEAD ${local} equals the pushed commit ${afterSha.slice(0, 12)}` };
  }
  const branchNote = pushedBranch && head.branch && head.branch !== pushedBranch ? ` (the push was to branch ${pushedBranch})` : "";
  return {
    matchesPush: false,
    detail: `local checkout HEAD ${local} differs from the pushed commit ${afterSha.slice(0, 12)}${branchNote}; the bridge never fetches or pulls, so the scan reflects the local checkout, not the pushed commit`,
  };
}

function clip(value: string): string {
  return value.length > MAX_DETAIL ? `${value.slice(0, MAX_DETAIL - 1)}…` : value;
}

function fromRow(row: DeliveryRow): WebhookDeliveryView {
  return {
    provider: row.provider,
    deliveryId: row.delivery_id,
    eventType: row.event_type,
    receivedAt: row.received_at,
    repository: row.repository,
    ref: row.ref,
    afterSha: row.after_sha,
    sender: row.sender,
    signatureValid: row.signature_valid === 1,
    status: row.status,
    detail: row.detail,
    tenantId: row.tenant_id,
    runId: row.run_id,
  };
}

// ───────────────────────────── intake ─────────────────────────────

export class WebhookIntake {
  private readonly deps: WebhookIntakeDeps;
  private rejected = 0;
  private lastRejectedAt: string | null = null;
  private unverifiedReads = 0;

  constructor(deps: WebhookIntakeDeps) {
    this.deps = deps;
  }

  config(): WebhookConfigView {
    return {
      github: { path: "/api/webhook/github", secretConfigured: !!this.deps.githubSecret },
      gitlab: { path: "/api/webhook/gitlab", tokenConfigured: !!this.deps.gitlabToken },
      bindHost: this.deps.bindHost,
      rejectedSinceStart: this.rejected,
      lastRejectedAt: this.lastRejectedAt,
      note: [
        "GitHub and GitLab can only deliver to an address they can reach. This bridge binds to",
        `${this.deps.bindHost} by default, so expose it through a public HTTPS reverse proxy or tunnel,`,
        "add the public host to SENTRA_WEB_ALLOWED_HOSTS, and configure the shared secret",
        "(SENTRA_GITHUB_WEBHOOK_SECRET / SENTRA_GITLAB_WEBHOOK_TOKEN) on both sides.",
        "Pushes trigger a scan of the registered tenant's local checkout; the bridge never fetches or pulls.",
      ].join(" "),
    };
  }

  deliveries(limit: number): WebhookDeliveryView[] {
    const rows = this.deps.db
      .query("SELECT * FROM webhook_deliveries ORDER BY received_at DESC, rowid DESC LIMIT ?")
      .all(limit) as DeliveryRow[];
    return rows.map(fromRow);
  }

  private reject(provider: WebhookProvider, reason: string): never {
    this.rejected += 1;
    this.lastRejectedAt = nowIso();
    log.warn("webhook delivery rejected", { provider, reason });
    throw new HttpError(401, "invalid_signature", `Webhook authentication failed: ${reason}`);
  }

  async receiveGitHub(headers: Headers, readBody: () => Promise<string>): Promise<WebhookResult> {
    const secret = this.deps.githubSecret;
    if (!secret) {
      throw new HttpError(503, "webhook_not_configured", "GitHub webhooks are disabled: SENTRA_GITHUB_WEBHOOK_SECRET is not set on this bridge");
    }
    // Everything that does not depend on the body is checked before the body is read.
    const signature = headers.get("x-hub-signature-256");
    if (!signature) this.reject("github", "missing X-Hub-Signature-256 header");
    if (!GITHUB_SIGNATURE_SHAPE.test(signature.trim())) this.reject("github", "malformed X-Hub-Signature-256 header");
    const deliveryId = normalizeDeliveryId(headers.get("x-github-delivery"));
    if (!deliveryId) throw new HttpError(400, "invalid_delivery", "Missing or malformed X-GitHub-Delivery header");
    const event = headers.get("x-github-event")?.trim() ?? "";
    if (!/^[a-z_]{1,64}$/.test(event)) throw new HttpError(400, "invalid_delivery", "Missing or malformed X-GitHub-Event header");

    const rawBody = await this.readUnverified(readBody);
    if (!verifyGitHubSignature(secret, rawBody, signature.trim())) this.reject("github", "X-Hub-Signature-256 does not match the body");
    if (this.exists("github", deliveryId)) return this.duplicate(deliveryId);

    const payloadSha256 = crypto.createHash("sha256").update(rawBody, "utf8").digest("hex");
    const payload = this.parseOrRecord({ provider: "github", deliveryId, eventType: event, payloadSha256 }, () =>
      parseWebhookPayload(rawBody, headers.get("content-type")),
    );
    const repository = object(payload.repository);
    const record: DeliveryRecord = {
      provider: "github",
      deliveryId,
      eventType: event,
      repository: text(repository?.full_name, 200),
      ref: text(payload.ref, 255),
      afterSha: sha(payload.after),
      sender: text(object(payload.sender)?.login, 100),
      payloadSha256,
    };

    if (event === "ping") {
      const hookId = typeof payload.hook_id === "number" ? payload.hook_id : null;
      return this.finish(record, "accepted", `ping received${hookId !== null ? ` for hook ${hookId}` : ""}; no automated action`, 200);
    }
    if (event !== "push") return this.finish(record, "ignored", "event recorded; no automated action", 200);
    if (payload.deleted === true || (typeof payload.after === "string" && ZERO_SHA.test(payload.after))) {
      return this.finish(record, "ignored", "push deleted a ref; nothing to scan", 200);
    }
    if (!record.repository) return this.finish(record, "ignored", "push payload names no repository", 200);
    const tenants = matchGitHubTenants(record.repository, this.deps.tenants(), this.deps.githubRepositoryOf);
    return this.dispatchPush(record, tenants);
  }

  async receiveGitLab(headers: Headers, readBody: () => Promise<string>): Promise<WebhookResult> {
    const token = this.deps.gitlabToken;
    if (!token) {
      throw new HttpError(503, "webhook_not_configured", "GitLab webhooks are disabled: SENTRA_GITLAB_WEBHOOK_TOKEN is not set on this bridge");
    }
    // The token is a header, so the sender is authenticated before any body byte is read.
    const presented = headers.get("x-gitlab-token");
    if (!presented) this.reject("gitlab", "missing X-Gitlab-Token header");
    if (!verifyGitLabToken(token, presented)) this.reject("gitlab", "X-Gitlab-Token does not match");

    const eventHeader = headers.get("x-gitlab-event")?.trim() ?? "";
    if (!/^[A-Za-z ]{1,64}$/.test(eventHeader)) throw new HttpError(400, "invalid_delivery", "Missing or malformed X-Gitlab-Event header");
    const rawBody = await readBody();
    const payloadSha256 = crypto.createHash("sha256").update(rawBody, "utf8").digest("hex");
    // X-Gitlab-Webhook-UUID identifies the hook configuration rather than one delivery on some
    // GitLab versions, so it is not used for de-duplication.
    const deliveryId =
      normalizeDeliveryId(headers.get("x-gitlab-event-uuid")) ??
      normalizeDeliveryId(headers.get("idempotency-key")) ??
      `body-sha256-${payloadSha256}`;
    if (this.exists("gitlab", deliveryId)) return this.duplicate(deliveryId);

    const headerEvent = eventHeader.toLowerCase().replace(/ /g, "_");
    const payload = this.parseOrRecord({ provider: "gitlab", deliveryId, eventType: headerEvent, payloadSha256 }, () =>
      parseWebhookPayload(rawBody, "application/json"),
    );
    const objectKind = text(payload.object_kind, 64);
    const event = objectKind && /^[a-z_]{1,64}$/.test(objectKind) ? objectKind : headerEvent;
    const project = object(payload.project);
    const record: DeliveryRecord = {
      provider: "gitlab",
      deliveryId,
      eventType: event,
      repository: text(project?.path_with_namespace, 200),
      ref: text(payload.ref, 255),
      afterSha: sha(payload.after) ?? sha(payload.checkout_sha),
      sender: text(payload.user_username, 100) ?? text(payload.user_name, 100),
      payloadSha256,
    };

    if (event !== "push") return this.finish(record, "ignored", "event recorded; no automated action", 200);
    if (typeof payload.after === "string" && ZERO_SHA.test(payload.after)) {
      return this.finish(record, "ignored", "push deleted a branch; nothing to scan", 200);
    }
    const webUrl = text(project?.web_url, 500);
    if (!record.repository || !webUrl) return this.finish(record, "ignored", "push payload names no project path or web URL", 200);
    const tenants = matchGitLabTenants({ pathWithNamespace: record.repository, webUrl }, this.deps.tenants(), this.deps.originUrlOf);
    return this.dispatchPush(record, tenants);
  }

  /** Reads a body that can only be authenticated afterwards, within the concurrency cap. */
  private async readUnverified(readBody: () => Promise<string>): Promise<string> {
    if (this.unverifiedReads >= MAX_UNVERIFIED_BODY_READS) {
      throw new HttpError(429, "webhook_busy", "Too many webhook deliveries are being received at once; redeliver later");
    }
    this.unverifiedReads += 1;
    try {
      return await readBody();
    } finally {
      this.unverifiedReads -= 1;
    }
  }

  private exists(provider: WebhookProvider, deliveryId: string): boolean {
    return this.deps.db.query("SELECT 1 AS present FROM webhook_deliveries WHERE provider = ? AND delivery_id = ?").get(provider, deliveryId) !== null;
  }

  /** Authenticated deliveries with an unreadable payload are recorded as rejected, then refused. */
  private parseOrRecord(
    partial: Pick<DeliveryRecord, "provider" | "deliveryId" | "eventType" | "payloadSha256">,
    parse: () => Record<string, unknown>,
  ): Record<string, unknown> {
    try {
      return parse();
    } catch (error) {
      if (error instanceof HttpError) {
        this.insert({ ...partial, repository: null, ref: null, afterSha: null, sender: null }, "rejected", error.message, null);
      }
      throw error;
    }
  }

  private duplicate(deliveryId: string): WebhookResult {
    return {
      httpStatus: 200,
      body: { status: "duplicate", deliveryId, detail: "delivery id already processed; ignored" },
      background: null,
    };
  }

  /** Inserts the delivery; a concurrent insert of the same id reads as a duplicate. */
  private insert(record: DeliveryRecord, status: WebhookDeliveryStatus, detail: string, tenantId: string | null): boolean {
    const result = this.deps.db
      .query(
        `INSERT OR IGNORE INTO webhook_deliveries (provider, delivery_id, event_type, received_at, repository, ref, after_sha, sender,
           signature_valid, status, detail, tenant_id, run_id, payload_sha256)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, ?)`,
      )
      .run(
        record.provider,
        record.deliveryId,
        record.eventType,
        nowIso(),
        record.repository,
        record.ref,
        record.afterSha,
        record.sender,
        status,
        clip(detail),
        tenantId,
        record.payloadSha256,
      );
    return result.changes > 0;
  }

  private finish(record: DeliveryRecord, status: WebhookDeliveryStatus, detail: string, httpStatus: number): WebhookResult {
    if (!this.insert(record, status, detail, null)) return this.duplicate(record.deliveryId);
    return { httpStatus, body: { status, deliveryId: record.deliveryId, detail }, background: null };
  }

  private dispatchPush(record: DeliveryRecord, tenants: TenantRecord[]): WebhookResult {
    if (tenants.length === 0) {
      return this.finish(record, "ignored", `no registered tenant is bound to ${record.repository}; nothing scanned`, 200);
    }
    const ids = tenants.map((tenant) => tenant.tenantId);
    const detail = `push accepted; queued SAST scans of the local checkout for tenant(s): ${ids.join(", ")}`;
    if (!this.insert(record, "accepted", detail, ids[0])) return this.duplicate(record.deliveryId);
    const background = this.scanTenants(record, tenants).catch((error) => {
      log.error("webhook scan dispatch failed", { deliveryId: record.deliveryId, error: error instanceof Error ? error.message : String(error) });
    });
    return { httpStatus: 202, body: { status: "accepted", deliveryId: record.deliveryId, detail, tenants: ids }, background };
  }

  private async scanTenants(record: DeliveryRecord, tenants: TenantRecord[]): Promise<void> {
    const actor: ActorRef = { label: `webhook:${record.provider}`, role: SYSTEM_ACTOR.role };
    const notes: string[] = [];
    let completed = 0;
    let failed = 0;
    let firstRunId: string | null = null;
    for (const tenant of tenants) {
      let head: GitHeadInfo | null;
      try {
        head = this.deps.headOf(tenant);
      } catch {
        head = null;
      }
      const { matchesPush, detail: comparison } = checkoutComparison(head, record.afterSha, record.ref);
      if (this.deps.scans.isRunning(tenant.tenantId)) {
        notes.push(`tenant ${tenant.tenantId}: skipped, a scan is already running`);
        continue;
      }
      let run: ScanRunView | null = null;
      let error: string | null = null;
      try {
        run = await this.deps.scans.run({ tenantId: tenant.tenantId, kind: "sast", trigger: "webhook", actor: SYSTEM_ACTOR });
      } catch (scanError) {
        error = scanError instanceof HttpError ? `${scanError.code}: ${scanError.message}` : scanError instanceof Error ? scanError.message : String(scanError);
      }
      if (run && run.status === "completed") {
        completed += 1;
        firstRunId ??= run.runId;
        notes.push(
          `tenant ${tenant.tenantId}: scan ${run.runId} completed (${run.filesScanned ?? 0} files, ${run.signalsFound ?? 0} signals); ${comparison}`,
        );
      } else {
        failed += 1;
        if (run) firstRunId ??= run.runId;
        const reason = error ?? run?.error ?? `scan ended with status ${run?.status ?? "unknown"}`;
        notes.push(`tenant ${tenant.tenantId}: scan${run ? ` ${run.runId}` : ""} failed: ${reason}; ${comparison}`);
      }
      this.deps.audit(actor, {
        action: "webhook_scan",
        outcome: run && run.status === "completed" ? "success" : "failure",
        tenantId: tenant.tenantId,
        target: record.repository,
        details: {
          provider: record.provider,
          deliveryId: record.deliveryId,
          ref: record.ref,
          afterSha: record.afterSha,
          runId: run?.runId ?? null,
          checkoutMatchesPush: matchesPush,
          ...(error ? { error } : {}),
        },
      });
    }
    const status: WebhookDeliveryStatus = failed > 0 ? "failed" : completed > 0 ? "scanned" : "ignored";
    this.deps.db
      .query("UPDATE webhook_deliveries SET status = ?, detail = ?, run_id = ? WHERE provider = ? AND delivery_id = ?")
      .run(status, clip(notes.join(" | ")), firstRunId, record.provider, record.deliveryId);
  }
}
