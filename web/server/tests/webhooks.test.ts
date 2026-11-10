import { afterAll, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { RepositoryRef, ScanRunView } from "../../src/types/api.ts";
import { openWebDb } from "../db.ts";
import type { GitHeadInfo } from "../git-meta.ts";
import { HttpError } from "../http-error.ts";
import type { ScanRunInput, ScanService } from "../services/types.ts";
import {
  checkoutComparison,
  matchGitHubTenants,
  matchGitLabTenants,
  parseRemoteHostPath,
  parseWebhookPayload,
  WebhookIntake,
  type WebhookIntakeDeps,
} from "../services/webhooks.ts";
import type { TenantRecord } from "../services/workspaces.ts";

const SECRET = "webhook-secret-for-tests";
const GITLAB_TOKEN = "gitlab-token-for-tests";
const AFTER = "c".repeat(40);
const OTHER = "d".repeat(40);

const created: { dir: string; db: Database }[] = [];

afterAll(() => {
  for (const entry of created) {
    try {
      entry.db.close();
    } catch {
      // already closed
    }
    fs.rmSync(entry.dir, { recursive: true, force: true });
  }
});

function tenant(tenantId: string, overrides: Partial<TenantRecord> = {}): TenantRecord {
  return {
    tenantId,
    name: tenantId,
    description: "",
    workspace: `/workspaces/${tenantId}`,
    isolationLevel: "single_operator",
    githubOwner: null,
    githubRepo: null,
    createdAt: "2026-11-10T00:00:00.000Z",
    createdBy: "admin",
    importedFrom: null,
    ...overrides,
  };
}

function runView(input: ScanRunInput, status: ScanRunView["status"], error: string | null = null): ScanRunView {
  return {
    runId: `run-${input.tenantId}`,
    tenantId: input.tenantId,
    workspace: `/workspaces/${input.tenantId}`,
    kind: input.kind,
    trigger: input.trigger,
    status,
    startedAt: "2026-11-10T00:00:00.000Z",
    finishedAt: "2026-11-10T00:00:01.000Z",
    actor: input.actor.label,
    filesScanned: 12,
    signalsFound: 3,
    packagesAudited: null,
    vulnerablePackages: null,
    gitHead: null,
    error,
    summary: null,
  };
}

interface Harness {
  intake: WebhookIntake;
  db: Database;
  scanCalls: ScanRunInput[];
  audits: { action: string; outcome: string; tenantId: string | null; details: Record<string, unknown> }[];
}

function harness(
  options: {
    githubSecret?: string | null;
    gitlabToken?: string | null;
    tenants?: TenantRecord[];
    repos?: Record<string, RepositoryRef | null>;
    origins?: Record<string, string | null>;
    heads?: Record<string, GitHeadInfo | null>;
    running?: string[];
    scanOutcome?: (input: ScanRunInput) => ScanRunView | Error;
    /** Scans wait for this promise, so tests can observe the accepted state first. */
    gate?: Promise<void>;
  } = {},
): Harness {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentra-webhook-"));
  const db = openWebDb(path.join(dir, "web.db"));
  created.push({ dir, db });
  const scanCalls: ScanRunInput[] = [];
  const audits: Harness["audits"] = [];
  const scans: ScanService = {
    isRunning: (tenantId) => (options.running ?? []).includes(tenantId),
    run: async (input) => {
      scanCalls.push(input);
      if (options.gate) await options.gate;
      const outcome = options.scanOutcome ? options.scanOutcome(input) : runView(input, "completed");
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  };
  const deps: WebhookIntakeDeps = {
    db,
    githubSecret: options.githubSecret === undefined ? SECRET : options.githubSecret,
    gitlabToken: options.gitlabToken === undefined ? GITLAB_TOKEN : options.gitlabToken,
    bindHost: "127.0.0.1",
    tenants: () => options.tenants ?? [],
    githubRepositoryOf: (record) => options.repos?.[record.tenantId] ?? null,
    originUrlOf: (record) => options.origins?.[record.tenantId] ?? null,
    headOf: (record) => options.heads?.[record.tenantId] ?? null,
    scans,
    audit: (_actor, entry) => audits.push({ action: entry.action, outcome: entry.outcome, tenantId: entry.tenantId, details: entry.details }),
  };
  return { intake: new WebhookIntake(deps), db, scanCalls, audits };
}

function sign(body: string, secret = SECRET): string {
  return `sha256=${crypto.createHmac("sha256", secret).update(body).digest("hex")}`;
}

function githubHeaders(body: string, overrides: Record<string, string | null> = {}): Headers {
  const values: Record<string, string | null> = {
    "content-type": "application/json",
    "x-github-event": "push",
    "x-github-delivery": crypto.randomUUID(),
    "x-hub-signature-256": sign(body),
    ...overrides,
  };
  const headers = new Headers();
  for (const [key, value] of Object.entries(values)) if (value !== null) headers.set(key, value);
  return headers;
}

function pushBody(fullName = "Octo/App", after = AFTER): string {
  return JSON.stringify({ ref: "refs/heads/main", after, repository: { full_name: fullName }, sender: { login: "octocat" } });
}

function rows(db: Database) {
  return db.query("SELECT * FROM webhook_deliveries ORDER BY received_at").all() as {
    delivery_id: string;
    status: string;
    detail: string | null;
    tenant_id: string | null;
    run_id: string | null;
    signature_valid: number;
    payload_sha256: string;
    repository: string | null;
    after_sha: string | null;
    sender: string | null;
  }[];
}

describe("github signature handling", () => {
  test("an unconfigured secret disables the endpoint (503) without reading the body", async () => {
    const { intake, db } = harness({ githubSecret: null });
    let read = false;
    const failure = await intake
      .receiveGitHub(githubHeaders("{}"), async () => {
        read = true;
        return "{}";
      })
      .catch((error: unknown) => error);
    expect(failure).toMatchObject({ status: 503, code: "webhook_not_configured" });
    expect(read).toBe(false);
    expect(rows(db)).toHaveLength(0);
  });

  test("missing and invalid signatures are rejected, counted in memory and never persisted", async () => {
    const { intake, db } = harness();
    const body = pushBody();
    const missing = await intake.receiveGitHub(githubHeaders(body, { "x-hub-signature-256": null }), async () => body).catch((error: unknown) => error);
    expect(missing).toMatchObject({ status: 401, code: "invalid_signature" });
    const wrong = await intake
      .receiveGitHub(githubHeaders(body, { "x-hub-signature-256": sign(body, "another-secret") }), async () => body)
      .catch((error: unknown) => error);
    expect(wrong).toMatchObject({ status: 401 });
    const tampered = await intake
      .receiveGitHub(githubHeaders(body), async () => body.replace("octocat", "mallory"))
      .catch((error: unknown) => error);
    expect(tampered).toMatchObject({ status: 401 });
    expect(rows(db)).toHaveLength(0);
    const config = intake.config();
    expect(config.rejectedSinceStart).toBe(3);
    expect(config.lastRejectedAt).not.toBeNull();
    expect(config.github.secretConfigured).toBe(true);
    expect(config.note).toContain("reverse proxy");
  });

  test("a valid signature without a delivery id is refused", async () => {
    const { intake } = harness();
    const body = pushBody();
    await expect(intake.receiveGitHub(githubHeaders(body, { "x-github-delivery": null }), async () => body)).rejects.toMatchObject({
      status: 400,
      code: "invalid_delivery",
    });
  });

  test("ping is accepted and recorded with the payload digest", async () => {
    const { intake, db } = harness();
    const body = JSON.stringify({ zen: "Keep it logically awesome.", hook_id: 42, repository: { full_name: "octo/app" } });
    const result = await intake.receiveGitHub(githubHeaders(body, { "x-github-event": "ping" }), async () => body);
    expect(result.httpStatus).toBe(200);
    expect(result.body.status).toBe("accepted");
    expect(result.body.detail).toContain("hook 42");
    const [row] = rows(db);
    expect(row.signature_valid).toBe(1);
    expect(row.payload_sha256).toBe(crypto.createHash("sha256").update(body).digest("hex"));
  });

  test("duplicate deliveries are acknowledged once", async () => {
    const { intake, db, scanCalls } = harness({ tenants: [tenant("t1")], repos: { t1: { owner: "octo", repo: "app", source: "configured" } } });
    const body = pushBody();
    const headers = githubHeaders(body);
    const first = await intake.receiveGitHub(headers, async () => body);
    await first.background;
    const second = await intake.receiveGitHub(headers, async () => body);
    expect(second).toMatchObject({ httpStatus: 200, body: { status: "duplicate" }, background: null });
    expect(rows(db)).toHaveLength(1);
    expect(scanCalls).toHaveLength(1);
  });

  test("authenticated but malformed payloads are recorded as rejected", async () => {
    const { intake, db } = harness();
    const body = "{not json";
    await expect(intake.receiveGitHub(githubHeaders(body), async () => body)).rejects.toMatchObject({ status: 400, code: "invalid_payload" });
    expect(rows(db).map((row) => row.status)).toEqual(["rejected"]);
  });

  test("form-encoded deliveries are parsed from the payload field", () => {
    const payload = JSON.stringify({ zen: "x" });
    const raw = `payload=${encodeURIComponent(payload)}`;
    expect(parseWebhookPayload(raw, "application/x-www-form-urlencoded")).toEqual({ zen: "x" });
    expect(() => parseWebhookPayload("a=b", "application/x-www-form-urlencoded")).toThrow(HttpError);
    expect(() => parseWebhookPayload("[1]", "application/json")).toThrow(HttpError);
  });
});

describe("push handling", () => {
  test("a push to a bound repository returns 202 and scans the local checkout in the background", async () => {
    let release = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { intake, db, scanCalls, audits } = harness({
      gate,
      tenants: [tenant("t1"), tenant("t2")],
      repos: { t1: { owner: "Octo", repo: "App", source: "git_remote" }, t2: { owner: "other", repo: "repo", source: "configured" } },
      heads: { t1: { branch: "main", sha: AFTER, detached: false } },
    });
    const body = pushBody("octo/app");
    const result = await intake.receiveGitHub(githubHeaders(body), async () => body);
    expect(result.httpStatus).toBe(202);
    expect(result.body).toMatchObject({ status: "accepted", tenants: ["t1"] });
    expect(rows(db)[0].status).toBe("accepted");
    release();
    await result.background;
    expect(scanCalls).toEqual([expect.objectContaining({ tenantId: "t1", kind: "sast", trigger: "webhook" })]);
    expect(scanCalls[0].actor).toEqual({ label: "system", role: "system" });
    const [row] = rows(db);
    expect(row.status).toBe("scanned");
    expect(row.run_id).toBe("run-t1");
    expect(row.tenant_id).toBe("t1");
    expect(row.repository).toBe("octo/app");
    expect(row.after_sha).toBe(AFTER);
    expect(row.sender).toBe("octocat");
    expect(row.detail).toContain("equals the pushed commit");
    expect(audits).toEqual([expect.objectContaining({ action: "webhook_scan", outcome: "success", tenantId: "t1" })]);
    expect(audits[0].details.checkoutMatchesPush).toBe(true);
  });

  test("the delivery says when the local checkout is not the pushed commit", async () => {
    const { intake, db } = harness({
      tenants: [tenant("t1")],
      repos: { t1: { owner: "octo", repo: "app", source: "configured" } },
      heads: { t1: { branch: "develop", sha: OTHER, detached: false } },
    });
    const body = pushBody("octo/app");
    await (await intake.receiveGitHub(githubHeaders(body), async () => body)).background;
    const detail = rows(db)[0].detail ?? "";
    expect(detail).toContain("differs from the pushed commit");
    expect(detail).toContain("never fetches or pulls");
    expect(detail).toContain("the push was to branch main");
  });

  test("pushes without a bound tenant are ignored with the reason", async () => {
    const { intake, db, scanCalls } = harness({ tenants: [tenant("t1")], repos: { t1: { owner: "octo", repo: "app", source: "configured" } } });
    const body = pushBody("someone/else");
    const result = await intake.receiveGitHub(githubHeaders(body), async () => body);
    expect(result).toMatchObject({ httpStatus: 200, body: { status: "ignored" }, background: null });
    expect(rows(db)[0].detail).toContain("no registered tenant");
    expect(scanCalls).toHaveLength(0);
  });

  test("branch deletions and other events trigger nothing", async () => {
    const { intake, scanCalls, db } = harness({ tenants: [tenant("t1")], repos: { t1: { owner: "octo", repo: "app", source: "configured" } } });
    const deletion = JSON.stringify({ ref: "refs/heads/x", after: "0".repeat(40), deleted: true, repository: { full_name: "octo/app" } });
    expect((await intake.receiveGitHub(githubHeaders(deletion), async () => deletion)).body.status).toBe("ignored");
    const issue = JSON.stringify({ action: "opened", repository: { full_name: "octo/app" } });
    const result = await intake.receiveGitHub(githubHeaders(issue, { "x-github-event": "issues" }), async () => issue);
    expect(result.body).toMatchObject({ status: "ignored", detail: "event recorded; no automated action" });
    expect(scanCalls).toHaveLength(0);
    expect(rows(db)).toHaveLength(2);
  });

  test("a running scan is not duplicated and a failing scan marks the delivery failed", async () => {
    const busy = harness({ tenants: [tenant("t1")], repos: { t1: { owner: "octo", repo: "app", source: "configured" } }, running: ["t1"] });
    const body = pushBody("octo/app");
    await (await busy.intake.receiveGitHub(githubHeaders(body), async () => body)).background;
    expect(busy.scanCalls).toHaveLength(0);
    expect(rows(busy.db)[0]).toMatchObject({ status: "ignored" });
    expect(rows(busy.db)[0].detail).toContain("already running");

    const broken = harness({
      tenants: [tenant("t1")],
      repos: { t1: { owner: "octo", repo: "app", source: "configured" } },
      scanOutcome: () => new HttpError(503, "core_unavailable", "binary missing"),
    });
    await (await broken.intake.receiveGitHub(githubHeaders(body), async () => body)).background;
    expect(rows(broken.db)[0].status).toBe("failed");
    expect(rows(broken.db)[0].detail).toContain("core_unavailable");
    expect(broken.audits[0]).toMatchObject({ outcome: "failure" });

    const failedRun = harness({
      tenants: [tenant("t1")],
      repos: { t1: { owner: "octo", repo: "app", source: "configured" } },
      scanOutcome: (input) => runView(input, "failed", "sentra scan failed: invalid_workspace"),
    });
    await (await failedRun.intake.receiveGitHub(githubHeaders(body), async () => body)).background;
    expect(rows(failedRun.db)[0]).toMatchObject({ status: "failed", run_id: "run-t1" });
  });
});

describe("gitlab intake", () => {
  function gitlabHeaders(overrides: Record<string, string | null> = {}): Headers {
    const values: Record<string, string | null> = {
      "x-gitlab-token": GITLAB_TOKEN,
      "x-gitlab-event": "Push Hook",
      "x-gitlab-event-uuid": crypto.randomUUID(),
      ...overrides,
    };
    const headers = new Headers();
    for (const [key, value] of Object.entries(values)) if (value !== null) headers.set(key, value);
    return headers;
  }

  const body = JSON.stringify({
    object_kind: "push",
    ref: "refs/heads/main",
    after: AFTER,
    user_username: "dev",
    project: { path_with_namespace: "Group/Sub/Project", web_url: "https://gitlab.example.com/group/sub/project" },
  });

  test("unconfigured token yields 503; wrong or missing tokens are rejected", async () => {
    const off = harness({ gitlabToken: null });
    await expect(off.intake.receiveGitLab(gitlabHeaders(), async () => body)).rejects.toMatchObject({ status: 503 });
    const on = harness();
    await expect(on.intake.receiveGitLab(gitlabHeaders({ "x-gitlab-token": "nope" }), async () => body)).rejects.toMatchObject({ status: 401 });
    await expect(on.intake.receiveGitLab(gitlabHeaders({ "x-gitlab-token": null }), async () => body)).rejects.toMatchObject({ status: 401 });
    expect(rows(on.db)).toHaveLength(0);
    expect(on.intake.config().rejectedSinceStart).toBe(2);
  });

  test("matches tenants by origin host and namespace path, and de-duplicates by body digest without a UUID", async () => {
    const { intake, db, scanCalls } = harness({
      tenants: [tenant("t1"), tenant("t2"), tenant("t3")],
      origins: {
        t1: "git@gitlab.example.com:group/sub/project.git",
        t2: "https://gitlab.com/group/sub/project.git",
        t3: "https://github.com/group/sub",
      },
    });
    const headers = gitlabHeaders({ "x-gitlab-event-uuid": null });
    const result = await intake.receiveGitLab(headers, async () => body);
    expect(result.httpStatus).toBe(202);
    expect(result.body.tenants).toEqual(["t1"]);
    expect(result.body.deliveryId).toBe(`body-sha256-${crypto.createHash("sha256").update(body).digest("hex")}`);
    await result.background;
    expect(scanCalls.map((call) => call.tenantId)).toEqual(["t1"]);
    expect((await intake.receiveGitLab(gitlabHeaders({ "x-gitlab-event-uuid": null }), async () => body)).body.status).toBe("duplicate");
    expect(rows(db)[0]).toMatchObject({ status: "scanned", repository: "Group/Sub/Project", sender: "dev" });
  });

  test("non-push events are recorded and ignored", async () => {
    const { intake } = harness();
    const mr = JSON.stringify({ object_kind: "merge_request", project: { path_with_namespace: "g/p", web_url: "https://gitlab.com/g/p" } });
    const result = await intake.receiveGitLab(gitlabHeaders({ "x-gitlab-event": "Merge Request Hook" }), async () => mr);
    expect(result.body).toMatchObject({ status: "ignored" });
    expect(intake.deliveries(10)[0]).toMatchObject({ provider: "gitlab", eventType: "merge_request", signatureValid: true });
  });
});

describe("tenant matching helpers", () => {
  test("GitHub matching is case-insensitive on owner/repo", () => {
    const tenants = [tenant("a"), tenant("b"), tenant("c")];
    const repos: Record<string, RepositoryRef | null> = {
      a: { owner: "Taiizor", repo: "Sentra", source: "git_remote" },
      b: { owner: "taiizor", repo: "sentra-web", source: "configured" },
      c: null,
    };
    expect(matchGitHubTenants("taiizor/SENTRA", tenants, (record) => repos[record.tenantId]).map((record) => record.tenantId)).toEqual(["a"]);
  });

  test("remote URLs are parsed for https, ssh and scp forms", () => {
    expect(parseRemoteHostPath("https://gitlab.com/Group/Project.git")).toEqual({ host: "gitlab.com", path: "group/project" });
    expect(parseRemoteHostPath("https://user@gitlab.example.com:8443/a/b/c/")).toEqual({ host: "gitlab.example.com", path: "a/b/c" });
    expect(parseRemoteHostPath("ssh://git@gitlab.example.com:2222/a/b.git")).toEqual({ host: "gitlab.example.com", path: "a/b" });
    expect(parseRemoteHostPath("git@gitlab.example.com:a/b.git")).toEqual({ host: "gitlab.example.com", path: "a/b" });
    expect(parseRemoteHostPath("C:/repos/project")).toBeNull();
    expect(parseRemoteHostPath("file:///srv/repo.git")).toBeNull();
    expect(parseRemoteHostPath("git@gitlab.com:a/../b.git")).toBeNull();
    // WHATWG URL parsing resolves dot segments the same way git's HTTP transport does.
    expect(parseRemoteHostPath("https://gitlab.com/a/../b")).toEqual({ host: "gitlab.com", path: "b" });
  });

  test("GitLab matching requires the same host and path", () => {
    const tenants = [tenant("a"), tenant("b")];
    const origins: Record<string, string> = { a: "git@gitlab.com:g/p.git", b: "git@gitlab.example.com:g/p.git" };
    const matched = matchGitLabTenants({ pathWithNamespace: "G/P", webUrl: "https://gitlab.example.com/G/P" }, tenants, (record) => origins[record.tenantId]);
    expect(matched.map((record) => record.tenantId)).toEqual(["b"]);
  });

  test("checkout comparison states what was actually scanned", () => {
    expect(checkoutComparison({ branch: "main", sha: AFTER, detached: false }, AFTER, "refs/heads/main").matchesPush).toBe(true);
    const mismatch = checkoutComparison({ branch: "main", sha: OTHER, detached: false }, AFTER, "refs/heads/main");
    expect(mismatch.matchesPush).toBe(false);
    expect(mismatch.detail).toContain("reflects the local checkout, not the pushed commit");
    expect(checkoutComparison(null, AFTER, null).matchesPush).toBeNull();
    expect(checkoutComparison({ branch: null, sha: OTHER, detached: true }, null, null).detail).toContain("no pushed commit sha");
  });
});
