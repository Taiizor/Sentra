import { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PERMISSION_MIN_ROLE } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { AuditLog, isAuditHandled, markAuditHandled } from "../audit-log.ts";
import { AuthService, SESSION_COOKIE } from "../auth.ts";
import { parseTokenGrants, type ServerConfig } from "../config.ts";
import { openWebDb } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { sseResponse, type Router } from "../http.ts";
import { clientIp, createApp, handleRequest } from "../main.ts";
import { assertSafeOutboundUrl, isBlockedAddress, isLoopbackAddress, parseIPv6 } from "../net-guard.ts";
import { assertPlainPath, lexicalAbsolute } from "../paths.ts";
import { PERMISSIONS } from "../permissions.ts";
import { AUDIT_VERIFICATIONS_PER_MINUTE } from "../routes/core-routes.ts";
import { deniedReason, resolveDiffDirectory } from "../routes/scans.ts";
import { Semaphore, SentraCli } from "../sentra-cli.ts";
import { lastCompletedRunAt, lastResultRunAt } from "../services/scans.ts";
import { expandMemberPattern } from "../services/topology.ts";
import { MAX_UNVERIFIED_BODY_READS, WebhookIntake } from "../services/webhooks.ts";
import { isLegacySeedRow, WorkspaceService } from "../services/workspaces.ts";

const TEST_ROOT = fs.realpathSync.native(fs.mkdtempSync(path.join(process.env.SENTRA_TEST_TMPDIR ?? os.tmpdir(), "sentra-hardening-")));
const openDbs: Database[] = [];

afterAll(() => {
  for (const db of openDbs) {
    try {
      db.close();
    } catch {
      // already closed
    }
  }
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(TEST_ROOT, prefix));
}

function freshDb(): Database {
  const db = openWebDb(path.join(tempDir("db-"), "web.db"));
  openDbs.push(db);
  return db;
}

function expectHttpError(fn: () => unknown, status: number, code?: string): HttpError {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(status);
    if (code) expect((error as HttpError).code).toBe(code);
    return error as HttpError;
  }
  throw new Error("expected an HttpError");
}

// ───────────────────────────── paths ─────────────────────────────

describe("UNC and device paths", () => {
  test("Windows rejects every separator form of a network or device prefix", () => {
    for (const candidate of [
      "\\\\localhost\\C$\\Windows",
      "\\/localhost/C$/Windows",
      "/\\localhost\\C$\\Windows",
      "//localhost/C$/Windows",
      "\\\\?\\C:\\Windows",
      "//./PhysicalDrive0",
      "\\??\\UNC\\server\\share",
    ]) {
      expectHttpError(() => assertPlainPath(candidate, "base", "win32"), 400, "invalid_path");
    }
    expect(() => assertPlainPath("C:\\work\\repo", "base", "win32")).not.toThrow();
    expect(() => assertPlainPath("C:/work/repo", "base", "win32")).not.toThrow();
    expect(() => assertPlainPath("src/main.rs", "path", "win32")).not.toThrow();
  });

  test("absolute Windows paths must start with a drive letter", () => {
    expect(lexicalAbsolute("C:/work/repo/../repo", "base", "win32")).toBe("C:\\work\\repo");
    expectHttpError(() => lexicalAbsolute("\\work\\repo", "base", "win32"), 400, "invalid_path");
    expectHttpError(() => lexicalAbsolute("work/repo", "base", "win32"), 400, "invalid_path");
    expect(lexicalAbsolute("/srv/repo", "base", "linux")).toBe("/srv/repo");
    expectHttpError(() => lexicalAbsolute("srv/repo", "base", "linux"), 400, "invalid_path");
  });

  test("diff directories are checked lexically before the disk is touched", () => {
    const workspace = tempDir("ws-");
    const dataDir = tempDir("data-");
    fs.mkdirSync(path.join(workspace, "base"));
    const app = {
      config: { dataDir } as ServerConfig,
      workspaces: { list: () => [{ workspace }] } as unknown as WorkspaceService,
    };
    expect(resolveDiffDirectory(app, { base: path.join(workspace, "base") }, "base")).toBe(fs.realpathSync.native(path.join(workspace, "base")));
    // Outside every workspace: refused with 403 even though the path does not exist (no lookup happened).
    expectHttpError(() => resolveDiffDirectory(app, { base: path.join(TEST_ROOT, "does-not-exist") }, "base"), 403, "path_not_in_workspace");
    expectHttpError(() => resolveDiffDirectory(app, { base: dataDir }, "base"), 403, "path_denied");
    expectHttpError(() => resolveDiffDirectory(app, { base: path.join(workspace, "missing") }, "base"), 404, "path_not_found");
  });

  test("the file viewer refuses the bridge's own data files by name", () => {
    expect(deniedReason("web-admin.token")).toContain("bridge data");
    expect(deniedReason("hidden/data/web-secret.key")).toContain("bridge data");
    expect(deniedReason("x/sentra-web.db-wal")).toContain("bridge data");
    expect(deniedReason("data/core-stores/t1.db")).toContain("bridge data");
    expect(deniedReason("src/main.rs")).toBeNull();
  });
});

// ───────────────────────────── sessions ─────────────────────────────

function authConfig(tokens: string, secretKey: Buffer): ServerConfig {
  return { tokenGrants: parseTokenGrants(tokens), sessionTtlMs: 60_000, secretKey } as ServerConfig;
}

function cookieRequest(sessionId: string): Request {
  return new Request("http://127.0.0.1/api/auth/session", { headers: { cookie: `${SESSION_COOKIE}=${sessionId}` } });
}

describe("session binding", () => {
  test("a session ends when the token that created it is rotated, even with the same role and label", () => {
    const db = freshDb();
    const key = crypto.randomBytes(32);
    const oldToken = "o".repeat(40);
    const newToken = "n".repeat(40);
    const before = new AuthService(db, authConfig(`admin:${oldToken}`, key));
    const { sessionId } = before.login(oldToken, "127.0.0.1");
    expect(before.authenticate(cookieRequest(sessionId))?.label).toBe("admin");

    // Restart with the same grant: the session survives.
    expect(new AuthService(db, authConfig(`admin:${oldToken}`, key)).authenticate(cookieRequest(sessionId))?.role).toBe("admin");

    // Rotation (same role, same default label): the old session is gone and deleted.
    const after = new AuthService(db, authConfig(`admin:${newToken}`, key));
    expect(after.authenticate(cookieRequest(sessionId))).toBeNull();
    expect((db.query("SELECT COUNT(*) AS c FROM web_sessions").get() as { c: number }).c).toBe(0);
  });

  test("sessions from before the binding migration are dropped", () => {
    const file = path.join(tempDir("migrate-"), "web.db");
    // Recreate a database at schema version 1 that holds a session without a grant fingerprint.
    const v1 = openWebDb(file);
    v1.exec("DELETE FROM schema_migrations WHERE version = 2");
    v1.exec("ALTER TABLE web_sessions DROP COLUMN grant_fingerprint");
    v1.exec("INSERT INTO web_sessions (id_hash, role, label, created_at, expires_at, last_seen_at) VALUES ('h', 'admin', 'admin', 'x', '9999', 'x')");
    v1.close();
    const migrated = openWebDb(file);
    openDbs.push(migrated);
    expect((migrated.query("SELECT COUNT(*) AS c FROM web_sessions").get() as { c: number }).c).toBe(0);
  });
});

// ───────────────────────────── core process queue ─────────────────────────────

describe("core process queue", () => {
  test("hands a released slot directly to the next waiter and bounds the queue", async () => {
    const semaphore = new Semaphore(1, 2);
    const first = await semaphore.acquire();
    const second = semaphore.acquire();
    const third = semaphore.acquire();
    await expect(semaphore.acquire()).rejects.toMatchObject({ status: 503, code: "core_busy" });
    expect(semaphore.pending).toBe(2);
    first();
    first(); // a second release is ignored
    const releaseSecond = await second;
    expect(semaphore.running).toBe(1);
    releaseSecond();
    (await third)();
    expect(semaphore.running).toBe(0);
  });

  test("a cancelled caller leaves the queue without taking a slot", async () => {
    const semaphore = new Semaphore(1, 4);
    const holder = await semaphore.acquire();
    const controller = new AbortController();
    const waiting = semaphore.acquire(controller.signal);
    controller.abort();
    await expect(waiting).rejects.toMatchObject({ status: 499, code: "aborted" });
    expect(semaphore.pending).toBe(0);
    holder();
    expect(semaphore.running).toBe(0);
    await expect(semaphore.acquire(controller.signal)).rejects.toMatchObject({ status: 499 });
  });

  test("shared read runs start one core process for concurrent callers", async () => {
    const dir = tempDir("cli-");
    const counter = path.join(dir, "runs.txt");
    // The Bun executable stands in for the core: it appends one byte per process start.
    const cli = new SentraCli(process.execPath, dir, 30_000, 2);
    const args = ["-e", `require("fs").appendFileSync(${JSON.stringify(counter)}, "x"); console.log("{}")`];
    const [a, b, c] = await Promise.all([
      cli.runShared(args, { ttlMs: 60_000 }),
      cli.runShared(args, { ttlMs: 60_000 }),
      cli.runShared(args, { ttlMs: 60_000 }),
    ]);
    expect([a.code, b.code, c.code]).toEqual([0, 0, 0]);
    expect(fs.readFileSync(counter, "utf8")).toBe("x");
    // Within the TTL the completed result is reused; with ttl 0 a new process starts.
    await cli.runShared(args, { ttlMs: 60_000 });
    expect(fs.readFileSync(counter, "utf8")).toBe("x");
    await cli.runShared(args, { ttlMs: 0 });
    expect(fs.readFileSync(counter, "utf8")).toBe("xx");
    // Regression: an explicit refresh (the Plugins tab's Rediscover) returned the kept result for
    // the whole TTL. `fresh` starts a new process, and its result replaces the kept one.
    await cli.runShared(args, { ttlMs: 60_000, fresh: true });
    expect(fs.readFileSync(counter, "utf8")).toBe("xxx");
    await cli.runShared(args, { ttlMs: 60_000 });
    expect(fs.readFileSync(counter, "utf8")).toBe("xxx");
    // A caller that goes away stops waiting; the shared run is unaffected.
    const controller = new AbortController();
    const slow = ["-e", `setTimeout(() => { require("fs").appendFileSync(${JSON.stringify(counter)}, "y"); console.log("{}"); }, 300)`];
    const waiting = cli.runShared(slow, { ttlMs: 60_000, signal: controller.signal });
    const other = cli.runShared(slow, { ttlMs: 60_000 });
    // A refresh joins a run still in progress instead of starting a second one.
    const refreshing = cli.runShared(slow, { ttlMs: 60_000, fresh: true });
    controller.abort();
    await expect(waiting).rejects.toMatchObject({ status: 499 });
    expect((await other).code).toBe(0);
    expect((await refreshing).code).toBe(0);
    expect(fs.readFileSync(counter, "utf8")).toBe("xxxy");
  }, 30_000);
});

// ───────────────────────────── outbound guard ─────────────────────────────

describe("outbound guard and IPv6 forms", () => {
  test("embedded IPv4 addresses are judged by their IPv4 target", () => {
    expect(parseIPv6("::ffff:127.0.0.1")).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
    for (const address of ["::ffff:7f00:1", "::ffff:a00:5", "::ffff:a9fe:a9fe", "::7f00:1", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "::", "::1"]) {
      expect(isBlockedAddress(address)).toBe(true);
    }
    for (const address of ["64:ff9b:1::5", "2001:0:4136:e378::1", "fe80::1", "febf::1", "fc00::1", "ff02::1", "2001:db8::1", "100::1"]) {
      expect(isBlockedAddress(address)).toBe(true);
    }
    expect(isBlockedAddress("2606:4700:4700::1111")).toBe(false);
    expect(isBlockedAddress("64:ff9b::808:808")).toBe(false);
    expect(isBlockedAddress("not-an-ip")).toBe(true);
    expect(isLoopbackAddress("::ffff:7f00:1")).toBe(true);
    expect(isLoopbackAddress("::1")).toBe(true);
    expect(isLoopbackAddress("::ffff:a00:5")).toBe(false);
  });

  test("URL literals in normalised IPv6 form are refused", async () => {
    for (const url of ["https://[::ffff:127.0.0.1]/v1", "https://[::ffff:10.0.0.5]/v1", "https://[::127.0.0.1]/v1", "https://[64:ff9b::a9fe:a9fe]/v1"]) {
      await expect(assertSafeOutboundUrl(url)).rejects.toMatchObject({ code: "endpoint_blocked" });
    }
    await expect(assertSafeOutboundUrl("https://[2606:4700:4700::1111]/v1")).resolves.toBeInstanceOf(URL);
  });
});

// ───────────────────────────── audit chain ─────────────────────────────

describe("audit chain head checkpoint", () => {
  const actor = { label: "alice", role: "admin" };

  test("removing the newest entries is detected", () => {
    const db = freshDb();
    const log = new AuditLog(db, crypto.randomBytes(32));
    for (let index = 0; index < 5; index += 1) log.append(actor, { action: `a${index}`, outcome: "success" });
    expect(log.verify()).toMatchObject({ valid: true, checkedEntries: 5, checkpointSeq: 5 });
    db.exec("DROP TRIGGER audit_log_no_delete");
    db.exec("DELETE FROM audit_log WHERE seq > 3");
    const result = log.verify();
    expect(result.valid).toBe(false);
    expect(result.firstInvalidSeq).toBe(4);
    expect(result.reason).toContain("newest entries were removed");
    // A later append does not hide the truncation: the checkpoint keeps the evidence.
    log.append(actor, { action: "after", outcome: "success" });
    expect(log.verify().valid).toBe(false);
  });

  test("a forged checkpoint is rejected and the limitation is stated", () => {
    const db = freshDb();
    const log = new AuditLog(db, crypto.randomBytes(32));
    log.append(actor, { action: "x", outcome: "success" });
    db.query("UPDATE settings SET value_json = ? WHERE key = 'audit.head_checkpoint'").run(JSON.stringify({ seq: 1, hash: "0".repeat(64), mac: "00" }));
    const result = log.verify();
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("checkpoint");
    expect(result.limitation).toContain("outside this host");
  });

  test("tenant counts can exclude global entries", () => {
    const db = freshDb();
    const log = new AuditLog(db, crypto.randomBytes(32));
    log.append(actor, { action: "authorization_denied", outcome: "denied" });
    log.append(actor, { action: "scan_completed", outcome: "success", tenantId: "small" });
    expect(log.count("small")).toBe(2);
    expect(log.count("small", { includeGlobal: false })).toBe(1);
  });

  test("errors can be marked as already audited", () => {
    const error = new HttpError(400, "x", "y");
    expect(isAuditHandled(error)).toBe(false);
    expect(markAuditHandled(error)).toBe(error);
    expect(isAuditHandled(error)).toBe(true);
    expect(isAuditHandled("text")).toBe(false);
  });
});

// ───────────────────────────── request dispatch ─────────────────────────────

const ADMIN_TOKEN = "a".repeat(40);
const VIEWER_TOKEN = "v".repeat(40);
const PORT = 3999;
const ORIGIN = `http://127.0.0.1:${PORT}`;

function appConfig(): ServerConfig {
  const dataDir = tempDir("bridge-data-");
  const tmp = path.join(dataDir, "tmp");
  fs.mkdirSync(tmp);
  return {
    repoRoot: tempDir("repo-"),
    webRoot: TEST_ROOT,
    host: "127.0.0.1",
    port: PORT,
    isLoopbackBind: true,
    production: false,
    staticDir: null,
    sentraBin: path.join(dataDir, "missing-sentra-binary"),
    ghBin: null,
    codeqlBin: null,
    dataDir,
    registryDbPath: path.join(dataDir, "sentra.db"),
    webDbPath: path.join(dataDir, "sentra-web.db"),
    backupDir: path.join(dataDir, "backups"),
    allowedOrigins: new Set([ORIGIN]),
    allowedHosts: new Set([`127.0.0.1:${PORT}`]),
    tokenGrants: parseTokenGrants(`admin:${ADMIN_TOKEN},viewer:${VIEWER_TOKEN}`),
    generatedAdminToken: null,
    sessionTtlMs: 60_000,
    cookieSecure: false,
    githubWebhookSecret: null,
    gitlabWebhookToken: null,
    githubTokenFromEnv: null,
    secretKey: crypto.randomBytes(32),
    maxBodyBytes: 1024 * 1024,
    cliTimeoutMs: 5_000,
    cliLongTimeoutMs: 5_000,
    cliMaxConcurrency: 1,
    trustProxy: false,
    workspaceRoots: [],
    pluginDir: null,
    tmpDir: tmp,
  };
}

function harness() {
  const { app, router } = createApp(appConfig());
  openDbs.push(app.db);
  const timeouts: number[] = [];
  const server = {
    requestIP: () => ({ address: "127.0.0.1", family: "IPv4" as const, port: 1 }),
    timeout: (_req: Request, seconds: number) => {
      timeouts.push(seconds);
    },
  };
  const send = async (method: string, pathname: string, init: { headers?: Record<string, string>; body?: unknown } = {}) => {
    const req = new Request(`${ORIGIN}${pathname}`, {
      method,
      headers: { host: `127.0.0.1:${PORT}`, ...(init.body !== undefined ? { "content-type": "application/json" } : {}), ...init.headers },
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    });
    const response = await handleRequest(req, server, app as AppContext, router as Router);
    const text = await response.text();
    return { status: response.status, headers: response.headers, body: text ? (JSON.parse(text) as Record<string, any>) : {} };
  };
  return { app, send, timeouts };
}

describe("request dispatch", () => {
  test("rejected state-changing requests of a signed-in principal leave an audit entry", async () => {
    const h = harness();
    const login = await h.send("POST", "/api/auth/login", { headers: { origin: ORIGIN }, body: { token: ADMIN_TOKEN } });
    expect(login.status).toBe(200);
    const cookie = (login.headers.get("set-cookie") ?? "").split(";")[0];

    const missingHeader = await h.send("POST", "/api/audit-log/verify", { headers: { cookie, origin: ORIGIN } });
    expect(missingHeader.status).toBe(403);
    expect(missingHeader.body.error.code).toBe("csrf_header_missing");
    const crossSite = await h.send("POST", "/api/audit-log/verify", { headers: { cookie, origin: "http://evil.example", "x-sentra-client": "console" } });
    expect(crossSite.body.error.code).toBe("origin_rejected");
    // Authenticated requests are exempt from the idle timeout.
    expect(h.timeouts).toContain(0);

    h.app.db
      .query("INSERT INTO tenants (tenant_id, name, workspace, isolation_level, created_at, created_by) VALUES ('t1', 'T1', ?, 'single_operator', 'x', 'test')")
      .run(tempDir("registered-ws-"));
    const diff = await h.send("POST", "/api/tenants/t1/diff", {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      body: { base: path.join(TEST_ROOT, "elsewhere"), head: path.join(TEST_ROOT, "elsewhere") },
    });
    expect(diff.status).toBe(403);
    const invalid = await h.send("POST", "/api/scan/snippet", { headers: { authorization: `Bearer ${ADMIN_TOKEN}` }, body: { code: "x", fileName: "../x.py" } });
    expect(invalid.status).toBe(400);

    const entries = h.app.audit.list({ limit: 20 }).map((entry) => `${entry.action}:${entry.outcome}:${String(entry.details.code ?? entry.details.error ?? "")}`);
    expect(entries).toContain("request_rejected:denied:csrf_header_missing");
    expect(entries).toContain("request_rejected:denied:origin_rejected");
    expect(entries.some((entry) => entry.startsWith("workspace_diff:denied:path_not_in_workspace"))).toBe(true);
    expect(entries).toContain("request_rejected:failure:invalid_request");
    expect(h.app.audit.verify().valid).toBe(true);
  });

  test("an authorization denial is recorded once, and audit verification is rate limited without audit noise", async () => {
    const h = harness();
    const denied = await h.send("POST", "/api/tenants", { headers: { authorization: `Bearer ${VIEWER_TOKEN}` }, body: {} });
    expect(denied.status).toBe(403);
    expect(h.app.audit.list({ limit: 10 }).map((entry) => entry.action)).toEqual(["authorization_denied"]);

    for (let index = 0; index < AUDIT_VERIFICATIONS_PER_MINUTE; index += 1) {
      expect((await h.send("POST", "/api/audit-log/verify", { headers: { authorization: `Bearer ${VIEWER_TOKEN}` } })).status).toBe(200);
    }
    const before = h.app.audit.count();
    const limited = await h.send("POST", "/api/audit-log/verify", { headers: { authorization: `Bearer ${VIEWER_TOKEN}` } });
    expect(limited.status).toBe(429);
    expect(h.app.audit.count()).toBe(before);
  });

  test("the overview counts only this tenant's audit entries and has no risk score without results", async () => {
    const h = harness();
    const workspace = tempDir("overview-ws-");
    h.app.db
      .query("INSERT INTO tenants (tenant_id, name, workspace, isolation_level, created_at, created_by) VALUES ('small', 'Small', ?, 'single_operator', 'x', 'test')")
      .run(workspace);
    h.app.audit.append({ label: "vic", role: "viewer" }, { action: "authorization_denied", outcome: "denied" });
    h.app.audit.append({ label: "admin", role: "admin" }, { action: "tenant_registered", outcome: "success", tenantId: "small" });
    const insertRun = h.app.db.query(
      "INSERT INTO scan_runs (run_id, tenant_id, workspace, kind, trigger, status, started_at, finished_at, actor, summary_json) VALUES (?, 'small', ?, ?, 'operator', 'completed', ?, ?, 'admin', ?)",
    );
    insertRun.run("run_probe", workspace, "codeql", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", JSON.stringify({ sast: null, dependency: null, codeql: {} }));
    const overview = await h.send("GET", "/api/tenants/small/overview", { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } });
    expect(overview.status).toBe(200);
    expect(overview.body.operatorAuditEntries).toBe(1);
    expect(overview.body.lastCompletedRunAt).toBe("2026-01-01T00:00:01Z");
    expect(overview.body.lastResultRunAt).toBeNull();
    expect(overview.body.riskScore).toBeNull();

    const sast = { filesScanned: 3, signalsFound: 0, bySeverity: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0 } };
    insertRun.run("run_sast", workspace, "sast", "2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z", JSON.stringify({ sast, dependency: null }));
    expect(lastResultRunAt(h.app, "small", workspace)).toBe("2026-01-02T00:00:01Z");
    expect(lastCompletedRunAt(h.app, "small", workspace)).toBe("2026-01-02T00:00:01Z");
    const scored = await h.send("GET", "/api/tenants/small/overview", { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } });
    expect(scored.body.riskScore.value).toBe(100);
  });
});

describe("client address behind a proxy", () => {
  const server = { requestIP: () => ({ address: "10.0.0.1", family: "IPv4" as const, port: 1 }) };
  const request = (forwarded: string) => new Request("http://x/", { headers: { "x-forwarded-for": forwarded } });

  test("uses the right-most X-Forwarded-For entry, which the trusted proxy appended", () => {
    expect(clientIp(request("1.1.1.1, 203.0.113.9"), server, { trustProxy: true })).toBe("203.0.113.9");
    expect(clientIp(request("203.0.113.9"), server, { trustProxy: true })).toBe("203.0.113.9");
    expect(clientIp(request("1.1.1.1, 203.0.113.9"), server, { trustProxy: false })).toBe("10.0.0.1");
  });
});

// ───────────────────────────── webhooks ─────────────────────────────

describe("webhook intake before the body is read", () => {
  function intake(options: { githubSecret?: string | null; gitlabToken?: string | null } = {}) {
    return new WebhookIntake({
      db: freshDb(),
      githubSecret: options.githubSecret ?? "gh-secret",
      gitlabToken: options.gitlabToken ?? "gl-token",
      bindHost: "127.0.0.1",
      tenants: () => [],
      githubRepositoryOf: () => null,
      originUrlOf: () => null,
      headOf: () => null,
      scans: { run: async () => Promise.reject(new Error("no scans")), isRunning: () => false },
      audit: () => {},
    });
  }
  const neverRead = async (): Promise<string> => {
    throw new Error("the body must not be read");
  };

  test("credentials that do not depend on the body are checked first", async () => {
    const hooks = intake();
    await expect(hooks.receiveGitLab(new Headers({ "x-gitlab-token": "wrong", "x-gitlab-event": "Push Hook" }), neverRead)).rejects.toMatchObject({ status: 401 });
    await expect(hooks.receiveGitHub(new Headers({ "x-github-event": "push" }), neverRead)).rejects.toMatchObject({ status: 401 });
    await expect(
      hooks.receiveGitHub(new Headers({ "x-hub-signature-256": "sha256=zz", "x-github-delivery": "d1d1d1d1-0000", "x-github-event": "push" }), neverRead),
    ).rejects.toMatchObject({ status: 401 });
    await expect(
      hooks.receiveGitHub(new Headers({ "x-hub-signature-256": `sha256=${"0".repeat(64)}`, "x-github-event": "push" }), neverRead),
    ).rejects.toMatchObject({ status: 400, code: "invalid_delivery" });
  });

  test("concurrent unauthenticated body reads are capped", async () => {
    const hooks = intake();
    const headers = new Headers({ "x-hub-signature-256": `sha256=${"0".repeat(64)}`, "x-github-delivery": "d1d1d1d1-0000", "x-github-event": "push" });
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const slowBody = async () => {
      await gate;
      return "{}";
    };
    const pending = Array.from({ length: MAX_UNVERIFIED_BODY_READS }, () => hooks.receiveGitHub(headers, slowBody).catch((error: unknown) => error));
    await expect(hooks.receiveGitHub(headers, slowBody)).rejects.toMatchObject({ status: 429, code: "webhook_busy" });
    release();
    // The held reads finish and fail signature verification (the signature is not for "{}").
    for (const outcome of await Promise.all(pending)) expect(outcome).toMatchObject({ status: 401 });
  });
});

// ───────────────────────────── stream errors ─────────────────────────────

describe("SSE fallback error", () => {
  test("follows the ScanStreamEvent error shape", async () => {
    const response = sseResponse(new Request("http://x/"), async () => {
      throw new HttpError(409, "scan_in_progress", "busy");
    });
    const text = await response.text();
    expect(text).toContain("event: error");
    expect(text).toContain('"type":"error","status":409,"code":"scan_in_progress","message":"busy"');
  });
});

// ───────────────────────────── topology links ─────────────────────────────

describe("topology member expansion", () => {
  test("does not follow a link in an intermediate path component", () => {
    const base = tempDir("topo-");
    const outside = path.join(base, "outside");
    fs.mkdirSync(path.join(outside, "home", "private-project-alpha"), { recursive: true });
    fs.writeFileSync(path.join(outside, "home", "private-project-alpha", "package.json"), "{}");
    const workspace = path.join(base, "ws");
    fs.mkdirSync(path.join(workspace, "packages", "app"), { recursive: true });
    fs.writeFileSync(path.join(workspace, "packages", "app", "package.json"), "{}");
    try {
      fs.symlinkSync(outside, path.join(workspace, "linkdir"), process.platform === "win32" ? "junction" : "dir");
    } catch {
      console.warn("symlink/junction creation not permitted on this host; link assertion skipped");
      return;
    }
    expect(expandMemberPattern(workspace, ".", "linkdir/home/*", "package.json")).toMatchObject({ dirs: [] });
    expect(expandMemberPattern(workspace, ".", "linkdir/home/private-project-alpha", "package.json").dirs).toEqual([]);
    expect(expandMemberPattern(workspace, ".", "packages/*", "package.json")).toEqual({ dirs: ["packages/app"], problem: null });
  });
});

// ───────────────────────────── contract and legacy import ─────────────────────────────

describe("permission matrix and legacy import", () => {
  test("every permission in the matrix is a real capability (no intel:sync)", () => {
    expect(Object.keys(PERMISSION_MIN_ROLE)).not.toContain("intel:sync");
    expect(PERMISSIONS).not.toContain("intel:sync" as never);
  });

  test("the seeded sentra-internal row is not imported while it carries the seed values", () => {
    expect(isLegacySeedRow({ tenantId: "sentra-internal", name: "Sentra Core (Internal)", description: "Core platform codebase and internal services" })).toBe(true);
    expect(isLegacySeedRow({ tenantId: "sentra-internal", name: "Our core repo", description: "Core platform codebase and internal services" })).toBe(false);
    expect(isLegacySeedRow({ tenantId: "acme-corp", name: "anything", description: null })).toBe(true);
    expect(isLegacySeedRow({ tenantId: "payments", name: "Payments", description: null })).toBe(false);

    const dataDir = tempDir("legacy-data-");
    const workspace = tempDir("legacy-ws-");
    const legacy = new Database(path.join(dataDir, "sentra.db"), { create: true });
    legacy.exec(
      "CREATE TABLE tenants (tenant_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, default_workspace TEXT, isolation_level TEXT, created_at TEXT NOT NULL)",
    );
    const insert = legacy.query("INSERT INTO tenants VALUES (?, ?, ?, ?, ?, ?)");
    insert.run("sentra-internal", "Sentra Core (Internal)", "Core platform codebase and internal services", workspace, "single_operator", "2025-01-01T00:00:00Z");
    insert.run("payments", "Payments", "Operator registration", workspace, "single_operator", "2025-01-02T00:00:00Z");
    legacy.close();
    const db = freshDb();
    const config = { dataDir, workspaceRoots: [] } as unknown as ServerConfig;
    const service = new WorkspaceService(db, {} as SentraCli, config);
    let summary: { imported: string[]; skipped: { tenantId: string; reason: string }[] } | null = null;
    service.importLegacyTenants(
      () => false,
      (value) => {
        summary = value as typeof summary;
      },
    );
    expect(service.list().map((tenant) => tenant.tenantId)).toEqual(["payments"]);
    expect(summary!.skipped[0]).toMatchObject({ tenantId: "sentra-internal" });
    expect(summary!.skipped[0].reason).toContain("not registered by an operator");
  });
});
