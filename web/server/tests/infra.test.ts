import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AuditLog, canonicalJson } from "../audit-log.ts";
import { parseCookies } from "../auth.ts";
import { ConfigError, parseTokenGrants } from "../config.ts";
import { openWebDb, WEB_DB_SCHEMA_VERSION } from "../db.ts";
import { parseGitHubRemote, readHead, readRemoteUrl } from "../git-meta.ts";
import { HttpError } from "../http-error.ts";
import { assertSafeOutboundUrl, isBlockedAddress, isLoopbackAddress } from "../net-guard.ts";
import { resolveInside } from "../paths.ts";
import { hasPermission } from "../permissions.ts";
import { SecretStore } from "../secrets.ts";
import { cliValue } from "../sentra-cli.ts";
import { verifyGitHubSignature, verifyGitLabToken } from "../webhook-verify.ts";
import { extractJsonObject } from "../llm.ts";

function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe("token grants", () => {
  test("parses role:token and role:label:token entries", () => {
    const grants = parseTokenGrants(`admin:${"a".repeat(32)},viewer:alice:${"b".repeat(40)}`);
    expect(grants.map((grant) => [grant.role, grant.label])).toEqual([
      ["admin", "admin"],
      ["viewer", "alice"],
    ]);
  });

  test("rejects short tokens, unknown roles and duplicates", () => {
    expect(() => parseTokenGrants("admin:short")).toThrow(ConfigError);
    expect(() => parseTokenGrants(`root:${"a".repeat(32)}`)).toThrow(ConfigError);
    expect(() => parseTokenGrants(`admin:${"a".repeat(32)},viewer:${"a".repeat(32)}`)).toThrow(ConfigError);
  });
});

describe("permissions", () => {
  test("publication and disclosure require admin", () => {
    expect(hasPermission("operator", "github:create-pr")).toBe(false);
    expect(hasPermission("operator", "github:comment")).toBe(false);
    expect(hasPermission("admin", "github:create-pr")).toBe(true);
    expect(hasPermission("viewer", "scan:run")).toBe(false);
    expect(hasPermission("operator", "scan:run")).toBe(true);
    expect(hasPermission("operator", "patch:apply")).toBe(false);
  });
});

describe("audit chain", () => {
  function freshLog() {
    const dir = tempDir("sentra-audit-");
    const db = openWebDb(path.join(dir, "web.db"));
    return { db, log: new AuditLog(db, crypto.randomBytes(32)) };
  }

  test("verifies an intact chain", () => {
    const { log } = freshLog();
    const actor = { label: "alice", role: "admin" };
    log.append(actor, { action: "scan_started", outcome: "success", tenantId: "t1", details: { b: 2, a: 1 } });
    log.append(actor, { action: "scan_finished", outcome: "success", tenantId: "t1" });
    const result = log.verify();
    expect(result.valid).toBe(true);
    expect(result.checkedEntries).toBe(2);
  });

  test("rejects UPDATE and DELETE through triggers", () => {
    const { db, log } = freshLog();
    log.append({ label: "alice", role: "admin" }, { action: "x", outcome: "success" });
    expect(() => db.exec("UPDATE audit_log SET action = 'y'")).toThrow();
    expect(() => db.exec("DELETE FROM audit_log")).toThrow();
  });

  test("detects tampering when triggers are bypassed", () => {
    const { db, log } = freshLog();
    log.append({ label: "alice", role: "admin" }, { action: "x", outcome: "success" });
    log.append({ label: "alice", role: "admin" }, { action: "y", outcome: "success" });
    db.exec("DROP TRIGGER audit_log_no_update");
    db.exec("UPDATE audit_log SET action = 'forged' WHERE seq = 1");
    const result = log.verify();
    expect(result.valid).toBe(false);
    expect(result.firstInvalidSeq).toBe(1);
  });

  test("canonical JSON sorts keys recursively", () => {
    expect(canonicalJson({ b: 1, a: { d: 1, c: [2, { f: 1, e: 0 }] } })).toBe('{"a":{"c":[2,{"e":0,"f":1}],"d":1},"b":1}');
  });
});

describe("secret store", () => {
  test("round-trips and binds ciphertext to the secret name", () => {
    const db = openWebDb(path.join(tempDir("sentra-secret-"), "web.db"));
    const store = new SecretStore(db, crypto.randomBytes(32));
    store.set("a", "value-a", "admin");
    store.set("b", "value-b", "admin");
    expect(store.get("a")).toBe("value-a");
    const cipherB = (db.query("SELECT ciphertext FROM secrets WHERE name = 'b'").get() as { ciphertext: string }).ciphertext;
    db.query("UPDATE secrets SET ciphertext = ? WHERE name = 'a'").run(cipherB);
    expect(() => store.get("a")).toThrow();
  });
});

describe("path jail", () => {
  test("rejects traversal outside the workspace", () => {
    const root = tempDir("sentra-ws-");
    fs.writeFileSync(path.join(root, "ok.txt"), "ok");
    expect(resolveInside(root, "ok.txt").relative).toBe("ok.txt");
    expect(() => resolveInside(root, "../escape.txt")).toThrow(HttpError);
    expect(() => resolveInside(root, path.resolve(root, "..", "x"))).toThrow(HttpError);
    expect(() => resolveInside(root, "a\u0000b")).toThrow(HttpError);
  });
});

describe("outbound URL guard", () => {
  test("classifies private and loopback addresses", () => {
    expect(isBlockedAddress("10.1.2.3")).toBe(true);
    expect(isBlockedAddress("169.254.169.254")).toBe(true);
    expect(isBlockedAddress("::ffff:192.168.1.1")).toBe(true);
    expect(isBlockedAddress("fd00::1")).toBe(true);
    expect(isBlockedAddress("8.8.8.8")).toBe(false);
    expect(isLoopbackAddress("127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("::1")).toBe(true);
  });

  test("blocks metadata endpoints and plain http", async () => {
    await expect(assertSafeOutboundUrl("https://169.254.169.254/latest")).rejects.toThrow(HttpError);
    await expect(assertSafeOutboundUrl("http://8.8.8.8/")).rejects.toThrow(HttpError);
    await expect(assertSafeOutboundUrl("https://user:pass@8.8.8.8/")).rejects.toThrow(HttpError);
    await expect(assertSafeOutboundUrl("https://8.8.8.8/v1")).resolves.toBeInstanceOf(URL);
    await expect(assertSafeOutboundUrl("http://127.0.0.1:11434/v1", { allowLoopback: true, allowHttp: true })).resolves.toBeInstanceOf(URL);
    await expect(assertSafeOutboundUrl("http://10.0.0.5:11434/v1", { allowLoopback: true, allowHttp: true })).rejects.toThrow(HttpError);
  });
});

describe("webhook verification", () => {
  test("accepts a valid GitHub signature and rejects forgeries", () => {
    const secret = "s3cr3t-value";
    const body = '{"zen":"hello"}';
    const signature = `sha256=${crypto.createHmac("sha256", secret).update(body).digest("hex")}`;
    expect(verifyGitHubSignature(secret, body, signature)).toBe(true);
    expect(verifyGitHubSignature(secret, `${body} `, signature)).toBe(false);
    expect(verifyGitHubSignature("other", body, signature)).toBe(false);
    expect(verifyGitHubSignature(secret, body, null)).toBe(false);
    expect(verifyGitHubSignature(secret, body, "sha1=abc")).toBe(false);
  });

  test("compares GitLab tokens", () => {
    expect(verifyGitLabToken("token-123", "token-123")).toBe(true);
    expect(verifyGitLabToken("token-123", "token-124")).toBe(false);
    expect(verifyGitLabToken("token-123", null)).toBe(false);
  });
});

describe("cli argument guard", () => {
  test("rejects values that look like flags", () => {
    expect(() => cliValue("--database", "workspace")).toThrow(HttpError);
    expect(() => cliValue("", "workspace")).toThrow(HttpError);
    expect(cliValue("C:/work/repo", "workspace")).toBe("C:/work/repo");
  });
});

describe("git metadata", () => {
  test("parses GitHub remotes", () => {
    expect(parseGitHubRemote("https://github.com/Taiizor/Sentra.git")).toEqual({ owner: "Taiizor", repo: "Sentra" });
    expect(parseGitHubRemote("git@github.com:owner/repo.git")).toEqual({ owner: "owner", repo: "repo" });
    expect(parseGitHubRemote("https://gitlab.com/owner/repo.git")).toBeNull();
  });

  test("reads HEAD and origin without executing git", () => {
    const root = tempDir("sentra-git-");
    const gitDir = path.join(root, ".git");
    fs.mkdirSync(path.join(gitDir, "refs", "heads"), { recursive: true });
    fs.writeFileSync(path.join(gitDir, "HEAD"), "ref: refs/heads/main\n");
    fs.writeFileSync(path.join(gitDir, "refs", "heads", "main"), `${"a".repeat(40)}\n`);
    fs.writeFileSync(path.join(gitDir, "config"), '[remote "origin"]\n\turl = https://github.com/o/r.git\n');
    expect(readHead(root)).toEqual({ branch: "main", sha: "a".repeat(40), detached: false });
    expect(readRemoteUrl(root)).toBe("https://github.com/o/r.git");
  });
});

describe("misc helpers", () => {
  test("parses cookies", () => {
    expect(parseCookies("a=1; sentra_session=abc; a=2")).toEqual({ a: "1", sentra_session: "abc" });
  });

  test("extracts JSON objects from fenced model output", () => {
    expect(extractJsonObject('Here:\n```json\n{"a":1}\n```')).toEqual({ a: 1 });
    expect(() => extractJsonObject("no json here")).toThrow(HttpError);
  });

  test("web database migrations are idempotent", () => {
    const file = path.join(tempDir("sentra-db-"), "web.db");
    openWebDb(file).close();
    const db = openWebDb(file);
    const count = (db.query("SELECT COUNT(*) AS c FROM schema_migrations").get() as { c: number }).c;
    expect(count).toBe(WEB_DB_SCHEMA_VERSION);
    expect(db).toBeInstanceOf(Database);
  });
});
