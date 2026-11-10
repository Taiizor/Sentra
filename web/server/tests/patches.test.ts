import type { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AppContext } from "../app-context.ts";
import { openWebDb } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { Router } from "../http.ts";
import { LlmGateway, type CompletionRequest, type CompletionResult } from "../llm.ts";
import { registerPatchRoutes } from "../routes/patches.ts";
import { SecretStore } from "../secrets.ts";
import type { CliResult, CliRunOptions } from "../sentra-cli.ts";
import {
  assertTransition,
  buildExcerpt,
  buildPullRequestBody,
  generateBranchName,
  isValidGitBranchName,
  parseModelPatch,
  PATCH_LIMITS,
  PatchService,
  renderExcerpt,
  sanitizeCommitMessage,
  validateUnifiedDiff,
  type PatchDeps,
} from "../services/patches.ts";
import type { TenantRecord } from "../services/workspaces.ts";

// Temporary files go under SENTRA_TEST_TMPDIR when set (falls back to the OS temp directory).
const TEST_ROOT = fs.mkdtempSync(path.join(process.env.SENTRA_TEST_TMPDIR ?? os.tmpdir(), "sentra-patches-test-"));
const openDatabases: Database[] = [];
afterAll(() => {
  for (const db of openDatabases) db.close();
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(TEST_ROOT, prefix)));
}

function httpError(fn: () => unknown): HttpError {
  try {
    fn();
  } catch (error) {
    if (error instanceof HttpError) return error;
    throw error;
  }
  throw new Error("expected an HttpError");
}

async function httpErrorAsync(promise: Promise<unknown>): Promise<HttpError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof HttpError) return error;
    throw error;
  }
  throw new Error("expected an HttpError");
}

const TARGET = "src/db.ts";
const GOOD_DIFF = [
  `--- a/${TARGET}`,
  `+++ b/${TARGET}`,
  "@@ -2,3 +2,3 @@",
  " export function find(db, id) {",
  "-  return db.query(\"SELECT * FROM users WHERE id = '\" + id + \"'\");",
  "+  return db.query(\"SELECT * FROM users WHERE id = ?\", [id]);",
  " }",
  "",
].join("\n");

describe("unified diff validation", () => {
  test("accepts a single-file diff with a/ b/ prefixes", () => {
    const result = validateUnifiedDiff(GOOD_DIFF, TARGET);
    expect(result.hunks).toBe(1);
    expect(result.additions).toBe(1);
    expect(result.deletions).toBe(1);
    expect(result.recounted).toBe(false);
    expect(result.diff.startsWith(`--- a/${TARGET}\n+++ b/${TARGET}\n@@ -2,3 +2,3 @@`)).toBe(true);
  });

  test("accepts bare paths, git preambles and CRLF; recounts wrong hunk headers", () => {
    const raw = [
      `diff --git a/${TARGET} b/${TARGET}`,
      "index 1111111..2222222 100644",
      `--- ${TARGET}`,
      `+++ ${TARGET}`,
      "@@ -2,9 +2,9 @@",
      " export function find(db, id) {",
      "-  old();",
      "+  safe();",
      "",
      " }",
    ].join("\r\n");
    const result = validateUnifiedDiff(raw, TARGET);
    expect(result.recounted).toBe(true);
    expect(result.diff).toContain("@@ -2,4 +2,4 @@");
    expect(result.diff).not.toContain("\r");
    // The blank context line regains its leading space.
    expect(result.diff.split("\n")).toContain(" ");
  });

  test("rejects a diff that names another file", () => {
    const error = httpError(() => validateUnifiedDiff(GOOD_DIFF.replaceAll(TARGET, "src/other.ts"), TARGET));
    expect(error.status).toBe(502);
    expect(error.code).toBe("ai_invalid_patch");
  });

  test("rejects file creation, deletion and renames", () => {
    expect(httpError(() => validateUnifiedDiff(GOOD_DIFF.replace(`--- a/${TARGET}`, "--- /dev/null"), TARGET)).code).toBe("ai_invalid_patch");
    expect(httpError(() => validateUnifiedDiff(`new file mode 100644\n${GOOD_DIFF}`, TARGET)).code).toBe("ai_invalid_patch");
    expect(httpError(() => validateUnifiedDiff(`rename from x\nrename to y\n${GOOD_DIFF}`, TARGET)).code).toBe("ai_invalid_patch");
  });

  test("rejects a second file section", () => {
    const second = GOOD_DIFF.replaceAll(TARGET, "src/other.ts");
    const error = httpError(() => validateUnifiedDiff(`${GOOD_DIFF}${second}`, TARGET));
    expect(error.message).toContain("more than one file");
  });

  test("rejects diffs without hunks, without changes, or with malformed lines", () => {
    expect(httpError(() => validateUnifiedDiff(`--- a/${TARGET}\n+++ b/${TARGET}\n`, TARGET)).message).toContain("no hunk");
    expect(httpError(() => validateUnifiedDiff(`--- a/${TARGET}\n+++ b/${TARGET}\n@@ -1,1 +1,1 @@\n same\n`, TARGET)).message).toContain(
      "no added or removed",
    );
    expect(httpError(() => validateUnifiedDiff(`--- a/${TARGET}\n+++ b/${TARGET}\n@@ -1,1 +1,1 @@\n-a\n*b\n`, TARGET)).message).toContain(
      "does not start with",
    );
    expect(httpError(() => validateUnifiedDiff(`--- a/${TARGET}\n+++ b/${TARGET}\n@@ x @@\n-a\n+b\n`, TARGET)).message).toContain("malformed");
    expect(httpError(() => validateUnifiedDiff("just prose", TARGET)).code).toBe("ai_invalid_patch");
    expect(httpError(() => validateUnifiedDiff(42, TARGET)).code).toBe("ai_invalid_patch");
  });

  test("enforces the size cap", () => {
    const huge = `${GOOD_DIFF}${"+x".repeat(PATCH_LIMITS.maxDiffBytes)}\n`;
    expect(httpError(() => validateUnifiedDiff(huge, TARGET)).message).toContain(`${PATCH_LIMITS.maxDiffBytes} bytes`);
  });
});

describe("branch names and commit messages", () => {
  test("generates a valid sentra/fix-<rule>-<hex> branch", () => {
    expect(generateBranchName("SENTRA-SAST-001", () => "a1b2c3")).toBe("sentra/fix-sentra-sast-001-a1b2c3");
    expect(generateBranchName("../..///", () => "000000")).toBe("sentra/fix-finding-000000");
    const random = generateBranchName("SENTRA-SAST-001");
    expect(random).toMatch(/^sentra\/fix-sentra-sast-001-[0-9a-f]{6}$/);
    expect(isValidGitBranchName(random)).toBe(true);
    expect(() => generateBranchName("x", () => "not-hex")).toThrow(HttpError);
  });

  test("applies git ref-format rules", () => {
    for (const valid of ["main", "develop", "release/1.2", "feature/x-y_z"]) expect(isValidGitBranchName(valid)).toBe(true);
    for (const invalid of ["", "-x", "a..b", "a b", "a~1", "a^", "a:b", "a?", "a*", "a[b", "a\\b", "a/", "/a", "a//b", "a.lock", "a/.hidden", "@", "a@{1}", "x."]) {
      expect(isValidGitBranchName(invalid)).toBe(false);
    }
  });

  test("keeps one subject line of at most 72 characters", () => {
    expect(sanitizeCommitMessage("fix(db): use parameterized query\n\nLong body", "R", TARGET)).toBe("fix(db): use parameterized query");
    const long = sanitizeCommitMessage(`fix: ${"word ".repeat(40)}`, "R", TARGET);
    expect(long.length).toBeLessThanOrEqual(72);
    expect(long.includes("\n")).toBe(false);
    expect(sanitizeCommitMessage("  \u0007\n", "SENTRA-SAST-001", TARGET)).toBe(`fix(security): remediate SENTRA-SAST-001 in ${TARGET}`);
    expect(sanitizeCommitMessage(undefined, "SENTRA-SAST-001", `deeply/nested/${"dir/".repeat(20)}file.ts`)).toBe(
      "fix(security): remediate SENTRA-SAST-001 in file.ts",
    );
  });
});

describe("state machine", () => {
  test("apply from proposed or rolled_back; rollback only from applied", () => {
    expect(assertTransition("apply", "proposed")).toBe("applied");
    expect(assertTransition("apply", "rolled_back")).toBe("applied");
    expect(httpError(() => assertTransition("apply", "applied")).status).toBe(409);
    expect(assertTransition("rollback", "applied")).toBe("rolled_back");
    expect(httpError(() => assertTransition("rollback", "proposed")).code).toBe("invalid_patch_state");
    expect(httpError(() => assertTransition("rollback", "rolled_back")).code).toBe("invalid_patch_state");
  });
});

describe("model output parsing", () => {
  test("accepts a fenced JSON object and caps strings", () => {
    const parsed = parseModelPatch(`Here:\n\`\`\`json\n${JSON.stringify({ diff: GOOD_DIFF, rootCause: "x".repeat(5000), testCode: "" })}\n\`\`\``);
    expect(parsed.diff).toBe(GOOD_DIFF);
    expect(parsed.rootCause?.endsWith("[truncated by Sentra]")).toBe(true);
    expect(parsed.testCode).toBeNull();
  });

  test("rejects non-JSON output and objects without a diff", () => {
    const notJson = httpError(() => parseModelPatch("I cannot help with that."));
    expect(notJson.code).toBe("ai_invalid_output");
    expect(notJson.status).toBe(502);
    expect(httpError(() => parseModelPatch(JSON.stringify({ rootCause: "x" }))).code).toBe("ai_invalid_patch");
    expect(httpError(() => parseModelPatch("[1,2,3]")).code).toBe("ai_invalid_output");
  });
});

describe("excerpts", () => {
  const file = Array.from({ length: 300 }, (_, index) => `line ${index + 1}`).join("\n") + "\n";

  test("takes ±radius lines and numbers them", () => {
    const excerpt = buildExcerpt(file, 150, 60);
    expect(excerpt.startLine).toBe(90);
    expect(excerpt.endLine).toBe(210);
    expect(excerpt.totalLines).toBe(300);
    const rendered = renderExcerpt(excerpt, new Map([[100, "matched SENTRA-SEC-001"]]));
    expect(rendered.split("\n")[0]).toBe(" 90 | line 90");
    expect(rendered).toContain("100 | [line withheld by Sentra: matched SENTRA-SEC-001]");
    expect(rendered).not.toContain("line 100\n");
  });

  test("clamps at file edges and rejects stale lines", () => {
    expect(buildExcerpt(file, 1, 60).startLine).toBe(1);
    expect(buildExcerpt(file, 300, 60).endLine).toBe(300);
    const stale = httpError(() => buildExcerpt(file, 301, 60));
    expect(stale.code).toBe("finding_stale");
    expect(stale.status).toBe(409);
  });

  test("shrinks the window to fit the byte cap and rejects oversized lines", () => {
    const wide = Array.from({ length: 200 }, () => "x".repeat(1000)).join("\n");
    const excerpt = buildExcerpt(wide, 100, 60, 48 * 1024);
    expect(excerpt.endLine - excerpt.startLine + 1).toBeLessThan(121);
    expect(renderExcerpt(excerpt).length).toBeLessThanOrEqual(48 * 1024);
    expect(httpError(() => buildExcerpt("y".repeat(100_000), 1, 60, 48 * 1024)).code).toBe("excerpt_too_large");
  });
});

describe("pull request body", () => {
  test("states provenance and that verification did not run", () => {
    const body = buildPullRequestBody({
      ruleId: "SENTRA-SAST-001",
      ruleName: "SqlInjectionStringInterpolation",
      severity: "Critical",
      cwe: "CWE-89",
      targetPath: TARGET,
      line: 3,
      provider: "openai",
      model: "gpt-test",
      baseBranch: "develop",
      baseSha: "a".repeat(40),
      hunks: 1,
      rootCause: "uses ``` fences",
      rationale: null,
    });
    expect(body).toContain("Verification:** not run — no tests were executed by Sentra");
    expect(body).toContain("`openai:gpt-test`");
    expect(body).toContain(`\`develop@${"a".repeat(12)}\``);
    expect(body).toContain("````text\nuses ``` fences\n````");
    expect(body.replace("It has not been verified.", "")).not.toMatch(/(?<!un)verified/i);
  });
});

// ───────────────────────────── service with fakes (no network, no real core) ─────────────────────────────

interface Harness {
  service: PatchService;
  root: string;
  tenant: TenantRecord;
  deps: PatchDeps;
  cliCalls: string[][];
  prompts: CompletionRequest[];
  prCalls: { newContent: string; body: string; branchName: string; commitMessage: string }[];
  setModelText(text: string): void;
  insertFinding(overrides?: Partial<Record<string, unknown>>): string;
}

const VULNERABLE_LINE = "  return db.query(\"SELECT * FROM users WHERE id = '\" + id + \"'\");";
const SAFE_LINE = "  return db.query(\"SELECT * FROM users WHERE id = ?\", [id]);";
const SOURCE = [
  "const key = \"AKIAABCDEFGHIJKLMNOP\";",
  "export function find(db, id) {",
  VULNERABLE_LINE,
  "}",
  "",
].join("\n");

function ok(json: unknown): CliResult {
  return { code: 0, stdout: JSON.stringify(json), stderr: "", json, timedOut: false, durationMs: 1 };
}

function fail(code: number, error: string): CliResult {
  return { code, stdout: "", stderr: JSON.stringify({ schema_version: 1, error }), json: undefined, timedOut: false, durationMs: 1 };
}

function flag(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  return index === -1 ? null : args[index + 1];
}

/**
 * A stand-in for the core CLI: secret scan of stdin, and `patch apply`/`patch rollback` that
 * replace the vulnerable line with the safe line. Only used to drive the service's control flow.
 */
function fakeCli(calls: string[][], options: { supportsFileName?: boolean } = {}) {
  const supportsFileName = options.supportsFileName ?? true;
  return {
    async run(args: string[], options: CliRunOptions = {}): Promise<CliResult> {
      calls.push(args);
      if (args[0] === "scan" && args[1] === "-") {
        if (args.includes("--file-name") && !supportsFileName) return fail(2, "invalid_arguments");
        const matches = (options.stdin ?? "")
          .split("\n")
          .map((text, index) => ({ text, line: index + 1 }))
          .filter((entry) => entry.text.includes("AKIA"))
          .map((entry) => ({ category: "SECRET_LEAK", rule_id: "SENTRA-SEC-001", line_number: entry.line, snippet: "AKIAAB...[REDACTED]" }));
        return ok({ schema_version: 1, command: "scan", matches });
      }
      if (args[0] === "patch" && args[1] === "apply") {
        const workspace = flag(args, "--workspace") as string;
        const target = flag(args, "--target") as string;
        const file = path.join(workspace, target);
        const current = fs.readFileSync(file, "utf8");
        if (!current.includes(VULNERABLE_LINE)) return fail(4, "patch_does_not_apply");
        if (args.includes("--dry-run")) {
          return ok({ schema_version: 1, command: "patch apply", status: "success", dry_run: true, target_path: target, already_patched: false, hunks: 1 });
        }
        const backupDir = flag(args, "--backup-dir") as string;
        const backup = path.join(backupDir, `${path.basename(target)}_${Date.now()}_${crypto.randomBytes(2).toString("hex")}.bak`);
        fs.writeFileSync(backup, current);
        fs.writeFileSync(file, current.replace(VULNERABLE_LINE, SAFE_LINE));
        return ok({
          schema_version: 1,
          command: "patch apply",
          status: "success",
          target_path: target,
          backup_path: backup,
          already_patched: false,
          audit_recorded: flag(args, "--database") !== null,
        });
      }
      if (args[0] === "patch" && args[1] === "rollback") {
        const backup = flag(args, "--backup") as string;
        const file = path.join(flag(args, "--workspace") as string, flag(args, "--target") as string);
        fs.writeFileSync(file, fs.readFileSync(backup));
        return ok({ schema_version: 1, command: "patch rollback", status: "success", restored_from: backup, audit_recorded: true });
      }
      return fail(2, "invalid_arguments");
    },
  };
}

function harness(): Harness {
  const dataDir = tempDir("data-");
  const root = tempDir("ws-");
  fs.mkdirSync(path.join(root, "src"));
  fs.writeFileSync(path.join(root, TARGET), SOURCE);
  const tmpDir = path.join(dataDir, "tmp");
  const backupDir = path.join(dataDir, "backups");
  fs.mkdirSync(tmpDir);
  fs.mkdirSync(backupDir);
  const db = openWebDb(path.join(dataDir, "web.db"));
  openDatabases.push(db);
  const cliCalls: string[][] = [];
  const prompts: CompletionRequest[] = [];
  const prCalls: Harness["prCalls"] = [];
  let modelText = JSON.stringify({
    rootCause: "String concatenation builds the SQL query.",
    rationale: "Use a bound parameter.",
    diff: GOOD_DIFF,
    originalSnippet: VULNERABLE_LINE,
    patchedSnippet: SAFE_LINE,
    testCode: "",
    commitMessage: "fix(db): bind the user id as a query parameter",
  });
  const tenant: TenantRecord = {
    tenantId: "acme",
    name: "Acme",
    description: "",
    workspace: root,
    isolationLevel: "single_operator",
    githubOwner: "acme",
    githubRepo: "app",
    createdAt: new Date().toISOString(),
    createdBy: "test",
    importedFrom: null,
  };
  const deps: PatchDeps = {
    db,
    config: { tmpDir, backupDir },
    cli: fakeCli(cliCalls),
    llm: {
      resolve: () => ({ provider: "openai", model: "gpt-test", endpoint: "https://api.openai.com/v1", apiKey: "k" }),
      async complete(request: CompletionRequest): Promise<CompletionResult> {
        prompts.push(request);
        return { provider: "openai", model: "gpt-test", text: modelText, latencyMs: 5, inputTokens: 100, outputTokens: 50 };
      },
    },
    workspaces: {
      workspaceRoot: () => root,
      coreStorePath: () => path.join(dataDir, "core.db"),
      coreStoreState: async () => ({ initialized: true, error: null }),
      repository: () => ({ owner: "acme", repo: "app", source: "configured" as const }),
    },
    github: {
      repository: async () => ({ fullName: "acme/app", private: true, defaultBranch: "develop", htmlUrl: "https://github.com/acme/app", permissions: null }),
      fileForPatch: async () => ({ baseSha: "b".repeat(40), blobSha: "c".repeat(40), content: SOURCE }),
      async createSingleFilePullRequest(_ref, input) {
        prCalls.push({ newContent: input.newContent, body: input.body, branchName: input.branchName, commitMessage: input.commitMessage });
        return { number: 7, htmlUrl: "https://github.com/acme/app/pull/7", commitSha: "d".repeat(40) };
      },
    },
  };
  let counter = 0;
  return {
    service: new PatchService(deps),
    root,
    tenant,
    deps,
    cliCalls,
    prompts,
    prCalls,
    setModelText: (text) => {
      modelText = text;
    },
    insertFinding(overrides = {}) {
      counter += 1;
      const now = new Date().toISOString();
      const row: Record<string, unknown> = {
        finding_id: `f-${counter}`,
        tenant_id: "acme",
        workspace: root,
        fingerprint: `fp-${counter}`,
        source: "sast",
        rule_id: "SENTRA-SAST-001",
        rule_name: "SqlInjectionStringInterpolation",
        cwe: "CWE-89",
        severity: "Critical",
        category: "SQL_INJECTION",
        file_path: TARGET,
        line: 3,
        rationale: "SQL query constructed via string concatenation",
        package_name: null,
        details_json: null,
        first_seen_run: "run-1",
        last_seen_run: "run-1",
        first_seen_at: now,
        last_seen_at: now,
        state: "open",
        ...overrides,
      };
      const columns = Object.keys(row);
      db.query(`INSERT INTO findings (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`).run(
        ...(columns.map((column) => row[column]) as (string | number | null)[]),
      );
      return row.finding_id as string;
    },
  };
}

const ACTOR = { label: "alice", role: "admin" };

describe("patch service", () => {
  test("no configured provider → 412 before any file access or core call", async () => {
    const h = harness();
    const findingId = h.insertFinding();
    const db = h.deps.db;
    const llm = new LlmGateway(db, new SecretStore(db, crypto.randomBytes(32)));
    const service = new PatchService({ ...h.deps, llm });
    const error = await httpErrorAsync(service.generate(h.tenant, findingId, undefined, ACTOR));
    expect(error.status).toBe(412);
    expect(error.code).toBe("ai_not_configured");
    expect(h.cliCalls).toHaveLength(0);
  });

  test("generates a dry-run-checked, unverified candidate without sending secrets", async () => {
    const h = harness();
    const findingId = h.insertFinding();
    const meta: Record<string, unknown> = {};
    const bundle = await h.service.generate(h.tenant, findingId, undefined, ACTOR, (m) => Object.assign(meta, m));
    expect(bundle.verificationStatus).toBe("not_run");
    expect(bundle.state).toBe("proposed");
    expect(bundle.appliesCleanly).toBe(true);
    expect(bundle.applyCheckDetail).toBe("dry-run applied 1 hunk(s)");
    expect(bundle.targetPath).toBe(TARGET);
    expect(bundle.branchName).toMatch(/^sentra\/fix-sentra-sast-001-[0-9a-f]{6}$/);
    expect(bundle.commitMessage).toBe("fix(db): bind the user id as a query parameter");
    expect(bundle.provider).toBe("openai");
    expect(meta).toMatchObject({ provider: "openai", model: "gpt-test", inputTokens: 100, outputTokens: 50, redactedLines: 1, appliesCleanly: true });

    const prompt = h.prompts[0];
    expect(prompt.expectJson).toBe(true);
    expect(prompt.maxTokens).toBe(4096);
    expect(prompt.system).toContain("untrusted");
    expect(prompt.user).toContain("3 | " + VULNERABLE_LINE);
    expect(prompt.user).toContain("[line withheld by Sentra: matched SENTRA-SEC-001]");
    expect(prompt.user).not.toContain("AKIA");

    const dryRun = h.cliCalls.find((args) => args.includes("--dry-run"));
    expect(dryRun).toBeDefined();
    expect(dryRun).not.toContain("--database");
    expect(fs.readFileSync(path.join(h.root, TARGET), "utf8")).toBe(SOURCE);
    expect(h.service.list("acme").map((entry) => entry.bundleId)).toEqual([bundle.bundleId]);
  });

  test("secret pre-check passes the file name, falls back for older cores and withholds recorded secret lines", async () => {
    const h = harness();
    h.insertFinding({ rule_id: "SENTRA-SEC-005", rule_name: "GenericSecret", category: "SECRET_LEAK", line: 2 });
    await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    expect(h.cliCalls[0]).toEqual(["scan", "-", "--file-name", "db.ts", "--json"]);
    expect(h.prompts[0].user).toContain("2 | [line withheld by Sentra: recorded finding SENTRA-SEC-005]");
    expect(h.prompts[0].user).toContain("2 line(s) were withheld");

    const calls: string[][] = [];
    const legacy = new PatchService({ ...h.deps, cli: fakeCli(calls, { supportsFileName: false }) });
    await legacy.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    expect(calls.slice(0, 2)).toEqual([
      ["scan", "-", "--file-name", "db.ts", "--json"],
      ["scan", "-", "--json"],
    ]);
  });

  test("fails closed when the secret pre-check cannot run", async () => {
    const h = harness();
    const broken = new PatchService({
      ...h.deps,
      cli: { run: async () => fail(1, "internal_error") },
    });
    const error = await httpErrorAsync(broken.generate(h.tenant, h.insertFinding(), undefined, ACTOR));
    expect(error.code).toBe("secret_precheck_failed");
    expect(h.prompts).toHaveLength(0);
  });

  test("records a failed dry-run honestly", async () => {
    const h = harness();
    const findingId = h.insertFinding();
    fs.writeFileSync(path.join(h.root, TARGET), SOURCE.replace(VULNERABLE_LINE, "  return 1;"));
    const bundle = await h.service.generate(h.tenant, findingId, undefined, ACTOR);
    expect(bundle.appliesCleanly).toBe(false);
    expect(bundle.applyCheckDetail).toContain("patch_does_not_apply");
  });

  test("rejects invalid model output without persisting anything", async () => {
    const h = harness();
    const findingId = h.insertFinding();
    h.setModelText("Sorry, no JSON here");
    expect((await httpErrorAsync(h.service.generate(h.tenant, findingId, undefined, ACTOR))).code).toBe("ai_invalid_output");
    h.setModelText(JSON.stringify({ diff: GOOD_DIFF.replaceAll(TARGET, "src/elsewhere.ts") }));
    expect((await httpErrorAsync(h.service.generate(h.tenant, findingId, undefined, ACTOR))).code).toBe("ai_invalid_patch");
    expect(h.service.list("acme")).toHaveLength(0);
  });

  test("refuses dependency, secret, resolved and unknown findings", async () => {
    const h = harness();
    const dependency = h.insertFinding({
      source: "dependency",
      file_path: "bun.lock",
      line: null,
      package_name: "lodash",
      details_json: JSON.stringify({ fixedVersions: ["4.17.21"] }),
    });
    const dependencyError = await httpErrorAsync(h.service.generate(h.tenant, dependency, undefined, ACTOR));
    expect(dependencyError.status).toBe(422);
    expect(dependencyError.code).toBe("dependency_finding");
    expect(dependencyError.message).toContain("Upgrade lodash to a fixed version: 4.17.21");

    const secret = h.insertFinding({ rule_id: "SENTRA-SEC-001", category: "SECRET_LEAK", line: 1 });
    const secretError = await httpErrorAsync(h.service.generate(h.tenant, secret, undefined, ACTOR));
    expect(secretError.code).toBe("secret_finding");
    expect(secretError.message).toContain("Rotate the credential");

    const resolved = h.insertFinding({ state: "resolved" });
    expect((await httpErrorAsync(h.service.generate(h.tenant, resolved, undefined, ACTOR))).code).toBe("finding_not_open");
    expect((await httpErrorAsync(h.service.generate(h.tenant, "missing", undefined, ACTOR))).status).toBe(404);
    expect(h.prompts).toHaveLength(0);
  });

  test("apply → rollback → apply follows the state machine and stores the core backup path", async () => {
    const h = harness();
    const bundle = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    const file = path.join(h.root, TARGET);

    const applied = await h.service.apply(h.tenant, bundle.bundleId, ACTOR);
    expect(applied.view.state).toBe("applied");
    expect(applied.view.appliedBy).toBe("alice");
    expect(applied.coreAuditRecorded).toBe(true);
    expect(fs.readFileSync(file, "utf8")).toContain(SAFE_LINE);
    const applyCall = h.cliCalls.find((args) => args[1] === "apply" && args.includes("--database"));
    expect(flag(applyCall as string[], "--backup-dir")).toBe(path.join(h.deps.config.backupDir, "acme"));
    expect((await httpErrorAsync(h.service.apply(h.tenant, bundle.bundleId, ACTOR))).code).toBe("invalid_patch_state");

    const rolledBack = await h.service.rollback(h.tenant, bundle.bundleId, ACTOR);
    expect(rolledBack.view.state).toBe("rolled_back");
    expect(rolledBack.view.rolledBackBy).toBe("alice");
    expect(fs.readFileSync(file, "utf8")).toBe(SOURCE);
    expect((await httpErrorAsync(h.service.rollback(h.tenant, bundle.bundleId, ACTOR))).code).toBe("invalid_patch_state");

    const reapplied = await h.service.apply(h.tenant, bundle.bundleId, ACTOR);
    expect(reapplied.view.state).toBe("applied");
    expect(reapplied.view.rolledBackAt).toBeNull();
  });

  test("apply maps patch_does_not_apply to 409 and leaves the bundle proposed", async () => {
    const h = harness();
    const bundle = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    fs.writeFileSync(path.join(h.root, TARGET), "changed\n");
    const error = await httpErrorAsync(h.service.apply(h.tenant, bundle.bundleId, ACTOR));
    expect(error.status).toBe(409);
    expect(error.code).toBe("patch_does_not_apply");
    expect(h.service.get("acme", bundle.bundleId).state).toBe("proposed");
  });

  test("rollback refuses to discard edits made after apply", async () => {
    const h = harness();
    const bundle = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    await h.service.apply(h.tenant, bundle.bundleId, ACTOR);
    const file = path.join(h.root, TARGET);
    fs.appendFileSync(file, "// operator edit\n");
    const error = await httpErrorAsync(h.service.rollback(h.tenant, bundle.bundleId, ACTOR));
    expect(error.code).toBe("target_modified_since_apply");
    expect(fs.readFileSync(file, "utf8")).toContain("// operator edit");
    expect(h.service.get("acme", bundle.bundleId).state).toBe("applied");
  });

  test("only one applied patch per file", async () => {
    const h = harness();
    const first = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    const second = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    await h.service.apply(h.tenant, first.bundleId, ACTOR);
    expect((await httpErrorAsync(h.service.apply(h.tenant, second.bundleId, ACTOR))).code).toBe("target_has_applied_patch");
  });

  test("opens a draft PR from content computed against the base branch", async () => {
    const h = harness();
    const bundle = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    const created = await h.service.createPullRequest(h.tenant, bundle.bundleId, undefined);
    expect(created).toMatchObject({ number: 7, baseBranch: "develop", baseSha: "b".repeat(40), branch: bundle.branchName });
    const call = h.prCalls[0];
    expect(call.newContent).toBe(SOURCE.replace(VULNERABLE_LINE, SAFE_LINE));
    expect(call.body).toContain("Verification:** not run");
    expect(call.body).toContain("`openai:gpt-test`");
    expect(call.commitMessage).toBe("fix(db): bind the user id as a query parameter");
    // The local workspace is untouched by PR creation.
    expect(fs.readFileSync(path.join(h.root, TARGET), "utf8")).toBe(SOURCE);
    expect(h.service.get("acme", bundle.bundleId).pullRequest).toEqual({ number: 7, url: "https://github.com/acme/app/pull/7" });
    expect((await httpErrorAsync(h.service.createPullRequest(h.tenant, bundle.bundleId, undefined))).code).toBe("pull_request_exists");
  });

  test("PR creation fails with 409 when the diff does not apply to the base branch, and 412 without a repository", async () => {
    const h = harness();
    const bundle = await h.service.generate(h.tenant, h.insertFinding(), undefined, ACTOR);
    const diverged = new PatchService({
      ...h.deps,
      github: { ...h.deps.github, fileForPatch: async () => ({ baseSha: "e".repeat(40), blobSha: "f".repeat(40), content: "different\n" }) },
    });
    const error = await httpErrorAsync(diverged.createPullRequest(h.tenant, bundle.bundleId, "main"));
    expect(error.status).toBe(409);
    expect(error.code).toBe("patch_does_not_apply");
    expect(error.message).toContain(`main@${"e".repeat(12)}`);

    const noRepo = new PatchService({ ...h.deps, workspaces: { ...h.deps.workspaces, repository: () => null } });
    expect((await httpErrorAsync(noRepo.createPullRequest(h.tenant, bundle.bundleId, undefined))).status).toBe(412);
    expect(h.prCalls).toHaveLength(0);
  });
});

describe("patch routes", () => {
  test("declare the expected permissions", () => {
    const router = new Router();
    registerPatchRoutes(router, {} as AppContext);
    const permissions = Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]));
    expect(permissions).toEqual({
      "POST /api/tenants/:tenantId/findings/:findingId/patches": "ai:generate",
      "GET /api/tenants/:tenantId/patches": "read",
      "POST /api/tenants/:tenantId/patches/:bundleId/apply": "patch:apply",
      "POST /api/tenants/:tenantId/patches/:bundleId/rollback": "patch:apply",
      "POST /api/tenants/:tenantId/patches/:bundleId/pull-request": "github:create-pr",
    });
  });
});
