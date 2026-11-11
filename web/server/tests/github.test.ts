import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { PrScanResultView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { AuditLog } from "../audit-log.ts";
import { openWebDb } from "../db.ts";
import { GitHubService, githubTokenShapeError, GITHUB_PAT_SECRET, type GitHubFetcher, type PullRequestFile } from "../github.ts";
import { HttpError } from "../http-error.ts";
import { Router, type Principal, type RouteContext } from "../http.ts";
import { pullNumberParam, registerGitHubRoutes } from "../routes/github.ts";
import { SecretStore } from "../secrets.ts";
import type { CliResult, CliRunOptions } from "../sentra-cli.ts";
import {
  allowedCommitStates,
  contentProblem,
  derivePrScanStatus,
  latestPrScan,
  mapCoreSeverity,
  mapScanMatches,
  planPrFiles,
  prFilePathProblem,
  prScanAtHead,
  prSecurityView,
  repositoryKey,
  runPrScan,
  savePrScan,
  scansForPulls,
} from "../services/pr-scan.ts";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

const created: { dir: string; close: () => void }[] = [];

function freshDb() {
  // Canonical: PR scan workspaces are compared with realpath results (/private/var on macOS, long
  // names instead of 8.3 short names on Windows CI runners).
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentra-gh-")));
  const db = openWebDb(path.join(dir, "web.db"));
  created.push({ dir, close: () => db.close() });
  return { dir, db };
}

afterAll(() => {
  for (const entry of created) {
    try {
      entry.close();
    } catch {
      // already closed
    }
    fs.rmSync(entry.dir, { recursive: true, force: true });
  }
});

function prFile(filename: string, status = "modified"): PullRequestFile {
  return { filename, status, additions: 1, deletions: 0, changes: 1, previousFilename: null };
}

function scanView(overrides: Partial<PrScanResultView> = {}): PrScanResultView {
  return {
    prNumber: 7,
    headSha: SHA_A,
    status: "clean",
    filesConsidered: 2,
    filesScanned: 2,
    skipped: [],
    matches: [],
    signalsFound: 0,
    criticalCount: 0,
    highCount: 0,
    scannedAt: "2026-11-10T10:00:00.000Z",
    scannedBy: "alice",
    error: null,
    ...overrides,
  };
}

describe("github token shape", () => {
  test("accepts every documented GitHub token prefix", () => {
    for (const prefix of ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]) {
      expect(githubTokenShapeError(`${prefix}${"A1b2".repeat(9)}`)).toBeNull();
    }
  });

  test("rejects unknown prefixes, whitespace, short and oversized values", () => {
    expect(githubTokenShapeError("")).not.toBeNull();
    expect(githubTokenShapeError(`sk-${"a".repeat(40)}`)).toContain("must start with");
    expect(githubTokenShapeError(`ghp_${"a".repeat(20)} x`)).toContain("whitespace");
    expect(githubTokenShapeError(` ghp_${"a".repeat(36)}`)).toContain("whitespace");
    expect(githubTokenShapeError("ghp_short")).toContain("too short");
    expect(githubTokenShapeError(`ghp_${"a".repeat(300)}`)).toContain("255");
    expect(githubTokenShapeError(`ghp_${"a".repeat(30)}-$`)).toContain("characters");
  });
});

describe("pull request number parameter", () => {
  test("accepts positive integers only", () => {
    expect(pullNumberParam("1")).toBe(1);
    expect(pullNumberParam("4242")).toBe(4242);
    for (const bad of [undefined, "", "0", "-1", "01", "1.5", "abc", "99999999999"]) {
      expect(() => pullNumberParam(bad)).toThrow(HttpError);
    }
  });
});

describe("PR scan path validation", () => {
  test("accepts ordinary repository paths", () => {
    for (const ok of ["src/main.rs", "a/b/c.ts", ".github/workflows/ci.yml", "web/server/x.test.ts", "README"]) {
      expect(prFilePathProblem(ok)).toBeNull();
    }
  });

  test("rejects traversal, absolute, drive, NUL, backslash and Windows-reserved paths", () => {
    const bad = [
      "",
      "../etc/passwd",
      "src/../../x",
      "./x",
      "/etc/passwd",
      "\\server\\share",
      "C:/Windows/x",
      "c:x",
      "src\\main.rs",
      "a//b",
      "a/b/",
      "x\u0000y",
      "x\ny",
      ".git/config",
      "sub/.GIT/hooks/pre-commit",
      "con.txt",
      "dir/NUL",
      "lpt1.log",
      "file:stream",
      "what?.txt",
      "trailing.",
      "trailing ",
      `${"a".repeat(256)}/x`,
    ];
    for (const value of bad) {
      expect(prFilePathProblem(value)).not.toBeNull();
    }
  });
});

describe("PR scan planning", () => {
  test("skips removed files and unsafe paths with reasons", () => {
    const plan = planPrFiles([prFile("src/a.ts"), prFile("old.ts", "removed"), prFile("../evil.ts")], true);
    expect(plan.candidates.map((file) => file.filename)).toEqual(["src/a.ts"]);
    expect(plan.nonRemoved).toBe(2);
    // The unsafe path still has content at the head, so it leaves part of the change unscanned.
    expect(plan.uncovered).toBe(1);
    expect(plan.skipped).toEqual([
      { path: "old.ts", reason: "removed in this pull request (no content at the head commit)" },
      { path: "../evil.ts", reason: "unsafe path: path contains a '.' or '..' segment" },
    ]);
  });

  test("detects case-insensitive collisions only on case-insensitive filesystems", () => {
    const files = [prFile("src/App.ts"), prFile("src/app.ts")];
    expect(planPrFiles(files, true).candidates).toHaveLength(1);
    expect(planPrFiles(files, true).skipped[0].reason).toContain("case-insensitive");
    expect(planPrFiles(files, false).candidates).toHaveLength(2);
  });

  test("detects file/directory conflicts", () => {
    const plan = planPrFiles([prFile("lib"), prFile("LIB/x.ts")], true);
    expect(plan.candidates.map((file) => file.filename)).toEqual(["lib"]);
    expect(plan.skipped).toHaveLength(1);
  });

  test("binary content is not scanned", () => {
    expect(contentProblem("plain text\n")).toBeNull();
    expect(contentProblem("PNG\u0000\u0001")).toContain("binary");
  });
});

describe("PR scan status mapping", () => {
  const base = { cliFailed: false, criticalCount: 0, signalsFound: 0, fetchFailures: 0, filesScanned: 3, eligibleFiles: 3, uncoveredFiles: 0 };

  test("derives clean / warnings / critical / failed", () => {
    expect(derivePrScanStatus(base)).toBe("clean");
    expect(derivePrScanStatus({ ...base, signalsFound: 2 })).toBe("warnings");
    expect(derivePrScanStatus({ ...base, signalsFound: 2, criticalCount: 1 })).toBe("critical");
    expect(derivePrScanStatus({ ...base, cliFailed: true, criticalCount: 1 })).toBe("failed");
  });

  test("never reports clean when coverage is incomplete", () => {
    expect(derivePrScanStatus({ ...base, fetchFailures: 1 })).toBe("failed");
    expect(derivePrScanStatus({ ...base, filesScanned: 0 })).toBe("failed");
    // A pull request that only deletes files has nothing to scan at its head.
    expect(derivePrScanStatus({ ...base, filesScanned: 0, eligibleFiles: 0 })).toBe("clean");
    // Critical signals stay visible even when other files could not be fetched.
    expect(derivePrScanStatus({ ...base, fetchFailures: 2, criticalCount: 1, signalsFound: 1 })).toBe("critical");
  });

  test("a partially scanned pull request cannot read as clean or warnings", () => {
    expect(derivePrScanStatus({ ...base, uncoveredFiles: 1 })).toBe("failed");
    expect(derivePrScanStatus({ ...base, uncoveredFiles: 497, signalsFound: 2 })).toBe("failed");
    expect(derivePrScanStatus({ ...base, uncoveredFiles: 3, signalsFound: 1, criticalCount: 1 })).toBe("critical");
    // 'failed' can only back an error or pending commit status, never success.
    expect(allowedCommitStates({ status: derivePrScanStatus({ ...base, uncoveredFiles: 1 }) })).toEqual(["error", "pending"]);
  });

  test("PR security: not_scanned, current head and stale", () => {
    expect(prSecurityView(SHA_A, []).status).toBe("not_scanned");
    expect(prSecurityView(SHA_A, []).scannedHeadSha).toBeNull();

    const current = prSecurityView(SHA_A, [scanView({ status: "warnings", signalsFound: 3 })]);
    expect(current.status).toBe("warnings");
    expect(current.signalsFound).toBe(3);

    const stale = prSecurityView(SHA_B, [scanView({ status: "critical", criticalCount: 2 })]);
    expect(stale.status).toBe("stale");
    expect(stale.scannedHeadSha).toBe(SHA_A);
    expect(stale.criticalCount).toBe(2);

    // A scan of the current head wins over a newer scan of an older head.
    const mixed = prSecurityView(SHA_A, [
      scanView({ headSha: SHA_B, scannedAt: "2026-11-10T12:00:00.000Z", status: "critical" }),
      scanView({ headSha: SHA_A, scannedAt: "2026-11-10T11:00:00.000Z", status: "clean" }),
    ]);
    expect(mixed.status).toBe("clean");
  });

  test("commit states must be backed by the scan of the current head", () => {
    expect(allowedCommitStates(null)).toEqual(["pending"]);
    expect(allowedCommitStates({ status: "clean" })).toContain("success");
    expect(allowedCommitStates({ status: "critical" })).not.toContain("success");
    expect(allowedCommitStates({ status: "failed" })).toEqual(["error", "pending"]);
    expect(allowedCommitStates({ status: "warnings" })).toEqual(["success", "failure", "pending"]);
  });

  test("maps core scan matches and severities", () => {
    expect(mapCoreSeverity("CRITICAL")).toBe("Critical");
    expect(mapCoreSeverity("INFORMATIONAL")).toBe("Informational");
    expect(mapCoreSeverity("bogus")).toBe("Unknown");
    const matches = mapScanMatches([
      {
        category: "SECRET_LEAK",
        cwe: "CWE-798",
        file_path: "src/probe.ts",
        line_number: 1,
        rationale: "Matched AWS Access Key format (AKIA...)",
        rule_id: "SENTRA-SEC-001",
        rule_name: "AwsAccessKeyId",
        severity: "CRITICAL",
        snippet: "AKIAAB...[REDACTED]",
      },
      { file_path: "x.ts" },
      "garbage",
    ]);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({ ruleId: "SENTRA-SEC-001", severity: "Critical", filePath: "src/probe.ts", line: 1 });
  });
});

describe("PR scan persistence", () => {
  test("stores one row per head sha and returns the latest", () => {
    const { db } = freshDb();
    const key = repositoryKey({ owner: "Taiizor", repo: "Sentra" });
    expect(key).toBe("taiizor/sentra");
    savePrScan(db, key, scanView({ headSha: SHA_A, scannedAt: "2026-11-10T10:00:00.000Z" }));
    savePrScan(db, key, scanView({ headSha: SHA_B, scannedAt: "2026-11-10T11:00:00.000Z", status: "warnings", signalsFound: 1 }));
    // Re-scanning the same head replaces its row.
    savePrScan(db, key, scanView({ headSha: SHA_A, scannedAt: "2026-11-10T12:00:00.000Z", status: "critical", criticalCount: 1 }));
    expect(latestPrScan(db, key, 7)?.headSha).toBe(SHA_A);
    expect(latestPrScan(db, key, 7)?.status).toBe("critical");
    expect(prScanAtHead(db, key, 7, SHA_B)?.status).toBe("warnings");
    expect(latestPrScan(db, key, 8)).toBeNull();
    const grouped = scansForPulls(db, key, [7, 8]);
    expect(grouped.get(7)).toHaveLength(2);
    expect(grouped.has(8)).toBe(false);
  });
});

function cliResult(json: unknown, code = 0): CliResult {
  const stdout = json === undefined ? "" : JSON.stringify(json);
  return { code, stdout, stderr: "", json, timedOut: false, durationMs: 5 };
}

describe("PR scan execution (fake GitHub and core)", () => {
  function setup(options: {
    files: PullRequestFile[];
    contents: Record<string, string | null | Error>;
    cli: (workspace: string, seen: Record<string, string>) => CliResult;
    changedFiles?: number;
  }) {
    const { dir, db } = freshDb();
    const tmpDir = path.join(dir, "tmp");
    const seen: Record<string, string> = {};
    let workspace = "";
    const github = {
      getPullRequest: async () => ({
        number: 7,
        state: "open",
        title: "t",
        htmlUrl: "https://github.com/o/r/pull/7",
        headSha: SHA_A,
        headRef: "feature",
        headRepoFullName: "o/r",
        baseRef: "main",
        isFork: false,
        changedFiles: options.changedFiles ?? options.files.length,
      }),
      listPullRequestFiles: async () => options.files,
      fileAtRef: async (_ref: unknown, filePath: string, gitRef: string) => {
        expect(gitRef).toBe(SHA_A);
        const value = options.contents[filePath];
        if (value instanceof Error) throw value;
        return value ?? null;
      },
    };
    const cli = {
      run: async (args: string[], _options?: CliRunOptions) => {
        expect(args.slice(0, 2)).toEqual(["scan", "--workspace"]);
        expect(args).not.toContain("--database");
        workspace = args[2];
        const walk = (current: string) => {
          for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory()) walk(full);
            else seen[path.relative(workspace, full).split(path.sep).join("/")] = fs.readFileSync(full, "utf8");
          }
        };
        walk(workspace);
        return options.cli(workspace, seen);
      },
    };
    return {
      db,
      tmpDir,
      seen,
      workspace: () => workspace,
      deps: { github, cli, db, tmpDir, scanTimeoutMs: 10_000, caseInsensitiveFs: true },
    };
  }

  const input = { ref: { owner: "o", repo: "r" }, prNumber: 7, actor: { label: "alice", role: "operator" } };

  test("materializes only changed files at the head, scans them and removes the temp dir", async () => {
    const env = setup({
      files: [prFile("src/a.ts"), prFile("a/b.ts"), prFile("gone.ts", "removed"), prFile("img.png")],
      contents: { "src/a.ts": "const k = 1;\n", "a/b.ts": "", "img.png": "\u0089PNG\u0000" },
      cli: () =>
        cliResult({
          schema_version: 1,
          command: "scan",
          files_scanned: 2,
          signals_found: 1,
          matches: [
            { file_path: "src/a.ts", line_number: 1, rule_id: "R1", rule_name: "Rule", severity: "HIGH", cwe: null, category: "X", rationale: "r", snippet: "s" },
          ],
          untrusted_execution: false,
        }),
    });
    const result = await runPrScan(env.deps, input);
    expect(env.seen).toEqual({ "src/a.ts": "const k = 1;\n", "a/b.ts": "" });
    expect(fs.existsSync(env.workspace())).toBe(false);
    expect(path.dirname(env.workspace())).toBe(fs.realpathSync.native(env.tmpDir));
    expect(result.status).toBe("warnings");
    expect(result.filesConsidered).toBe(4);
    expect(result.filesScanned).toBe(2);
    expect(result.highCount).toBe(1);
    expect(result.scannedBy).toBe("alice");
    // Removed and binary files have nothing to scan; they do not make the result partial.
    expect(result.skipped.map((entry) => entry.path).sort()).toEqual(["gone.ts", "img.png"]);
    expect(latestPrScan(env.db, "o/r", 7)?.status).toBe("warnings");
  });

  test("files left out by the bridge make the scan failed even when the scanned part is clean", async () => {
    const env = setup({
      files: [prFile("src/a.ts"), prFile("../x.ts")],
      contents: { "src/a.ts": "const k = 1;\n" },
      changedFiles: 500,
      cli: () => cliResult({ schema_version: 1, command: "scan", files_scanned: 1, signals_found: 0, matches: [] }),
    });
    const result = await runPrScan(env.deps, input);
    expect(result.status).toBe("failed");
    expect(result.filesScanned).toBe(1);
    // One unsafe path plus 498 changed files beyond the listed ones.
    expect(result.error).toContain("Incomplete coverage: 499 changed file(s)");
    expect(allowedCommitStates(result)).toEqual(["error", "pending"]);
  });

  test("a failing core run is stored as failed, never clean", async () => {
    const env = setup({
      files: [prFile("src/a.ts")],
      contents: { "src/a.ts": "x" },
      cli: () => ({ code: 4, stdout: "", stderr: '{"schema_version":1,"error":"invalid_workspace"}', json: undefined, timedOut: false, durationMs: 1 }),
    });
    const result = await runPrScan(env.deps, input);
    expect(result.status).toBe("failed");
    expect(result.error).toContain("invalid_workspace");
    expect(fs.existsSync(env.workspace())).toBe(false);
  });

  test("download failures and oversized files are reported; coverage gaps fail the scan", async () => {
    const env = setup({
      files: [prFile("big.txt"), prFile("flaky.ts"), prFile("ok.ts")],
      contents: {
        "big.txt": new HttpError(502, "upstream_too_large", "too large") as unknown as Error,
        "flaky.ts": new HttpError(502, "upstream_unreachable", "network") as unknown as Error,
        "ok.ts": "fine",
      },
      changedFiles: 400,
      cli: () => cliResult({ schema_version: 1, command: "scan", files_scanned: 1, signals_found: 0, matches: [] }),
    });
    const result = await runPrScan(env.deps, input);
    expect(result.status).toBe("failed");
    expect(result.error).toContain("could not be downloaded");
    const reasons = Object.fromEntries(result.skipped.map((entry) => [entry.path, entry.reason]));
    expect(reasons["big.txt"]).toContain("larger than 1 MiB");
    expect(reasons["flaky.ts"]).toContain("could not be downloaded");
    expect(Object.keys(reasons).some((key) => key.includes("397 further changed files"))).toBe(true);
  });

  test("nothing scannable is reported as failed instead of clean", async () => {
    const env = setup({
      files: [prFile("logo.png")],
      contents: { "logo.png": "\u0000\u0001" },
      cli: () => {
        throw new Error("the core must not run without files");
      },
    });
    const result = await runPrScan(env.deps, input);
    expect(result.status).toBe("failed");
    expect(result.filesScanned).toBe(0);
    expect(result.error).toContain("No changed file could be scanned");
  });
});

describe("GitHub service with an injected fetcher", () => {
  interface Call {
    url: string;
    method: string;
    headers: Record<string, string>;
    body: unknown;
  }

  function service(responses: (call: Call) => { status: number; text: string; headers?: Record<string, string> }, envToken: string | null = "ghp_envtokenenvtokenenvtoken123456") {
    const { db } = freshDb();
    const secrets = new SecretStore(db, crypto.randomBytes(32));
    const calls: Call[] = [];
    const fetcher: GitHubFetcher = async (input, init) => {
      const call: Call = {
        url: String(input),
        method: String(init.method ?? "GET"),
        headers: init.headers as Record<string, string>,
        body: typeof init.body === "string" ? JSON.parse(init.body) : undefined,
      };
      calls.push(call);
      const response = responses(call);
      return {
        status: response.status,
        ok: response.status >= 200 && response.status < 300,
        headers: new Headers(response.headers ?? {}),
        text: response.text,
      };
    };
    return { github: new GitHubService(secrets, envToken, os.tmpdir(), { fetcher, ghTokenReader: () => null }), calls, secrets };
  }

  test("no credential means not configured, never a simulated connection", async () => {
    const { github, calls } = service(() => ({ status: 200, text: "{}" }), null);
    expect(github.resolveAuth()).toBeNull();
    await expect(github.viewer()).rejects.toMatchObject({ status: 412, code: "github_not_configured" });
    expect(calls).toHaveLength(0);
  });

  test("a stored PAT takes precedence over the environment token", () => {
    const { github, secrets } = service(() => ({ status: 200, text: "{}" }));
    expect(github.resolveAuth()?.source).toBe("env_token");
    secrets.set(GITHUB_PAT_SECRET, "ghp_storedstoredstoredstored1234567", "admin");
    expect(github.resolveAuth()).toEqual({ source: "stored_pat", token: "ghp_storedstoredstoredstored1234567" });
  });

  test("viewer verifies an explicit token and maps rejection", async () => {
    const { github, calls } = service((call) =>
      call.headers.Authorization === "Bearer ghp_goodgoodgoodgoodgoodgood1234"
        ? { status: 200, text: JSON.stringify({ login: "octo" }), headers: { "x-oauth-scopes": "repo" } }
        : { status: 401, text: JSON.stringify({ message: "Bad credentials" }) },
    );
    expect(await github.viewer({ source: "stored_pat", token: "ghp_goodgoodgoodgoodgoodgood1234" })).toEqual({ login: "octo", scopes: "repo" });
    expect(calls[0].url.endsWith("/user")).toBe(true);
    const failure = await github.viewer({ source: "stored_pat", token: "ghp_badbadbadbadbadbadbad1234" }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HttpError);
    expect((failure as HttpError).status).toBe(502);
    expect((failure as HttpError).details).toEqual({ githubStatus: 401 });
    expect((failure as HttpError).message).toContain("Bad credentials");
  });

  test("raw file reads distinguish empty files from missing files and pass the size cap", async () => {
    const seenCaps: (number | undefined)[] = [];
    const { db } = freshDb();
    const fetcher: GitHubFetcher = async (input, init) => {
      seenCaps.push(init.maxResponseBytes);
      const url = String(input);
      if (url.includes("/contents/missing.ts")) return { status: 404, ok: false, headers: new Headers(), text: '{"message":"Not Found"}' };
      return { status: 200, ok: true, headers: new Headers(), text: "" };
    };
    const github = new GitHubService(new SecretStore(db, crypto.randomBytes(32)), "ghp_envtokenenvtokenenvtoken123456", os.tmpdir(), {
      fetcher,
      ghTokenReader: () => null,
    });
    expect(await github.fileAtRef({ owner: "o", repo: "r" }, "empty.ts", SHA_A, { maxBytes: 1024 })).toBe("");
    expect(await github.fileAtRef({ owner: "o", repo: "r" }, "missing.ts", SHA_A)).toBeNull();
    expect(seenCaps[0]).toBe(1024);
  });

  test("comment and commit status writes hit the right endpoints and check responses", async () => {
    const { github, calls } = service((call) => {
      if (call.url.endsWith("/issues/7/comments")) return { status: 201, text: JSON.stringify({ id: 99, html_url: "https://github.com/o/r/pull/7#issuecomment-99" }) };
      if (call.url.includes("/statuses/")) return { status: 201, text: JSON.stringify({ id: 5 }) };
      return { status: 500, text: "{}" };
    });
    expect(await github.postIssueComment({ owner: "o", repo: "r" }, 7, "hello")).toEqual({
      id: 99,
      htmlUrl: "https://github.com/o/r/pull/7#issuecomment-99",
    });
    expect(calls[0]).toMatchObject({ method: "POST", body: { body: "hello" } });
    await github.createCommitStatus({ owner: "o", repo: "r" }, SHA_A, "pending", "x".repeat(200));
    expect(calls[1].url).toContain(`/repos/o/r/statuses/${SHA_A}`);
    expect(calls[1].body).toEqual({ state: "pending", context: "sentra/security-scan", description: "x".repeat(140) });
    await expect(github.createCommitStatus({ owner: "o", repo: "r" }, "not-a-sha", "success", "x")).rejects.toMatchObject({ status: 400 });
  });

  test("a rejected write surfaces GitHub's status instead of reporting success", async () => {
    const { github } = service(() => ({ status: 403, text: JSON.stringify({ message: "Resource not accessible by integration" }) }));
    await expect(github.postIssueComment({ owner: "o", repo: "r" }, 7, "hello")).rejects.toMatchObject({
      status: 403,
      code: "github_forbidden",
    });
  });

  test("draft PR creation deletes its branch when a later step fails", async () => {
    const { github, calls } = service((call) => {
      if (call.method === "POST" && call.url.endsWith("/git/refs")) return { status: 201, text: "{}" };
      if (call.method === "PUT") return { status: 201, text: JSON.stringify({ commit: { sha: SHA_B } }) };
      if (call.method === "POST" && call.url.endsWith("/pulls")) return { status: 422, text: JSON.stringify({ message: "Validation Failed" }) };
      if (call.method === "DELETE") return { status: 204, text: "" };
      return { status: 500, text: "{}" };
    });
    await expect(
      github.createSingleFilePullRequest(
        { owner: "o", repo: "r" },
        {
          baseBranch: "main",
          baseSha: SHA_A,
          branchName: "sentra/fix-1",
          filePath: "src/a.ts",
          blobSha: SHA_B,
          newContent: "x",
          commitMessage: "m",
          title: "t",
          body: "b",
        },
      ),
    ).rejects.toMatchObject({ code: "github_conflict" });
    const pullCall = calls.find((call) => call.url.endsWith("/pulls"));
    expect(pullCall).toBeDefined();
    expect((pullCall!.body as { draft: boolean }).draft).toBe(true);
    expect(calls.at(-1)).toMatchObject({ method: "DELETE" });
    expect(calls.at(-1)?.url).toContain("/git/refs/heads/sentra/fix-1");
  });

  test("open pull requests come only from GitHub, with real check counts", async () => {
    const { github } = service(() => ({
      status: 200,
      text: JSON.stringify({
        data: {
          repository: {
            pullRequests: {
              pageInfo: { hasNextPage: false, endCursor: null },
              nodes: [
                {
                  number: 3,
                  title: "Add feature",
                  isDraft: false,
                  url: "https://github.com/o/r/pull/3",
                  createdAt: "2026-11-01T00:00:00Z",
                  updatedAt: "2026-11-02T00:00:00Z",
                  additions: 10,
                  deletions: 2,
                  changedFiles: 4,
                  headRefName: "sentra/fix",
                  headRefOid: SHA_A,
                  baseRefName: "main",
                  author: null,
                  commits: {
                    nodes: [
                      {
                        commit: {
                          statusCheckRollup: {
                            state: "FAILURE",
                            contexts: {
                              nodes: [
                                { __typename: "CheckRun", status: "COMPLETED", conclusion: "SUCCESS" },
                                { __typename: "CheckRun", status: "COMPLETED", conclusion: "FAILURE" },
                                { __typename: "CheckRun", status: "IN_PROGRESS", conclusion: null },
                                { __typename: "StatusContext", state: "PENDING" },
                              ],
                            },
                          },
                        },
                      },
                    ],
                  },
                },
              ],
            },
          },
        },
      }),
    }));
    const { pulls, fetchedAt } = await github.listOpenPullRequestsWithMeta({ owner: "o", repo: "r" });
    expect(Number.isNaN(Date.parse(fetchedAt))).toBe(false);
    expect(pulls).toHaveLength(1);
    expect(pulls[0]).toMatchObject({ number: 3, filesCount: 4, headSha: SHA_A, author: { login: "ghost", avatarUrl: null } });
    expect(pulls[0].checks).toEqual({ total: 4, successful: 1, failed: 1, inProgress: 2, rollupState: "FAILURE" });
  });
});

describe("GitHub routes (fake app context, no network)", () => {
  const ADMIN: Principal = { role: "admin", label: "root", via: "bearer" };

  function routeHarness(options: { credential?: boolean; tokenValid?: boolean } = {}) {
    const { dir, db } = freshDb();
    const secretKey = crypto.randomBytes(32);
    const secrets = new SecretStore(db, secretKey);
    const audit = new AuditLog(db, secretKey);
    const writes: { kind: string; args: unknown[] }[] = [];
    const reads: string[] = [];
    const tenant = {
      tenantId: "t1",
      name: "t1",
      description: "",
      workspace: dir,
      isolationLevel: "single_operator" as const,
      githubOwner: "o",
      githubRepo: "r",
      createdAt: "2026-11-10T00:00:00.000Z",
      createdBy: "root",
      importedFrom: null,
    };
    const github = {
      resolveAuth: () => (options.credential === false ? null : { source: "gh_cli" as const, token: "gho_x" }),
      invalidateCaches: () => {
        reads.push("invalidate");
      },
      viewer: async (auth?: { token: string }) => {
        reads.push(`viewer:${auth ? "explicit" : "resolved"}`);
        if (auth && options.tokenValid === false) {
          throw new HttpError(502, "github_auth_failed", "GitHub rejected the credential (HTTP 401: Bad credentials)", { githubStatus: 401 });
        }
        return { login: "octo", scopes: null };
      },
      repository: async () => ({ fullName: "o/r", private: true, defaultBranch: "main", htmlUrl: "https://github.com/o/r", permissions: null }),
      getPullRequest: async (_ref: unknown, number: number) => {
        reads.push(`pr:${number}`);
        return { number, state: "open", title: "t", htmlUrl: "", headSha: SHA_A, headRef: "f", headRepoFullName: "o/r", baseRef: "main", isFork: false, changedFiles: 1 };
      },
      postIssueComment: async (...args: unknown[]) => {
        writes.push({ kind: "comment", args });
        return { id: 1, htmlUrl: "https://github.com/o/r/pull/7#issuecomment-1" };
      },
      createCommitStatus: async (...args: unknown[]) => {
        writes.push({ kind: "status", args });
      },
    };
    const app = {
      db,
      secrets,
      audit,
      github,
      workspaces: {
        get: (id: string) => {
          if (id !== "t1") throw new HttpError(404, "tenant_not_found", "no");
          return tenant;
        },
        repository: () => ({ owner: "o", repo: "r", source: "configured" as const }),
      },
      cli: { available: () => true },
      config: { tmpDir: path.join(dir, "tmp"), cliLongTimeoutMs: 1000 },
    } as unknown as AppContext;
    const router = new Router();
    registerGitHubRoutes(router, app);

    async function call(method: string, pathname: string, body?: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
      const matched = router.match(method, pathname);
      if (!matched || matched === "method_not_allowed") throw new Error(`no route for ${method} ${pathname}`);
      const url = new URL(`http://127.0.0.1${pathname}`);
      const ctx: RouteContext = {
        req: new Request(url, { method }),
        url,
        params: matched.params,
        principal: ADMIN,
        ip: "127.0.0.1",
        readJson: async () => (body ?? {}) as Record<string, unknown>,
        readText: async () => JSON.stringify(body ?? {}),
      };
      try {
        const response = await matched.route.handler(ctx);
        return { status: response.status, body: (await response.json()) as Record<string, unknown> };
      } catch (error) {
        if (error instanceof HttpError) return { status: error.status, body: { code: error.code, details: error.details } };
        throw error;
      }
    }

    return { call, writes, reads, db, audit, secrets };
  }

  test("routes declare the expected permissions", () => {
    const router = new Router();
    registerGitHubRoutes(router, {} as AppContext);
    const permissions = Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]));
    expect(permissions).toEqual({
      "GET /api/tenants/:tenantId/github": "github:read",
      "PUT /api/tenants/:tenantId/github/repository": "settings:write",
      "PUT /api/settings/github/token": "settings:write",
      "DELETE /api/settings/github/token": "settings:write",
      "GET /api/tenants/:tenantId/github/pulls": "github:read",
      "GET /api/tenants/:tenantId/github/pulls/:number/workflows": "github:read",
      "GET /api/tenants/:tenantId/github/pulls/:number/scan": "github:read",
      "POST /api/tenants/:tenantId/github/pulls/:number/scan": "github:scan",
      "POST /api/tenants/:tenantId/github/pulls/:number/comment": "github:comment",
      "POST /api/tenants/:tenantId/github/pulls/:number/status": "github:status",
    });
  });

  test("a commit status the stored scan cannot back is refused before any write", async () => {
    const h = routeHarness();
    const refused = await h.call("POST", "/api/tenants/t1/github/pulls/7/status", { state: "success", description: "ok" });
    expect(refused.status).toBe(409);
    expect(refused.body.code).toBe("status_not_backed_by_scan");
    expect(h.writes).toHaveLength(0);

    savePrScan(h.db, "o/r", scanView({ prNumber: 7, headSha: SHA_A, status: "critical", criticalCount: 1, signalsFound: 1 }));
    expect((await h.call("POST", "/api/tenants/t1/github/pulls/7/status", { state: "success", description: "ok" })).status).toBe(409);
    const posted = await h.call("POST", "/api/tenants/t1/github/pulls/7/status", { state: "failure", description: "1 critical candidate signal" });
    expect(posted).toEqual({ status: 201, body: { sha: SHA_A, state: "failure" } });
    expect(h.writes).toEqual([{ kind: "status", args: [{ owner: "o", repo: "r" }, SHA_A, "failure", "1 critical candidate signal"] }]);
    const actions = h.audit.list({ limit: 10 }).map((entry) => `${entry.action}:${entry.outcome}`);
    expect(actions).toEqual(["github_commit_status_set:success", "github_commit_status_set:failure", "github_commit_status_set:failure"]);
  });

  test("comments confirm the number is a pull request and never audit the body", async () => {
    const h = routeHarness();
    const result = await h.call("POST", "/api/tenants/t1/github/pulls/7/comment", { body: "secret-ish text body" });
    expect(result).toEqual({ status: 201, body: { id: 1, url: "https://github.com/o/r/pull/7#issuecomment-1" } });
    expect(h.reads).toContain("pr:7");
    const [entry] = h.audit.list({ limit: 1 });
    expect(entry.action).toBe("github_pr_comment_posted");
    expect(JSON.stringify(entry.details)).not.toContain("secret-ish");
    expect(entry.details).toMatchObject({ bodyLength: 20, prNumber: 7, disclosure: "public" });
  });

  test("missing credentials yield 412 instead of a simulated result", async () => {
    const h = routeHarness({ credential: false });
    expect((await h.call("GET", "/api/tenants/t1/github/pulls")).body.code).toBe("github_not_configured");
    expect((await h.call("POST", "/api/tenants/t1/github/pulls/7/comment", { body: "x" })).status).toBe(412);
    const status = await h.call("GET", "/api/tenants/t1/github");
    expect(status.body).toMatchObject({ viewer: null, repositoryInfo: null, credential: { source: null, storedTokenConfigured: false } });
    expect(String(status.body.viewerError)).toContain("No GitHub credential");
    expect(status.body.viewerErrorKind).toBe("no_credential");
    expect(h.writes).toHaveLength(0);
  });

  test("a token is stored only after GitHub accepted it, and never audited", async () => {
    const token = `ghp_${"A".repeat(36)}`;
    const rejected = routeHarness({ tokenValid: false });
    const refused = await rejected.call("PUT", "/api/settings/github/token", { token });
    expect(refused).toMatchObject({ status: 422, body: { code: "github_token_rejected" } });
    expect(rejected.secrets.has(GITHUB_PAT_SECRET)).toBe(false);

    const accepted = routeHarness();
    const stored = await accepted.call("PUT", "/api/settings/github/token", { token });
    expect(stored.status).toBe(200);
    expect(stored.body).toMatchObject({ storedTokenConfigured: true });
    expect(accepted.secrets.get(GITHUB_PAT_SECRET)).toBe(token);
    expect(accepted.reads).toEqual(["viewer:explicit", "invalidate"]);
    const removed = await accepted.call("DELETE", "/api/settings/github/token");
    expect(removed.body).toMatchObject({ storedTokenConfigured: false, storedTokenUpdatedAt: null });
    const audit = JSON.stringify(accepted.audit.list({ limit: 10 }));
    expect(audit).not.toContain(token);
    expect(audit).toContain("github_token_stored");
    expect(audit).toContain("github_token_removed");
    expect((await accepted.call("PUT", "/api/settings/github/token", { token: "nope" })).status).toBe(400);
  });
});
