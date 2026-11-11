import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { CoverageUnitView, ModelReconReportView, ToolAvailability, TopologyReportView } from "../../src/types/api.ts";
import { openWebDb } from "../db.ts";
import { describeSearchScope } from "../executables.ts";
import { HttpError } from "../http-error.ts";
import { listModelReports, MODEL_RECON_DISCLAIMER, parsePromptOutput, saveModelReport } from "../routes/research.ts";
import {
  CoverageLedger,
  parseCoverageId,
  parseUpsertRequest,
  tenantFindingLookup,
  validateCoverageUnits,
} from "../services/coverage.ts";
import {
  computeTopology,
  latestTopologyReport,
  parseCargoToml,
  parseCodeqlProbe,
  parseGoMod,
  parsePackageJson,
  parsePep508,
  parsePyproject,
  parseRequirementsTxt,
  renderGroundedContext,
  saveTopologyReport,
  walkWorkspace,
  type TopologySources,
} from "../services/topology.ts";

const created: string[] = [];

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  created.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of created) fs.rmSync(dir, { recursive: true, force: true });
});

function write(root: string, rel: string, content: string): void {
  const target = path.join(root, ...rel.split("/"));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

function expectHttpError(fn: () => unknown, status: number, code?: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(status);
    if (code) expect((error as HttpError).code).toBe(code);
    return;
  }
  throw new Error("expected an HttpError");
}

function listFiles(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) visit(absolute);
      else out.push(`${path.relative(root, absolute)}:${fs.statSync(absolute).size}`);
    }
  };
  visit(root);
  return out.sort();
}

// ───────────────────────────── coverage ledger ─────────────────────────────

const validBody = (overrides: Record<string, unknown> = {}) => ({
  surface: "http-api",
  boundary: "auth",
  subsystem: "web-server",
  attackClass: "idor",
  status: "planned",
  wave: 1,
  reviewedPaths: [],
  localChecks: [],
  resultFingerprints: [],
  ...overrides,
});

describe("coverage ids and upsert validation", () => {
  test("parses a four-segment id", () => {
    expect(parseCoverageId("http-api/auth/web-server/idor")).toEqual({
      surface: "http-api",
      boundary: "auth",
      subsystem: "web-server",
      attackClass: "idor",
    });
  });

  test("rejects malformed ids", () => {
    for (const bad of ["a/b/c", "a/b/c/d/e", "A/b/c/d", "-a/b/c/d", "a/b/c/d e", `a/b/c/${"x".repeat(64)}`, "a//c/d"]) {
      expectHttpError(() => parseCoverageId(bad), 400, "invalid_coverage_id");
    }
  });

  test("body dimensions must repeat the id segments", () => {
    expectHttpError(() => parseUpsertRequest("http-api/auth/web-server/idor", validBody({ boundary: "other" })), 400, "coverage_id_mismatch");
  });

  test("enforces list sizes, string lengths, status and wave", () => {
    const id = "http-api/auth/web-server/idor";
    expectHttpError(() => parseUpsertRequest(id, validBody({ reviewedPaths: Array.from({ length: 201 }, (_, i) => `f${i}.ts`) })), 400);
    expectHttpError(() => parseUpsertRequest(id, validBody({ localChecks: ["x".repeat(501)] })), 400);
    expectHttpError(() => parseUpsertRequest(id, validBody({ unresolved: "y".repeat(501) })), 400);
    expectHttpError(() => parseUpsertRequest(id, validBody({ status: "verified" })), 400);
    expectHttpError(() => parseUpsertRequest(id, validBody({ wave: -1 })), 400);
    expectHttpError(() => parseUpsertRequest(id, validBody({ resultFingerprints: [42] })), 400);
  });

  test("normalizes lists and optional strings", () => {
    const parsed = parseUpsertRequest(
      "http-api/auth/web-server/idor",
      validBody({ reviewedPaths: [" src/a.ts ", "src/a.ts"], owner: "", unresolved: "  waiting on host  " }),
    );
    expect(parsed.reviewedPaths).toEqual(["src/a.ts"]);
    expect(parsed.owner).toBeNull();
    expect(parsed.unresolved).toBe("waiting on host");
  });
});

describe("coverage ledger storage", () => {
  test("creates, updates, isolates tenants and deletes", async () => {
    const db = openWebDb(path.join(tempDir("sentra-cov-db-"), "web.db"));
    const ledger = new CoverageLedger(db);
    const id = "http-api/auth/web-server/idor";
    const first = ledger.upsert("t1", id, parseUpsertRequest(id, validBody()), "alice");
    expect(first.created).toBe(true);
    await Bun.sleep(5);
    const second = ledger.upsert("t1", id, parseUpsertRequest(id, validBody({ status: "candidate", wave: 2 })), "bob");
    expect(second.created).toBe(false);
    expect(second.unit.createdAt).toBe(first.unit.createdAt);
    expect(second.unit.updatedBy).toBe("bob");
    expect(second.unit.status).toBe("candidate");
    expect(ledger.list("t1")).toHaveLength(1);
    expect(ledger.list("t2")).toHaveLength(0);
    expect(ledger.delete("t2", id)).toBe(false);
    expect(ledger.delete("t1", id)).toBe(true);
    expect(ledger.list("t1")).toHaveLength(0);
    db.close();
  });
});

describe("coverage validation", () => {
  function unit(coverageId: string, overrides: Partial<CoverageUnitView>): CoverageUnitView {
    const [surface, boundary, subsystem, attackClass] = coverageId.split("/");
    return {
      coverageId,
      surface,
      boundary,
      subsystem,
      attackClass,
      status: "planned",
      wave: 0,
      owner: null,
      reviewedPaths: [],
      localChecks: [],
      resultFingerprints: [],
      unresolved: null,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      updatedBy: "alice",
      ...overrides,
    };
  }

  function setup() {
    const base = tempDir("sentra-cov-val-");
    const workspace = path.join(base, "ws");
    write(workspace, "src/app.ts", "export {};\n");
    write(workspace, "a/file.ts", "export {};\n");
    write(base, "outside.txt", "outside\n");
    const db = openWebDb(path.join(base, "web.db"));
    const insert = db.query(
      `INSERT INTO findings (finding_id, tenant_id, workspace, fingerprint, source, rule_id, rule_name, severity,
         first_seen_run, last_seen_run, first_seen_at, last_seen_at, state)
       VALUES (?, ?, ?, ?, 'sast', 'R1', 'Rule', 'High', 'run', 'run', '2026-01-01', '2026-01-01', 'open')`,
    );
    insert.run("f-1", "t1", workspace, "fp-1");
    insert.run("f-2", "t1", workspace, "fp-2");
    insert.run("f-9", "t2", workspace, "fp-other");
    return { workspace: fs.realpathSync.native(workspace), db };
  }

  test("a complete ledger passes", () => {
    const { workspace, db } = setup();
    const result = validateCoverageUnits(
      [
        unit("http/auth/web/idor", { status: "covered", reviewedPaths: ["src/app.ts", "a/file.ts"], localChecks: ["bun test"] }),
        unit("http/auth/web/sqli", { status: "candidate", resultFingerprints: ["fp-1", "f-2"] }),
        unit("http/auth/web/xss", { status: "blocked", unresolved: "needs a running instance" }),
      ],
      { workspaceRoot: workspace, workspaceError: null, findingExists: tenantFindingLookup(db, "t1") },
    );
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.checkedUnits).toBe(3);
    db.close();
  });

  test("reports every rule violation with the unit id", () => {
    const { workspace, db } = setup();
    const result = validateCoverageUnits(
      [
        unit("http/auth/web/a", { status: "covered" }),
        unit("http/auth/web/b", { status: "candidate" }),
        unit("http/auth/web/c", { status: "candidate", resultFingerprints: ["fp-other", "missing", "fp-1"] }),
        unit("http/auth/web/d", { status: "deferred" }),
        unit("http/auth/web/e", { reviewedPaths: ["../outside.txt", "missing.ts", "/etc/passwd"] }),
        unit("http/auth/web/f", { surface: "other" }),
        unit("Bad/id", {}),
      ],
      { workspaceRoot: workspace, workspaceError: null, findingExists: tenantFindingLookup(db, "t1") },
    );
    const rules = result.errors.map((error) => `${error.coverageId}:${error.rule}`);
    expect(result.valid).toBe(false);
    expect(rules).toContain("http/auth/web/a:covered_requires_reviewed_paths");
    expect(rules).toContain("http/auth/web/a:covered_requires_local_checks");
    expect(rules).toContain("http/auth/web/b:candidate_requires_fingerprints");
    expect(rules.filter((rule) => rule === "http/auth/web/c:result_fingerprint_unknown")).toHaveLength(2);
    expect(rules).toContain("http/auth/web/d:unresolved_reason_required");
    expect(rules).toContain("http/auth/web/e:reviewed_path_outside_workspace");
    expect(rules).toContain("http/auth/web/e:reviewed_path_missing");
    expect(rules).toContain("http/auth/web/e:reviewed_path_not_relative");
    expect(rules).toContain("http/auth/web/f:id_format");
    expect(rules).toContain("Bad/id:id_format");
    db.close();
  });

  test("reports an unavailable workspace instead of passing path checks", () => {
    const { db } = setup();
    const result = validateCoverageUnits([unit("http/auth/web/a", { reviewedPaths: ["src/app.ts"] })], {
      workspaceRoot: null,
      workspaceError: "workspace directory is missing",
      findingExists: tenantFindingLookup(db, "t1"),
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].rule).toBe("workspace_unavailable");
    expect(result.errors[0].message).toContain("workspace directory is missing");
    db.close();
  });
});

// ───────────────────────────── topology ─────────────────────────────

describe("manifest parsers", () => {
  test("package.json dependencies, devDependencies and workspaces", () => {
    const parsed = parsePackageJson(
      JSON.stringify({ name: "app", workspaces: { packages: ["packages/*"] }, dependencies: { react: "^19.0.0" }, devDependencies: { vite: "7" } }),
    );
    expect(parsed.packageName).toBe("app");
    expect(parsed.workspaceMembers).toEqual(["packages/*"]);
    expect(parsed.dependencies).toEqual([
      { name: "react", version: "^19.0.0" },
      { name: "vite", version: "7" },
    ]);
  });

  test("Cargo.toml dependency forms, workspace members and multi-line strings", () => {
    const parsed = parseCargoToml(
      [
        "[package]",
        'name = "core-crate"',
        'description = """',
        "[dependencies]",
        'fake = "9"',
        '"""',
        "",
        "[workspace]",
        "members = [",
        '  "crates/*", # comment',
        '  "tools/gen",',
        "]",
        "",
        "[workspace.dependencies]",
        'serde = { version = "1.0", features = ["derive"] }',
        'tokio = "1" # runtime',
        "",
        "[dependencies]",
        "serde.workspace = true",
        'local = { path = "../local" }',
        "",
        "[dependencies.regex]",
        'version = "1.10"',
        "",
        "[dev-dependencies]",
        'ignored = "1"',
      ].join("\n"),
    );
    expect(parsed.packageName).toBe("core-crate");
    expect(parsed.workspaceMembers).toEqual(["crates/*", "tools/gen"]);
    expect(parsed.dependencies).toEqual([
      { name: "serde", version: "1.0" },
      { name: "tokio", version: "1" },
      { name: "local", version: null },
      { name: "regex", version: "1.10" },
    ]);
  });

  test("go.mod require lines skip indirect dependencies", () => {
    const parsed = parseGoMod(
      ["module example.com/app", "", "go 1.22", "", "require github.com/a/b v1.2.3", "require (", "\tgithub.com/c/d v0.1.0", "\tgithub.com/e/f v2.0.0 // indirect", ")"].join("\n"),
    );
    expect(parsed.packageName).toBe("example.com/app");
    expect(parsed.dependencies).toEqual([
      { name: "github.com/a/b", version: "v1.2.3" },
      { name: "github.com/c/d", version: "v0.1.0" },
    ]);
  });

  test("pyproject [project].dependencies and requirements.txt", () => {
    const parsed = parsePyproject(['[project]', 'name = "py"', "dependencies = [", '  "requests[security]>=2.31,<3",', '  "django",', "]", "[tool.other]", 'dependencies = ["no"]'].join("\n"));
    expect(parsed.packageName).toBe("py");
    expect(parsed.dependencies).toEqual([
      { name: "requests", version: ">=2.31,<3" },
      { name: "django", version: null },
    ]);
    expect(parseRequirementsTxt("# c\nflask==3.0.0  # web\n-r base.txt\nhttps://x/y.whl\nnumpy\n").dependencies).toEqual([
      { name: "flask", version: "==3.0.0" },
      { name: "numpy", version: null },
    ]);
    expect(parsePep508("pkg @ https://example.com/pkg.whl")).toEqual({ name: "pkg", version: null });
  });

  test("codeql probe output mapping", () => {
    expect(
      parseCodeqlProbe({ primary_language: "rust", detected_languages: [{ language: "python", files_count: 2 }, { language: "rust", files_count: 9 }] }),
    ).toEqual({
      primaryLanguage: "rust",
      languages: [
        { language: "rust", filesCount: 9 },
        { language: "python", filesCount: 2 },
      ],
    });
    expect(() => parseCodeqlProbe({ command: "codeql" })).toThrow();
  });
});

function buildTree(): { root: string; outside: string } {
  const base = tempDir("sentra-topo-");
  const root = path.join(base, "ws");
  const outside = path.join(base, "outside");
  write(outside, "package.json", JSON.stringify({ name: "outside-pkg", dependencies: { leaked: "1" } }));
  write(root, "package.json", JSON.stringify({ name: "root-app", workspaces: ["packages/*"], dependencies: { react: "^19.0.0" }, devDependencies: { typescript: "~5.8.0" } }));
  write(root, "packages/api/package.json", JSON.stringify({ name: "@x/api", dependencies: { hono: "4.0.0" } }));
  write(root, "packages/api/src/index.ts", "import x from 'y';\n\nBun.serve({ fetch() { return new Response('ok'); } });\n");
  write(root, "packages/notes/README.md", "no manifest here\n");
  write(root, "Cargo.toml", '[workspace]\nmembers = ["crates/*", "tools/gen", "../escape"]\n\n[workspace.dependencies]\nserde = { version = "1.0" }\n');
  write(root, "crates/core/Cargo.toml", '[package]\nname = "core-crate"\n\n[dependencies]\nserde.workspace = true\nanyhow = "1.0"\n');
  write(root, "crates/core/src/main.rs", "#[tokio::main]\nasync fn main() {\n}\n");
  write(root, "tools/gen/Cargo.toml", '[package]\nname = "gen"\n');
  write(root, "tools/gen/src/main.rs", "fn main() {}\n");
  write(root, "go.mod", "module example.com/svc\n\nrequire github.com/a/b v1.0.0\n");
  write(root, "cmd/svc/main.go", "package main\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", nil)\n}\n");
  write(root, "pyproject.toml", '[project]\nname = "py"\ndependencies = ["requests>=2"]\n');
  write(root, "app.py", "from flask import Flask\napp = Flask(__name__)\nif __name__ == \"__main__\":\n    app.run()\n");
  write(root, ".github/workflows/ci.yml", "on:\n  pull_request_target:\n    branches: [main]\n");
  write(root, "Dockerfile", "FROM scratch\n");
  write(root, "docker-compose.yml", "services: {}\n");
  write(root, "node_modules/evil/package.json", JSON.stringify({ name: "evil", dependencies: { bad: "1" } }));
  write(root, "target/debug/Cargo.toml", '[package]\nname = "build-artifact"\n');
  write(root, "Build/package.json", JSON.stringify({ name: "skipped-case-insensitive" }));
  write(root, "a/b/c/d/e/f/package.json", JSON.stringify({ name: "depth-six" }));
  write(root, "a/b/c/d/e/f/g/package.json", JSON.stringify({ name: "depth-seven" }));
  write(root, "lib/index.ts", "Bun.serve({});\n");
  return { root, outside };
}

function tryLink(target: string, link: string): boolean {
  try {
    fs.symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
    return true;
  } catch {
    return false;
  }
}

describe("workspace walk", () => {
  test("finds manifests, honours the skip list and the depth limit", () => {
    const { root } = buildTree();
    const walk = walkWorkspace(root, { maxDepth: 6, maxEntries: 20_000 });
    const paths = walk.manifests.map((manifest) => manifest.path);
    expect(paths).toContain("package.json");
    expect(paths).toContain("packages/api/package.json");
    expect(paths).toContain("crates/core/Cargo.toml");
    expect(paths).toContain("go.mod");
    expect(paths).toContain("pyproject.toml");
    expect(paths).toContain(".github/workflows/ci.yml");
    expect(paths).toContain("Dockerfile");
    expect(paths).toContain("docker-compose.yml");
    expect(paths).toContain("a/b/c/d/e/f/package.json");
    expect(paths).not.toContain("a/b/c/d/e/f/g/package.json");
    expect(paths.some((p) => p.startsWith("node_modules/") || p.startsWith("target/") || p.startsWith("Build/"))).toBe(false);
    expect(walk.depthLimitReached).toBe(true);
    expect(walk.skippedDirectories).toBeGreaterThanOrEqual(3);
    const ci = walk.manifests.find((manifest) => manifest.path === ".github/workflows/ci.yml");
    expect(ci?.kind).toBe("github-workflow");
    expect(walk.manifests.find((manifest) => manifest.path === "go.mod")?.ecosystem).toBe("Go");
  });

  test("stops at the entry limit", () => {
    const { root } = buildTree();
    const walk = walkWorkspace(root, { maxDepth: 6, maxEntries: 5 });
    expect(walk.entriesVisited).toBe(5);
    expect(walk.entryLimitReached).toBe(true);
  });

  test("does not follow symbolic links or junctions", () => {
    const { root, outside } = buildTree();
    if (!tryLink(outside, path.join(root, "linked"))) {
      console.warn("symlink/junction creation not permitted on this host; link assertion skipped");
      return;
    }
    const walk = walkWorkspace(root);
    expect(walk.manifests.some((manifest) => manifest.path.startsWith("linked/"))).toBe(false);
    expect(walk.symlinksSkipped).toBeGreaterThanOrEqual(1);
  });
});

const FAKE_TOOL: ToolAvailability = {
  name: "git",
  available: false,
  path: null,
  resolvedPath: null,
  resolvedVia: null,
  source: null,
  onProcessPath: false,
  binary: null,
  usage: "not_used",
  usageNote: "Never executed.",
  shadowed: [],
  selection: "automatic",
  configuredPath: null,
  configuredPathProblem: null,
  pathConfigurable: true,
  pathHint: null,
};

function fakeSources(overrides: Partial<TopologySources> = {}): TopologySources {
  return {
    languageProbe: async () => ({ primaryLanguage: "rust", languages: [{ language: "rust", filesCount: 2 }] }),
    lockfileInventory: async () => {
      throw new Error("sentra inventory failed: invalid_workspace");
    },
    tools: async () => [FAKE_TOOL],
    // A host where the persisted PATH read failed: the note must not claim it was searched.
    toolSearchScope: () => describeSearchScope({ persistedPathRead: false, persistedPathError: "powershell.exe exited with code 1" }, "win32"),
    ...overrides,
  };
}

describe("topology report", () => {
  test("is computed from the real tree without modifying it", async () => {
    const { root, outside } = buildTree();
    tryLink(outside, path.join(root, "linked"));
    const before = listFiles(root);
    const report = await computeTopology(root, fakeSources());
    expect(listFiles(root)).toEqual(before);

    expect(report.workspace).toBe(root);
    expect(report.primaryLanguage).toBe("rust");
    expect(report.frameworks).toContainEqual({ name: "react", version: "^19.0.0", manifest: "package.json" });
    expect(report.frameworks).toContainEqual({ name: "serde", version: "1.0", manifest: "Cargo.toml" });
    expect(report.frameworks).toContainEqual({ name: "anyhow", version: "1.0", manifest: "crates/core/Cargo.toml" });
    expect(report.frameworks).toContainEqual({ name: "github.com/a/b", version: "v1.0.0", manifest: "go.mod" });
    expect(report.frameworks).toContainEqual({ name: "requests", version: ">=2", manifest: "pyproject.toml" });
    expect(report.frameworks.some((framework) => ["leaked", "bad"].includes(framework.name))).toBe(false);

    expect(report.subsystems).toContainEqual({ name: "@x/api", path: "packages/api", kind: "package-json-workspace-member" });
    expect(report.subsystems).toContainEqual({ name: "core-crate", path: "crates/core", kind: "cargo-workspace-member" });
    expect(report.subsystems).toContainEqual({ name: "gen", path: "tools/gen", kind: "cargo-workspace-member" });
    expect(report.subsystems.some((subsystem) => subsystem.path === "packages/notes")).toBe(false);
    expect(report.notes.some((note) => note.includes("'../escape'"))).toBe(true);

    const entry = (p: string) => report.entrypoints.find((candidate) => candidate.path === p);
    expect(entry("packages/api/src/index.ts")?.kind).toBe("http-server");
    expect(entry("packages/api/src/index.ts")?.evidence).toContain("'Bun.serve(' at line 3");
    expect(entry("crates/core/src/main.rs")?.kind).toBe("async-runtime-main");
    expect(entry("cmd/svc/main.go")?.kind).toBe("http-server");
    expect(entry("app.py")?.kind).toBe("script-main");
    expect(entry(".github/workflows/ci.yml")?.evidence).toContain("'pull_request_target' at line 2");
    // index.ts outside a package.json root is not a candidate.
    expect(entry("lib/index.ts")).toBeUndefined();

    expect(report.lockfiles).toEqual([]);
    expect(report.packagesTotal).toBe(0);
    expect(report.notes.some((note) => note.includes("Lockfile inventory unavailable") && note.includes("invalid_workspace"))).toBe(true);
    expect(report.notes.some((note) => note.includes("heuristic"))).toBe(true);
    expect(report.tools).toEqual([FAKE_TOOL]);
    const toolNote = report.notes.find((note) => note.startsWith("Tool availability"));
    expect(toolNote).toBe(
      "Tool availability on the Sentra host searched the bridge process PATH and standard install locations; the persisted system and user PATH (registry) could not be read (powershell.exe exited with code 1). Executable headers were read; no tool was executed.",
    );
    const unscoped = await computeTopology(root, fakeSources({ toolSearchScope: undefined }));
    expect(unscoped.notes).toContain("Tool availability was determined on the Sentra host from file lookups and executable headers; no tool was executed.");
  });

  test("reports a failed language probe instead of guessing", async () => {
    const { root } = buildTree();
    const report = await computeTopology(
      root,
      fakeSources({
        languageProbe: async () => {
          throw new Error("core_unavailable");
        },
        lockfileInventory: async () => ({ lockfiles: [{ path: "bun.lock", kind: "Bun", ecosystem: "npm", packages: 3, parseError: null }], totalPackages: 3 }),
      }),
    );
    expect(report.languages).toEqual([]);
    expect(report.primaryLanguage).toBeNull();
    expect(report.notes.some((note) => note.startsWith("Language probe failed") && note.includes("core_unavailable"))).toBe(true);
    expect(report.packagesTotal).toBe(3);
  });

  test("caps declared dependencies at 300 and says so", async () => {
    const root = tempDir("sentra-topo-cap-");
    const dependencies = Object.fromEntries(Array.from({ length: 350 }, (_, i) => [`dep-${i}`, `${i}.0.0`]));
    write(root, "package.json", JSON.stringify({ name: "big", dependencies }));
    const report = await computeTopology(root, fakeSources());
    expect(report.frameworks).toHaveLength(300);
    expect(report.notes.some((note) => note.includes("50 further declared dependencies were omitted"))).toBe(true);
  });

  test("persists, reloads and renders grounded context", async () => {
    const { root } = buildTree();
    const db = openWebDb(path.join(tempDir("sentra-topo-db-"), "web.db"));
    const content = await computeTopology(root, fakeSources());
    const report: TopologyReportView = { reportId: "r-1", tenantId: "t1", createdAt: "2026-01-01T00:00:00.000Z", createdBy: "alice", ...content };
    expect(latestTopologyReport(db, "t1")).toBeNull();
    saveTopologyReport(db, report);
    expect(latestTopologyReport(db, "t1")).toEqual(report);
    expect(latestTopologyReport(db, "t2")).toBeNull();
    const text = renderGroundedContext(report);
    expect(text.startsWith("Grounded workspace context (computed by Sentra)")).toBe(true);
    expect(text).toContain("r-1");
    expect(text).toContain("packages/api/src/index.ts [http-server]");
    expect(text).toContain("react ^19.0.0 (package.json)");
    db.close();
  });
});

describe("model recon persistence", () => {
  test("stores reports with the disclaimer and lists newest first", () => {
    const db = openWebDb(path.join(tempDir("sentra-model-db-"), "web.db"));
    const base: ModelReconReportView = {
      reportId: "m-1",
      tenantId: "t1",
      createdAt: "2026-01-01T00:00:00.000Z",
      createdBy: "alice",
      provider: "anthropic",
      model: "claude-test",
      workflow: "scout",
      topologyReportId: "r-1",
      output: "hypothesis",
      inputTokens: 10,
      outputTokens: 20,
      latencyMs: 30,
      disclaimer: MODEL_RECON_DISCLAIMER,
    };
    saveModelReport(db, base, "/ws");
    saveModelReport(db, { ...base, reportId: "m-2", createdAt: "2026-01-02T00:00:00.000Z", workflow: "threat-model" }, "/ws");
    const reports = listModelReports(db, "t1", 50);
    expect(reports.map((report) => report.reportId)).toEqual(["m-2", "m-1"]);
    expect(reports[1]).toEqual(base);
    expect(listModelReports(db, "t2", 50)).toEqual([]);
    db.close();
  });

  test("rejects a prompt document without system and user prompts", () => {
    expect(parsePromptOutput({ system_prompt: "s", user_prompt: "u" })).toEqual({ system: "s", user: "u" });
    expectHttpError(() => parsePromptOutput({ composite_prompt: "x" }), 502, "core_output_invalid");
  });
});
