import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { PluginsView, PluginView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import type { AuditEntryInput } from "../audit-log.ts";
import { HttpError } from "../http-error.ts";
import { Router, type AuthedContext } from "../http.ts";
import {
  mapPluginList,
  mapProbe,
  mapRun,
  MAX_PLUGIN_ARGS_BYTES,
  pluginIdParam,
  PLUGINS_NOT_CONFIGURED_NOTE,
  registerPluginRoutes,
  requireDeclaredCapability,
  serializePluginArgs,
} from "../routes/plugins.ts";
import type { CliResult } from "../sentra-cli.ts";

const created: string[] = [];

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  created.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of created) fs.rmSync(dir, { recursive: true, force: true });
});

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

async function expectRejects(promise: Promise<unknown>, status: number, code?: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(status);
    if (code) expect((error as HttpError).code).toBe(code);
    return;
  }
  throw new Error("expected the promise to reject with an HttpError");
}

const PLUGIN_DIR = path.resolve(os.tmpdir(), "sentra-plugin-fixture");

function listEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "org.example.scanner",
    name: "Example Scanner",
    version: "1.0.0",
    family: "analysis_tool",
    manifest_path: `${PLUGIN_DIR.replace(/\\/g, "/")}/scanner/manifest.json`,
    executable_path: "bun run adapter.ts",
    capabilities: ["static_analysis", "source_discovery"],
    egress_policy: "StrictlyDenied",
    quotas: { max_memory_mib: 512, max_execution_time_secs: 60 },
    ...overrides,
  };
}

const plugin: PluginView = {
  id: "org.example.scanner",
  name: "Example Scanner",
  version: "1.0.0",
  family: "analysis_tool",
  manifestPath: `${PLUGIN_DIR.replace(/\\/g, "/")}/scanner/manifest.json`,
  executablePath: "bun run adapter.ts",
  capabilities: ["static_analysis"],
  declaredEgressPolicy: "StrictlyDenied",
  declaredQuotas: { maxMemoryMib: 512, maxExecutionTimeSecs: 60 },
};

describe("plugin input validation", () => {
  test("plugin ids", () => {
    expect(pluginIdParam("org.sentra.adapter-1_x")).toBe("org.sentra.adapter-1_x");
    for (const bad of [undefined, "", "../x", "a b", "a/b", "x".repeat(129), "a;b"]) {
      expectHttpError(() => pluginIdParam(bad), 400, "invalid_plugin_id");
    }
  });

  test("capabilities must be well-formed and declared by the plugin", () => {
    expect(requireDeclaredCapability(plugin, "static_analysis")).toBe("static_analysis");
    expectHttpError(() => requireDeclaredCapability(plugin, "fuzz_execution"), 400, "capability_not_declared");
    expectHttpError(() => requireDeclaredCapability(plugin, "--evil"), 400, "invalid_capability");
    expectHttpError(() => requireDeclaredCapability(plugin, "Static Analysis"), 400, "invalid_capability");
  });

  test("args must be a JSON object of at most 16 KiB", () => {
    expect(serializePluginArgs(undefined)).toBe("{}");
    expect(serializePluginArgs(null)).toBe("{}");
    expect(serializePluginArgs({ rules: ["a"], depth: 2 })).toBe('{"rules":["a"],"depth":2}');
    expectHttpError(() => serializePluginArgs(["a"]), 400);
    expectHttpError(() => serializePluginArgs("{}"), 400);
    expectHttpError(() => serializePluginArgs({ blob: "x".repeat(MAX_PLUGIN_ARGS_BYTES) }), 400);
  });
});

describe("plugin output mapping", () => {
  test("list keeps only manifests inside the plugin directory and maps declarations", () => {
    const { plugins, ignored } = mapPluginList(
      {
        plugins: [
          listEntry(),
          listEntry({ id: "org.example.outside", manifest_path: path.resolve(os.tmpdir(), "elsewhere/manifest.json") }),
          listEntry({ id: "org.example.noquota", executable_path: "", quotas: null, egress_policy: "" }),
          { broken: true },
        ],
      },
      PLUGIN_DIR,
    );
    expect(ignored).toBe(2);
    expect(plugins.map((entry) => entry.id)).toEqual(["org.example.scanner", "org.example.noquota"]);
    expect(plugins[0].declaredQuotas).toEqual({ maxMemoryMib: 512, maxExecutionTimeSecs: 60 });
    expect(plugins[0].declaredEgressPolicy).toBe("StrictlyDenied");
    expect(plugins[1].executablePath).toBeNull();
    expect(plugins[1].declaredQuotas).toBeNull();
    expect(plugins[1].declaredEgressPolicy).toBe("undeclared");
    expectHttpError(() => mapPluginList({ count: 0 }, PLUGIN_DIR), 502, "core_output_invalid");
  });

  test("probe output requires an applicable flag", () => {
    expect(
      mapProbe(
        { plugin_id: "org.example.scanner", name: "Example", applicable: false, details: "no lockfiles", unsupported_reason: "nothing to scan", capabilities: ["static_analysis"] },
        "org.example.scanner",
      ),
    ).toEqual({
      pluginId: "org.example.scanner",
      name: "Example",
      applicable: false,
      details: "no lockfiles",
      unsupportedReason: "nothing to scan",
      capabilities: ["static_analysis"],
    });
    expectHttpError(() => mapProbe({ plugin_id: "x" }, "x"), 502, "core_output_invalid");
  });

  test("run output is adapter-reported and carries the workspace note", () => {
    const view = mapRun(
      { plugin_id: plugin.id, task_id: "task-1", capability: "static_analysis", exit_code: 3, summary: "2 issues", evidence_refs: ["sha256:abc"] },
      plugin,
      "static_analysis",
      { stdout: "x".repeat(70 * 1024), stderr: "" },
    );
    expect(view.exitCode).toBe(3);
    expect(view.taskId).toBe("task-1");
    expect(view.reportedEvidenceRefs).toEqual(["sha256:abc"]);
    expect(view.summary.startsWith("2 issues")).toBe(true);
    expect(view.summary).toContain("not in the tenant workspace");
    expect(view.stdout).toContain("[truncated at");
    expectHttpError(() => mapRun({ summary: "x" }, plugin, "static_analysis", { stdout: "", stderr: "" }), 502);
  });
});

// ───────────────────────────── routes against a fake context ─────────────────────────────

interface Harness {
  router: Router;
  audits: AuditEntryInput[];
  calls: string[][];
}

function harness(pluginDir: string | null, respond: (args: string[]) => Partial<CliResult>): Harness {
  const audits: AuditEntryInput[] = [];
  const calls: string[][] = [];
  const workspace = tempDir("sentra-plugin-ws-");
  const run = async (args: string[]): Promise<CliResult> => {
    calls.push(args);
    const partial = respond(args);
    const stdout = partial.stdout ?? "";
    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      parsed = undefined;
    }
    return { code: 0, stderr: "", timedOut: false, durationMs: 1, json: parsed, ...partial, stdout };
  };
  const fake = {
    config: { pluginDir, cliTimeoutMs: 5_000, cliLongTimeoutMs: 10_000 },
    // runShared is the read-only path (plugin list); this double runs every call.
    cli: { run, runShared: (args: string[]) => run(args) },
    workspaces: {
      get: (tenantId: string) => {
        if (tenantId !== "t1") throw new HttpError(404, "tenant_not_found", "unknown tenant");
        return { tenantId, workspace };
      },
      workspaceRoot: () => workspace,
    },
    audit: { append: (_principal: unknown, entry: AuditEntryInput) => audits.push(entry) },
  };
  const router = new Router();
  registerPluginRoutes(router, fake as unknown as AppContext);
  return { router, audits, calls };
}

async function call(h: Harness, method: string, pathname: string, body: Record<string, unknown> = {}): Promise<Response> {
  const matched = h.router.match(method, pathname);
  if (!matched || matched === "method_not_allowed") throw new Error(`no route for ${method} ${pathname}`);
  const ctx: AuthedContext = {
    req: new Request(`http://127.0.0.1${pathname}`, { method }),
    url: new URL(`http://127.0.0.1${pathname}`),
    params: matched.params,
    principal: { role: "admin", label: "tester", via: "bearer" },
    ip: "127.0.0.1",
    readJson: async () => body,
    readText: async () => JSON.stringify(body),
  };
  return matched.route.handler(ctx);
}

const listStdout = JSON.stringify({ schema_version: 1, command: "plugin", action: "list", count: 1, plugins: [listEntry()] });

describe("plugin routes", () => {
  test("report 'not configured' honestly when SENTRA_PLUGIN_DIR is unset", async () => {
    const h = harness(null, () => ({}));
    const response = await call(h, "GET", "/api/plugins");
    const body = (await response.json()) as PluginsView;
    expect(body).toEqual({ pluginDir: null, configured: false, plugins: [], note: PLUGINS_NOT_CONFIGURED_NOTE });
    expect(h.calls).toHaveLength(0);
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" }), 412, "plugins_not_configured");
  });

  test("list passes only --dir and returns declared (unenforced) metadata", async () => {
    const h = harness(PLUGIN_DIR, () => ({ stdout: listStdout }));
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(h.calls[0]).toEqual(["plugin", "list", "--dir", PLUGIN_DIR, "--json"]);
    expect(body.configured).toBe(true);
    expect(body.plugins.map((entry) => entry.id)).toEqual(["org.example.scanner"]);
    expect(body.note).toContain("not enforced");
  });

  test("invalid JSON from the core is an error, not an empty list", async () => {
    const h = harness(PLUGIN_DIR, () => ({ stdout: '{"plugins":[{"details":"C:\\path"}]' }));
    await expectRejects(call(h, "GET", "/api/plugins"), 502, "core_output_invalid");
  });

  test("probe failures surface as errors and are audited", async () => {
    const h = harness(PLUGIN_DIR, (args) =>
      args[1] === "list" ? { stdout: listStdout } : { code: 5, stdout: "", stderr: '{"schema_version":1,"error":"plugin_probe_failed"}' },
    );
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" }), 422, "core_command_failed");
    expect(h.audits).toHaveLength(1);
    expect(h.audits[0].action).toBe("plugin_probed");
    expect(h.audits[0].outcome).toBe("failure");
    expect(String(h.audits[0].details?.error)).toContain("plugin_probe_failed");
  });

  test("probe of a plugin outside the listing is rejected", async () => {
    const h = harness(PLUGIN_DIR, () => ({ stdout: listStdout }));
    await expectRejects(call(h, "POST", "/api/plugins/org.example.other/probe", { tenantId: "t1" }), 404, "plugin_not_found");
  });

  test("run rejects undeclared capabilities before spawning the adapter", async () => {
    const h = harness(PLUGIN_DIR, () => ({ stdout: listStdout }));
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/run", { tenantId: "t1", capability: "fuzz_execution" }), 400, "capability_not_declared");
    expect(h.calls.every((args) => args[1] === "list")).toBe(true);
    expect(h.audits[0].outcome).toBe("failure");
  });

  test("run passes --args as JSON and records the adapter-reported exit code", async () => {
    const runStdout = JSON.stringify({
      schema_version: 1,
      command: "plugin",
      action: "run",
      plugin_id: "org.example.scanner",
      task_id: "task-7",
      capability: "static_analysis",
      exit_code: 0,
      summary: "done",
      evidence_refs: [],
    });
    const h = harness(PLUGIN_DIR, (args) => ({ stdout: args[1] === "list" ? listStdout : runStdout }));
    const response = await call(h, "POST", "/api/plugins/org.example.scanner/run", {
      tenantId: "t1",
      capability: "static_analysis",
      args: { secret: "never-audited" },
    });
    const body = (await response.json()) as { taskId: string; exitCode: number };
    expect(body.taskId).toBe("task-7");
    const runArgs = h.calls.find((args) => args[1] === "run") ?? [];
    expect(runArgs[runArgs.indexOf("--args") + 1]).toBe('{"secret":"never-audited"}');
    expect(runArgs).toContain("--workspace");
    const audit = h.audits.find((entry) => entry.action === "plugin_run");
    expect(audit?.outcome).toBe("success");
    expect(JSON.stringify(audit)).not.toContain("never-audited");
    expect(audit?.details?.adapterReportedExitCode).toBe(0);
  });
});
