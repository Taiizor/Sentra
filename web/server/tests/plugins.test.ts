import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  diagnosticSummary,
  directoryStateLabel,
  normalizePluginsView,
} from "../../src/components/dashboard/plugins-format.ts";
import type { PluginsView, PluginView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import type { AuditEntryInput } from "../audit-log.ts";
import { HttpError } from "../http-error.ts";
import { Router, type AuthedContext } from "../http.ts";
import {
  boundedProbe,
  hostCanonicalPath,
  isWithinOn,
  mapCoreDiagnostics,
  NO_PLATFORM_DEFAULT_MESSAGE,
  parsePlatformDefaultResult,
  platformDefaultQueryEnv,
  platformDefaultRefusal,
  PluginDirectoryResolver,
  probeProblem,
  type PluginDirectoryDeps,
  type ProtectedLocation,
} from "../plugin-directory.ts";
import {
  mapPluginList,
  mapProbe,
  mapRun,
  MAX_PLUGIN_ARGS_BYTES,
  pluginIdParam,
  PLUGINS_NOT_CONFIGURED_NOTE,
  pluginsHint,
  protectedLocations,
  registerPluginRoutes,
  requireDeclaredCapability,
  serializePluginArgs,
} from "../routes/plugins.ts";
import { childEnv, SentraCli, type CliResult, type CliRunOptions } from "../sentra-cli.ts";

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

function cliResult(partial: Partial<CliResult>): CliResult {
  const stdout = partial.stdout ?? "";
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    parsed = undefined;
  }
  return { code: 0, stderr: "", timedOut: false, durationMs: 1, json: parsed, ...partial, stdout };
}

const UNAVAILABLE = { code: 2, stdout: "", stderr: '{"error":"plugin_dir_unavailable","message":"no plugin directory: pass --dir or set SENTRA_PLUGIN_DIR to an absolute path","schema_version":1}\n' };

function defaultListing(directory: string): Partial<CliResult> {
  return { stdout: JSON.stringify({ schema_version: 1, command: "plugin", action: "list", directories: [directory], count: 0, plugins: [], has_errors: false, diagnostics: [] }) };
}

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
  test("list keeps only manifests inside the plugin directory and reports the ignored entries", () => {
    const outside = path.resolve(os.tmpdir(), "elsewhere/manifest.json");
    const { plugins, ignored } = mapPluginList(
      {
        plugins: [
          listEntry(),
          listEntry({ id: "org.example.outside", manifest_path: outside }),
          listEntry({ id: "org.example.noquota", executable_path: "", quotas: null, egress_policy: "" }),
          { broken: true },
        ],
      },
      PLUGIN_DIR,
    );
    expect(ignored.map((entry) => [entry.severity, entry.code, entry.path])).toEqual([
      ["warning", "plugin_entry_ignored", outside],
      ["warning", "plugin_entry_ignored", null],
    ]);
    expect(plugins.map((entry) => entry.id)).toEqual(["org.example.scanner", "org.example.noquota"]);
    expect(plugins[0].declaredQuotas).toEqual({ maxMemoryMib: 512, maxExecutionTimeSecs: 60 });
    expect(plugins[0].declaredEgressPolicy).toBe("StrictlyDenied");
    expect(plugins[1].executablePath).toBeNull();
    expect(plugins[1].declaredQuotas).toBeNull();
    expect(plugins[1].declaredEgressPolicy).toBe("undeclared");
    expectHttpError(() => mapPluginList({ count: 0 }, PLUGIN_DIR), 502, "core_output_invalid");
  });

  test("core diagnostics are passed through field for field", () => {
    // Shape of `sentra plugin list --json` (PluginListJson / PluginDiagnosticJson in sentra-cli).
    const mapped = mapCoreDiagnostics({
      has_errors: true,
      diagnostics: [
        { path: "C:/plugins/broken/manifest.json", severity: "error", code: "manifest_invalid_json", message: "Invalid plugin manifest: ..." },
        { path: "C:/plugins/x/manifest.json", severity: "warning", code: "manifest_unknown_field", message: "ignored unknown manifest keys: extra" },
        { path: "", severity: "notice", code: "", message: 7 },
        "not an object",
      ],
    });
    expect(mapped.hasErrors).toBe(true);
    expect(mapped.diagnostics).toEqual([
      { severity: "error", code: "manifest_invalid_json", message: "Invalid plugin manifest: ...", path: "C:/plugins/broken/manifest.json" },
      { severity: "warning", code: "manifest_unknown_field", message: "ignored unknown manifest keys: extra", path: "C:/plugins/x/manifest.json" },
      // An unknown severity is shown as a warning; missing fields stay visible as such.
      { severity: "warning", code: "unknown", message: "", path: null },
    ]);
    // has_errors is the core's own flag; errors in the list also set it.
    expect(mapCoreDiagnostics({ has_errors: false, diagnostics: [{ severity: "error", code: "x", message: "m", path: "p" }] }).hasErrors).toBe(true);
    expect(mapCoreDiagnostics({ plugins: [] })).toEqual({ diagnostics: [], hasErrors: false });
    const many = mapCoreDiagnostics({ diagnostics: Array.from({ length: 250 }, (_, index) => ({ severity: "warning", code: `c${index}`, message: "m", path: null })) });
    expect(many.diagnostics).toHaveLength(201);
    expect(many.diagnostics[200].code).toBe("plugin_diagnostics_truncated");
    expect(many.diagnostics[200].message).toContain("50 more");
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

  test("run output is adapter-reported", () => {
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
    expect(view.summary).toBe("2 issues");
    expect(view.stdout).toContain("[truncated at");
    expectHttpError(() => mapRun({ summary: "x" }, plugin, "static_analysis", { stdout: "", stderr: "" }), 502);
  });
});

// ───────────────────────────── plugin directory resolution ─────────────────────────────

describe("platform default query", () => {
  test("passes the core's variables for the platform explicitly and never SENTRA_PLUGIN_DIR", () => {
    const { overrides, diagnostics } = platformDefaultQueryEnv({ SENTRA_PLUGIN_DIR: "/ops/plugins", HOME: "/home/op", XDG_CONFIG_HOME: "/cfg", APPDATA: "/x", PATH: "/usr/bin" }, "linux");
    expect(overrides).toEqual({ SENTRA_PLUGIN_DIR: undefined, XDG_CONFIG_HOME: "/cfg", HOME: "/home/op" });
    expect(diagnostics).toEqual([]);
    // Relative values are passed as they are: the core decides to ignore them.
    expect(platformDefaultQueryEnv({ HOME: "rel", XDG_CONFIG_HOME: "" }, "darwin").overrides).toEqual({ SENTRA_PLUGIN_DIR: undefined, HOME: "rel" });
    // Windows variable names are case-insensitive.
    expect(platformDefaultQueryEnv({ AppData: "C:\\Users\\op\\AppData\\Roaming" }, "win32").overrides).toEqual({ SENTRA_PLUGIN_DIR: undefined, APPDATA: "C:\\Users\\op\\AppData\\Roaming" });
  });

  test("a UNC or device APPDATA is withheld on Windows (the core would open the share)", () => {
    for (const value of ["\\\\files\\profiles\\op\\AppData", "//files/profiles", "\\\\?\\C:\\Users\\op", "\\??\\C:\\x"]) {
      const { overrides, diagnostics } = platformDefaultQueryEnv({ APPDATA: value, HOME: "C:\\Users\\op" }, "win32");
      expect(overrides.APPDATA).toBeUndefined();
      expect("HOME" in overrides).toBe(false);
      expect(diagnostics.map((entry) => [entry.severity, entry.code, entry.path])).toEqual([["warning", "plugin_dir_network_path", value]]);
    }
    // POSIX has no UNC paths; the core resolves `//x` itself.
    expect(platformDefaultQueryEnv({ HOME: "//srv/home" }, "linux").overrides.HOME).toBe("//srv/home");
  });

  test("Windows: HOME and XDG_CONFIG_HOME on a share are not reported (the core reads only APPDATA there)", () => {
    // Regression: a UNC HOME (Git for Windows, a home-drive policy) produced a permanent
    // plugin_dir_network_path warning about a variable that has no effect on the directory.
    const { overrides, diagnostics } = platformDefaultQueryEnv(
      { APPDATA: "C:\\Users\\op\\AppData\\Roaming", HOME: "\\\\files\\home\\op", XDG_CONFIG_HOME: "//files/cfg" },
      "win32",
    );
    expect(diagnostics).toEqual([]);
    expect(overrides).toEqual({ SENTRA_PLUGIN_DIR: undefined, APPDATA: "C:\\Users\\op\\AppData\\Roaming" });
  });

  test("interprets the core's answer", () => {
    expect(parsePlatformDefaultResult(cliResult(defaultListing("C:/Users/op/AppData/Roaming/sentra/plugins")))).toEqual({
      reported: "C:/Users/op/AppData/Roaming/sentra/plugins",
      diagnostics: [],
    });
    expect(parsePlatformDefaultResult(cliResult(UNAVAILABLE))).toEqual({
      reported: null,
      diagnostics: [{ severity: "info", code: "plugin_dir_unavailable", message: NO_PLATFORM_DEFAULT_MESSAGE, path: null }],
    });
    expectHttpError(() => parsePlatformDefaultResult(cliResult({ code: 5, stderr: '{"error":"io_error"}' })), 422, "core_command_failed");
    expectHttpError(() => parsePlatformDefaultResult(cliResult({ timedOut: true, code: 1 })), 504, "core_timeout");
    expectHttpError(() => parsePlatformDefaultResult(cliResult({ stdout: '{"plugins":[]}' })), 502, "core_output_invalid");
  });

  test("childEnv applies overrides on top of the allowlist", () => {
    const env = childEnv({ XDG_CONFIG_HOME: "/cfg", SENTRA_PLUGIN_DIR: undefined, PATH: undefined });
    expect(env.NO_COLOR).toBe("1");
    expect(env.XDG_CONFIG_HOME).toBe("/cfg");
    expect("PATH" in env).toBe(false);
    expect("SENTRA_PLUGIN_DIR" in env).toBe(false);
    // XDG_CONFIG_HOME is outside the allowlist: only the platform-default query passes it.
    expect("XDG_CONFIG_HOME" in childEnv()).toBe(false);
  });
});

describe("platform default refusal", () => {
  const none = () => null;

  test("Windows: absolute drive-letter paths only", async () => {
    expect(await platformDefaultRefusal("C:/Users/op/AppData/Roaming/sentra/plugins", [], "win32", none)).toBeNull();
    expect(await platformDefaultRefusal("//files/profiles/op/sentra/plugins", [], "win32", none)).toBe("is a UNC network path or a device path");
    expect(await platformDefaultRefusal("\\\\?\\C:\\sentra\\plugins", [], "win32", none)).toBe("is a UNC network path or a device path");
    expect(await platformDefaultRefusal("C:sentra\\plugins", [], "win32", none)).toBe("is not an absolute path on a local drive");
    expect(await platformDefaultRefusal("\\sentra\\plugins", [], "win32", none)).toBe("is not an absolute path on a local drive");
    expect(await platformDefaultRefusal("C:\\sentra\nplugins", [], "win32", none)).toBe("contains control characters");
  });

  test("Windows: a drive-letter path whose real path is a share is refused (mapped drive or link)", async () => {
    // Regression: only the reported form was checked, so H:\... on a mapped network drive, or an
    // %APPDATA%\sentra link to \\server\share, was accepted and the core scanned the share.
    for (const real of ["\\\\files\\home\\op\\AppData\\Roaming\\sentra\\plugins", "\\\\?\\UNC\\evil\\share\\plugins", "//evil/share/plugins"]) {
      const refusal = await platformDefaultRefusal("H:/AppData/Roaming/sentra/plugins", [], "win32", () => real);
      expect(refusal).toStartWith("resolves to a UNC network path or a device path");
      expect(refusal).toContain(real);
    }
    // A real path that cannot be determined is refused too, the reason included.
    const timedOut = Object.assign(new Error("H:\\AppData did not answer within 2 s"), { code: "ETIMEDOUT" });
    expect(
      await platformDefaultRefusal("H:/AppData/Roaming/sentra/plugins", [], "win32", () => {
        throw timedOut;
      }),
    ).toBe("could not be resolved to its real path (H:\\AppData did not answer within 2 s; the drive or network share it is on may be slow or unreachable)");
    // macOS and Linux: network mounts are not detected (documented); `//x` is a local path there.
    expect(await platformDefaultRefusal("/nfs/home/op/.config/sentra/plugins", [], "linux", () => "//srv/x")).toBeNull();
  });

  test("Windows: overlap with protected locations, case-insensitively and in both directions", async () => {
    const data: ProtectedLocation = { label: "the bridge data directory", path: "D:\\Sentra-Data" };
    expect(await platformDefaultRefusal("d:/sentra-data/sentra/plugins", [data], "win32", none)).toBe("is inside the bridge data directory (D:\\Sentra-Data)");
    const workspace: ProtectedLocation = { label: "the workspace of 'app'", path: "C:\\Users\\op\\AppData\\Roaming\\sentra\\plugins\\checkout" };
    expect(await platformDefaultRefusal("C:/Users/op/AppData/Roaming/sentra/plugins", [workspace], "win32", none)).toBe(
      "contains the workspace of 'app' (C:\\Users\\op\\AppData\\Roaming\\sentra\\plugins\\checkout)",
    );
    // A sibling with a common prefix is not inside.
    expect(await platformDefaultRefusal("D:/Sentra-Data2/sentra/plugins", [data], "win32", none)).toBeNull();
  });

  test("the real path is compared too (a junction into a workspace)", async () => {
    const repo: ProtectedLocation = { label: "the repository checkout", path: "E:\\src\\sentra" };
    const canonical = (value: string) => (value.toLowerCase().startsWith("c:\\users\\op\\appdata\\roaming\\sentra") ? value.replace(/^C:\\Users\\op\\AppData\\Roaming\\sentra/i, "E:\\src\\sentra\\examples") : null);
    expect(await platformDefaultRefusal("C:/Users/op/AppData/Roaming/sentra/plugins", [repo], "win32", canonical)).toBe("is inside the repository checkout (E:\\src\\sentra)");
    // A protected location whose real path cannot be determined is compared in its reported form.
    const failing = (value: string) => {
      if (value === "E:\\src\\sentra") throw new Error("EACCES");
      return null;
    };
    expect(await platformDefaultRefusal("E:/src/sentra/plugins", [repo], "win32", failing)).toBe("is inside the repository checkout (E:\\src\\sentra)");
    expect(await platformDefaultRefusal("C:/Users/op/AppData/Roaming/sentra/plugins", [repo], "win32", failing)).toBeNull();
  });

  test("macOS: case-insensitive; Linux: case-sensitive", async () => {
    const repo: ProtectedLocation = { label: "the repository checkout", path: "/Users/op/Library" };
    expect(await platformDefaultRefusal("/users/op/library/Application Support/sentra/plugins", [repo], "darwin", none)).toBe("is inside the repository checkout (/Users/op/Library)");
    const tmp: ProtectedLocation = { label: "the system temporary directory", path: "/tmp" };
    expect(await platformDefaultRefusal("/tmp/cfg/sentra/plugins", [tmp], "linux", none)).toBe("is inside the system temporary directory (/tmp)");
    expect(await platformDefaultRefusal("/TMP/cfg/sentra/plugins", [tmp], "linux", none)).toBeNull();
    expect(await platformDefaultRefusal("cfg/sentra/plugins", [], "linux", none)).toBe("is not an absolute path");
    expect(isWithinOn("/home/op", "/home/op2/x", "linux")).toBe(false);
    expect(isWithinOn("/home/op", "/home/op", "linux")).toBe(true);
  });

  test("hostCanonicalPath resolves the nearest existing ancestor", async () => {
    const base = tempDir("sentra-canon-");
    const real = fs.realpathSync.native(base);
    expect(await hostCanonicalPath(path.join(base, "missing", "deeper"))).toBe(path.join(real, "missing", "deeper"));
    expect(await hostCanonicalPath(base)).toBe(real);
  });

  test("hostCanonicalPath rejects a component that exists but cannot be resolved", async () => {
    // Walking up past it would hide a link to a share behind its local parent.
    const calls: string[] = [];
    const realpath = async (value: string) => {
      calls.push(value);
      if (calls.length === 1) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      throw Object.assign(new Error("access denied"), { code: "EACCES" });
    };
    const target = path.join(os.tmpdir(), "link-to-share", "plugins");
    await expect(hostCanonicalPath(target, realpath)).rejects.toMatchObject({ code: "EACCES" });
    expect(calls).toEqual([target, path.dirname(target)]);
  });

  test("boundedProbe times out, joins a pending call and forgets a settled one", async () => {
    const pending = new Map<string, Promise<unknown>>();
    let starts = 0;
    let release: (value: string) => void = () => undefined;
    const hung = () => {
      starts += 1;
      return new Promise<string>((resolve) => {
        release = resolve;
      });
    };
    await expect(boundedProbe(pending, "k", "H:\\x", 20, hung)).rejects.toMatchObject({ code: "ETIMEDOUT", message: "H:\\x did not answer within 20 ms" });
    await expect(boundedProbe(pending, "k", "H:\\x", 20, hung)).rejects.toMatchObject({ code: "ETIMEDOUT" });
    expect(starts).toBe(1);
    release("done");
    expect(await boundedProbe(pending, "k", "H:\\x", 20, hung)).toBe("done");
    expect(pending.size).toBe(0);
    expect(probeProblem(Object.assign(new Error("x"), { code: "EACCES" }))).toBe("EACCES: x");
  });

  test("protected locations: data, temporary directories, repository and every registered workspace", () => {
    const locations = protectedLocations({
      config: { dataDir: "/srv/sentra-data", tmpDir: "/srv/sentra-data/tmp", repoRoot: "/src/sentra" },
      workspaces: { list: () => [{ tenantId: "app", workspace: "/work/app" }] },
    } as unknown as AppContext);
    expect(locations.map((entry) => entry.path)).toEqual(["/srv/sentra-data", "/srv/sentra-data/tmp", os.tmpdir(), "/src/sentra", "/work/app"]);
    expect(locations[4].label).toBe("the workspace of 'app'");
  });
});

interface FakeCore {
  calls: { args: string[]; options: CliRunOptions }[];
  runCli: PluginDirectoryDeps["runCli"];
}

function fakeCore(respond: (args: string[], options: CliRunOptions) => Partial<CliResult> | Error): FakeCore {
  const calls: FakeCore["calls"] = [];
  return {
    calls,
    runCli: async (args, options) => {
      calls.push({ args, options });
      const answer = respond(args, options);
      if (answer instanceof Error) throw answer;
      return cliResult(answer);
    },
  };
}

function resolver(overrides: Partial<PluginDirectoryDeps> & Pick<PluginDirectoryDeps, "runCli">): PluginDirectoryResolver {
  return new PluginDirectoryResolver({
    platform: "win32",
    environmentDir: null,
    env: { APPDATA: "C:\\Users\\op\\AppData\\Roaming" },
    timeoutMs: 5_000,
    protectedLocations: () => [],
    canonical: () => null,
    isDirectory: () => true,
    ...overrides,
  });
}

describe("plugin directory resolution order", () => {
  test("SENTRA_PLUGIN_DIR wins and never asks the core", async () => {
    const core = fakeCore(() => new Error("must not run"));
    let exists = true;
    const directories = resolver({ runCli: core.runCli, environmentDir: "D:\\ops\\plugins", isDirectory: () => exists });
    expect(await directories.current()).toEqual({ directory: "D:\\ops\\plugins", source: "environment", exists: true, refusedDirectory: null, diagnostics: [] });
    exists = false;
    const gone = await directories.current();
    expect(gone.exists).toBe(false);
    expect(gone.diagnostics.map((entry) => [entry.severity, entry.code])).toEqual([["error", "plugin_dir_not_found"]]);
    expect(core.calls).toHaveLength(0);
  });

  test("otherwise the directory the core reports, asked once; existence is checked on every call", async () => {
    const core = fakeCore(() => defaultListing("C:/Users/op/AppData/Roaming/sentra/plugins"));
    let exists = false;
    const directories = resolver({ runCli: core.runCli, isDirectory: () => exists });
    const missing = await directories.current();
    expect(missing).toMatchObject({ directory: "C:\\Users\\op\\AppData\\Roaming\\sentra\\plugins", source: "platform_default", exists: false });
    expect(missing.diagnostics.map((entry) => [entry.severity, entry.code])).toEqual([["info", "plugin_dir_not_found"]]);
    exists = true;
    expect(await directories.current()).toMatchObject({ source: "platform_default", exists: true, diagnostics: [] });
    expect(core.calls).toHaveLength(1);
    expect(core.calls[0].args).toEqual(["plugin", "list", "--json"]);
    expect(core.calls[0].options.env).toEqual({ SENTRA_PLUGIN_DIR: undefined, APPDATA: "C:\\Users\\op\\AppData\\Roaming" });
  });

  test("macOS and Linux hosts hand HOME and XDG_CONFIG_HOME to the core", async () => {
    for (const [platform, env, reported] of [
      ["darwin", { HOME: "/Users/op" }, "/Users/op/Library/Application Support/sentra/plugins"],
      ["linux", { HOME: "/home/op", XDG_CONFIG_HOME: "/home/op/.cfg" }, "/home/op/.cfg/sentra/plugins"],
    ] as const) {
      const core = fakeCore(() => defaultListing(reported));
      const state = await resolver({ runCli: core.runCli, platform, env }).current();
      expect(state).toMatchObject({ directory: reported, source: "platform_default" });
      expect(core.calls[0].options.env).toMatchObject({ SENTRA_PLUGIN_DIR: undefined, ...env });
    }
  });

  test("none when the core has no platform default; the answer is kept", async () => {
    const core = fakeCore(() => UNAVAILABLE);
    const directories = resolver({ runCli: core.runCli, env: {} });
    const state = await directories.current();
    expect(state).toMatchObject({ directory: null, source: "none", exists: false, refusedDirectory: null });
    expect(state.diagnostics.map((entry) => entry.code)).toEqual(["plugin_dir_unavailable"]);
    await directories.current();
    expect(core.calls).toHaveLength(1);
  });

  test("a failed query is not kept", async () => {
    let attempt = 0;
    const core = fakeCore(() => (++attempt === 1 ? new HttpError(503, "core_unavailable", "missing") : defaultListing("C:/x/sentra/plugins")));
    const directories = resolver({ runCli: core.runCli });
    await expectRejects(directories.current(), 503, "core_unavailable");
    expect(await directories.current()).toMatchObject({ source: "platform_default", directory: "C:\\x\\sentra\\plugins" });
  });

  test("a refused default becomes none, re-evaluated on every call (workspaces change at runtime)", async () => {
    const core = fakeCore(() => defaultListing("C:/Users/op/AppData/Roaming/sentra/plugins"));
    const locations: ProtectedLocation[] = [];
    const directories = resolver({ runCli: core.runCli, protectedLocations: () => locations });
    expect((await directories.current()).source).toBe("platform_default");
    locations.push({ label: "the workspace of 'cfg'", path: "C:\\Users\\op\\AppData\\Roaming" });
    const refused = await directories.current();
    expect(refused).toMatchObject({ directory: null, source: "none", refusedDirectory: "C:/Users/op/AppData/Roaming/sentra/plugins" });
    expect(refused.diagnostics.map((entry) => [entry.severity, entry.code, entry.path])).toEqual([["warning", "plugin_dir_refused", "C:/Users/op/AppData/Roaming/sentra/plugins"]]);
    expect(refused.diagnostics[0].message).toContain("inside the workspace of 'cfg'");
    expect(core.calls).toHaveLength(1);
  });

  test("a withheld UNC APPDATA yields none with both diagnostics", async () => {
    const core = fakeCore(() => UNAVAILABLE);
    const state = await resolver({ runCli: core.runCli, env: { APPDATA: "\\\\files\\op" } }).current();
    expect(state.source).toBe("none");
    expect(state.diagnostics.map((entry) => entry.code)).toEqual(["plugin_dir_network_path", "plugin_dir_unavailable"]);
    expect(core.calls[0].options.env?.APPDATA).toBeUndefined();
  });

  test("a drive-letter APPDATA whose real path is a share is withheld before the core scans it", async () => {
    // Regression: H: on a mapped network drive (or an %APPDATA%\sentra link to a share) was handed
    // to the core, which scanned the share while answering.
    const core = fakeCore(() => UNAVAILABLE);
    const checked: string[] = [];
    const canonical = (value: string) => {
      checked.push(value);
      return value.replace(/^H:/i, "\\\\files\\home\\op");
    };
    const state = await resolver({ runCli: core.runCli, env: { APPDATA: "H:\\AppData\\Roaming" }, canonical }).current();
    expect(checked[0]).toBe("H:\\AppData\\Roaming\\sentra\\plugins");
    expect(core.calls[0].options.env?.APPDATA).toBeUndefined();
    expect(state).toMatchObject({ directory: null, source: "none" });
    expect(state.diagnostics.map((entry) => [entry.code, entry.path])).toEqual([
      ["plugin_dir_network_path", "H:\\AppData\\Roaming"],
      ["plugin_dir_unavailable", null],
    ]);
    expect(state.diagnostics[0].message).toContain("\\\\files\\home\\op\\AppData\\Roaming\\sentra\\plugins");
  });

  test("an APPDATA check that does not answer asks nothing of the core and is retried", async () => {
    // Regression: realpath and stat were synchronous, so an offline mapped drive blocked the
    // bridge until the SMB timeout on every listing.
    const core = fakeCore(() => defaultListing("H:/AppData/Roaming/sentra/plugins"));
    let online = false;
    let starts = 0;
    const canonical = (value: string) => {
      starts += 1;
      return online ? value : new Promise<string | null>(() => undefined);
    };
    const directories = resolver({ runCli: core.runCli, env: { APPDATA: "H:\\AppData\\Roaming" }, canonical, probeTimeoutMs: 20 });
    const offline = await directories.current();
    expect(offline).toMatchObject({ directory: null, source: "none" });
    expect(offline.diagnostics.map((entry) => [entry.severity, entry.code])).toEqual([["warning", "plugin_dir_not_answering"]]);
    expect(offline.diagnostics[0].message).toContain("did not answer within 20 ms");
    expect(core.calls).toHaveLength(0);
    // The hung call is joined, not started again.
    await directories.current();
    expect(starts).toBe(1);
    expect(core.calls).toHaveLength(0);
    // Once the drive answers (a new resolver here, since the hung call above never settles), the core is asked.
    online = true;
    const back = await resolver({ runCli: core.runCli, env: { APPDATA: "H:\\AppData\\Roaming" }, canonical, probeTimeoutMs: 20 }).current();
    expect(back).toMatchObject({ source: "platform_default", directory: "H:\\AppData\\Roaming\\sentra\\plugins" });
    expect(core.calls).toHaveLength(1);
  });

  test("a reported default whose real path is a share is refused", async () => {
    const core = fakeCore(() => defaultListing("H:/AppData/Roaming/sentra/plugins"));
    // The check before the query still sees a local path (the link to the share appeared since);
    // the check of the reported directory, made on every listing, sees the share.
    let calls = 0;
    const canonical = (value: string) => (++calls === 1 ? value : "\\\\evil\\share\\plugins");
    const state = await resolver({ runCli: core.runCli, env: { APPDATA: "H:\\AppData\\Roaming" }, canonical }).current();
    expect(state).toMatchObject({ directory: null, source: "none", refusedDirectory: "H:/AppData/Roaming/sentra/plugins" });
    expect(state.diagnostics.map((entry) => entry.code)).toEqual(["plugin_dir_refused"]);
    expect(state.diagnostics[0].message).toContain("resolves to a UNC network path or a device path (\\\\evil\\share\\plugins)");
  });

  test("a directory check that does not answer is reported, not taken as missing", async () => {
    const core = fakeCore(() => new Error("must not run"));
    let starts = 0;
    const directories = resolver({
      runCli: core.runCli,
      environmentDir: "H:\\ops\\plugins",
      probeTimeoutMs: 20,
      isDirectory: () => {
        starts += 1;
        return new Promise<boolean>(() => undefined);
      },
    });
    const state = await directories.current();
    expect(state).toMatchObject({ directory: "H:\\ops\\plugins", source: "environment", exists: false });
    expect(state.diagnostics.map((entry) => [entry.severity, entry.code])).toEqual([["error", "plugin_dir_not_answering"]]);
    await directories.current();
    expect(starts).toBe(1);
  });
});

describe("plugin hints", () => {
  const base = { refusedDirectory: null };
  test("tell the operator what to do next", () => {
    expect(pluginsHint({ ...base, directory: null, source: "none", exists: false }, 0, false)).toContain("Set SENTRA_PLUGIN_DIR");
    expect(pluginsHint({ directory: null, source: "none", exists: false, refusedDirectory: "C:/x" }, 0, false)).toContain("outside the bridge data");
    expect(pluginsHint({ ...base, directory: "C:\\d", source: "platform_default", exists: false }, 0, false)).toBe(
      "Set SENTRA_PLUGIN_DIR on the bridge host and restart, or create C:\\d and add adapters (one subdirectory with a manifest.json each).",
    );
    expect(pluginsHint({ ...base, directory: "/ops", source: "environment", exists: false }, 0, false)).toContain("no longer exists");
    expect(pluginsHint({ ...base, directory: "/ops", source: "environment", exists: true }, 2, true)).toContain("Entries with an error are not loaded");
    expect(pluginsHint({ ...base, directory: "/ops", source: "environment", exists: true }, 0, false)).toContain("Add adapters to /ops");
    expect(pluginsHint({ ...base, directory: "/ops", source: "environment", exists: true }, 1, false)).toBeNull();
  });
});

// ───────────────────────────── routes against a fake context ─────────────────────────────

interface Harness {
  router: Router;
  audits: AuditEntryInput[];
  calls: string[][];
  /** `fresh` of every runShared call, in order. */
  shared?: boolean[];
}

function harness(
  respond: (args: string[]) => Partial<CliResult>,
  directoryDeps: Partial<PluginDirectoryDeps> = { environmentDir: PLUGIN_DIR },
): Harness {
  const audits: AuditEntryInput[] = [];
  const calls: string[][] = [];
  const shared: boolean[] = [];
  const workspace = tempDir("sentra-plugin-ws-");
  const run = async (args: string[]): Promise<CliResult> => {
    calls.push(args);
    return cliResult(respond(args));
  };
  const fake = {
    config: { pluginDir: directoryDeps.environmentDir ?? null, cliTimeoutMs: 5_000, cliLongTimeoutMs: 10_000 },
    // runShared is the read-only path (plugin list); this double runs every call.
    cli: {
      run,
      runShared: (args: string[], options: { fresh?: boolean }) => {
        shared.push(options.fresh === true);
        return run(args);
      },
    },
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
  registerPluginRoutes(router, fake as unknown as AppContext, { directories: resolver({ runCli: (args) => run(args), ...directoryDeps }) });
  return { router, audits, calls, shared };
}

/** `target` is a path, optionally with a query string. */
async function call(h: Harness, method: string, target: string, body: Record<string, unknown> = {}): Promise<Response> {
  const url = new URL(`http://127.0.0.1${target}`);
  const matched = h.router.match(method, url.pathname);
  if (!matched || matched === "method_not_allowed") throw new Error(`no route for ${method} ${target}`);
  const ctx: AuthedContext = {
    req: new Request(url, { method }),
    url,
    params: matched.params,
    principal: { role: "admin", label: "tester", via: "bearer" },
    ip: "127.0.0.1",
    readJson: async () => body,
    readText: async () => JSON.stringify(body),
  };
  return matched.route.handler(ctx);
}

const listStdout = JSON.stringify({ schema_version: 1, command: "plugin", action: "list", count: 1, plugins: [listEntry()], has_errors: false, diagnostics: [] });

describe("plugin routes", () => {
  test("no directory at all: honest 'not configured' listing, probe and run answer 412", async () => {
    const h = harness((args) => (args.includes("--dir") ? { stdout: listStdout } : UNAVAILABLE), { environmentDir: null, env: {} });
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(body).toMatchObject({ directory: null, directorySource: "none", directoryExists: false, pluginDir: null, configured: false, plugins: [], hasErrors: false, note: PLUGINS_NOT_CONFIGURED_NOTE });
    expect(body.diagnostics.map((entry) => entry.code)).toEqual(["plugin_dir_unavailable"]);
    expect(body.hint).toContain("Set SENTRA_PLUGIN_DIR on the bridge host");
    // Only the platform-default query ran, never a listing.
    expect(h.calls).toEqual([["plugin", "list", "--json"]]);
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" }), 412, "plugins_not_configured");
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/run", { tenantId: "t1", capability: "static_analysis" }), 412, "plugins_not_configured");
  });

  test("a refused platform default is 'none' too (412), with the refused path in a diagnostic", async () => {
    const h = harness((args) => (args.includes("--dir") ? { stdout: listStdout } : defaultListing("C:/repo/plugins")), {
      environmentDir: null,
      protectedLocations: () => [{ label: "the repository checkout", path: "C:\\repo" }],
    });
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(body).toMatchObject({ directory: null, directorySource: "none", configured: false });
    expect(body.diagnostics).toEqual([expect.objectContaining({ severity: "warning", code: "plugin_dir_refused", path: "C:/repo/plugins" })]);
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" }), 412, "plugins_not_configured");
  });

  test("list passes only --dir and returns declared (unenforced) metadata", async () => {
    const h = harness(() => ({ stdout: listStdout }));
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(h.calls[0]).toEqual(["plugin", "list", "--dir", PLUGIN_DIR, "--json"]);
    expect(body).toMatchObject({ directory: PLUGIN_DIR, directorySource: "environment", directoryExists: true, configured: true, hasErrors: false, hint: null, diagnostics: [] });
    expect(body.plugins.map((entry) => entry.id)).toEqual(["org.example.scanner"]);
    expect(body.note).toContain("not enforced");
  });

  test("Rediscover (refresh=1) and probe/run list again instead of reusing the 15-second listing", async () => {
    // Regression: Rediscover re-issued GET /api/plugins, which reused a listing for up to 15 s, so
    // a fixed manifest or a new adapter appeared only later and probe/run answered 404 meanwhile.
    const probeStdout = JSON.stringify({ plugin_id: "org.example.scanner", applicable: true, details: "", capabilities: [] });
    const h = harness((args) => ({ stdout: args[1] === "list" ? listStdout : probeStdout }));
    await call(h, "GET", "/api/plugins");
    await call(h, "GET", "/api/plugins?refresh=1");
    await call(h, "GET", "/api/plugins?refresh=0");
    await call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" });
    expect(h.shared).toEqual([false, true, false, true]);
    expect(pluginsHint({ directory: "/ops", source: "environment", exists: true, refusedDirectory: null }, 0, false)).toContain("then select Rediscover");
  });

  test("a missing directory is reported without running the core; probe finds nothing (404, not 412)", async () => {
    const h = harness(() => ({ stdout: listStdout }), { environmentDir: PLUGIN_DIR, isDirectory: () => false });
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(body).toMatchObject({ directory: PLUGIN_DIR, directorySource: "environment", directoryExists: false, configured: true, hasErrors: true });
    expect(body.diagnostics.map((entry) => [entry.severity, entry.code])).toEqual([["error", "plugin_dir_not_found"]]);
    expect(h.calls).toHaveLength(0);
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" }), 404, "plugin_not_found");
  });

  test("probe and run use the platform default directory", async () => {
    const defaultDir = path.resolve(os.tmpdir(), "sentra-default-plugins");
    const entry = listEntry({ manifest_path: `${defaultDir.replace(/\\/g, "/")}/scanner/manifest.json` });
    const probeStdout = JSON.stringify({ plugin_id: "org.example.scanner", applicable: true, details: "", capabilities: [] });
    const h = harness(
      (args) => {
        if (args[1] === "list") return args.includes("--dir") ? { stdout: JSON.stringify({ plugins: [entry], has_errors: false, diagnostics: [] }) } : defaultListing(defaultDir.replace(/\\/g, "/"));
        return { stdout: probeStdout };
      },
      { environmentDir: null, platform: process.platform, env: {} },
    );
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(body).toMatchObject({ directory: defaultDir, directorySource: "platform_default", configured: true, directoryExists: true });
    const probe = (await (await call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" })).json()) as { applicable: boolean };
    expect(probe.applicable).toBe(true);
    const probeArgs = h.calls.find((args) => args[1] === "probe") ?? [];
    expect(probeArgs[probeArgs.indexOf("--dir") + 1]).toBe(defaultDir);
  });

  test("core diagnostics and has_errors reach the listing", async () => {
    const stdout = JSON.stringify({
      plugins: [listEntry()],
      has_errors: true,
      diagnostics: [{ path: `${PLUGIN_DIR}/broken/manifest.json`, severity: "error", code: "manifest_invalid_json", message: "bad" }],
    });
    const h = harness(() => ({ stdout }));
    const body = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(body.hasErrors).toBe(true);
    expect(body.diagnostics).toEqual([{ severity: "error", code: "manifest_invalid_json", message: "bad", path: `${PLUGIN_DIR}/broken/manifest.json` }]);
    expect(body.hint).toContain("Entries with an error are not loaded");
  });

  test("invalid JSON from the core is an error, not an empty list", async () => {
    const h = harness(() => ({ stdout: '{"plugins":[{"details":"C:\\path"}]' }));
    await expectRejects(call(h, "GET", "/api/plugins"), 502, "core_output_invalid");
  });

  test("probe failures surface as errors and are audited", async () => {
    const h = harness((args) =>
      args[1] === "list" ? { stdout: listStdout } : { code: 5, stdout: "", stderr: '{"schema_version":1,"error":"plugin_probe_failed"}' },
    );
    await expectRejects(call(h, "POST", "/api/plugins/org.example.scanner/probe", { tenantId: "t1" }), 422, "core_command_failed");
    expect(h.audits).toHaveLength(1);
    expect(h.audits[0].action).toBe("plugin_probed");
    expect(h.audits[0].outcome).toBe("failure");
    expect(String(h.audits[0].details?.error)).toContain("plugin_probe_failed");
  });

  test("probe and run failures carry the adapter's reported reason (bounded and sanitised)", async () => {
    const stderr = JSON.stringify({
      schema_version: 1,
      error: "plugin_adapter_error",
      message: "semgrep executable not found on PATH\r\nInstall semgrep and retry",
      reason: "semgrep executable not found on PATH",
      process_exit_code: 0,
      timed_out: false,
      killed_by_host: false,
    });
    const h = harness((args) => (args[1] === "list" ? { stdout: listStdout } : { code: 5, stdout: "", stderr }));
    for (const [action, body] of [
      ["probe", { tenantId: "t1" }],
      ["run", { tenantId: "t1", capability: "static_analysis" }],
    ] as const) {
      try {
        await call(h, "POST", `/api/plugins/org.example.scanner/${action}`, body);
        throw new Error("expected a failure");
      } catch (error) {
        expect(error).toBeInstanceOf(HttpError);
        const failure = error as HttpError;
        expect(failure).toMatchObject({ status: 422, code: "core_command_failed" });
        expect(failure.message).toBe(`sentra plugin ${action} failed: plugin_adapter_error: semgrep executable not found on PATH Install semgrep and retry`);
        expect(failure.details).toMatchObject({ coreError: "plugin_adapter_error", coreMessage: "semgrep executable not found on PATH Install semgrep and retry" });
      }
    }
    expect(h.audits.map((entry) => String(entry.details?.error))).toEqual([
      expect.stringContaining("semgrep executable not found on PATH"),
      expect.stringContaining("semgrep executable not found on PATH"),
    ]);
  });

  test("probe of a plugin outside the listing is rejected", async () => {
    const h = harness(() => ({ stdout: listStdout }));
    await expectRejects(call(h, "POST", "/api/plugins/org.example.other/probe", { tenantId: "t1" }), 404, "plugin_not_found");
  });

  test("run rejects undeclared capabilities before spawning the adapter", async () => {
    const h = harness(() => ({ stdout: listStdout }));
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
    const h = harness((args) => ({ stdout: args[1] === "list" ? listStdout : runStdout }));
    const response = await call(h, "POST", "/api/plugins/org.example.scanner/run", {
      tenantId: "t1",
      capability: "static_analysis",
      args: { secret: "never-audited" },
    });
    const body = (await response.json()) as { taskId: string; exitCode: number };
    expect(body.taskId).toBe("task-7");
    const runArgs = h.calls.find((args) => args[1] === "run") ?? [];
    expect(runArgs[runArgs.indexOf("--args") + 1]).toBe('{"secret":"never-audited"}');
    expect(runArgs[runArgs.indexOf("--dir") + 1]).toBe(PLUGIN_DIR);
    expect(runArgs).toContain("--workspace");
    const audit = h.audits.find((entry) => entry.action === "plugin_run");
    expect(audit?.outcome).toBe("success");
    expect(JSON.stringify(audit)).not.toContain("never-audited");
    expect(audit?.details?.adapterReportedExitCode).toBe(0);
  });
});

// ───────────────────────────── against the real core binary ─────────────────────────────

const REPO_ROOT = path.resolve(import.meta.dir, "..", "..", "..");
const CORE_BIN = (() => {
  const exe = process.platform === "win32" ? "sentra.exe" : "sentra";
  const candidates = [process.env.SENTRA_BIN, path.join(REPO_ROOT, "target", "release", exe), path.join(REPO_ROOT, "target", "debug", exe)];
  return candidates.find((candidate): candidate is string => typeof candidate === "string" && candidate.length > 0 && fs.existsSync(candidate)) ?? null;
})();

/** Variables that make the core's platform default `<base>/...` on this host, and that directory. */
function platformDefaultFor(base: string): { env: Record<string, string>; expected: string } {
  if (process.platform === "win32") return { env: { APPDATA: base }, expected: path.join(base, "sentra", "plugins") };
  if (process.platform === "darwin") return { env: { HOME: base }, expected: path.join(base, "Library", "Application Support", "sentra", "plugins") };
  return { env: { XDG_CONFIG_HOME: base }, expected: path.join(base, "sentra", "plugins") };
}

function copyManifest(adapter: string, target: string): void {
  fs.mkdirSync(target, { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, "examples", "adapters", adapter, "manifest.json"), path.join(target, "manifest.json"));
}

describe.skipIf(CORE_BIN === null)("with the real core binary", () => {
  const cli = () => new SentraCli(CORE_BIN as string, tempDir("sentra-plugin-cwd-"), 30_000, 2);

  test("the platform default is the directory the core itself reports (this host's rules)", async () => {
    const base = tempDir("sentra-plugin-cfg-");
    const { env, expected } = platformDefaultFor(base);
    const core = cli();
    const directories = new PluginDirectoryResolver({
      platform: process.platform,
      environmentDir: null,
      // SENTRA_PLUGIN_DIR in the bridge environment must not reach this query.
      env: { ...env, SENTRA_PLUGIN_DIR: tempDir("sentra-plugin-env-") },
      runCli: (args, options) => core.run(args, options),
      timeoutMs: 30_000,
      protectedLocations: () => [],
    });
    const state = await directories.current();
    expect(state).toMatchObject({ directory: expected, source: "platform_default", exists: false });
    // Never created by the bridge.
    expect(fs.existsSync(expected)).toBe(false);
  });

  if (process.platform === "linux") {
    test("Linux: XDG_CONFIG_HOME first, HOME/.config when it is unset or relative", async () => {
      const home = tempDir("sentra-plugin-home-");
      for (const env of [{ HOME: home }, { HOME: home, XDG_CONFIG_HOME: "relative" }]) {
        const core = cli();
        const state = await new PluginDirectoryResolver({ platform: "linux", environmentDir: null, env, runCli: (a, o) => core.run(a, o), timeoutMs: 30_000, protectedLocations: () => [] }).current();
        expect(state.directory).toBe(path.join(home, ".config", "sentra", "plugins"));
      }
    });
  }

  test("no platform variables: the core has no default, so none", async () => {
    const core = cli();
    const state = await new PluginDirectoryResolver({ platform: process.platform, environmentDir: null, env: {}, runCli: (a, o) => core.run(a, o), timeoutMs: 30_000, protectedLocations: () => [] }).current();
    expect(state).toMatchObject({ directory: null, source: "none" });
    expect(state.diagnostics.map((entry) => entry.code)).toEqual(["plugin_dir_unavailable"]);
  });

  test("listing a default directory created later: valid, invalid and duplicate manifests", async () => {
    const base = tempDir("sentra-plugin-cfg-");
    const { env, expected } = platformDefaultFor(base);
    const core = cli();
    const workspace = tempDir("sentra-plugin-ws-");
    const app = {
      config: { pluginDir: null, cliTimeoutMs: 30_000, cliLongTimeoutMs: 30_000 },
      cli: core,
      workspaces: { get: (tenantId: string) => ({ tenantId, workspace }), workspaceRoot: () => workspace },
      audit: { append: () => undefined },
    };
    const router = new Router();
    const directories = new PluginDirectoryResolver({ platform: process.platform, environmentDir: null, env, runCli: (a, o) => core.run(a, o), timeoutMs: 30_000, protectedLocations: () => [] });
    registerPluginRoutes(router, app as unknown as AppContext, { directories });
    const h: Harness = { router, audits: [], calls: [] };

    const before = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(before).toMatchObject({ directory: expected, directorySource: "platform_default", directoryExists: false, configured: true, plugins: [] });
    expect(before.hint).toBe(`Set SENTRA_PLUGIN_DIR on the bridge host and restart, or create ${expected} and add adapters (one subdirectory with a manifest.json each).`);
    // The directory exists but holds no adapter: probe reaches discovery (404), not 412.
    await expectRejects(call(h, "POST", "/api/plugins/org.sentra.adapter.snyk/probe", { tenantId: "t1" }), 404, "plugin_not_found");

    copyManifest("sentra-adapter-snyk", path.join(expected, "snyk"));
    copyManifest("sentra-adapter-semgrep", path.join(expected, "semgrep-a"));
    copyManifest("sentra-adapter-semgrep", path.join(expected, "semgrep-b"));
    fs.mkdirSync(path.join(expected, "broken"));
    fs.writeFileSync(path.join(expected, "broken", "manifest.json"), "{ not json");

    const after = (await (await call(h, "GET", "/api/plugins")).json()) as PluginsView;
    expect(after).toMatchObject({ directory: expected, directoryExists: true, hasErrors: true });
    expect(after.plugins.map((entry) => entry.id)).toEqual(["org.sentra.adapter.snyk"]);
    const slash = (value: string | null) => (value ?? "").replace(/\\/g, "/");
    expect(after.diagnostics.map((entry) => [entry.severity, entry.code, slash(entry.path).slice(slash(expected).length)])).toEqual([
      ["error", "manifest_invalid_json", "/broken/manifest.json"],
      ["error", "duplicate_plugin_id", "/semgrep-a/manifest.json"],
      ["error", "duplicate_plugin_id", "/semgrep-b/manifest.json"],
    ]);
    expect(after.diagnostics[1].message).toContain("org.sentra.adapter.semgrep");
    expect(after.hint).toContain("Entries with an error are not loaded");
  });
});

// ───────────────────────────── console wording ─────────────────────────────

describe("plugins tab normalisation", () => {
  test("the current shape passes through", () => {
    const current: PluginsView = {
      directory: "C:\\plugins",
      directorySource: "platform_default",
      directoryExists: true,
      pluginDir: "C:\\plugins",
      configured: true,
      plugins: [plugin],
      diagnostics: [{ severity: "info", code: "x", message: "m", path: null }],
      hasErrors: false,
      hint: null,
      note: "n",
    };
    expect(normalizePluginsView(current)).toEqual({ ...current, legacy: false });
  });

  test("a contract 3 bridge renders instead of crashing", () => {
    expect(normalizePluginsView({ pluginDir: "/ops/plugins", configured: true, plugins: [plugin], note: "old" })).toEqual({
      directory: "/ops/plugins",
      directorySource: "environment",
      directoryExists: true,
      pluginDir: "/ops/plugins",
      configured: true,
      plugins: [plugin],
      diagnostics: [],
      hasErrors: false,
      hint: null,
      note: "old",
      legacy: true,
    });
    expect(normalizePluginsView({ pluginDir: null, configured: false, plugins: [], note: "x" })).toMatchObject({ directorySource: "none", configured: false, legacy: true });
    for (const garbage of [null, [], "x", { diagnostics: "x", plugins: {} }]) {
      expect(normalizePluginsView(garbage)).toMatchObject({ directory: null, directorySource: "none", plugins: [], diagnostics: [], configured: false });
    }
    expect(normalizePluginsView({ directorySource: "none", diagnostics: [{ severity: "fatal", code: 3 }, 4] }).diagnostics).toEqual([
      { severity: "warning", code: "unknown", message: "", path: null },
    ]);
  });

  test("the tab, card and run dialog say which manifest limits the core enforces", () => {
    // Regression: all three said no quota was enforced, while the core enforces the execution time
    // limit and the frame and output quotas (and the tab's own note said so).
    const dir = path.join(import.meta.dir, "..", "..", "src", "components", "dashboard");
    for (const file of ["plugins-tab.tsx", "plugin-card.tsx", "plugin-run-dialog.tsx"]) {
      const text = fs.readFileSync(path.join(dir, file), "utf8").replace(/\s+/g, " ");
      expect(text).not.toContain("Declared by the manifest, not enforced");
      expect(text).not.toContain("declared quotas and egress policy are not enforced");
      expect(text).not.toContain("Quotas and egress policies in a manifest are declarations; they are not enforced");
      expect(text).toMatch(/The core enforces the manifest's execution time limit|enforced by the core, at most one hour/);
      expect(text).toMatch(/memory quota and egress policy are not enforced|declared only, not enforced/);
    }
  });

  test("summary and state labels", () => {
    expect(
      diagnosticSummary([
        { severity: "error", code: "a", message: "", path: null },
        { severity: "error", code: "b", message: "", path: null },
        { severity: "warning", code: "c", message: "", path: null },
        { severity: "info", code: "d", message: "", path: null },
      ]),
    ).toBe("2 errors, 1 warning, 1 note");
    expect(diagnosticSummary([])).toBe("");
    expect(directoryStateLabel({ directory: null, directoryExists: false })).toBeNull();
    expect(directoryStateLabel({ directory: "/x", directoryExists: false })).toBe("does not exist");
    expect(directoryStateLabel({ directory: "/x", directoryExists: true })).toBe("exists");
  });
});
