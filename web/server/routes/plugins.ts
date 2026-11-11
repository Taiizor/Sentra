import path from "node:path";
import type { PluginProbeView, PluginRunView, PluginsView, PluginView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { HttpError, json, type Router } from "../http.ts";
import { isWithin } from "../paths.ts";
import { cliFailure, cliValue, type CliResult } from "../sentra-cli.ts";
import { requiredString } from "../validate.ts";
import { audited } from "./helpers.ts";

/**
 * Plugin adapters discovered by the core (`sentra plugin list/probe/run`) from the directory
 * configured in SENTRA_PLUGIN_DIR. Adapters are third-party subprocesses: everything they
 * return (applicability, exit code, summary, evidence references) is adapter-reported.
 */

export const PLUGIN_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
export const PLUGIN_CAPABILITY_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
export const MAX_PLUGIN_ARGS_BYTES = 16 * 1024;
const MAX_STREAM_CHARS = 64 * 1024;

export const PLUGINS_NOT_CONFIGURED_NOTE =
  "Set SENTRA_PLUGIN_DIR to a directory of adapter manifests. The example adapters in examples/adapters return simulated output and are never loaded by default.";

const PLUGINS_CONFIGURED_NOTE =
  "Adapters are discovered from SENTRA_PLUGIN_DIR (a manifest.json in that directory or in its immediate subdirectories). " +
  "Probe and run start the adapter as a subprocess on the Sentra host with an allowlisted environment; no isolation profile is applied. " +
  "The core enforces the time limit and frame/output quotas and kills the adapter process tree when a session ends; " +
  "the declared egress policy and memory quota are not enforced. Results are reported by the adapter itself.";

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function invalidOutput(command: string, detail: string): HttpError {
  return new HttpError(502, "core_output_invalid", `sentra ${command} returned an unexpected document: ${detail}`);
}

export function pluginIdParam(value: string | undefined): string {
  if (!value || !PLUGIN_ID_PATTERN.test(value)) {
    throw new HttpError(400, "invalid_plugin_id", "Plugin ids are 1-128 characters of A-Z, a-z, 0-9, '.', '_' or '-'");
  }
  return value;
}

/** Maps `plugin list --json`, keeping only manifests located inside the configured directory. */
export function mapPluginList(document: unknown, pluginDir: string): { plugins: PluginView[]; ignored: number } {
  const doc = asRecord(document);
  if (!doc || !Array.isArray(doc.plugins)) throw invalidOutput("plugin list", "no plugins array");
  const plugins: PluginView[] = [];
  let ignored = 0;
  for (const raw of doc.plugins) {
    const entry = asRecord(raw);
    if (!entry || typeof entry.id !== "string" || typeof entry.manifest_path !== "string") {
      ignored += 1;
      continue;
    }
    if (!isWithin(pluginDir, path.resolve(entry.manifest_path))) {
      ignored += 1;
      continue;
    }
    const quotas = asRecord(entry.quotas);
    const memory = quotas?.max_memory_mib;
    const time = quotas?.max_execution_time_secs;
    plugins.push({
      id: entry.id,
      name: typeof entry.name === "string" ? entry.name : entry.id,
      version: typeof entry.version === "string" ? entry.version : "",
      family: typeof entry.family === "string" ? entry.family : "unknown",
      manifestPath: entry.manifest_path,
      executablePath: typeof entry.executable_path === "string" && entry.executable_path ? entry.executable_path : null,
      capabilities: strings(entry.capabilities),
      declaredEgressPolicy: typeof entry.egress_policy === "string" && entry.egress_policy ? entry.egress_policy : "undeclared",
      declaredQuotas:
        typeof memory === "number" && typeof time === "number" ? { maxMemoryMib: memory, maxExecutionTimeSecs: time } : null,
    });
  }
  return { plugins, ignored };
}

/** The capability must be one the plugin's manifest declares. */
export function requireDeclaredCapability(plugin: PluginView, capability: string): string {
  if (!PLUGIN_CAPABILITY_PATTERN.test(capability)) {
    throw new HttpError(400, "invalid_capability", "Capabilities are 1-64 characters of a-z, 0-9, '_', '.' or '-'");
  }
  if (!plugin.capabilities.includes(capability)) {
    throw new HttpError(400, "capability_not_declared", `Plugin '${plugin.id}' does not declare the capability '${capability}'`);
  }
  return capability;
}

/** Serializes optional adapter arguments (a JSON object of at most 16 KiB). */
export function serializePluginArgs(value: unknown): string {
  if (value === undefined || value === null) return "{}";
  if (!asRecord(value)) throw new HttpError(400, "invalid_request", "'args' must be a JSON object");
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, "utf8") > MAX_PLUGIN_ARGS_BYTES) {
    throw new HttpError(400, "invalid_request", `'args' must serialize to at most ${MAX_PLUGIN_ARGS_BYTES} bytes`);
  }
  return text;
}

export function mapProbe(document: unknown, pluginId: string): PluginProbeView {
  const doc = asRecord(document);
  if (!doc || typeof doc.applicable !== "boolean") throw invalidOutput("plugin probe", "no applicable flag");
  return {
    pluginId: typeof doc.plugin_id === "string" ? doc.plugin_id : pluginId,
    name: typeof doc.name === "string" ? doc.name : null,
    applicable: doc.applicable,
    details: typeof doc.details === "string" ? doc.details : "",
    unsupportedReason: typeof doc.unsupported_reason === "string" ? doc.unsupported_reason : null,
    capabilities: strings(doc.capabilities),
  };
}

function bounded(text: string): string {
  return text.length > MAX_STREAM_CHARS ? `${text.slice(0, MAX_STREAM_CHARS)}\n[truncated at ${MAX_STREAM_CHARS} characters]` : text;
}

export function mapRun(document: unknown, plugin: PluginView, capability: string, result: Pick<CliResult, "stdout" | "stderr">): PluginRunView {
  const doc = asRecord(document);
  if (!doc || typeof doc.exit_code !== "number" || typeof doc.summary !== "string") {
    throw invalidOutput("plugin run", "no exit_code/summary");
  }
  // The core sends the tenant workspace to the adapter (Execute frame `workspace_root`);
  // exit code, summary and evidence references remain adapter-reported.
  const summary = doc.summary;
  return {
    pluginId: typeof doc.plugin_id === "string" ? doc.plugin_id : plugin.id,
    capability: typeof doc.capability === "string" ? doc.capability : capability,
    taskId: typeof doc.task_id === "string" && doc.task_id ? doc.task_id : null,
    exitCode: doc.exit_code,
    summary,
    reportedEvidenceRefs: strings(doc.evidence_refs),
    stdout: bounded(result.stdout),
    stderr: bounded(result.stderr),
  };
}

/** Plugin listings are read views; one `sentra plugin list` run is reused for this long. */
const PLUGIN_LIST_TTL_MS = 15_000;

/**
 * Runs a `sentra plugin ...` command and returns the CLI result with parsed JSON. `sharedTtlMs`
 * marks a read-only command whose run may be shared with concurrent callers (SentraCli.runShared).
 */
async function runPluginCommand(
  app: AppContext,
  args: string[],
  timeoutMs: number,
  sharedTtlMs?: number,
): Promise<CliResult & { document: unknown }> {
  const command = `plugin ${args[1] ?? ""}`.trim();
  const result = sharedTtlMs === undefined ? await app.cli.run(args, { timeoutMs }) : await app.cli.runShared(args, { ttlMs: sharedTtlMs, timeoutMs });
  if (result.timedOut) throw new HttpError(504, "core_timeout", `sentra ${command} timed out after ${Math.round(timeoutMs / 1000)} s`);
  if (result.code !== 0) throw cliFailure(command, result);
  if (result.json === undefined) {
    // Guard against stdout that is not a JSON document (e.g. a diagnostic printed by an adapter).
    throw new HttpError(502, "core_output_invalid", `sentra ${command} exited 0 but printed output that is not valid JSON`);
  }
  return { ...result, document: result.json };
}

function requirePluginDir(app: AppContext): string {
  if (!app.config.pluginDir) {
    throw new HttpError(412, "plugins_not_configured", PLUGINS_NOT_CONFIGURED_NOTE);
  }
  return app.config.pluginDir;
}

async function listPlugins(app: AppContext): Promise<PluginsView> {
  const pluginDir = app.config.pluginDir;
  if (!pluginDir) return { pluginDir: null, configured: false, plugins: [], note: PLUGINS_NOT_CONFIGURED_NOTE };
  const result = await runPluginCommand(
    app,
    ["plugin", "list", "--dir", cliValue(pluginDir, "pluginDir"), "--json"],
    app.config.cliTimeoutMs,
    PLUGIN_LIST_TTL_MS,
  );
  const { plugins, ignored } = mapPluginList(result.document, pluginDir);
  const note = ignored > 0 ? `${PLUGINS_CONFIGURED_NOTE} ${ignored} discovered entr${ignored === 1 ? "y was" : "ies were"} ignored (outside SENTRA_PLUGIN_DIR or malformed).` : PLUGINS_CONFIGURED_NOTE;
  return { pluginDir, configured: true, plugins, note };
}

async function findPlugin(app: AppContext, pluginId: string): Promise<PluginView> {
  const listing = await listPlugins(app);
  const plugin = listing.plugins.find((candidate) => candidate.id === pluginId);
  if (!plugin) throw new HttpError(404, "plugin_not_found", `Plugin '${pluginId}' is not in SENTRA_PLUGIN_DIR`);
  return plugin;
}

export function registerPluginRoutes(router: Router, app: AppContext): void {
  router.get("/api/plugins", { auth: "session", permission: "read" }, async () => json(await listPlugins(app)));

  router.post("/api/plugins/:pluginId/probe", { auth: "session", permission: "plugin:probe", maxBodyBytes: 4096 }, async (ctx) => {
    const pluginId = pluginIdParam(ctx.params.pluginId);
    const body = await ctx.readJson();
    const tenant = app.workspaces.get(requiredString(body, "tenantId", { max: 64 }));
    const pluginDir = requirePluginDir(app);
    const view = await audited(
      app,
      ctx.principal,
      { action: "plugin_probed", tenantId: tenant.tenantId, target: pluginId },
      async () => {
        const plugin = await findPlugin(app, pluginId);
        const root = app.workspaces.workspaceRoot(tenant);
        const result = await runPluginCommand(
          app,
          [
            "plugin",
            "probe",
            "--id",
            cliValue(plugin.id, "pluginId"),
            "--dir",
            cliValue(pluginDir, "pluginDir"),
            "--workspace",
            cliValue(root, "workspace"),
            "--json",
          ],
          app.config.cliTimeoutMs,
        );
        return mapProbe(result.document, plugin.id);
      },
      (probe) => ({ applicable: probe.applicable }),
    );
    return json(view);
  });

  router.post("/api/plugins/:pluginId/run", { auth: "session", permission: "plugin:run", maxBodyBytes: 64 * 1024 }, async (ctx) => {
    const pluginId = pluginIdParam(ctx.params.pluginId);
    const body = await ctx.readJson();
    const tenant = app.workspaces.get(requiredString(body, "tenantId", { max: 64 }));
    const requestedCapability = requiredString(body, "capability", { max: 64 });
    const args = serializePluginArgs(body.args);
    const pluginDir = requirePluginDir(app);
    const view = await audited(
      app,
      ctx.principal,
      {
        action: "plugin_run",
        tenantId: tenant.tenantId,
        target: pluginId,
        details: { capability: requestedCapability, argsBytes: Buffer.byteLength(args, "utf8") },
      },
      async () => {
        const plugin = await findPlugin(app, pluginId);
        const capability = requireDeclaredCapability(plugin, requestedCapability);
        const root = app.workspaces.workspaceRoot(tenant);
        const result = await runPluginCommand(
          app,
          [
            "plugin",
            "run",
            "--id",
            cliValue(plugin.id, "pluginId"),
            "--dir",
            cliValue(pluginDir, "pluginDir"),
            "--capability",
            cliValue(capability, "capability"),
            "--args",
            cliValue(args, "args", MAX_PLUGIN_ARGS_BYTES),
            "--workspace",
            cliValue(root, "workspace"),
            "--json",
          ],
          app.config.cliLongTimeoutMs,
        );
        return mapRun(result.document, plugin, capability, result);
      },
      (run) => ({ adapterReportedExitCode: run.exitCode, taskId: run.taskId, reportedEvidenceRefs: run.reportedEvidenceRefs.length }),
    );
    return json(view);
  });
}
