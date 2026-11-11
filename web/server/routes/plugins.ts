import os from "node:os";
import path from "node:path";
import type { PluginDiagnosticView, PluginDirectorySource, PluginProbeView, PluginRunView, PluginsView, PluginView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { HttpError, json, type Router } from "../http.ts";
import { isWithin } from "../paths.ts";
import {
  mapCoreDiagnostics,
  PluginDirectoryResolver,
  type PluginDirectoryState,
  type ProtectedLocation,
} from "../plugin-directory.ts";
import { cliFailure, cliValue, type CliResult } from "../sentra-cli.ts";
import { requiredString } from "../validate.ts";
import { audited } from "./helpers.ts";

/**
 * Plugin adapters discovered by the core (`sentra plugin list/probe/run`) from the plugin
 * directory: SENTRA_PLUGIN_DIR, otherwise the core's platform default (plugin-directory.ts).
 * Every core call names the directory with --dir. Adapters are third-party subprocesses:
 * everything they return (applicability, exit code, summary, evidence references) is
 * adapter-reported.
 */

export const PLUGIN_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
export const PLUGIN_CAPABILITY_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
export const MAX_PLUGIN_ARGS_BYTES = 16 * 1024;
const MAX_STREAM_CHARS = 64 * 1024;

export const PLUGINS_NOT_CONFIGURED_NOTE =
  "No plugin directory is in use: SENTRA_PLUGIN_DIR is not set and the core's platform default plugin directory is unavailable or was refused. The example adapters in examples/adapters are never loaded by default; the Snyk and Ollama examples return simulated output.";

const DISCOVERY_RULE = "a manifest.json in that directory or in its immediate subdirectories";

const EXECUTION_NOTE =
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

/**
 * Maps `plugin list --json`, keeping only manifests located inside the plugin directory. Entries
 * the bridge drops (malformed, or a manifest outside the directory) come back as diagnostics.
 */
export function mapPluginList(document: unknown, pluginDir: string): { plugins: PluginView[]; ignored: PluginDiagnosticView[] } {
  const doc = asRecord(document);
  if (!doc || !Array.isArray(doc.plugins)) throw invalidOutput("plugin list", "no plugins array");
  const plugins: PluginView[] = [];
  const ignored: PluginDiagnosticView[] = [];
  for (const raw of doc.plugins) {
    const entry = asRecord(raw);
    if (!entry || typeof entry.id !== "string" || typeof entry.manifest_path !== "string") {
      ignored.push({
        severity: "warning",
        code: "plugin_entry_ignored",
        message: "The core listed an entry without an id or manifest path; the bridge ignored it.",
        path: null,
      });
      continue;
    }
    if (!isWithin(pluginDir, path.resolve(entry.manifest_path))) {
      ignored.push({
        severity: "warning",
        code: "plugin_entry_ignored",
        message: `The manifest of '${entry.id}' is outside the plugin directory; the bridge ignored it.`,
        path: entry.manifest_path,
      });
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

export function pluginsNote(source: PluginDirectorySource): string {
  if (source === "environment") return `Adapters are discovered from SENTRA_PLUGIN_DIR (${DISCOVERY_RULE}). ${EXECUTION_NOTE}`;
  if (source === "platform_default") {
    return `SENTRA_PLUGIN_DIR is not set, so adapters are discovered from the core's platform default plugin directory (${DISCOVERY_RULE}). ${EXECUTION_NOTE}`;
  }
  return PLUGINS_NOT_CONFIGURED_NOTE;
}

/** What the host operator can do next; null when the directory is in use and loaded cleanly. */
export function pluginsHint(state: Pick<PluginDirectoryState, "directory" | "source" | "exists" | "refusedDirectory">, pluginCount: number, hasErrors: boolean): string | null {
  if (state.directory === null) {
    return state.refusedDirectory !== null
      ? "Set SENTRA_PLUGIN_DIR on the bridge host to a directory outside the bridge data and temporary directories, the repository and every registered workspace, then restart the bridge."
      : "Set SENTRA_PLUGIN_DIR on the bridge host to an absolute directory of adapter manifests, then restart the bridge.";
  }
  if (!state.exists) {
    return state.source === "environment"
      ? `SENTRA_PLUGIN_DIR points to ${state.directory}, which no longer exists. Recreate it, or set SENTRA_PLUGIN_DIR to another directory and restart the bridge.`
      : `Set SENTRA_PLUGIN_DIR on the bridge host and restart, or create ${state.directory} and add adapters (one subdirectory with a manifest.json each).`;
  }
  if (hasErrors) return "Entries with an error are not loaded. Fix or remove the manifests named in the diagnostics, then select Rediscover.";
  if (pluginCount === 0) return `Add adapters to ${state.directory} (one subdirectory with a manifest.json each), then select Rediscover.`;
  return null;
}

/** Locations a platform default plugin directory must not overlap (see plugin-directory.ts). */
export function protectedLocations(app: Pick<AppContext, "config" | "workspaces">): ProtectedLocation[] {
  return [
    { label: "the bridge data directory", path: app.config.dataDir },
    { label: "the bridge temporary directory", path: app.config.tmpDir },
    { label: "the system temporary directory", path: os.tmpdir() },
    { label: "the repository checkout", path: app.config.repoRoot },
    ...app.workspaces.list().map((tenant) => ({ label: `the workspace of '${tenant.tenantId}'`, path: tenant.workspace })),
  ];
}

export function createPluginDirectoryResolver(app: AppContext): PluginDirectoryResolver {
  return new PluginDirectoryResolver({
    platform: process.platform,
    environmentDir: app.config.pluginDir,
    env: process.env,
    runCli: (args, options) => app.cli.run(args, options),
    timeoutMs: app.config.cliTimeoutMs,
    protectedLocations: () => protectedLocations(app),
  });
}

const resolvers = new WeakMap<AppContext, PluginDirectoryResolver>();

/** The one resolver of an app, shared by the plugin routes and the console's `plugins` command. */
export function pluginDirectoryResolver(app: AppContext): PluginDirectoryResolver {
  let resolver = resolvers.get(app);
  if (!resolver) {
    resolver = createPluginDirectoryResolver(app);
    resolvers.set(app, resolver);
  }
  return resolver;
}

/**
 * Plugin listings are read views; one `sentra plugin list` run is reused for this long. Rediscover
 * (`GET /api/plugins?refresh=1`) and the listing before a probe or run never reuse a completed run.
 */
const PLUGIN_LIST_TTL_MS = 15_000;

/**
 * Runs a `sentra plugin ...` command and returns the CLI result with parsed JSON. `shared` marks a
 * read-only command whose run may be shared with concurrent callers (SentraCli.runShared); with
 * `fresh`, a completed run is not reused.
 */
async function runPluginCommand(
  app: AppContext,
  args: string[],
  timeoutMs: number,
  shared?: { ttlMs: number; fresh: boolean },
): Promise<CliResult & { document: unknown }> {
  const command = `plugin ${args[1] ?? ""}`.trim();
  const result = shared === undefined ? await app.cli.run(args, { timeoutMs }) : await app.cli.runShared(args, { ttlMs: shared.ttlMs, timeoutMs, fresh: shared.fresh });
  if (result.timedOut) throw new HttpError(504, "core_timeout", `sentra ${command} timed out after ${Math.round(timeoutMs / 1000)} s`);
  if (result.code !== 0) throw cliFailure(command, result);
  if (result.json === undefined) {
    // Guard against stdout that is not a JSON document (e.g. a diagnostic printed by an adapter).
    throw new HttpError(502, "core_output_invalid", `sentra ${command} exited 0 but printed output that is not valid JSON`);
  }
  return { ...result, document: result.json };
}

function pluginsView(state: PluginDirectoryState, plugins: PluginView[], listingDiagnostics: PluginDiagnosticView[], coreHasErrors: boolean): PluginsView {
  const diagnostics = [...state.diagnostics, ...listingDiagnostics];
  const hasErrors = coreHasErrors || diagnostics.some((diagnostic) => diagnostic.severity === "error");
  return {
    directory: state.directory,
    directorySource: state.source,
    directoryExists: state.exists,
    pluginDir: state.directory,
    configured: state.directory !== null,
    plugins,
    diagnostics,
    hasErrors,
    hint: pluginsHint(state, plugins.length, hasErrors),
    note: pluginsNote(state.source),
  };
}

/** `fresh`: list again instead of reusing a listing completed within PLUGIN_LIST_TTL_MS. */
async function listPlugins(app: AppContext, directories: PluginDirectoryResolver, options: { fresh: boolean }): Promise<PluginsView> {
  const state = await directories.current();
  // A missing directory is reported without starting the core; it is checked again next time.
  if (state.directory === null || !state.exists) return pluginsView(state, [], [], false);
  const result = await runPluginCommand(
    app,
    ["plugin", "list", "--dir", cliValue(state.directory, "pluginDir"), "--json"],
    app.config.cliTimeoutMs,
    { ttlMs: PLUGIN_LIST_TTL_MS, fresh: options.fresh },
  );
  const { plugins, ignored } = mapPluginList(result.document, state.directory);
  const core = mapCoreDiagnostics(result.document);
  // The directory can disappear between the existence check and the core's scan.
  const exists = !core.diagnostics.some((diagnostic) => diagnostic.code === "plugin_dir_not_found");
  return pluginsView({ ...state, exists }, plugins, [...core.diagnostics, ...ignored], core.hasErrors);
}

/** The plugin directory in use (it may not exist yet); 412 when there is none. */
export async function requirePluginDirectory(directories: PluginDirectoryResolver): Promise<string> {
  const state = await directories.current();
  if (state.directory === null) {
    throw new HttpError(412, "plugins_not_configured", `No plugin directory is in use. ${pluginsHint(state, 0, false) ?? ""}`.trim());
  }
  return state.directory;
}

/**
 * The plugin as currently listed. The listing is always fresh, so an adapter added or a manifest
 * changed a moment ago is found and checked against its current declaration.
 */
async function findPlugin(app: AppContext, directories: PluginDirectoryResolver, pluginId: string): Promise<{ plugin: PluginView; directory: string }> {
  const listing = await listPlugins(app, directories, { fresh: true });
  const plugin = listing.plugins.find((candidate) => candidate.id === pluginId);
  if (!plugin || listing.directory === null) throw new HttpError(404, "plugin_not_found", `Plugin '${pluginId}' is not in the plugin directory`);
  return { plugin, directory: listing.directory };
}

/** `options.directories` replaces the app's resolver (tests inject platform, environment and probes). */
export function registerPluginRoutes(router: Router, app: AppContext, options: { directories?: PluginDirectoryResolver } = {}): void {
  if (options.directories) resolvers.set(app, options.directories);
  const directories = pluginDirectoryResolver(app);

  // `?refresh=1` (Rediscover) lists again instead of reusing a listing from the last 15 seconds.
  router.get("/api/plugins", { auth: "session", permission: "read" }, async (ctx) =>
    json(await listPlugins(app, directories, { fresh: ctx.url.searchParams.get("refresh") === "1" })),
  );

  router.post("/api/plugins/:pluginId/probe", { auth: "session", permission: "plugin:probe", maxBodyBytes: 4096 }, async (ctx) => {
    const pluginId = pluginIdParam(ctx.params.pluginId);
    const body = await ctx.readJson();
    const tenant = app.workspaces.get(requiredString(body, "tenantId", { max: 64 }));
    await requirePluginDirectory(directories);
    const view = await audited(
      app,
      ctx.principal,
      { action: "plugin_probed", tenantId: tenant.tenantId, target: pluginId },
      async () => {
        const { plugin, directory } = await findPlugin(app, directories, pluginId);
        const root = app.workspaces.workspaceRoot(tenant);
        const result = await runPluginCommand(
          app,
          [
            "plugin",
            "probe",
            "--id",
            cliValue(plugin.id, "pluginId"),
            "--dir",
            cliValue(directory, "pluginDir"),
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
    await requirePluginDirectory(directories);
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
        const { plugin, directory } = await findPlugin(app, directories, pluginId);
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
            cliValue(directory, "pluginDir"),
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
