import type { AiSettingsView, ListModelsResponse, ProviderId } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { HttpError, json, type AuthedContext, type Router } from "../http.ts";
import { isProviderId, PROVIDER_IDS, PROVIDERS } from "../llm.ts";
import { optionalBoolean, type JsonObject } from "../validate.ts";
import { audited } from "./helpers.ts";

const MAX_LISTED_MODELS = 2000;

export function aiSettingsView(app: Pick<AppContext, "llm">): AiSettingsView {
  return app.llm.status();
}

function providerParam(ctx: AuthedContext): ProviderId {
  const value = ctx.params.provider;
  if (!isProviderId(value)) {
    throw new HttpError(404, "unknown_provider", `Unknown AI provider. Supported providers: ${PROVIDER_IDS.join(", ")}`);
  }
  return value;
}

/** `undefined` = leave unchanged, `null` = reset, string = new value. */
function nullableString(body: JsonObject, field: string, max: number): string | null | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (value === null || value === "") return null;
  if (typeof value !== "string") throw new HttpError(400, "invalid_request", `'${field}' must be a string or null`);
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.length > max) throw new HttpError(400, "invalid_request", `'${field}' must be at most ${max} characters`);
  // oxlint-disable-next-line no-control-regex -- intentional: rejects control characters in provider settings
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) throw new HttpError(400, "invalid_request", `'${field}' contains control characters`);
  return trimmed;
}

/** Origin and path only: a query string could carry a credential and must not reach the audit chain. */
export function auditableEndpoint(endpoint: string | null): string | null {
  if (endpoint === null) return null;
  try {
    const url = new URL(endpoint);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return "[unparseable endpoint]";
  }
}

export interface ProviderUpdate {
  model?: string | null;
  endpoint?: string | null;
  apiKey?: string;
  clearKey?: boolean;
}

/**
 * Validates an UpdateProviderRequest. The key is checked here, before anything is saved, so a
 * rejected key never leaves a half-applied model/endpoint change behind.
 */
export function parseProviderUpdate(body: JsonObject): ProviderUpdate {
  const known = new Set(["model", "endpoint", "apiKey", "clearKey"]);
  for (const key of Object.keys(body)) {
    if (!known.has(key)) throw new HttpError(400, "invalid_request", `Unknown field '${key}'`);
  }
  const update: ProviderUpdate = {};
  const model = nullableString(body, "model", 200);
  if (model !== undefined) update.model = model;
  const endpoint = nullableString(body, "endpoint", 2048);
  if (endpoint !== undefined) update.endpoint = endpoint;
  const clearKey = optionalBoolean(body, "clearKey");
  if (clearKey !== undefined) update.clearKey = clearKey;
  const apiKey = body.apiKey;
  if (apiKey !== undefined && apiKey !== null && apiKey !== "") {
    if (typeof apiKey !== "string") throw new HttpError(400, "invalid_request", "'apiKey' must be a string");
    if (apiKey.length < 8 || apiKey.length > 512 || /\s/.test(apiKey)) {
      throw new HttpError(400, "invalid_api_key", "API keys must be 8-512 characters without whitespace");
    }
    if (update.clearKey) throw new HttpError(400, "invalid_request", "'apiKey' and 'clearKey' cannot be combined");
    update.apiKey = apiKey;
  }
  return update;
}

/**
 * AI provider configuration. Keys are write-only: responses carry only a masked suffix and the
 * audit chain records which fields changed, never the key itself.
 */
export function registerAiSettingsRoutes(router: Router, app: AppContext): void {
  router.get("/api/settings/ai", { auth: "session", permission: "read" }, () => json(aiSettingsView(app)));

  router.put("/api/settings/ai/providers/:provider", { auth: "session", permission: "settings:write", maxBodyBytes: 8 * 1024 }, async (ctx) => {
    const provider = providerParam(ctx);
    const update = parseProviderUpdate(await ctx.readJson());
    if (update.apiKey !== undefined && !PROVIDERS[provider].requiresKey) {
      throw new HttpError(400, "invalid_request", `${PROVIDERS[provider].label} does not use an API key`);
    }
    const details: Record<string, unknown> = {
      provider,
      fields: Object.keys(update).filter((field) => field !== "apiKey"),
      key: update.apiKey !== undefined ? "set" : update.clearKey ? "cleared" : "unchanged",
    };
    if (update.model !== undefined) details.model = update.model;
    if (update.endpoint !== undefined) details.endpoint = auditableEndpoint(update.endpoint);
    await audited(app, ctx.principal, { action: "ai_provider_updated", target: provider, details }, () =>
      app.llm.updateProvider(provider, update, ctx.principal.label),
    );
    return json(aiSettingsView(app));
  });

  router.put("/api/settings/ai/default", { auth: "session", permission: "settings:write", maxBodyBytes: 4 * 1024 }, async (ctx) => {
    const body = await ctx.readJson();
    const raw = body.provider;
    let requested: ProviderId | null;
    if (raw === null) requested = null;
    else if (isProviderId(raw)) requested = raw;
    else throw new HttpError(400, "invalid_request", `'provider' is required and must be null or one of: ${PROVIDER_IDS.join(", ")}`);
    await audited(app, ctx.principal, { action: "ai_default_provider_set", target: requested ?? "none", details: { provider: requested } }, () => {
      if (requested !== null) {
        const status = app.llm.status().providers.find((entry) => entry.id === requested);
        if (!status?.ready) {
          throw new HttpError(
            409,
            "provider_not_ready",
            `${PROVIDERS[requested].label} is not ready: configure a model${PROVIDERS[requested].requiresKey ? " and an API key" : ""} first`,
          );
        }
      }
      app.llm.setDefaultProvider(requested, ctx.principal.label);
    });
    return json(aiSettingsView(app));
  });

  router.post("/api/settings/ai/providers/:provider/models", { auth: "session", permission: "ai:test" }, async (ctx) => {
    const provider = providerParam(ctx);
    const result = await audited(
      app,
      ctx.principal,
      { action: "ai_provider_tested", target: provider, details: { provider, method: "list_models" } },
      () => app.llm.listModels(provider),
      (listed) => ({ modelCount: listed.models.length, latencyMs: listed.latencyMs }),
    );
    const body: ListModelsResponse = {
      provider,
      models: result.models.slice(0, MAX_LISTED_MODELS),
      latencyMs: result.latencyMs,
    };
    return json(body);
  });
}
