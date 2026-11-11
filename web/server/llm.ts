import type { Database } from "bun:sqlite";
import { nowIso, parseJsonColumn } from "./db.ts";
import { HttpError } from "./http-error.ts";
import { assertSafeOutboundUrl, fetchWithLimits } from "./net-guard.ts";
import type { SecretStore } from "./secrets.ts";
import { maskSecret } from "./secrets.ts";

/**
 * Model provider gateway for the bridge. Model output is always treated as an unverified
 * candidate: nothing returned here is ever labelled verified, and there is no canned
 * fallback when a provider is missing or fails.
 */

export const PROVIDER_IDS = ["anthropic", "openai", "gemini", "deepseek", "xai", "openrouter", "opencode", "local"] as const;
export type ProviderId = (typeof PROVIDER_IDS)[number];

interface ProviderSpec {
  label: string;
  protocol: "anthropic" | "openai" | "gemini";
  defaultEndpoint: string;
  requiresKey: boolean;
  /** Only loopback endpoints are accepted (local runtimes such as Ollama or LM Studio). */
  loopbackOnly: boolean;
  /** Whether operators may point the provider at a different (public HTTPS) endpoint. */
  customEndpoint: boolean;
}

export const PROVIDERS: Record<ProviderId, ProviderSpec> = {
  anthropic: { label: "Anthropic", protocol: "anthropic", defaultEndpoint: "https://api.anthropic.com/v1", requiresKey: true, loopbackOnly: false, customEndpoint: false },
  openai: { label: "OpenAI", protocol: "openai", defaultEndpoint: "https://api.openai.com/v1", requiresKey: true, loopbackOnly: false, customEndpoint: true },
  gemini: { label: "Google Gemini", protocol: "gemini", defaultEndpoint: "https://generativelanguage.googleapis.com/v1beta", requiresKey: true, loopbackOnly: false, customEndpoint: false },
  deepseek: { label: "DeepSeek", protocol: "openai", defaultEndpoint: "https://api.deepseek.com", requiresKey: true, loopbackOnly: false, customEndpoint: false },
  xai: { label: "xAI", protocol: "openai", defaultEndpoint: "https://api.x.ai/v1", requiresKey: true, loopbackOnly: false, customEndpoint: false },
  openrouter: { label: "OpenRouter", protocol: "openai", defaultEndpoint: "https://openrouter.ai/api/v1", requiresKey: true, loopbackOnly: false, customEndpoint: false },
  opencode: { label: "OpenCode Zen", protocol: "openai", defaultEndpoint: "https://opencode.ai/zen/v1", requiresKey: true, loopbackOnly: false, customEndpoint: false },
  local: { label: "Local (OpenAI-compatible, loopback only)", protocol: "openai", defaultEndpoint: "http://127.0.0.1:11434/v1", requiresKey: false, loopbackOnly: true, customEndpoint: true },
};

export function isProviderId(value: unknown): value is ProviderId {
  return typeof value === "string" && (PROVIDER_IDS as readonly string[]).includes(value);
}

export interface ProviderSettings {
  model: string | null;
  endpoint: string | null;
}

export interface AiSettings {
  defaultProvider: ProviderId | null;
  providers: Partial<Record<ProviderId, ProviderSettings>>;
  updatedAt: string | null;
  updatedBy: string | null;
}

export interface ProviderStatusView {
  id: ProviderId;
  label: string;
  model: string | null;
  endpoint: string;
  usesCustomEndpoint: boolean;
  requiresKey: boolean;
  keyConfigured: boolean;
  maskedKey: string | null;
  keyUpdatedAt: string | null;
  ready: boolean;
  customEndpointAllowed: boolean;
  loopbackOnly: boolean;
}

const SETTINGS_KEY = "ai.settings";
const keySecretName = (provider: ProviderId) => `ai.key.${provider}`;

export interface CompletionRequest {
  system: string;
  user: string;
  maxTokens: number;
  expectJson: boolean;
}

export interface CompletionResult {
  provider: ProviderId;
  model: string;
  text: string;
  latencyMs: number;
  inputTokens: number | null;
  outputTokens: number | null;
}

export class LlmGateway {
  private readonly db: Database;
  private readonly secrets: SecretStore;

  constructor(db: Database, secrets: SecretStore) {
    this.db = db;
    this.secrets = secrets;
  }

  settings(): AiSettings {
    const row = this.db.query("SELECT value_json, updated_at, updated_by FROM settings WHERE key = ?").get(SETTINGS_KEY) as {
      value_json: string;
      updated_at: string;
      updated_by: string;
    } | null;
    const parsed = parseJsonColumn<{ defaultProvider?: unknown; providers?: Record<string, ProviderSettings> }>(row?.value_json, {});
    const providers: AiSettings["providers"] = {};
    for (const [id, value] of Object.entries(parsed.providers ?? {})) {
      if (isProviderId(id)) providers[id] = { model: value.model ?? null, endpoint: value.endpoint ?? null };
    }
    return {
      defaultProvider: isProviderId(parsed.defaultProvider) ? parsed.defaultProvider : null,
      providers,
      updatedAt: row?.updated_at ?? null,
      updatedBy: row?.updated_by ?? null,
    };
  }

  private saveSettings(next: AiSettings, actor: string): void {
    this.db
      .query(
        `INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      )
      .run(SETTINGS_KEY, JSON.stringify({ defaultProvider: next.defaultProvider, providers: next.providers }), nowIso(), actor);
  }

  async updateProvider(
    provider: ProviderId,
    update: { model?: string | null; endpoint?: string | null; apiKey?: string | null; clearKey?: boolean },
    actor: string,
  ): Promise<void> {
    const spec = PROVIDERS[provider];
    // Validate every input before anything is persisted, so a rejected key never leaves a
    // half-applied update behind.
    if (!update.clearKey && update.apiKey) {
      if (update.apiKey.length < 8 || update.apiKey.length > 512 || /\s/.test(update.apiKey)) {
        throw new HttpError(400, "invalid_api_key", "API keys must be 8-512 characters without whitespace");
      }
    }
    const current = this.settings();
    const existing = current.providers[provider] ?? { model: null, endpoint: null };
    let endpoint = existing.endpoint;
    if (update.endpoint !== undefined) {
      if (update.endpoint === null || update.endpoint === "") {
        endpoint = null;
      } else {
        if (!spec.customEndpoint) {
          throw new HttpError(400, "invalid_endpoint", `${spec.label} does not support a custom endpoint`);
        }
        const url = await assertSafeOutboundUrl(update.endpoint, { allowLoopback: spec.loopbackOnly, allowHttp: spec.loopbackOnly });
        if (url.search || url.hash) {
          // A credential pasted into a query string would otherwise be stored and displayed.
          throw new HttpError(400, "invalid_endpoint", "Endpoints must not contain a query string or fragment");
        }
        if (spec.loopbackOnly && !["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)) {
          throw new HttpError(400, "invalid_endpoint", "Local provider endpoints must use 127.0.0.1, localhost or [::1]");
        }
        endpoint = url.toString().replace(/\/+$/, "");
      }
    }
    const model = update.model !== undefined ? update.model || null : existing.model;
    if (model !== null && !/^[A-Za-z0-9._:/@+-]{1,200}$/.test(model)) {
      throw new HttpError(400, "invalid_model", "Model identifiers may contain letters, digits and . _ : / @ + -");
    }
    current.providers[provider] = { model, endpoint };
    this.saveSettings(current, actor);
    if (update.clearKey) {
      this.secrets.delete(keySecretName(provider));
    } else if (update.apiKey) {
      if (update.apiKey.length < 8 || update.apiKey.length > 512 || /\s/.test(update.apiKey)) {
        throw new HttpError(400, "invalid_api_key", "API keys must be 8-512 characters without whitespace");
      }
      this.secrets.set(keySecretName(provider), update.apiKey, actor);
    }
  }

  setDefaultProvider(provider: ProviderId | null, actor: string): void {
    const current = this.settings();
    current.defaultProvider = provider;
    this.saveSettings(current, actor);
  }

  status(): { defaultProvider: ProviderId | null; providers: ProviderStatusView[]; updatedAt: string | null; updatedBy: string | null } {
    const settings = this.settings();
    const providers = PROVIDER_IDS.map((id): ProviderStatusView => {
      const spec = PROVIDERS[id];
      const configured = settings.providers[id];
      const key = spec.requiresKey ? this.secrets.get(keySecretName(id)) : null;
      const model = configured?.model ?? null;
      return {
        id,
        label: spec.label,
        model,
        endpoint: configured?.endpoint ?? spec.defaultEndpoint,
        usesCustomEndpoint: !!configured?.endpoint,
        requiresKey: spec.requiresKey,
        keyConfigured: !!key,
        maskedKey: key ? maskSecret(key) : null,
        keyUpdatedAt: this.secrets.meta(keySecretName(id))?.updatedAt ?? null,
        ready: !!model && (!spec.requiresKey || !!key),
        customEndpointAllowed: spec.customEndpoint,
        loopbackOnly: spec.loopbackOnly,
      };
    });
    return { defaultProvider: settings.defaultProvider, providers, updatedAt: settings.updatedAt, updatedBy: settings.updatedBy };
  }

  /** Resolves the provider to use, failing with 412 when nothing usable is configured. */
  resolve(requested?: ProviderId | null): { provider: ProviderId; model: string; endpoint: string; apiKey: string | null } {
    const settings = this.settings();
    const provider = requested ?? settings.defaultProvider;
    if (!provider) {
      throw new HttpError(412, "ai_not_configured", "No AI provider is configured. An admin can configure one under Settings → AI providers.");
    }
    const spec = PROVIDERS[provider];
    const configured = settings.providers[provider];
    if (!configured?.model) {
      throw new HttpError(412, "ai_not_configured", `${spec.label} has no model configured.`);
    }
    const apiKey = spec.requiresKey ? this.secrets.get(keySecretName(provider)) : null;
    if (spec.requiresKey && !apiKey) {
      throw new HttpError(412, "ai_not_configured", `${spec.label} has no API key configured.`);
    }
    return { provider, model: configured.model, endpoint: configured.endpoint ?? spec.defaultEndpoint, apiKey };
  }

  private async guard(provider: ProviderId, endpoint: string): Promise<void> {
    const spec = PROVIDERS[provider];
    await assertSafeOutboundUrl(endpoint, { allowLoopback: spec.loopbackOnly, allowHttp: spec.loopbackOnly });
  }

  /** Lists models from the provider's own catalog endpoint (validates connectivity and key). */
  async listModels(provider: ProviderId): Promise<{ models: string[]; latencyMs: number }> {
    const spec = PROVIDERS[provider];
    const configured = this.settings().providers[provider];
    const endpoint = configured?.endpoint ?? spec.defaultEndpoint;
    const apiKey = spec.requiresKey ? this.secrets.get(keySecretName(provider)) : null;
    if (spec.requiresKey && !apiKey) {
      throw new HttpError(412, "ai_not_configured", `${spec.label} has no API key configured.`);
    }
    await this.guard(provider, endpoint);
    const started = performance.now();
    let url: string;
    const headers: Record<string, string> = { "User-Agent": "sentra-web-bridge" };
    if (spec.protocol === "anthropic") {
      url = `${endpoint}/models?limit=1000`;
      headers["x-api-key"] = apiKey ?? "";
      headers["anthropic-version"] = "2023-06-01";
    } else if (spec.protocol === "gemini") {
      url = `${endpoint}/models?pageSize=1000`;
      headers["x-goog-api-key"] = apiKey ?? "";
    } else {
      url = `${endpoint}/models`;
      if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    }
    const response = await fetchWithLimits(url, { headers, timeoutMs: 20_000, maxResponseBytes: 16 * 1024 * 1024 });
    const latencyMs = Math.round(performance.now() - started);
    if (!response.ok) {
      throw new HttpError(502, "ai_provider_error", `${spec.label} rejected the request (HTTP ${response.status}): ${providerMessage(response.text)}`);
    }
    const parsed = JSON.parse(response.text) as { data?: { id: string }[]; models?: { name: string }[] };
    const models = spec.protocol === "gemini"
      ? (parsed.models ?? []).map((model) => model.name.replace(/^models\//, ""))
      : (parsed.data ?? []).map((model) => model.id);
    return { models: models.filter((id) => typeof id === "string").sort(), latencyMs };
  }

  async complete(request: CompletionRequest, requested?: ProviderId | null): Promise<CompletionResult> {
    const target = this.resolve(requested);
    const spec = PROVIDERS[target.provider];
    await this.guard(target.provider, target.endpoint);
    const started = performance.now();
    let url: string;
    let body: unknown;
    const headers: Record<string, string> = { "Content-Type": "application/json", "User-Agent": "sentra-web-bridge" };
    if (spec.protocol === "anthropic") {
      url = `${target.endpoint}/messages`;
      headers["x-api-key"] = target.apiKey ?? "";
      headers["anthropic-version"] = "2023-06-01";
      body = {
        model: target.model,
        max_tokens: request.maxTokens,
        system: request.system,
        messages: [{ role: "user", content: request.user }],
      };
    } else if (spec.protocol === "gemini") {
      url = `${target.endpoint}/models/${encodeURIComponent(target.model)}:generateContent`;
      headers["x-goog-api-key"] = target.apiKey ?? "";
      body = {
        systemInstruction: { parts: [{ text: request.system }] },
        contents: [{ role: "user", parts: [{ text: request.user }] }],
        generationConfig: { maxOutputTokens: request.maxTokens, ...(request.expectJson ? { responseMimeType: "application/json" } : {}) },
      };
    } else {
      url = `${target.endpoint}/chat/completions`;
      if (target.apiKey) headers.Authorization = `Bearer ${target.apiKey}`;
      if (target.provider === "openrouter") headers["X-Title"] = "Sentra";
      body = {
        model: target.model,
        messages: [
          { role: "system", content: request.system },
          { role: "user", content: request.user },
        ],
      };
    }
    const response = await fetchWithLimits(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      timeoutMs: 180_000,
      maxResponseBytes: 8 * 1024 * 1024,
    });
    const latencyMs = Math.round(performance.now() - started);
    if (!response.ok) {
      throw new HttpError(502, "ai_provider_error", `${spec.label} returned HTTP ${response.status}: ${providerMessage(response.text)}`);
    }
    let parsed: any;
    try {
      parsed = JSON.parse(response.text);
    } catch {
      throw new HttpError(502, "ai_provider_error", `${spec.label} returned a non-JSON response`);
    }
    let text = "";
    let inputTokens: number | null = null;
    let outputTokens: number | null = null;
    if (spec.protocol === "anthropic") {
      text = (parsed.content ?? []).filter((block: any) => block?.type === "text").map((block: any) => block.text).join("");
      inputTokens = parsed.usage?.input_tokens ?? null;
      outputTokens = parsed.usage?.output_tokens ?? null;
      if (parsed.stop_reason === "max_tokens") {
        throw new HttpError(502, "ai_output_truncated", "The model response was truncated (max_tokens reached)");
      }
    } else if (spec.protocol === "gemini") {
      text = (parsed.candidates?.[0]?.content?.parts ?? []).map((part: any) => part?.text ?? "").join("");
      inputTokens = parsed.usageMetadata?.promptTokenCount ?? null;
      outputTokens = parsed.usageMetadata?.candidatesTokenCount ?? null;
    } else {
      text = parsed.choices?.[0]?.message?.content ?? "";
      inputTokens = parsed.usage?.prompt_tokens ?? null;
      outputTokens = parsed.usage?.completion_tokens ?? null;
      if (parsed.choices?.[0]?.finish_reason === "length") {
        throw new HttpError(502, "ai_output_truncated", "The model response was truncated (length limit reached)");
      }
    }
    if (!text.trim()) {
      throw new HttpError(502, "ai_empty_response", `${spec.label} returned an empty response`);
    }
    return { provider: target.provider, model: target.model, text, latencyMs, inputTokens, outputTokens };
  }
}

function providerMessage(text: string): string {
  try {
    const parsed = JSON.parse(text) as { error?: { message?: string } | string; message?: string };
    const message = typeof parsed.error === "string" ? parsed.error : parsed.error?.message ?? parsed.message;
    if (message) return message.slice(0, 300);
  } catch {
    // fall through
  }
  return text.slice(0, 200) || "no details";
}

/** Extracts the first JSON object from model output (handles fenced code blocks). */
export function extractJsonObject(raw: string): Record<string, unknown> {
  let text = raw.trim();
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) text = fenced[1].trim();
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch {
    // try the outermost braces next
  }
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const parsed = JSON.parse(text.slice(start, end + 1));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      // fall through
    }
  }
  throw new HttpError(502, "ai_invalid_output", "The model did not return the requested JSON object");
}
