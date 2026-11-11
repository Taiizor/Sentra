import type { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AiSettingsView, PromptView, SkillSummaryView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { AuditLog } from "../audit-log.ts";
import { openWebDb } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { Router, type AuthedContext, type Principal } from "../http.ts";
import { LlmGateway } from "../llm.ts";
import { auditableEndpoint, parseProviderUpdate, registerAiSettingsRoutes } from "../routes/ai-settings.ts";
import { parsePromptOutput, parseSkillDetail, parseSkillsList, PROMPT_WORKFLOWS, registerPromptRoutes, templateWarning } from "../routes/prompts.ts";
import { SecretStore } from "../secrets.ts";
import type { CliResult } from "../sentra-cli.ts";
import type { JsonObject } from "../validate.ts";

const TEST_ROOT = fs.mkdtempSync(path.join(process.env.SENTRA_TEST_TMPDIR ?? os.tmpdir(), "sentra-ai-settings-test-"));
const openDatabases: Database[] = [];
afterAll(() => {
  for (const db of openDatabases) db.close();
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

const ADMIN: Principal = { role: "admin", label: "alice", via: "bearer" };
const API_KEY = "sk-test-0123456789abcdefWXYZ";

function httpError(fn: () => unknown): HttpError {
  try {
    fn();
  } catch (error) {
    if (error instanceof HttpError) return error;
    throw error;
  }
  throw new Error("expected an HttpError");
}

async function call(router: Router, method: string, pathname: string, body?: JsonObject): Promise<{ status: number; body: any }> {
  const matched = router.match(method, pathname);
  if (matched === null || matched === "method_not_allowed") throw new Error(`no route for ${method} ${pathname}`);
  const url = new URL(`http://127.0.0.1${pathname}`);
  const ctx: AuthedContext = {
    req: new Request(url, { method }),
    url,
    params: matched.params,
    principal: ADMIN,
    ip: "127.0.0.1",
    readJson: async () => body ?? {},
    readText: async () => JSON.stringify(body ?? {}),
  };
  try {
    const response = await matched.route.handler(ctx);
    return { status: response.status, body: await response.json() };
  } catch (error) {
    if (error instanceof HttpError) return { status: error.status, body: { error: { code: error.code, message: error.message } } };
    throw error;
  }
}

function settingsHarness() {
  const dir = fs.mkdtempSync(path.join(TEST_ROOT, "data-"));
  const db = openWebDb(path.join(dir, "web.db"));
  openDatabases.push(db);
  const key = crypto.randomBytes(32);
  const audit = new AuditLog(db, key);
  const llm = new LlmGateway(db, new SecretStore(db, key));
  const router = new Router();
  registerAiSettingsRoutes(router, { llm, audit } as unknown as AppContext);
  return { db, audit, llm, router };
}

describe("provider update parsing", () => {
  test("accepts partial updates and nulls", () => {
    expect(parseProviderUpdate({ model: " gpt-4.1 ", endpoint: null })).toEqual({ model: "gpt-4.1", endpoint: null });
    expect(parseProviderUpdate({ model: "" })).toEqual({ model: null });
    expect(parseProviderUpdate({ apiKey: API_KEY })).toEqual({ apiKey: API_KEY });
    expect(parseProviderUpdate({ clearKey: true })).toEqual({ clearKey: true });
  });

  test("rejects unknown fields, bad keys and contradictory requests before anything is saved", () => {
    expect(httpError(() => parseProviderUpdate({ provider: "openai" })).status).toBe(400);
    expect(httpError(() => parseProviderUpdate({ apiKey: "short" })).code).toBe("invalid_api_key");
    expect(httpError(() => parseProviderUpdate({ apiKey: "has whitespace inside" })).code).toBe("invalid_api_key");
    expect(httpError(() => parseProviderUpdate({ apiKey: API_KEY, clearKey: true })).status).toBe(400);
    expect(httpError(() => parseProviderUpdate({ model: 5 })).status).toBe(400);
    expect(httpError(() => parseProviderUpdate({ clearKey: "yes" })).status).toBe(400);
  });

  test("endpoints are audited without query strings", () => {
    expect(auditableEndpoint("https://example.com/v1?key=secret")).toBe("https://example.com/v1");
    expect(auditableEndpoint(null)).toBeNull();
    expect(auditableEndpoint("not a url")).toBe("[unparseable endpoint]");
  });
});

describe("AI settings routes", () => {
  test("declare the expected permissions", () => {
    const { router } = settingsHarness();
    expect(Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]))).toEqual({
      "GET /api/settings/ai": "read",
      "PUT /api/settings/ai/providers/:provider": "settings:write",
      "PUT /api/settings/ai/default": "settings:write",
      "POST /api/settings/ai/providers/:provider/models": "ai:test",
    });
  });

  test("stores keys write-only and never writes them to the audit chain", async () => {
    const { router, db } = settingsHarness();
    const updated = await call(router, "PUT", "/api/settings/ai/providers/openai", { model: "gpt-test", apiKey: API_KEY });
    expect(updated.status).toBe(200);
    const view = updated.body as AiSettingsView;
    const openai = view.providers.find((provider) => provider.id === "openai");
    expect(openai).toMatchObject({ model: "gpt-test", keyConfigured: true, ready: true, maskedKey: "••••••••WXYZ" });
    expect(JSON.stringify(view)).not.toContain(API_KEY);

    const fetched = await call(router, "GET", "/api/settings/ai");
    expect(JSON.stringify(fetched.body)).not.toContain(API_KEY);

    const rows = db.query("SELECT action, outcome, details_json FROM audit_log").all() as { action: string; outcome: string; details_json: string }[];
    expect(rows).toHaveLength(1);
    expect(rows[0].action).toBe("ai_provider_updated");
    expect(rows[0].details_json).not.toContain(API_KEY);
    expect(JSON.parse(rows[0].details_json)).toMatchObject({ provider: "openai", key: "set", model: "gpt-test" });

    const cleared = await call(router, "PUT", "/api/settings/ai/providers/openai", { clearKey: true });
    expect((cleared.body as AiSettingsView).providers.find((provider) => provider.id === "openai")?.keyConfigured).toBe(false);
  });

  test("a rejected key leaves the stored settings untouched", async () => {
    const { router, llm } = settingsHarness();
    const response = await call(router, "PUT", "/api/settings/ai/providers/openai", { model: "gpt-test", apiKey: "bad key" });
    expect(response.status).toBe(400);
    expect(llm.settings().providers.openai).toBeUndefined();
  });

  test("rejects unknown providers and keys for providers without keys", async () => {
    const { router } = settingsHarness();
    expect((await call(router, "PUT", "/api/settings/ai/providers/nope", { model: "x" })).status).toBe(404);
    expect((await call(router, "PUT", "/api/settings/ai/providers/local", { apiKey: API_KEY })).status).toBe(400);
  });

  test("the default provider must be ready (or null)", async () => {
    const { router, db } = settingsHarness();
    const notReady = await call(router, "PUT", "/api/settings/ai/default", { provider: "anthropic" });
    expect(notReady.status).toBe(409);
    expect(notReady.body.error.code).toBe("provider_not_ready");
    expect((await call(router, "PUT", "/api/settings/ai/default", { provider: "bogus" })).status).toBe(400);
    expect((await call(router, "PUT", "/api/settings/ai/default", {})).status).toBe(400);

    await call(router, "PUT", "/api/settings/ai/providers/openai", { model: "gpt-test", apiKey: API_KEY });
    const ready = await call(router, "PUT", "/api/settings/ai/default", { provider: "openai" });
    expect(ready.status).toBe(200);
    expect((ready.body as AiSettingsView).defaultProvider).toBe("openai");
    const reset = await call(router, "PUT", "/api/settings/ai/default", { provider: null });
    expect((reset.body as AiSettingsView).defaultProvider).toBeNull();

    const outcomes = (db.query("SELECT action, outcome FROM audit_log WHERE action = 'ai_default_provider_set' ORDER BY seq").all() as {
      outcome: string;
    }[]).map((row) => row.outcome);
    expect(outcomes).toEqual(["failure", "success", "success"]);
  });

  test("listing models without a key fails with 412 and is audited as a failed provider test", async () => {
    const { router, db } = settingsHarness();
    const response = await call(router, "POST", "/api/settings/ai/providers/anthropic/models");
    expect(response.status).toBe(412);
    expect(response.body.error.code).toBe("ai_not_configured");
    const row = db.query("SELECT action, outcome, target FROM audit_log").get() as { action: string; outcome: string; target: string };
    expect(row).toEqual({ action: "ai_provider_tested", outcome: "failure", target: "anthropic" });
  });

  test("a generation request without any configured provider fails with 412", () => {
    const { llm } = settingsHarness();
    expect(httpError(() => llm.resolve(null)).status).toBe(412);
    expect(httpError(() => llm.resolve("openai")).code).toBe("ai_not_configured");
  });
});

// ───────────────────────────── skills and prompts ─────────────────────────────

const SKILLS_OUTPUT = [
  {
    category: "api-security",
    description: "Security-test REST APIs.",
    id: "api-security-testing",
    name: "API Security Testing",
    tags: ["api", "owasp"],
  },
  { category: "secrets", description: "Find secrets.", id: "secret-scanning", name: "Secret Scanning", tags: [] },
];
const SKILLS_LIST_OUTPUT = { schema_version: 1, command: "skills list", count: SKILLS_OUTPUT.length, skills: SKILLS_OUTPUT };

describe("skills and prompt parsing", () => {
  test("parses the skills list envelope and skill details", () => {
    const skills = parseSkillsList(SKILLS_LIST_OUTPUT);
    expect(skills.map((skill) => skill.id)).toEqual(["api-security-testing", "secret-scanning"]);
    expect(skills[0].tags).toEqual(["api", "owasp"]);
    expect(parseSkillDetail({ ...SKILLS_OUTPUT[0], content: "# Skill" }).content).toBe("# Skill");
    expect(httpError(() => parseSkillsList(SKILLS_OUTPUT)).code).toBe("core_invalid_output");
    expect(httpError(() => parseSkillsList({ skills: [] })).code).toBe("core_invalid_output");
    expect(httpError(() => parseSkillsList({ schema_version: 1, skills: [{ id: 1 }] })).code).toBe("core_invalid_output");
    expect(httpError(() => parseSkillDetail(SKILLS_OUTPUT[0])).code).toBe("core_invalid_output");
  });

  test("every workflow carries a template warning naming its fixed context", () => {
    for (const workflow of PROMPT_WORKFLOWS) {
      expect(templateWarning(workflow)).toContain("does not read the workspace");
    }
    expect(templateWarning("patch-remediation")).toContain("CWE-89");
    expect(templateWarning("threat-model")).toContain("Web application with database, cache, and authentication services");
    expect(templateWarning("api-bola")).toContain("'GET'");
    expect(templateWarning("verify")).toContain("placeholder");
    expect(templateWarning("scout")).toContain("General repository surface mapping");
    expect(templateWarning("skill-audit")).toContain("placeholder");
  });

  test("maps the core prompt document", () => {
    const view = parsePromptOutput(
      {
        command: "prompt",
        composite_prompt: "SYSTEM:\nS\n\nUSER:\nU",
        expected_schema: null,
        name: "Surface Reconnaissance (Scout)",
        role: "scout",
        schema_version: 1,
        scope: "/ws",
        skills: [],
        system_prompt: "S",
        user_prompt: "U",
        workflow: "scout",
      },
      "scout",
    );
    expect(view).toMatchObject({ workflow: "scout", systemPrompt: "S", userPrompt: "U", expectedSchema: null, skills: [] });
    expect(view.templateWarning).toContain("General repository surface mapping");
    expect(httpError(() => parsePromptOutput({ name: "x" }, "scout")).code).toBe("core_invalid_output");
  });
});

describe("skills and prompt routes", () => {
  function promptHarness() {
    const workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(TEST_ROOT, "ws-")));
    const calls: string[][] = [];
    const tenant = { tenantId: "acme", workspace };
    const result = (json: unknown, code = 0): CliResult => ({
      code,
      stdout: JSON.stringify(json),
      stderr: "",
      json: code === 0 ? json : undefined,
      timedOut: false,
      durationMs: 1,
    });
    const cli = {
      binaryPath: "/fake/sentra",
      async run(args: string[]): Promise<CliResult> {
        calls.push(args);
        if (args[0] === "skills" && args[1] === "list") return result(SKILLS_LIST_OUTPUT);
        if (args[0] === "skills" && args[1] === "show") {
          const skill = SKILLS_OUTPUT.find((entry) => entry.id === args[2]);
          if (!skill) return { ...result({ schema_version: 1, error: "skill_not_found" }, 7) };
          return result({ ...skill, content: "# body" });
        }
        if (args[0] === "prompt") {
          return result({
            composite_prompt: "C",
            expected_schema: "{}",
            name: "N",
            role: "analyst",
            scope: args[3],
            skills: args.includes("--skills") ? args[args.indexOf("--skills") + 1].split(",") : [],
            system_prompt: "S",
            user_prompt: "U",
            workflow: args[1],
          });
        }
        return result({ error: "invalid_arguments" }, 2);
      },
      async runShared(args: string[]): Promise<CliResult> {
        return this.run(args);
      },
    };
    const workspaces = {
      get: (id: string) => {
        if (id !== "acme") throw new HttpError(404, "tenant_not_found", "no");
        return tenant;
      },
      workspaceRoot: () => workspace,
    };
    const router = new Router();
    registerPromptRoutes(router, { cli, workspaces } as unknown as AppContext);
    return { router, calls, workspace };
  }

  test("declare the expected permissions", () => {
    const { router } = promptHarness();
    expect(Object.fromEntries(router.list().map((route) => [`${route.method} ${route.path}`, route.options.permission]))).toEqual({
      "GET /api/skills": "read",
      "GET /api/skills/:skillId": "read",
      "POST /api/tenants/:tenantId/prompts": "prompt:generate",
    });
  });

  test("lists skills once (cached) and maps skill_not_found to 404", async () => {
    const { router, calls } = promptHarness();
    const first = await call(router, "GET", "/api/skills");
    await call(router, "GET", "/api/skills");
    expect((first.body.skills as SkillSummaryView[]).length).toBe(2);
    expect(calls.filter((args) => args[1] === "list")).toHaveLength(1);
    expect((await call(router, "GET", "/api/skills/api-security-testing")).body.content).toBe("# body");
    expect((await call(router, "GET", "/api/skills/unknown-skill")).status).toBe(404);
    expect((await call(router, "GET", "/api/skills/Bad_Id")).status).toBe(400);
    // Unknown ids are answered from the cached listing without starting a core process.
    expect(calls.filter((args) => args[1] === "show").map((args) => args[2])).toEqual(["api-security-testing"]);
  });

  test("renders prompts for the tenant workspace and validates skills", async () => {
    const { router, calls, workspace } = promptHarness();
    const response = await call(router, "POST", "/api/tenants/acme/prompts", { workflow: "api-bola", skills: ["api-security-testing"] });
    expect(response.status).toBe(200);
    const view = response.body as PromptView;
    expect(view.workflow).toBe("api-bola");
    expect(view.scope).toBe(workspace);
    expect(view.skills).toEqual(["api-security-testing"]);
    expect(view.templateWarning).toContain("'GET'");
    expect(calls.find((args) => args[0] === "prompt")).toEqual(["prompt", "api-bola", "--scope", workspace, "--skills", "api-security-testing", "--json"]);

    const unknown = await call(router, "POST", "/api/tenants/acme/prompts", { workflow: "scout", skills: ["does-not-exist"] });
    expect(unknown.status).toBe(400);
    expect(unknown.body.error.code).toBe("unknown_skill");
    expect((await call(router, "POST", "/api/tenants/acme/prompts", { workflow: "nope" })).status).toBe(400);
    expect((await call(router, "POST", "/api/tenants/acme/prompts", { workflow: "scout", skills: ["--evil"] })).status).toBe(400);
  });
});
