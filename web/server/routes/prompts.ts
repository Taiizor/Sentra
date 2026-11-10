import type { PromptView, PromptWorkflow, SkillDetailView, SkillSummaryView } from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { HttpError, json, type Router } from "../http.ts";
import { cliFailure, cliValue, type CliResult } from "../sentra-cli.ts";
import { oneOf, optionalStringArray } from "../validate.ts";
import { tenantParam } from "./helpers.ts";

export const SKILL_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const PROMPT_WORKFLOWS: readonly PromptWorkflow[] = ["scout", "threat-model", "api-bola", "patch-remediation", "skill-audit", "verify"];
const MAX_PROMPT_SKILLS = 10;
const SKILLS_CACHE_MS = 5 * 60_000;

const COMMON_NOTE =
  "The core does not read the workspace for this prompt: only the workspace path is interpolated as the scope. Review and replace the fixed context before sending the prompt to a model.";

/**
 * Context the core's `sentra prompt` command fills from fixed templates rather than from the
 * target (crates/sentra-cli/src/lib.rs, render_prompt). Surfaced with every prompt so the
 * operator knows which parts are placeholders.
 */
const TEMPLATE_FIELDS: Record<PromptWorkflow, string> = {
  scout: "The 'Tech Stack / Architecture' line is the fixed text 'General repository surface mapping and trust boundary analysis'.",
  "threat-model":
    "'Target Repository' is always '.', the 'System Context' is the fixed text 'Web application with database, cache, and authentication services', and the system prompt is the Scout persona.",
  "api-bola":
    "The endpoint method is always 'GET', the endpoint path is the workspace path, and the code snippet is a placeholder comment instead of a real route handler.",
  "patch-remediation":
    "The vulnerability is always 'Autonomous Remediation (CWE-89)', the file path is the workspace path, and the vulnerable code is a placeholder comment. The 'Three-Tier' tests and proofs it asks for are never executed by Sentra.",
  "skill-audit": "The skill name is the workspace path and the skill content is a placeholder comment instead of a real skill definition.",
  verify:
    "The reproduction test, the candidate diff and the 'isolated execution evidence' are placeholder comments; no execution happened. A model answering this prompt has nothing real to verify.",
};

export function templateWarning(workflow: PromptWorkflow): string {
  return `${TEMPLATE_FIELDS[workflow]} ${COMMON_NOTE}`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function invalidOutput(command: string): HttpError {
  return new HttpError(502, "core_invalid_output", `sentra ${command} returned an unexpected document`);
}

function skillSummary(value: unknown, command: string): SkillSummaryView {
  const record = asRecord(value);
  if (
    !record ||
    typeof record.id !== "string" ||
    typeof record.name !== "string" ||
    typeof record.category !== "string" ||
    typeof record.description !== "string"
  ) {
    throw invalidOutput(command);
  }
  const tags = Array.isArray(record.tags) ? record.tags.filter((tag): tag is string => typeof tag === "string") : [];
  return { id: record.id, name: record.name, category: record.category, description: record.description, tags };
}

/** `sentra skills list --json` prints a bare array (no schema_version envelope). */
export function parseSkillsList(output: unknown): SkillSummaryView[] {
  if (!Array.isArray(output)) throw invalidOutput("skills list");
  return output.map((entry) => skillSummary(entry, "skills list"));
}

export function parseSkillDetail(output: unknown): SkillDetailView {
  const record = asRecord(output);
  if (!record || typeof record.content !== "string") throw invalidOutput("skills show");
  return { ...skillSummary(record, "skills show"), content: record.content };
}

export function parsePromptOutput(output: unknown, workflow: PromptWorkflow): PromptView {
  const record = asRecord(output);
  if (
    !record ||
    typeof record.name !== "string" ||
    typeof record.role !== "string" ||
    typeof record.scope !== "string" ||
    typeof record.system_prompt !== "string" ||
    typeof record.user_prompt !== "string" ||
    typeof record.composite_prompt !== "string"
  ) {
    throw invalidOutput("prompt");
  }
  return {
    workflow,
    name: record.name,
    role: record.role,
    scope: record.scope,
    skills: Array.isArray(record.skills) ? record.skills.filter((skill): skill is string => typeof skill === "string") : [],
    systemPrompt: record.system_prompt,
    userPrompt: record.user_prompt,
    compositePrompt: record.composite_prompt,
    expectedSchema: typeof record.expected_schema === "string" ? record.expected_schema : null,
    templateWarning: templateWarning(workflow),
  };
}

function coreError(result: CliResult): string | null {
  for (const stream of [result.stderr, result.stdout]) {
    const trimmed = stream.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const parsed = asRecord(JSON.parse(trimmed));
      if (parsed && typeof parsed.error === "string") return parsed.error;
    } catch {
      // not JSON
    }
  }
  return null;
}

/**
 * Built-in AppSec skills (embedded in the core binary) and the core's prompt templates.
 * Prompt generation only renders text; it does not call a model and changes no state.
 */
export function registerPromptRoutes(router: Router, app: AppContext): void {
  // Skills are compiled into the binary, so a short cache keyed by the binary path is exact.
  let skillsCache: { binary: string; at: number; skills: SkillSummaryView[] } | null = null;

  async function listSkills(): Promise<SkillSummaryView[]> {
    const binary = app.cli.binaryPath;
    if (skillsCache && skillsCache.binary === binary && Date.now() - skillsCache.at < SKILLS_CACHE_MS) return skillsCache.skills;
    // Concurrent cache misses share one core run.
    const result = await app.cli.runShared(["skills", "list", "--json"], { ttlMs: 0, timeoutMs: 30_000 });
    if (result.timedOut) throw new HttpError(504, "core_timeout", "sentra skills list timed out");
    if (result.code !== 0 || result.json === undefined) throw cliFailure("skills list", result);
    const skills = parseSkillsList(result.json);
    skillsCache = { binary, at: Date.now(), skills };
    return skills;
  }

  router.get("/api/skills", { auth: "session", permission: "read" }, async () => {
    const body: { skills: SkillSummaryView[] } = { skills: await listSkills() };
    return json(body);
  });

  router.get("/api/skills/:skillId", { auth: "session", permission: "read" }, async (ctx) => {
    const skillId = ctx.params.skillId;
    if (!skillId || !SKILL_ID_RE.test(skillId)) throw new HttpError(400, "invalid_request", "Invalid skill id");
    // Unknown ids are answered from the cached listing, so arbitrary ids cannot each start a core run.
    if (!(await listSkills()).some((skill) => skill.id === skillId)) {
      throw new HttpError(404, "skill_not_found", `Skill '${skillId}' does not exist`);
    }
    const result = await app.cli.runShared(["skills", "show", cliValue(skillId, "skillId"), "--json"], {
      ttlMs: SKILLS_CACHE_MS,
      timeoutMs: 30_000,
      signal: ctx.req.signal,
    });
    if (result.timedOut) throw new HttpError(504, "core_timeout", "sentra skills show timed out");
    if (result.code !== 0 || result.json === undefined) {
      if (coreError(result) === "skill_not_found") throw new HttpError(404, "skill_not_found", `Skill '${skillId}' does not exist`);
      throw cliFailure("skills show", result);
    }
    return json(parseSkillDetail(result.json));
  });

  router.post("/api/tenants/:tenantId/prompts", { auth: "session", permission: "prompt:generate", maxBodyBytes: 8 * 1024 }, async (ctx) => {
    const tenant = tenantParam(app, ctx);
    const body = await ctx.readJson();
    const workflow = oneOf(body.workflow, "workflow", PROMPT_WORKFLOWS);
    const requested = optionalStringArray(body, "skills", { maxItems: MAX_PROMPT_SKILLS, max: 64, pattern: SKILL_ID_RE }) ?? [];
    const skills = [...new Set(requested)];
    if (skills.length > 0) {
      const known = new Set((await listSkills()).map((skill) => skill.id));
      const unknown = skills.filter((id) => !known.has(id));
      if (unknown.length > 0) throw new HttpError(400, "unknown_skill", `Unknown skill id(s): ${unknown.join(", ")}`);
    }
    const workspace = app.workspaces.workspaceRoot(tenant);
    const args = ["prompt", workflow, "--scope", cliValue(workspace, "workspace")];
    if (skills.length > 0) args.push("--skills", cliValue(skills.join(","), "skills"));
    args.push("--json");
    const result = await app.cli.run(args, { timeoutMs: 30_000 });
    if (result.timedOut) throw new HttpError(504, "core_timeout", "sentra prompt timed out");
    if (result.code !== 0 || result.json === undefined) throw cliFailure("prompt", result);
    return json(parsePromptOutput(result.json, workflow));
  });
}
