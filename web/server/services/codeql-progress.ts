import type { CodeqlProgressEventKind, CodeqlProgressStep, CodeqlProgressView, CodeqlSuite } from "../../src/types/api.ts";
import { sanitizeCoreMessage } from "../sentra-cli.ts";

/**
 * Progress events of `sentra codeql analyze|packs --progress`: one JSON object per stderr line,
 * each with `"progress": true` (the final error document has no such member):
 *
 *   {"progress":true,"event":"step_started"|"step_finished"|"step_failed"|"heartbeat"|"language_skipped",
 *    "step":"version"|"pack_download"|"database_create"|"database_analyze","language":string|null,
 *    "pack":string|null,"elapsed_ms":number|null,"duration_ms":number|null,"message":string|null}
 *
 * The core sends a heartbeat every 15 s while a step runs. Lines are parsed defensively: anything
 * that is not such an object is not a progress event, and every value is checked and bounded.
 */

export const PROGRESS_EVENTS: readonly CodeqlProgressEventKind[] = ["step_started", "step_finished", "step_failed", "heartbeat", "language_skipped"];
export const PROGRESS_STEPS: readonly CodeqlProgressStep[] = ["version", "pack_download", "database_create", "database_analyze"];

/** Longest line that is parsed as a progress event. */
const MAX_PROGRESS_LINE_CHARS = 8192;

const LANGUAGE_ID = /^[a-z][a-z0-9_+#-]{0,39}$/;
const PACK_NAME = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

function milliseconds(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value < 1e12 ? Math.round(value) : null;
}

/** The progress fields of one stderr line, or null when the line is not a progress event. */
export function parseProgressLine(line: string): Omit<CodeqlProgressView, "text"> | null {
  const text = line.trim();
  if (!text.startsWith("{") || text.length > MAX_PROGRESS_LINE_CHARS || !text.includes('"progress"')) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const doc = parsed as Record<string, unknown>;
  if (doc.progress !== true) return null;
  const event = PROGRESS_EVENTS.find((candidate) => candidate === doc.event);
  if (!event) return null;
  const step = PROGRESS_STEPS.find((candidate) => candidate === doc.step) ?? null;
  // Every event but a skip belongs to a step; an unknown step is not shown as something else.
  if (step === null && event !== "language_skipped") return null;
  const language = typeof doc.language === "string" && LANGUAGE_ID.test(doc.language) ? doc.language : null;
  const pack = typeof doc.pack === "string" && PACK_NAME.test(doc.pack) ? doc.pack : null;
  return {
    event,
    step,
    language,
    pack,
    elapsedMs: milliseconds(doc.elapsed_ms),
    durationMs: milliseconds(doc.duration_ms),
    message: sanitizeCoreMessage(doc.message),
  };
}

/** A duration for people: "45 s", "2 min 15 s", "4 min", "1 h 5 min". */
export function formatElapsed(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms) || ms < 0) return "unknown time";
  const totalSeconds = Math.round(ms / 1000);
  if (totalSeconds < 60) return `${totalSeconds} s`;
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return minutes > 0 ? `${hours} h ${minutes} min` : `${hours} h`;
  return seconds > 0 ? `${minutes} min ${seconds} s` : `${minutes} min`;
}

export interface ProgressContext {
  /** Suite of the analysis, named in "Analyzing <language> (<suite> suite)". */
  suite?: CodeqlSuite | null;
  /** Runtime passed as --typescript-runtime ("Bun"), named when the javascript database is created. */
  typescriptRuntime?: string | null;
  /**
   * True for a scan's host analysis, where a pack download happens because the pack is not cached
   * yet ("first run only"); false for an explicit download in Settings > CodeQL > Query packs.
   */
  scan?: boolean;
}

/** The core's start message of a retry ("Retrying the download of <pack> (attempt 2 of 2)"). */
const RETRY_MESSAGE = /^Retrying the download of \S+ \(attempt \d+ of \d+\)$/;

/** The query pack an event is about: its pack member, else codeql/<language>-queries. */
function packOf(event: Pick<CodeqlProgressView, "pack" | "language">): string {
  if (event.pack) return event.pack;
  return event.language ? `codeql/${event.language}-queries` : "the query pack";
}

function withReason(text: string, message: string | null): string {
  return message ? `${text}: ${message}` : text;
}

/** The readable line the console shows for a progress event. */
export function describeProgress(event: Omit<CodeqlProgressView, "text">, context: ProgressContext = {}): string {
  const language = event.language ?? "the workspace";
  const pack = packOf(event);
  const after = (ms: number | null) => (ms === null ? "" : ` after ${formatElapsed(ms)}`);
  const took = (ms: number | null) => (ms === null ? "" : ` in ${formatElapsed(ms)}`);
  const still = (ms: number | null) => (ms === null ? "" : ` (${formatElapsed(ms)})`);
  if (event.event === "language_skipped") return withReason(`Skipping ${language}`, event.message ?? "not analysed on the host");
  switch (event.step) {
    case "version":
      if (event.event === "step_started") return "Checking the CodeQL version";
      if (event.event === "heartbeat") return `Still checking the CodeQL version${still(event.elapsedMs)}`;
      if (event.event === "step_finished") return `CodeQL version checked${took(event.durationMs)}${event.message ? `: ${event.message}` : ""}`;
      return withReason(`The CodeQL version check failed${after(event.durationMs)}`, event.message);
    case "pack_download":
      if (event.event === "step_started") {
        // The core announces its one retry; the first attempt is the download itself.
        if (event.message && RETRY_MESSAGE.test(event.message)) return event.message;
        return context.scan
          ? `Downloading query pack ${pack} — first run only; can take several minutes on a slow connection`
          : `Downloading query pack ${pack}; can take several minutes on a slow connection`;
      }
      if (event.event === "heartbeat") return `Still downloading ${pack}${still(event.elapsedMs)}`;
      if (event.event === "step_finished") return `Downloaded ${pack}${took(event.durationMs)}; it stays in the pack cache`;
      return withReason(`Downloading ${pack} failed${after(event.durationMs)}`, event.message);
    case "database_create":
      if (event.event === "step_started") {
        const typescript = event.language === "javascript" && context.typescriptRuntime ? `; TypeScript is parsed with ${context.typescriptRuntime}` : "";
        return `Creating the ${language} database (build mode none${typescript})`;
      }
      if (event.event === "heartbeat") return `Still creating the ${language} database${still(event.elapsedMs)}`;
      if (event.event === "step_finished") return `Created the ${language} database${took(event.durationMs)}`;
      return withReason(`Creating the ${language} database failed${after(event.durationMs)}`, event.message);
    case "database_analyze":
      if (event.event === "step_started") return `Analyzing ${language}${context.suite ? ` (${context.suite} suite)` : ""}`;
      if (event.event === "heartbeat") return `Still analyzing ${language}${still(event.elapsedMs)}`;
      if (event.event === "step_finished") {
        // The core says "<language> analyzed: <n> results (<suite> suite)"; the count is what matters here.
        const count = event.message ? /\b(\d{1,9}) results?\b/.exec(event.message)?.[0] : undefined;
        if (count) return `${language} finished: ${count}${took(event.durationMs)}`;
        return `${language} finished${took(event.durationMs)}${event.message ? ` (${event.message})` : ""}`;
      }
      return withReason(`Analyzing ${language} failed${after(event.durationMs)}`, event.message);
    default:
      return withReason(`CodeQL ${event.event.replace("_", " ")}`, event.message);
  }
}

/** Parses a stderr line and describes it; null when the line is not a progress event. */
export function progressFromLine(line: string, context: ProgressContext = {}): CodeqlProgressView | null {
  const event = parseProgressLine(line);
  return event ? { ...event, text: describeProgress(event, context) } : null;
}
