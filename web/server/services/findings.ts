import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import type {
  CodeqlFindingDetails,
  DependencyFindingDetails,
  FindingOrigin,
  FindingSource,
  FindingState,
  FindingView,
  SastMatchView,
  Severity,
  TaintStepView,
  TrendPoint,
  TriageVerdict,
} from "../../src/types/api.ts";
import { SEVERITIES } from "../../src/types/api.ts";
import { parseJsonColumn } from "../db.ts";
import { HttpError } from "../http-error.ts";

/**
 * Finding persistence for the web bridge. Scanner and advisory output are stored as
 * candidates; the only human-controlled state is the triage verdict. Nothing here marks a
 * finding as validated or verified.
 */

// ───────────────────────────── core scan output mapping ─────────────────────────────

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Informational",
  INFORMATIONAL: "Informational",
};

/** Maps a core severity string (CRITICAL/HIGH/MEDIUM/LOW/INFO[RMATIONAL]) to the UI scale. */
export function normalizeSeverity(raw: unknown): Severity {
  if (typeof raw !== "string") return "Unknown";
  return SEVERITY_MAP[raw.trim().toUpperCase()] ?? "Unknown";
}

export function severityRank(severity: Severity): number {
  const index = SEVERITIES.indexOf(severity);
  return index === -1 ? SEVERITIES.length : index;
}

export function emptySeverityCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0 };
}

/**
 * Matches one row of the Markdown table the core appends to taint findings
 * (`TaintVulnerability::to_markdown_trace`):
 * `| 1 | \`🔴 SOURCE\` | \`12\` | \`input\` | \`code\` | explanation |`.
 * The code cell never contains backticks (the core replaces them), so it may contain pipes.
 */
const TAINT_ROW = /^\|\s*(\d+)\s*\|\s*`?([^|`]*)`?\s*\|\s*`?([^|`]*)`?\s*\|\s*`([^`]*)`\s*\|\s*`([^`]*)`\s*\|(.*)\|\s*$/u;

function taintRole(cell: string): TaintStepView["role"] | null {
  const upper = cell.toUpperCase();
  if (upper.includes("SOURCE")) return "SOURCE";
  if (upper.includes("PROPAGAT")) return "PROPAGATION";
  if (upper.includes("SANITIZ")) return "SANITIZER";
  if (upper.includes("SINK")) return "SINK";
  return null;
}

/**
 * Splits a core rationale into plain text and the structured taint trace it may embed.
 * Backticks are stripped before line numbers are parsed (the old dashboard parsed the
 * backtick-wrapped cell and fell back to the sink line for every step).
 */
export function parseTaintTrace(rationale: string | null | undefined): { trace: TaintStepView[] | null; text: string | null } {
  if (!rationale) return { trace: null, text: null };
  const steps: TaintStepView[] = [];
  const kept: string[] = [];
  let inTable = false;
  for (const rawLine of rationale.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (/^#{1,6}\s.*taint/i.test(line)) {
      inTable = true;
      continue;
    }
    if (line.startsWith("|")) {
      const row = TAINT_ROW.exec(line);
      if (row) {
        const role = taintRole(row[2]);
        if (role) {
          const lineNumber = Number.parseInt(row[3].replace(/`/g, "").trim(), 10);
          const variable = row[4].trim();
          const code = row[5].trim();
          steps.push({
            step: Number.parseInt(row[1], 10),
            role,
            line: Number.isInteger(lineNumber) && lineNumber > 0 ? lineNumber : null,
            variable: variable.length > 0 ? variable : null,
            code: code.length > 0 ? code : null,
          });
          continue;
        }
      }
      // Header and alignment rows of the trace table.
      if (inTable) continue;
    }
    kept.push(rawLine);
  }
  const text = kept.join("\n").trim();
  return { trace: steps.length > 0 ? steps.sort((a, b) => a.step - b.step) : null, text: text.length > 0 ? text : null };
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** One SAST match from `sentra scan --json`, plus the parsed taint trace. */
export interface ParsedSastMatch extends SastMatchView {
  taintTrace: TaintStepView[] | null;
}

export interface ParsedScanOutput {
  filesScanned: number;
  signalsFound: number;
  matches: ParsedSastMatch[];
}

/** Maps the JSON document printed by `sentra scan ... --json` (core render_scan). */
export function parseScanOutput(raw: unknown): ParsedScanOutput {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new HttpError(502, "core_output_invalid", "sentra scan did not print a JSON object");
  }
  const doc = raw as Record<string, unknown>;
  if (!Array.isArray(doc.matches)) {
    throw new HttpError(502, "core_output_invalid", "sentra scan output has no matches array");
  }
  const matches: ParsedSastMatch[] = [];
  for (const item of doc.matches) {
    if (item === null || typeof item !== "object") continue;
    const match = item as Record<string, unknown>;
    const ruleId = stringOrNull(match.rule_id);
    const filePath = stringOrNull(match.file_path);
    const line = typeof match.line_number === "number" && Number.isInteger(match.line_number) ? match.line_number : 0;
    if (!ruleId || !filePath) continue;
    const { trace, text } = parseTaintTrace(typeof match.rationale === "string" ? match.rationale : null);
    matches.push({
      ruleId,
      ruleName: stringOrNull(match.rule_name) ?? ruleId,
      cwe: stringOrNull(match.cwe),
      severity: normalizeSeverity(match.severity),
      category: stringOrNull(match.category),
      filePath: filePath.replace(/\\/g, "/"),
      line,
      snippet: typeof match.snippet === "string" ? match.snippet : null,
      rationale: text,
      taintTrace: trace,
    });
  }
  const filesScanned = typeof doc.files_scanned === "number" ? doc.files_scanned : 0;
  const signalsFound = typeof doc.signals_found === "number" ? doc.signals_found : matches.length;
  return { filesScanned, signalsFound, matches };
}

/** One-line rendering of a parsed taint trace, e.g. `SOURCE line 3 (input) -> SINK line 7`. */
export function describeTaintTrace(trace: TaintStepView[]): string {
  const steps = trace.map((step) => `${step.role}${step.line !== null ? ` line ${step.line}` : ""}${step.variable ? ` (${step.variable})` : ""}`);
  return `Pattern-based taint trace reported by the core: ${steps.join(" -> ")}`;
}

/**
 * Public SAST match shape. SastMatchView has no trace field, so a taint trace is rendered
 * into the rationale text instead of being dropped.
 */
export function toSastMatchView(match: ParsedSastMatch): SastMatchView {
  return {
    ruleId: match.ruleId,
    ruleName: match.ruleName,
    cwe: match.cwe,
    severity: match.severity,
    category: match.category,
    filePath: match.filePath,
    line: match.line,
    snippet: match.snippet,
    rationale: match.rationale ?? (match.taintTrace ? describeTaintTrace(match.taintTrace) : null),
  };
}

// ───────────────────────────── fingerprints ─────────────────────────────

export function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeSnippet(snippet: string | null, line: number): string {
  const collapsed = (snippet ?? "").replace(/\s+/g, " ").trim();
  return collapsed.length > 0 ? collapsed : `line:${line}`;
}

/**
 * SAST fingerprint: rule, file, normalized snippet (or the line when there is no snippet) and
 * the occurrence index among identical rule/file/snippet triples, so moving code within a
 * file keeps the identity while duplicated lines stay distinct.
 */
export function sastFingerprint(ruleId: string, filePath: string, normalizedSnippetOrLine: string, occurrenceIndex: number): string {
  return sha256Hex(`sast|${ruleId}|${filePath}|${normalizedSnippetOrLine}|${occurrenceIndex}`);
}

export function dependencyFingerprint(ecosystem: string, name: string, version: string, vulnId: string, lockfile: string): string {
  return sha256Hex(`dep|${ecosystem}|${name}|${version}|${vulnId}|${lockfile}`);
}

export function findingIdFor(tenantId: string, workspace: string, fingerprint: string): string {
  return `fnd_${sha256Hex(`${tenantId}|${workspace}|${fingerprint}`).slice(0, 24)}`;
}

// ───────────────────────────── candidates ─────────────────────────────

export interface CandidateFinding {
  fingerprint: string;
  source: FindingSource;
  /** CodeQL candidates only: how the result reached the bridge. Null (or absent) for SAST and dependency candidates. */
  origin?: FindingOrigin | null;
  /** CodeQL candidates only. */
  codeql?: CodeqlFindingDetails | null;
  ruleId: string;
  ruleName: string;
  cwe: string | null;
  severity: Severity;
  category: string | null;
  filePath: string | null;
  line: number | null;
  snippet: string | null;
  rationale: string | null;
  taintTrace: TaintStepView[] | null;
  dependency: DependencyFindingDetails | null;
}

/** Builds SAST candidates with occurrence-indexed fingerprints (ordered by file, line). */
export function sastCandidates(matches: ParsedSastMatch[]): CandidateFinding[] {
  const ordered = [...matches].sort((a, b) =>
    a.filePath === b.filePath ? a.line - b.line || a.ruleId.localeCompare(b.ruleId) : a.filePath.localeCompare(b.filePath),
  );
  const occurrences = new Map<string, number>();
  return ordered.map((match) => {
    const normalized = normalizeSnippet(match.snippet, match.line);
    const key = `${match.ruleId}\u0000${match.filePath}\u0000${normalized}`;
    const index = occurrences.get(key) ?? 0;
    occurrences.set(key, index + 1);
    return {
      fingerprint: sastFingerprint(match.ruleId, match.filePath, normalized, index),
      source: "sast",
      ruleId: match.ruleId,
      ruleName: match.ruleName,
      cwe: match.cwe,
      severity: match.severity,
      category: match.category,
      filePath: match.filePath,
      line: match.line > 0 ? match.line : null,
      snippet: match.snippet,
      rationale: match.rationale,
      taintTrace: match.taintTrace,
      dependency: null,
    };
  });
}

export const DEPENDENCY_CATEGORY = "DEPENDENCY_VULNERABILITY";

/** Builds the candidate for one package/advisory pair reported by OSV. */
export function dependencyCandidate(details: DependencyFindingDetails, severity: Severity, cwes: string[]): CandidateFinding {
  return {
    fingerprint: dependencyFingerprint(details.ecosystem, details.packageName, details.packageVersion, details.advisoryId, details.lockfile),
    source: "dependency",
    ruleId: details.advisoryId,
    ruleName: details.summary ?? details.advisoryId,
    cwe: cwes.length > 0 ? cwes.join(", ") : null,
    severity,
    category: DEPENDENCY_CATEGORY,
    filePath: details.lockfile,
    line: null,
    snippet: `${details.packageName}@${details.packageVersion}`,
    rationale: `${details.packageName}@${details.packageVersion} (${details.ecosystem}) from ${details.lockfile} is listed as affected by OSV advisory ${details.advisoryId}. Presence in a lockfile does not establish that the vulnerable code is reachable.`,
    taintTrace: null,
    dependency: details,
  };
}

// ───────────────────────────── persistence ─────────────────────────────

export interface FindingRow {
  finding_id: string;
  tenant_id: string;
  workspace: string;
  fingerprint: string;
  source: FindingSource;
  origin: FindingOrigin | null;
  rule_id: string;
  rule_name: string;
  cwe: string | null;
  severity: Severity;
  category: string | null;
  file_path: string | null;
  line: number | null;
  snippet: string | null;
  rationale: string | null;
  package_name: string | null;
  package_version: string | null;
  advisory_id: string | null;
  details_json: string | null;
  first_seen_run: string;
  last_seen_run: string;
  first_seen_at: string;
  last_seen_at: string;
  state: FindingState;
  resolved_run: string | null;
  resolved_at: string | null;
  triage_verdict: TriageVerdict | null;
  triage_reason: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
}

/** FindingView plus the stable fingerprint (used by the SARIF export). */
export interface StoredFinding extends FindingView {
  fingerprint: string;
}

export const LEGACY_FIXED_VERSIONS_NOTE =
  "Recorded by an earlier bridge version: fix versions from every affected range, not filtered for the installed version. The next dependency scan refreshes this list.";

function detailsJson(candidate: CandidateFinding): string | null {
  if (candidate.source === "dependency" && candidate.dependency) return JSON.stringify(candidate.dependency);
  if (candidate.source === "sast" && candidate.taintTrace) return JSON.stringify({ taintTrace: candidate.taintTrace });
  if (candidate.source === "codeql" && candidate.codeql) return JSON.stringify(candidate.codeql);
  return null;
}

/** Stored CodeQL details, or null when the column is missing or not an object. */
export function parseCodeqlDetails(raw: string | null): CodeqlFindingDetails | null {
  const parsed = parseJsonColumn<CodeqlFindingDetails | null>(raw, null);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
}

export function rowToFinding(row: FindingRow): StoredFinding {
  let taintTrace: TaintStepView[] | null = null;
  let dependency: DependencyFindingDetails | null = null;
  let codeql: CodeqlFindingDetails | null = null;
  if (row.source === "sast") {
    const parsed = parseJsonColumn<{ taintTrace?: TaintStepView[] } | null>(row.details_json, null);
    taintTrace = Array.isArray(parsed?.taintTrace) ? parsed.taintTrace : null;
  } else if (row.source === "codeql") {
    codeql = parseCodeqlDetails(row.details_json);
  } else {
    dependency = parseJsonColumn<DependencyFindingDetails | null>(row.details_json, null);
    if (dependency && dependency.fixedVersionsNote === undefined) {
      // Written before fix versions were filtered for the installed version.
      const listed = Array.isArray(dependency.fixedVersions) && dependency.fixedVersions.length > 0;
      dependency = { ...dependency, fixedVersionsNote: listed ? LEGACY_FIXED_VERSIONS_NOTE : null };
    }
  }
  return {
    findingId: row.finding_id,
    tenantId: row.tenant_id,
    source: row.source,
    ruleId: row.rule_id,
    ruleName: row.rule_name,
    cwe: row.cwe,
    severity: row.severity,
    category: row.category,
    filePath: row.file_path,
    line: row.line,
    snippet: row.snippet,
    rationale: row.rationale,
    taintTrace,
    dependency,
    origin: row.origin ?? null,
    codeql,
    state: row.state,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    firstSeenRun: row.first_seen_run,
    lastSeenRun: row.last_seen_run,
    resolvedAt: row.resolved_at,
    triage:
      row.triage_verdict && row.triaged_by && row.triaged_at
        ? { verdict: row.triage_verdict, reason: row.triage_reason ?? "", by: row.triaged_by, at: row.triaged_at }
        : null,
    fingerprint: row.fingerprint,
  };
}

/** Strips the internal fingerprint so responses match FindingView exactly. */
export function toFindingView(finding: StoredFinding): FindingView {
  const { fingerprint: _fingerprint, ...view } = finding;
  return view;
}

/**
 * One reconciliation scope: a source and, for CodeQL, an origin. Candidates outside every scope are
 * ignored, and only open findings of a scope can be resolved, so one origin never closes another's
 * findings (a SARIF import never resolves a host-analysis finding, and the reverse).
 */
export interface ReconcileScope {
  source: FindingSource;
  /** Null for SAST and dependency findings. */
  origin: FindingOrigin | null;
  /**
   * Which open findings of the scope this run covered (for example the languages and rules a
   * CodeQL analysis ran, or the repository a GitHub sync read). Findings it does not cover are
   * never resolved. Absent: the whole scope.
   */
  covers?: (finding: { details: unknown; ruleId: string }) => boolean;
  /** False when the run saw only part of the scope (a truncated result list): nothing is resolved. Default true. */
  resolve?: boolean;
}

export interface ReconcileInput {
  tenantId: string;
  /** The tenant's registered (canonical) workspace path; part of the finding identity. */
  workspace: string;
  runId: string;
  at: string;
  candidates: CandidateFinding[];
  /** Sources whose stage completed in this run (SAST and dependency; origin null). Only these can be resolved. */
  completedSources?: FindingSource[];
  /** Further completed scopes (CodeQL origins). */
  scopes?: ReconcileScope[];
}

function scopeKey(source: FindingSource, origin: FindingOrigin | null | undefined): string {
  return `${source}\u0000${origin ?? ""}`;
}

export interface ReconcileResult {
  /** First seen in this run. */
  created: number;
  /** Previously resolved, seen again in this run. */
  reopened: number;
  /** Already open before this run and seen again. */
  stillOpen: number;
  /** Previously open, not seen by a completed stage of the same source. */
  resolved: number;
}

/**
 * Reconciles one run's candidates against stored findings in a single transaction:
 * new → inserted open; seen again → last_seen refreshed (reopened when resolved);
 * open but not seen by a COMPLETED scope (source, and for CodeQL the origin) → resolved, limited
 * to the findings the scope covered. Findings of a source whose stage failed or was skipped, of
 * another origin, or outside what the scope covered are never resolved.
 */
export function reconcileFindings(db: Database, input: ReconcileInput): ReconcileResult {
  const scopes: ReconcileScope[] = [
    ...(input.completedSources ?? []).map((source): ReconcileScope => ({ source, origin: null })),
    ...(input.scopes ?? []),
  ];
  const completed = new Set(scopes.map((scope) => scopeKey(scope.source, scope.origin)));
  const unique = new Map<string, CandidateFinding>();
  for (const candidate of input.candidates) {
    if (completed.has(scopeKey(candidate.source, candidate.origin)) && !unique.has(candidate.fingerprint)) unique.set(candidate.fingerprint, candidate);
  }
  const apply = db.transaction((): ReconcileResult => {
    const result: ReconcileResult = { created: 0, reopened: 0, stillOpen: 0, resolved: 0 };
    const select = db.query("SELECT finding_id, state FROM findings WHERE tenant_id = ? AND workspace = ? AND fingerprint = ?");
    const insert = db.query(
      `INSERT INTO findings (finding_id, tenant_id, workspace, fingerprint, source, origin, rule_id, rule_name, cwe, severity, category,
         file_path, line, snippet, rationale, package_name, package_version, advisory_id, details_json,
         first_seen_run, last_seen_run, first_seen_at, last_seen_at, state)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`,
    );
    const update = db.query(
      `UPDATE findings SET rule_name = ?, cwe = ?, severity = ?, category = ?, file_path = ?, line = ?, snippet = ?, rationale = ?,
         package_name = ?, package_version = ?, advisory_id = ?, details_json = ?, last_seen_run = ?, last_seen_at = ?,
         state = 'open', resolved_run = NULL, resolved_at = NULL
       WHERE finding_id = ?`,
    );
    for (const candidate of unique.values()) {
      const existing = select.get(input.tenantId, input.workspace, candidate.fingerprint) as { finding_id: string; state: FindingState } | null;
      const dep = candidate.dependency;
      if (!existing) {
        insert.run(
          findingIdFor(input.tenantId, input.workspace, candidate.fingerprint),
          input.tenantId,
          input.workspace,
          candidate.fingerprint,
          candidate.source,
          candidate.source === "codeql" ? (candidate.origin ?? null) : null,
          candidate.ruleId,
          candidate.ruleName,
          candidate.cwe,
          candidate.severity,
          candidate.category,
          candidate.filePath,
          candidate.line,
          candidate.snippet,
          candidate.rationale,
          dep?.packageName ?? null,
          dep?.packageVersion ?? null,
          dep?.advisoryId ?? null,
          detailsJson(candidate),
          input.runId,
          input.runId,
          input.at,
          input.at,
        );
        result.created += 1;
        continue;
      }
      update.run(
        candidate.ruleName,
        candidate.cwe,
        candidate.severity,
        candidate.category,
        candidate.filePath,
        candidate.line,
        candidate.snippet,
        candidate.rationale,
        dep?.packageName ?? null,
        dep?.packageVersion ?? null,
        dep?.advisoryId ?? null,
        detailsJson(candidate),
        input.runId,
        input.at,
        existing.finding_id,
      );
      if (existing.state === "resolved") result.reopened += 1;
      else result.stillOpen += 1;
    }
    const openOfScope = db.query(
      "SELECT finding_id, fingerprint, rule_id, details_json FROM findings WHERE tenant_id = ? AND workspace = ? AND source = ? AND origin IS ? AND state = 'open'",
    );
    const resolve = db.query("UPDATE findings SET state = 'resolved', resolved_run = ?, resolved_at = ? WHERE finding_id = ?");
    const resolvedScopes = new Set<string>();
    for (const scope of scopes) {
      if (scope.resolve === false) continue;
      const key = scopeKey(scope.source, scope.origin);
      // A scope listed twice is resolved once (the first entry wins).
      if (resolvedScopes.has(key)) continue;
      resolvedScopes.add(key);
      const rows = openOfScope.all(input.tenantId, input.workspace, scope.source, scope.origin ?? null) as {
        finding_id: string;
        fingerprint: string;
        rule_id: string;
        details_json: string | null;
      }[];
      for (const row of rows) {
        if (unique.has(row.fingerprint)) continue;
        if (scope.covers && !scope.covers({ details: parseJsonColumn<unknown>(row.details_json, null), ruleId: row.rule_id })) continue;
        resolve.run(input.runId, input.at, row.finding_id);
        result.resolved += 1;
      }
    }
    return result;
  });
  return apply.immediate();
}

// ───────────────────────────── queries ─────────────────────────────

export interface FindingFilter {
  state: FindingState | "all";
  source?: FindingSource;
  /** CodeQL origin; only CodeQL findings have one. */
  origin?: FindingOrigin;
  severity?: Severity;
}

export function listFindings(db: Database, tenantId: string, workspace: string, filter: FindingFilter): StoredFinding[] {
  const clauses = ["tenant_id = ?", "workspace = ?"];
  const params: string[] = [tenantId, workspace];
  if (filter.state !== "all") {
    clauses.push("state = ?");
    params.push(filter.state);
  }
  if (filter.source) {
    clauses.push("source = ?");
    params.push(filter.source);
  }
  if (filter.origin) {
    clauses.push("origin = ?");
    params.push(filter.origin);
  }
  if (filter.severity) {
    clauses.push("severity = ?");
    params.push(filter.severity);
  }
  const rows = db.query(`SELECT * FROM findings WHERE ${clauses.join(" AND ")}`).all(...params) as FindingRow[];
  return rows
    .map(rowToFinding)
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        (a.state === b.state ? 0 : a.state === "open" ? -1 : 1) ||
        (a.filePath ?? "").localeCompare(b.filePath ?? "") ||
        (a.line ?? 0) - (b.line ?? 0) ||
        a.ruleId.localeCompare(b.ruleId),
    );
}

export function findFinding(db: Database, tenantId: string, findingId: string): StoredFinding | null {
  const row = db.query("SELECT * FROM findings WHERE tenant_id = ? AND finding_id = ?").get(tenantId, findingId) as FindingRow | null;
  return row ? rowToFinding(row) : null;
}

/** Returns a tenant's finding or throws 404. Shared with other route modules (patches). */
export function getFinding(db: Database, tenantId: string, findingId: string): StoredFinding {
  if (!/^fnd_[0-9a-f]{24}$/.test(findingId)) throw new HttpError(404, "finding_not_found", "Finding not found");
  const finding = findFinding(db, tenantId, findingId);
  if (!finding) throw new HttpError(404, "finding_not_found", "Finding not found");
  return finding;
}

export function triageFinding(
  db: Database,
  tenantId: string,
  findingId: string,
  input: { verdict: TriageVerdict; reason: string; by: string; at: string },
): StoredFinding {
  getFinding(db, tenantId, findingId);
  db.query("UPDATE findings SET triage_verdict = ?, triage_reason = ?, triaged_by = ?, triaged_at = ? WHERE tenant_id = ? AND finding_id = ?").run(
    input.verdict,
    input.reason,
    input.by,
    input.at,
    tenantId,
    findingId,
  );
  return getFinding(db, tenantId, findingId);
}

/** Open SAST secret findings of one file, keyed by line, for file-view redaction. */
export function openSecretLines(db: Database, tenantId: string, workspace: string): { filePath: string; line: number; ruleId: string }[] {
  return (
    db
      .query(
        "SELECT file_path, line, rule_id FROM findings WHERE tenant_id = ? AND workspace = ? AND source = 'sast' AND state = 'open' AND category = 'SECRET_LEAK' AND file_path IS NOT NULL AND line IS NOT NULL",
      )
      .all(tenantId, workspace) as { file_path: string; line: number; rule_id: string }[]
  ).map((row) => ({ filePath: row.file_path, line: row.line, ruleId: row.rule_id }));
}

// ───────────────────────────── overview & trends ─────────────────────────────

export interface FindingCounts {
  openTotal: number;
  bySeverity: Record<Severity, number>;
  bySource: Record<FindingSource, number>;
  /**
   * Open CodeQL findings (not triaged as rejected) per origin; they add up to bySource.codeql.
   * Each origin is stored and counted on its own, so one CodeQL result reported by host
   * analysis, a SARIF import and GitHub code scanning counts once per origin.
   */
  codeqlByOrigin: Record<FindingOrigin, number>;
  byTriage: { untriaged: number; confirmed: number; needs_validation: number; rejected: number };
  resolved: number;
}

/** Open totals exclude findings triaged as rejected; byTriage covers every open finding. */
export function findingCounts(db: Database, tenantId: string, workspace: string): FindingCounts {
  const rows = db
    .query("SELECT state, severity, source, origin, triage_verdict FROM findings WHERE tenant_id = ? AND workspace = ?")
    .all(tenantId, workspace) as { state: FindingState; severity: Severity; source: FindingSource; origin: FindingOrigin | null; triage_verdict: TriageVerdict | null }[];
  const counts: FindingCounts = {
    openTotal: 0,
    bySeverity: emptySeverityCounts(),
    bySource: { sast: 0, dependency: 0, codeql: 0 },
    codeqlByOrigin: { host_analysis: 0, sarif_import: 0, github_code_scanning: 0 },
    byTriage: { untriaged: 0, confirmed: 0, needs_validation: 0, rejected: 0 },
    resolved: 0,
  };
  for (const row of rows) {
    if (row.state === "resolved") {
      counts.resolved += 1;
      continue;
    }
    counts.byTriage[row.triage_verdict ?? "untriaged"] += 1;
    if (row.triage_verdict === "rejected") continue;
    counts.openTotal += 1;
    counts.bySeverity[row.severity in counts.bySeverity ? row.severity : "Unknown"] += 1;
    counts.bySource[row.source] += 1;
    if (row.source === "codeql" && row.origin && row.origin in counts.codeqlByOrigin) counts.codeqlByOrigin[row.origin] += 1;
  }
  return counts;
}

export const RISK_SCORE_FORMULA =
  "max(0, 100 - 15*critical - 7*high - 3*medium - 1*low), counted over open findings not triaged as rejected. A heuristic summary of unvalidated candidates, not a security rating.";

export function riskScoreValue(bySeverity: Record<Severity, number>): number {
  return Math.max(0, 100 - 15 * bySeverity.Critical - 7 * bySeverity.High - 3 * bySeverity.Medium - 1 * bySeverity.Low);
}

const DAY_MS = 86_400_000;

function utcDayStart(ms: number): number {
  const date = new Date(ms);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

function parseTime(value: string | null): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Per-UTC-day series computed only from stored rows. Limitations that follow from the
 * schema: triage is evaluated as of now (no triage history), and a reopened finding loses
 * its earlier resolution timestamp.
 */
export function computeTrends(db: Database, tenantId: string, workspace: string, days: number, nowMs = Date.now()): TrendPoint[] {
  const today = utcDayStart(nowMs);
  const firstDay = today - (days - 1) * DAY_MS;
  const runs = (
    db.query("SELECT started_at FROM scan_runs WHERE tenant_id = ? AND workspace = ?").all(tenantId, workspace) as { started_at: string }[]
  )
    .map((row) => parseTime(row.started_at))
    .filter((ms): ms is number => ms !== null);
  const findings = (
    db
      .query("SELECT first_seen_at, resolved_at, severity, triage_verdict FROM findings WHERE tenant_id = ? AND workspace = ?")
      .all(tenantId, workspace) as { first_seen_at: string; resolved_at: string | null; severity: Severity; triage_verdict: TriageVerdict | null }[]
  ).map((row) => ({
    firstSeen: parseTime(row.first_seen_at),
    resolvedAt: parseTime(row.resolved_at),
    critical: row.severity === "Critical",
    rejected: row.triage_verdict === "rejected",
  }));
  const points: TrendPoint[] = [];
  for (let start = firstDay; start <= today; start += DAY_MS) {
    const end = start + DAY_MS;
    const inDay = (ms: number | null) => ms !== null && ms >= start && ms < end;
    let openAtEnd = 0;
    let openCriticalAtEnd = 0;
    let created = 0;
    let resolved = 0;
    for (const finding of findings) {
      if (inDay(finding.firstSeen)) created += 1;
      if (inDay(finding.resolvedAt)) resolved += 1;
      if (finding.rejected || finding.firstSeen === null || finding.firstSeen >= end) continue;
      if (finding.resolvedAt !== null && finding.resolvedAt < end) continue;
      openAtEnd += 1;
      if (finding.critical) openCriticalAtEnd += 1;
    }
    points.push({
      date: new Date(start).toISOString().slice(0, 10),
      scans: runs.filter(inDay).length,
      newFindings: created,
      resolvedFindings: resolved,
      openAtEndOfDay: openAtEnd,
      openCriticalAtEndOfDay: openCriticalAtEnd,
    });
  }
  return points;
}
