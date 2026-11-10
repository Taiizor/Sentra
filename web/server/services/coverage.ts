import type { Database } from "bun:sqlite";
import fs from "node:fs";
import type {
  CoverageStatus,
  CoverageUnitView,
  CoverageValidationView,
  UpsertCoverageUnitRequest,
} from "../../src/types/api.ts";
import { nowIso, parseJsonColumn } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { resolveInside } from "../paths.ts";
import type { JsonObject } from "../validate.ts";

/**
 * Operator-maintained security-audit coverage ledger. Units are claims recorded by people
 * (or agents acting through the API); nothing here marks a unit as verified. The validator
 * only checks structural rules and facts the bridge can observe itself: that reviewed paths
 * exist inside the tenant workspace and that result fingerprints name findings this bridge
 * actually recorded for the tenant.
 */

export const COVERAGE_STATUSES: readonly CoverageStatus[] = [
  "planned",
  "candidate",
  "covered",
  "needs_validation",
  "deferred",
  "blocked",
  "out_of_scope",
];

/** Statuses that are only meaningful together with the reason the unit is not resolved. */
const STATUSES_REQUIRING_REASON: ReadonlySet<CoverageStatus> = new Set(["needs_validation", "blocked", "deferred", "out_of_scope"]);

export const COVERAGE_SEGMENT_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;
export const COVERAGE_MAX_LIST_ITEMS = 200;
export const COVERAGE_MAX_STRING = 500;
export const COVERAGE_MAX_WAVE = 10_000;

export interface CoverageIdParts {
  surface: string;
  boundary: string;
  subsystem: string;
  attackClass: string;
}

/** Splits `<surface>/<boundary>/<subsystem>/<attackClass>` and checks every segment. */
export function parseCoverageId(coverageId: string): CoverageIdParts {
  const segments = coverageId.split("/");
  if (segments.length !== 4 || !segments.every((segment) => COVERAGE_SEGMENT_PATTERN.test(segment))) {
    throw new HttpError(
      400,
      "invalid_coverage_id",
      "Coverage ids must look like <surface>/<boundary>/<subsystem>/<attackClass>; each segment is 1-63 chars of a-z, 0-9, '_' or '-' and starts with a letter or digit",
    );
  }
  const [surface, boundary, subsystem, attackClass] = segments;
  return { surface, boundary, subsystem, attackClass };
}

function boundedString(value: unknown, field: string, allowEmpty: boolean): string {
  if (typeof value !== "string") throw new HttpError(400, "invalid_request", `'${field}' must be a string`);
  const trimmed = value.trim();
  if (!allowEmpty && trimmed.length === 0) throw new HttpError(400, "invalid_request", `'${field}' must not be empty`);
  if (trimmed.length > COVERAGE_MAX_STRING) {
    throw new HttpError(400, "invalid_request", `'${field}' must be at most ${COVERAGE_MAX_STRING} characters`);
  }
  // oxlint-disable-next-line no-control-regex -- intentional: rejects control characters other than tab and line breaks
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(trimmed)) {
    throw new HttpError(400, "invalid_request", `'${field}' contains control characters`);
  }
  return trimmed;
}

function stringList(body: JsonObject, field: string): string[] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new HttpError(400, "invalid_request", `'${field}' must be an array of strings`);
  if (value.length > COVERAGE_MAX_LIST_ITEMS) {
    throw new HttpError(400, "invalid_request", `'${field}' accepts at most ${COVERAGE_MAX_LIST_ITEMS} items`);
  }
  const items = value.map((item, index) => boundedString(item, `${field}[${index}]`, false));
  return [...new Set(items)];
}

function nullableString(body: JsonObject, field: string): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  const text = boundedString(value, field, true);
  return text.length > 0 ? text : null;
}

/**
 * Validates an upsert body against the coverage id from the route. The id is authoritative:
 * the four dimension fields must repeat its segments exactly.
 */
export function parseUpsertRequest(coverageId: string, body: JsonObject): UpsertCoverageUnitRequest {
  const parts = parseCoverageId(coverageId);
  const dimensions: [keyof CoverageIdParts, string][] = [
    ["surface", parts.surface],
    ["boundary", parts.boundary],
    ["subsystem", parts.subsystem],
    ["attackClass", parts.attackClass],
  ];
  for (const [field, expected] of dimensions) {
    const value = body[field];
    if (value !== expected) {
      throw new HttpError(400, "coverage_id_mismatch", `'${field}' must equal the coverage id segment '${expected}'`);
    }
  }
  const status = body.status;
  if (typeof status !== "string" || !(COVERAGE_STATUSES as readonly string[]).includes(status)) {
    throw new HttpError(400, "invalid_request", `'status' must be one of: ${COVERAGE_STATUSES.join(", ")}`);
  }
  const wave = body.wave;
  if (typeof wave !== "number" || !Number.isInteger(wave) || wave < 0 || wave > COVERAGE_MAX_WAVE) {
    throw new HttpError(400, "invalid_request", `'wave' must be an integer between 0 and ${COVERAGE_MAX_WAVE}`);
  }
  return {
    ...parts,
    status: status as CoverageStatus,
    wave,
    owner: nullableString(body, "owner"),
    reviewedPaths: stringList(body, "reviewedPaths"),
    localChecks: stringList(body, "localChecks"),
    resultFingerprints: stringList(body, "resultFingerprints"),
    unresolved: nullableString(body, "unresolved"),
  };
}

interface CoverageRow {
  tenant_id: string;
  coverage_id: string;
  surface: string;
  boundary: string;
  subsystem: string;
  attack_class: string;
  status: CoverageStatus;
  wave: number;
  owner: string | null;
  reviewed_paths_json: string;
  local_checks_json: string;
  result_fingerprints_json: string;
  unresolved: string | null;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

function stringArrayColumn(value: string): string[] {
  const parsed = parseJsonColumn<unknown>(value, []);
  return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
}

function toView(row: CoverageRow): CoverageUnitView {
  return {
    coverageId: row.coverage_id,
    surface: row.surface,
    boundary: row.boundary,
    subsystem: row.subsystem,
    attackClass: row.attack_class,
    status: row.status,
    wave: row.wave,
    owner: row.owner,
    reviewedPaths: stringArrayColumn(row.reviewed_paths_json),
    localChecks: stringArrayColumn(row.local_checks_json),
    resultFingerprints: stringArrayColumn(row.result_fingerprints_json),
    unresolved: row.unresolved,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    updatedBy: row.updated_by,
  };
}

/** Per-tenant coverage units stored in the bridge database (`coverage_units`). */
export class CoverageLedger {
  private readonly db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  list(tenantId: string): CoverageUnitView[] {
    const rows = this.db
      .query("SELECT * FROM coverage_units WHERE tenant_id = ? ORDER BY coverage_id ASC")
      .all(tenantId) as CoverageRow[];
    return rows.map(toView);
  }

  get(tenantId: string, coverageId: string): CoverageUnitView | null {
    const row = this.db
      .query("SELECT * FROM coverage_units WHERE tenant_id = ? AND coverage_id = ?")
      .get(tenantId, coverageId) as CoverageRow | null;
    return row ? toView(row) : null;
  }

  upsert(tenantId: string, coverageId: string, input: UpsertCoverageUnitRequest, actor: string): { unit: CoverageUnitView; created: boolean } {
    const now = nowIso();
    const write = this.db.transaction((): boolean => {
      const existing = this.db
        .query("SELECT created_at FROM coverage_units WHERE tenant_id = ? AND coverage_id = ?")
        .get(tenantId, coverageId) as { created_at: string } | null;
      this.db
        .query(
          `INSERT INTO coverage_units (tenant_id, coverage_id, surface, boundary, subsystem, attack_class, status, wave, owner,
             reviewed_paths_json, local_checks_json, result_fingerprints_json, unresolved, created_at, updated_at, updated_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, coverage_id) DO UPDATE SET
             surface = excluded.surface, boundary = excluded.boundary, subsystem = excluded.subsystem,
             attack_class = excluded.attack_class, status = excluded.status, wave = excluded.wave, owner = excluded.owner,
             reviewed_paths_json = excluded.reviewed_paths_json, local_checks_json = excluded.local_checks_json,
             result_fingerprints_json = excluded.result_fingerprints_json, unresolved = excluded.unresolved,
             updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
        )
        .run(
          tenantId,
          coverageId,
          input.surface,
          input.boundary,
          input.subsystem,
          input.attackClass,
          input.status,
          input.wave,
          input.owner ?? null,
          JSON.stringify(input.reviewedPaths),
          JSON.stringify(input.localChecks),
          JSON.stringify(input.resultFingerprints),
          input.unresolved ?? null,
          existing?.created_at ?? now,
          now,
          actor,
        );
      return existing === null;
    });
    const created = write();
    const unit = this.get(tenantId, coverageId);
    if (!unit) throw new HttpError(500, "coverage_write_failed", "The coverage unit could not be read back after writing");
    return { unit, created };
  }

  delete(tenantId: string, coverageId: string): boolean {
    const result = this.db.query("DELETE FROM coverage_units WHERE tenant_id = ? AND coverage_id = ?").run(tenantId, coverageId);
    return result.changes > 0;
  }
}

/** Returns a lookup that is true when `ref` is the fingerprint or id of a finding of the tenant. */
export function tenantFindingLookup(db: Database, tenantId: string): (ref: string) => boolean {
  const statement = db.query("SELECT 1 AS hit FROM findings WHERE tenant_id = ? AND (fingerprint = ? OR finding_id = ?) LIMIT 1");
  return (ref: string) => statement.get(tenantId, ref, ref) !== null;
}

export interface CoverageValidationContext {
  /** Canonical workspace root, or null when the workspace is unavailable. */
  workspaceRoot: string | null;
  /** Why the workspace is unavailable (reported on every unit that needs it). */
  workspaceError: string | null;
  findingExists: (ref: string) => boolean;
}

export type CoverageValidationError = CoverageValidationView["errors"][number];

/**
 * Checks every unit against the ledger rules. Every rule here is evaluated for real; the
 * result is `valid: true` only when no unit produced an error.
 */
export function validateCoverageUnits(units: readonly CoverageUnitView[], context: CoverageValidationContext): CoverageValidationView {
  const errors: CoverageValidationError[] = [];
  for (const unit of units) {
    const add = (rule: string, message: string) => errors.push({ coverageId: unit.coverageId, rule, message });

    let parts: CoverageIdParts | null = null;
    try {
      parts = parseCoverageId(unit.coverageId);
    } catch (error) {
      add("id_format", error instanceof Error ? error.message : String(error));
    }
    if (
      parts &&
      (parts.surface !== unit.surface ||
        parts.boundary !== unit.boundary ||
        parts.subsystem !== unit.subsystem ||
        parts.attackClass !== unit.attackClass)
    ) {
      add("id_format", "The coverage id does not match the unit's surface/boundary/subsystem/attackClass fields");
    }

    if (unit.status === "covered") {
      if (unit.reviewedPaths.length === 0) add("covered_requires_reviewed_paths", "A covered unit must list the paths that were reviewed");
      if (unit.localChecks.length === 0) add("covered_requires_local_checks", "A covered unit must list the local checks that support it");
    }
    if (unit.status === "candidate" && unit.resultFingerprints.length === 0) {
      add("candidate_requires_fingerprints", "A candidate unit must reference at least one finding fingerprint or finding id");
    }
    if (STATUSES_REQUIRING_REASON.has(unit.status) && !(unit.unresolved ?? "").trim()) {
      add("unresolved_reason_required", `A unit with status '${unit.status}' must state the unresolved reason`);
    }

    if (unit.reviewedPaths.length > 0) {
      if (context.workspaceRoot === null) {
        add("workspace_unavailable", `Reviewed paths cannot be checked: ${context.workspaceError ?? "the workspace is unavailable"}`);
      } else {
        for (const reviewed of unit.reviewedPaths) {
          const problem = reviewedPathProblem(context.workspaceRoot, reviewed);
          if (problem) add(problem.rule, problem.message);
        }
      }
    }

    for (const fingerprint of unit.resultFingerprints) {
      if (!context.findingExists(fingerprint)) {
        add("result_fingerprint_unknown", `'${fingerprint}' matches no finding fingerprint or finding id recorded for this tenant`);
      }
    }
  }
  return { valid: errors.length === 0, checkedUnits: units.length, errors, validatedAt: nowIso() };
}

function reviewedPathProblem(root: string, reviewed: string): { rule: string; message: string } | null {
  const normalized = reviewed.replace(/\\/g, "/");
  if (/^([A-Za-z]:)?\//.test(normalized)) {
    return { rule: "reviewed_path_not_relative", message: `'${reviewed}' must be a workspace-relative path` };
  }
  let absolute: string;
  try {
    // The "./" prefix keeps resolveInside from treating a leading "a/" or "b/" directory as a
    // diff prefix; containment (including through links) is still enforced by resolveInside.
    absolute = resolveInside(root, `./${normalized}`, "reviewedPath").absolute;
  } catch (error) {
    if (error instanceof HttpError && error.code === "path_outside_workspace") {
      return { rule: "reviewed_path_outside_workspace", message: `'${reviewed}' resolves outside the workspace` };
    }
    return { rule: "reviewed_path_invalid", message: `'${reviewed}': ${error instanceof Error ? error.message : String(error)}` };
  }
  if (!fs.existsSync(absolute)) {
    return { rule: "reviewed_path_missing", message: `'${reviewed}' does not exist in the workspace` };
  }
  return null;
}
