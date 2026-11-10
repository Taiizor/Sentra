import type { Database } from "bun:sqlite";
import type {
  DependencyFindingDetails,
  DependencyInventoryView,
  DependencyPackageView,
  IntelStatusView,
  LockfileView,
  OsvAffectedView,
  OsvQueryResponse,
  OsvVulnerabilityView,
  Severity,
} from "../../src/types/api.ts";
import type { AppContext } from "../app-context.ts";
import { nowIso, parseJsonColumn } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { fetchWithLimits } from "../net-guard.ts";
import { cliValue, requireJson } from "../sentra-cli.ts";
import type { SettingsStore } from "./settings-store.ts";
import { cvss3BaseScore, cvssRating } from "./cvss.ts";
import { comparatorFor, evaluateRange, sortVersions } from "./osv-versions.ts";
import { dependencyCandidate, severityRank, type CandidateFinding } from "./findings.ts";
import type { ActorRef, OsvService } from "./types.ts";

/**
 * OSV.dev client and dependency-vulnerability mapping. Lookups disclose package names and
 * versions to a third party, so they only run while the admin policy switch
 * (`intel.osv`) is on. The host is fixed; no credentials are ever sent.
 */

export const OSV_ENDPOINT = "https://api.osv.dev";
export const OSV_PRIVACY_NOTE =
  "Enabling OSV sends package names and versions from registered workspaces to https://api.osv.dev. No source code is sent.";
const SETTING_KEY = "intel.osv";
const LAST_QUERY_KEY = "intel.osv.last_query";
const BATCH_LIMIT = 1000;
const MAX_PAGES_PER_QUERY = 50;
const VULN_CONCURRENCY = 8;
const VULN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

// ───────────────────────────── OSV record shapes (JSON boundary) ─────────────────────────────

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvSeverityEntry {
  type?: string;
  score?: string;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string; purl?: string };
  ranges?: { type?: string; events?: OsvEvent[] }[];
  versions?: string[];
  severity?: OsvSeverityEntry[];
}

export interface OsvRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  withdrawn?: string;
  severity?: OsvSeverityEntry[];
  affected?: OsvAffected[];
  references?: { type?: string; url?: string }[];
  database_specific?: Record<string, unknown>;
}

export interface OsvPackageQuery {
  name: string;
  ecosystem: string;
  version: string | null;
}

export interface OsvVulnRef {
  id: string;
  modified: string | null;
}

/** Minimal HTTP surface so tests can inject a fake OSV without network access. */
export type OsvFetcher = (url: string, init: { method: "GET" | "POST"; body?: string }) => Promise<{ status: number; text: string }>;

export const defaultOsvFetcher: OsvFetcher = async (url, init) => {
  const response = await fetchWithLimits(url, {
    method: init.method,
    body: init.body,
    headers: init.body !== undefined ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
    timeoutMs: 60_000,
    maxResponseBytes: 32 * 1024 * 1024,
  });
  return { status: response.status, text: response.text };
};

function str(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function strArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

/** Validates the parts of an OSV record the bridge reads; null when it is not a record. */
export function sanitizeOsvRecord(raw: unknown): OsvRecord | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const doc = raw as Record<string, unknown>;
  const id = str(doc.id);
  if (!id) return null;
  const severityList = (value: unknown): OsvSeverityEntry[] =>
    Array.isArray(value)
      ? value
          .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object")
          .map((entry) => ({ type: str(entry.type), score: str(entry.score) }))
      : [];
  const affected = Array.isArray(doc.affected)
    ? doc.affected
        .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object")
        .map((entry): OsvAffected => {
          const pkg = entry.package && typeof entry.package === "object" ? (entry.package as Record<string, unknown>) : {};
          return {
            package: { name: str(pkg.name), ecosystem: str(pkg.ecosystem), purl: str(pkg.purl) },
            ranges: Array.isArray(entry.ranges)
              ? entry.ranges
                  .filter((range): range is Record<string, unknown> => range !== null && typeof range === "object")
                  .map((range) => ({
                    type: str(range.type),
                    events: Array.isArray(range.events)
                      ? range.events
                          .filter((event): event is Record<string, unknown> => event !== null && typeof event === "object")
                          .map((event) => ({
                            introduced: str(event.introduced),
                            fixed: str(event.fixed),
                            last_affected: str(event.last_affected),
                            limit: str(event.limit),
                          }))
                      : [],
                  }))
              : [],
            versions: strArray(entry.versions),
            severity: severityList(entry.severity),
          };
        })
    : [];
  const references = Array.isArray(doc.references)
    ? doc.references
        .filter((ref): ref is Record<string, unknown> => ref !== null && typeof ref === "object")
        .map((ref) => ({ type: str(ref.type), url: str(ref.url) }))
    : [];
  return {
    id,
    summary: str(doc.summary),
    details: str(doc.details),
    aliases: strArray(doc.aliases),
    modified: str(doc.modified),
    published: str(doc.published),
    withdrawn: str(doc.withdrawn),
    severity: severityList(doc.severity),
    affected,
    references,
    database_specific:
      doc.database_specific && typeof doc.database_specific === "object" && !Array.isArray(doc.database_specific)
        ? (doc.database_specific as Record<string, unknown>)
        : undefined,
  };
}

// ───────────────────────────── mapping ─────────────────────────────

function samePackage(affected: OsvAffected, name: string, ecosystem: string): boolean {
  const affectedName = affected.package?.name;
  const affectedEcosystem = affected.package?.ecosystem;
  if (!affectedName || !affectedEcosystem) return false;
  // OSV ecosystems may carry a release suffix (e.g. "Debian:12"); the base name must match.
  if (affectedEcosystem.split(":")[0] !== ecosystem.split(":")[0]) return false;
  if (affectedName === name) return true;
  // PyPI names are case-insensitive and treat -, _ and . as equivalent (PEP 503).
  if (ecosystem === "PyPI") {
    const normalize = (value: string) => value.toLowerCase().replace(/[-_.]+/g, "-");
    return normalize(affectedName) === normalize(name);
  }
  return false;
}

export interface DerivedSeverity {
  severity: Severity;
  severitySource: DependencyFindingDetails["severitySource"];
  cvssVector: string | null;
  cvssScore: number | null;
}

const DATABASE_SEVERITY: Record<string, Severity> = {
  LOW: "Low",
  MODERATE: "Medium",
  MEDIUM: "Medium",
  HIGH: "High",
  CRITICAL: "Critical",
};

/**
 * Severity precedence: `database_specific.severity` (GHSA-style LOW/MODERATE/HIGH/CRITICAL),
 * else the CVSS v3.x base score of a CVSS_V3 vector (record-level, then the matching
 * affected entry), else Unknown. Other vector types are kept but not scored.
 */
export function deriveSeverity(record: OsvRecord, pkg?: { name: string; ecosystem: string }): DerivedSeverity {
  const entries: OsvSeverityEntry[] = [...(record.severity ?? [])];
  if (pkg) {
    for (const affected of record.affected ?? []) {
      if (samePackage(affected, pkg.name, pkg.ecosystem)) entries.push(...(affected.severity ?? []));
    }
  }
  const v3Entries = entries.filter((entry) => entry.type === "CVSS_V3" && typeof entry.score === "string");
  const scored = v3Entries
    .map((entry) => cvss3BaseScore(entry.score as string))
    .filter((value): value is NonNullable<typeof value> => value !== null)
    .sort((a, b) => (a.version === b.version ? 0 : a.version === "3.1" ? -1 : 1));
  const best = scored[0] ?? null;
  const fallbackVector = best?.vector ?? entries.find((entry) => typeof entry.score === "string")?.score ?? null;

  const dbSeverity = record.database_specific?.severity;
  if (typeof dbSeverity === "string" && DATABASE_SEVERITY[dbSeverity.trim().toUpperCase()]) {
    return {
      severity: DATABASE_SEVERITY[dbSeverity.trim().toUpperCase()],
      severitySource: "database_specific",
      cvssVector: fallbackVector,
      cvssScore: best?.score ?? null,
    };
  }
  if (best) {
    return { severity: cvssRating(best.score), severitySource: "cvss_v3", cvssVector: best.vector, cvssScore: best.score };
  }
  return { severity: "Unknown", severitySource: "none", cvssVector: fallbackVector, cvssScore: null };
}

/** Every `fixed` event of the affected entries that match the package and ecosystem (unfiltered). */
export function allFixedVersions(record: OsvRecord, name: string, ecosystem: string): string[] {
  const fixed = new Set<string>();
  for (const affected of record.affected ?? []) {
    if (!samePackage(affected, name, ecosystem)) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return sortVersions([...fixed], comparatorFor("ECOSYSTEM", ecosystem));
}

export interface FixedVersions {
  fixedVersions: string[];
  /** Null when the list was filtered for the installed version; otherwise how it was built. */
  note: string | null;
}

/**
 * The fixes that apply to `version`: for every SEMVER/ECOSYSTEM range of the package that
 * contains the version, the `fixed` event closing that interval (none when the interval ends
 * with `last_affected` only). A record can list several ranges (e.g. one per release line), and
 * fixes of other ranges are not upgrades for this version, so they are left out. When no range
 * can be evaluated for the version, the unfiltered fixes newer than it (or all of them, when
 * even that cannot be decided) are returned with a note saying so.
 */
export function fixedVersionsFor(record: OsvRecord, name: string, ecosystem: string, version: string | null): FixedVersions {
  const all = allFixedVersions(record, name, ecosystem);
  if (!version) {
    return { fixedVersions: all, note: all.length > 0 ? "No version was given, so the fix versions of every affected range are listed." : null };
  }
  const fixes = new Set<string>();
  let contained = false;
  let unevaluable = false;
  for (const affected of record.affected ?? []) {
    if (!samePackage(affected, name, ecosystem)) continue;
    for (const range of affected.ranges ?? []) {
      if (range.type === "GIT") continue;
      const compare = comparatorFor(range.type, ecosystem);
      const verdict = compare ? evaluateRange(range.events ?? [], version, compare) : ({ evaluable: false } as const);
      if (!verdict.evaluable) {
        unevaluable = true;
        continue;
      }
      if (verdict.affected) {
        contained = true;
        if (verdict.fix) fixes.add(verdict.fix);
      }
    }
  }
  const ordering = comparatorFor("ECOSYSTEM", ecosystem);
  if (contained) {
    return {
      fixedVersions: sortVersions([...fixes], ordering),
      note: unevaluable ? `Some ranges of this advisory could not be evaluated for ${version}; fixes from those ranges are not listed.` : null,
    };
  }
  if (all.length === 0) return { fixedVersions: [], note: null };
  const newer = ordering ? all.filter((fix) => (ordering(fix, version) ?? 1) > 0) : all;
  const reason = unevaluable
    ? `Sentra cannot order the versions in every range of this advisory`
    : `OSV matched ${version}, but none of the advisory's ranges contains it (it may be listed by exact version)`;
  return {
    fixedVersions: newer,
    note: `${reason}; the listed fix versions${ordering && newer.length !== all.length ? ` (those newer than ${version})` : ""} come from every affected range and were not matched to the installed version.`,
  };
}

// ───────────────────────────── aliases ─────────────────────────────

/** Ecosystem-native advisory prefixes, preferred as the primary id of an alias group. */
const NATIVE_PREFIX: Record<string, string> = { "crates.io": "RUSTSEC-", PyPI: "PYSEC-", Go: "GO-" };

function primaryRank(id: string, ecosystem: string): number {
  const native = NATIVE_PREFIX[ecosystem.split(":")[0]];
  if (native && id.startsWith(native)) return 0;
  if (id.startsWith("GHSA-")) return 1;
  return 2;
}

/**
 * Groups records that describe the same vulnerability: OSV `aliases` name the same issue in
 * other databases, so records are joined when one lists the other's id or both list a shared
 * alias (e.g. one CVE). Each group is ordered with its primary record first: the
 * ecosystem-native advisory, else GHSA, else the lowest id, so the choice is stable across runs.
 */
export function groupAliases(records: readonly OsvRecord[], ecosystem: string): OsvRecord[][] {
  const parent = new Map<string, string>();
  const find = (token: string): string => {
    let root = token;
    while (parent.get(root) !== root) root = parent.get(root) as string;
    parent.set(token, root);
    return root;
  };
  const union = (a: string, b: string) => {
    const rootA = find(a);
    const rootB = find(b);
    if (rootA !== rootB) parent.set(rootB, rootA);
  };
  for (const record of records) {
    for (const token of [record.id, ...(record.aliases ?? [])]) if (!parent.has(token)) parent.set(token, token);
    for (const alias of record.aliases ?? []) union(record.id, alias);
  }
  const groups = new Map<string, OsvRecord[]>();
  for (const record of records) {
    const root = find(record.id);
    const group = groups.get(root) ?? [];
    if (!group.some((existing) => existing.id === record.id)) group.push(record);
    groups.set(root, group);
  }
  return [...groups.values()].map((group) =>
    group.sort((a, b) => primaryRank(a.id, ecosystem) - primaryRank(b.id, ecosystem) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  );
}

export function cwesOf(record: OsvRecord): string[] {
  return strArray(record.database_specific?.cwe_ids);
}

function referencesOf(record: OsvRecord): { type: string; url: string }[] {
  return (record.references ?? [])
    .filter((ref): ref is { type?: string; url: string } => typeof ref.url === "string" && /^https?:\/\//i.test(ref.url))
    .map((ref) => ({ type: ref.type ?? "WEB", url: ref.url }));
}

function affectedViews(record: OsvRecord): OsvAffectedView[] {
  return (record.affected ?? []).map((affected) => {
    const ranges: OsvAffectedView["ranges"] = [];
    for (const range of affected.ranges ?? []) {
      let current: OsvAffectedView["ranges"][number] | null = null;
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) {
          current = { type: range.type ?? "UNKNOWN", introduced: event.introduced, fixed: null, lastAffected: null };
          ranges.push(current);
          continue;
        }
        if (event.fixed === undefined && event.last_affected === undefined) continue;
        if (!current || current.fixed !== null || current.lastAffected !== null) {
          current = { type: range.type ?? "UNKNOWN", introduced: null, fixed: null, lastAffected: null };
          ranges.push(current);
        }
        if (event.fixed !== undefined) current.fixed = event.fixed;
        if (event.last_affected !== undefined) current.lastAffected = event.last_affected;
      }
    }
    return {
      ecosystem: affected.package?.ecosystem ?? "",
      package: affected.package?.name ?? "",
      ranges,
      versions: affected.versions ?? [],
    };
  });
}

export function toVulnerabilityView(record: OsvRecord, pkg?: { name: string; ecosystem: string; version?: string | null }): OsvVulnerabilityView {
  const severity = deriveSeverity(record, pkg);
  const fixes = pkg ? fixedVersionsFor(record, pkg.name, pkg.ecosystem, pkg.version ?? null) : { fixedVersions: [], note: null };
  return {
    id: record.id,
    summary: record.summary ?? null,
    details: record.details ?? null,
    aliases: record.aliases ?? [],
    severity: severity.severity,
    severitySource: severity.severitySource,
    cvssVector: severity.cvssVector,
    cvssScore: severity.cvssScore,
    published: record.published ?? null,
    modified: record.modified ?? null,
    withdrawn: record.withdrawn ?? null,
    affected: affectedViews(record),
    references: referencesOf(record),
    fixedVersions: fixes.fixedVersions,
    fixedVersionsNote: fixes.note,
    cwes: cwesOf(record),
  };
}

export interface DependencyAdvisory {
  details: DependencyFindingDetails;
  severity: Severity;
  cwes: string[];
}

function earliest(values: (string | undefined)[]): string | null {
  const known = values.filter((value): value is string => !!value && !Number.isNaN(Date.parse(value)));
  return known.length === 0 ? null : known.reduce((a, b) => (Date.parse(a) <= Date.parse(b) ? a : b));
}

function latest(values: (string | undefined)[]): string | null {
  const known = values.filter((value): value is string => !!value && !Number.isNaN(Date.parse(value)));
  return known.length === 0 ? null : known.reduce((a, b) => (Date.parse(a) >= Date.parse(b) ? a : b));
}

/**
 * Builds one dependency finding for an inventory package from an alias group (see
 * groupAliases; primary record first). The primary id is the advisory id and every other id
 * and alias is listed in `aliases`. Severity is the primary record's, or the first alias that
 * publishes one when the primary does not. Fix versions are those that apply to the installed
 * version, merged across the group; unfiltered lists are used only when no record could be
 * evaluated for the version, with the caveat in `fixedVersionsNote`.
 */
export function dependencyAdvisory(group: readonly OsvRecord[], pkg: DependencyPackageView & { ecosystem: string }): DependencyAdvisory {
  const [primary] = group;
  const target = { name: pkg.name, ecosystem: pkg.ecosystem };
  const rated = group.map((record) => ({ record, severity: deriveSeverity(record, target) }));
  const chosen = rated.find((entry) => entry.severity.severity !== "Unknown") ?? rated[0];
  const fixes = group.map((record) => fixedVersionsFor(record, pkg.name, pkg.ecosystem, pkg.version || null));
  const precise = fixes.filter((entry) => entry.note === null);
  const used = precise.length > 0 ? precise : fixes;
  const ordering = comparatorFor("ECOSYSTEM", pkg.ecosystem);
  const fixedVersions = sortVersions([...new Set(used.flatMap((entry) => entry.fixedVersions))], ordering);
  const aliases = [...new Set(group.flatMap((record) => [record.id, ...(record.aliases ?? [])]))].filter((id) => id !== primary.id).sort();
  const references = new Map<string, { type: string; url: string }>();
  for (const record of group) for (const reference of referencesOf(record)) if (!references.has(reference.url)) references.set(reference.url, reference);
  const cwes = [...new Set(group.flatMap((record) => cwesOf(record)))];
  return {
    severity: chosen.severity.severity,
    cwes,
    details: {
      packageName: pkg.name,
      packageVersion: pkg.version,
      ecosystem: pkg.ecosystem,
      lockfile: pkg.lockfile,
      advisoryId: primary.id,
      aliases,
      summary: group.find((record) => record.summary)?.summary ?? null,
      details: group.find((record) => record.details)?.details ?? null,
      fixedVersions,
      fixedVersionsNote: precise.length > 0 ? null : (used.find((entry) => entry.note !== null)?.note ?? null),
      references: [...references.values()],
      published: earliest(group.map((record) => record.published)),
      modified: latest(group.map((record) => record.modified)),
      severitySource: chosen.severity.severitySource,
      cvssVector: chosen.severity.cvssVector,
      cvssScore: chosen.severity.cvssScore,
    },
  };
}

/** DependencyFindingDetails for one inventory package matched by a single OSV record. */
export function dependencyDetails(record: OsvRecord, pkg: DependencyPackageView & { ecosystem: string }): DependencyFindingDetails {
  return dependencyAdvisory([record], pkg).details;
}

// ───────────────────────────── inventory ─────────────────────────────

/** Maps `sentra inventory --json` (snake_case) to the public inventory view. */
export function mapInventory(raw: unknown, generatedAt = nowIso()): DependencyInventoryView & { truncated: boolean } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new HttpError(502, "core_output_invalid", "sentra inventory did not print a JSON object");
  }
  const doc = raw as Record<string, unknown>;
  if (!Array.isArray(doc.lockfiles) || !Array.isArray(doc.packages)) {
    throw new HttpError(502, "core_output_invalid", "sentra inventory output is missing lockfiles or packages");
  }
  const lockfiles: LockfileView[] = doc.lockfiles
    .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object")
    .filter((entry) => typeof entry.path === "string")
    .map((entry) => ({
      path: (entry.path as string).replace(/\\/g, "/"),
      kind: str(entry.kind) ?? "unknown",
      ecosystem: str(entry.ecosystem) ?? null,
      packages: typeof entry.packages === "number" ? entry.packages : 0,
      parseError: str(entry.parse_error) ?? null,
    }));
  const packages: DependencyPackageView[] = doc.packages
    .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object")
    .filter((entry) => typeof entry.name === "string" && typeof entry.lockfile === "string")
    .map((entry) => ({
      name: entry.name as string,
      version: str(entry.version) ?? "",
      ecosystem: str(entry.ecosystem) ?? null,
      lockfile: (entry.lockfile as string).replace(/\\/g, "/"),
    }));
  return {
    lockfiles,
    packages,
    totalPackages: typeof doc.total_packages === "number" ? doc.total_packages : packages.length,
    generatedAt,
    truncated: doc.truncated === true,
  };
}

// ───────────────────────────── client ─────────────────────────────

export interface OsvLookupResult {
  /** Records per query, in query order (withdrawn records included). */
  perQuery: OsvRecord[][];
  fetchedRecords: number;
  cachedRecords: number;
  queriedAt: string;
}

export class OsvClient {
  private readonly db: Database;
  private readonly settings: SettingsStore;
  private readonly fetcher: OsvFetcher;

  constructor(db: Database, settings: SettingsStore, fetcher: OsvFetcher = defaultOsvFetcher) {
    this.db = db;
    this.settings = settings;
    this.fetcher = fetcher;
  }

  private parse(text: string, what: string): unknown {
    try {
      return JSON.parse(text);
    } catch {
      throw new HttpError(502, "osv_invalid_response", `OSV.dev returned invalid JSON for ${what}`);
    }
  }

  /** POST /v1/querybatch in chunks of at most 1000, following next_page_token per query. */
  async queryBatch(queries: OsvPackageQuery[]): Promise<OsvVulnRef[][]> {
    const results: OsvVulnRef[][] = queries.map(() => []);
    let pending = queries.map((query, index) => ({ index, query, pageToken: null as string | null, pages: 0 }));
    while (pending.length > 0) {
      const next: typeof pending = [];
      for (let offset = 0; offset < pending.length; offset += BATCH_LIMIT) {
        const chunk = pending.slice(offset, offset + BATCH_LIMIT);
        const body = JSON.stringify({
          queries: chunk.map(({ query, pageToken }) => ({
            package: { name: query.name, ecosystem: query.ecosystem },
            ...(query.version ? { version: query.version } : {}),
            ...(pageToken ? { page_token: pageToken } : {}),
          })),
        });
        const response = await this.fetcher(`${OSV_ENDPOINT}/v1/querybatch`, { method: "POST", body });
        if (response.status !== 200) {
          throw new HttpError(502, "osv_unavailable", `OSV.dev querybatch returned HTTP ${response.status}`);
        }
        const parsed = this.parse(response.text, "querybatch") as { results?: unknown };
        if (!Array.isArray(parsed.results) || parsed.results.length !== chunk.length) {
          throw new HttpError(502, "osv_invalid_response", "OSV.dev querybatch returned an unexpected number of results");
        }
        parsed.results.forEach((entry, position) => {
          const item = chunk[position];
          const result = entry && typeof entry === "object" ? (entry as Record<string, unknown>) : {};
          if (Array.isArray(result.vulns)) {
            for (const vuln of result.vulns) {
              const ref = vuln && typeof vuln === "object" ? (vuln as Record<string, unknown>) : {};
              const id = str(ref.id);
              if (id && VULN_ID_PATTERN.test(id)) results[item.index].push({ id, modified: str(ref.modified) ?? null });
            }
          }
          const token = str(result.next_page_token);
          if (token) {
            if (item.pages + 1 >= MAX_PAGES_PER_QUERY) {
              throw new HttpError(502, "osv_pagination_limit", `OSV.dev pagination exceeded ${MAX_PAGES_PER_QUERY} pages for ${item.query.name}`);
            }
            next.push({ ...item, pageToken: token, pages: item.pages + 1 });
          }
        });
      }
      pending = next;
    }
    this.settings.set(LAST_QUERY_KEY, { at: nowIso() }, "system");
    return results.map((refs) => {
      const byId = new Map<string, OsvVulnRef>();
      for (const ref of refs) if (!byId.has(ref.id)) byId.set(ref.id, ref);
      return [...byId.values()];
    });
  }

  private cached(id: string): { record: OsvRecord; modified: string | null } | null {
    const row = this.db.query("SELECT modified, record_json FROM osv_cache WHERE vuln_id = ?").get(id) as {
      modified: string | null;
      record_json: string;
    } | null;
    if (!row) return null;
    const record = sanitizeOsvRecord(parseJsonColumn<unknown>(row.record_json, null));
    return record ? { record, modified: row.modified } : null;
  }

  private async fetchRecord(id: string): Promise<OsvRecord> {
    const response = await this.fetcher(`${OSV_ENDPOINT}/v1/vulns/${encodeURIComponent(id)}`, { method: "GET" });
    if (response.status !== 200) {
      throw new HttpError(502, "osv_unavailable", `OSV.dev returned HTTP ${response.status} for ${id}`);
    }
    const record = sanitizeOsvRecord(this.parse(response.text, id));
    if (!record || record.id !== id) {
      throw new HttpError(502, "osv_invalid_response", `OSV.dev returned an unexpected record for ${id}`);
    }
    this.db
      .query(
        `INSERT INTO osv_cache (vuln_id, modified, fetched_at, record_json) VALUES (?, ?, ?, ?)
         ON CONFLICT(vuln_id) DO UPDATE SET modified = excluded.modified, fetched_at = excluded.fetched_at, record_json = excluded.record_json`,
      )
      .run(id, record.modified ?? null, nowIso(), JSON.stringify(record));
    return record;
  }

  /**
   * GET /v1/vulns/{id} with at most 8 concurrent requests. A cached record is reused unless
   * querybatch reports a newer `modified` timestamp.
   */
  async records(refs: OsvVulnRef[]): Promise<{ records: Map<string, OsvRecord>; fetched: number; cached: number }> {
    const unique = new Map<string, string | null>();
    for (const ref of refs) {
      const known = unique.get(ref.id);
      if (!unique.has(ref.id) || (ref.modified && (!known || ref.modified > known))) unique.set(ref.id, ref.modified);
    }
    const records = new Map<string, OsvRecord>();
    const toFetch: string[] = [];
    let cached = 0;
    for (const [id, modified] of unique) {
      const hit = this.cached(id);
      const stale =
        hit !== null && modified !== null && (hit.modified === null || Date.parse(modified) > Date.parse(hit.modified));
      if (hit && !stale) {
        records.set(id, hit.record);
        cached += 1;
      } else {
        toFetch.push(id);
      }
    }
    let cursor = 0;
    const worker = async () => {
      while (cursor < toFetch.length) {
        const id = toFetch[cursor];
        cursor += 1;
        records.set(id, await this.fetchRecord(id));
      }
    };
    await Promise.all(Array.from({ length: Math.min(VULN_CONCURRENCY, toFetch.length) }, worker));
    return { records, fetched: toFetch.length, cached };
  }

  async lookup(queries: OsvPackageQuery[]): Promise<OsvLookupResult> {
    if (queries.length === 0) return { perQuery: [], fetchedRecords: 0, cachedRecords: 0, queriedAt: nowIso() };
    const refs = await this.queryBatch(queries);
    const queriedAt = nowIso();
    const { records, fetched, cached } = await this.records(refs.flat());
    return {
      perQuery: refs.map((list) => list.map((ref) => records.get(ref.id)).filter((record): record is OsvRecord => record !== undefined)),
      fetchedRecords: fetched,
      cachedRecords: cached,
      queriedAt,
    };
  }

  cachedCount(): number {
    return (this.db.query("SELECT COUNT(*) AS c FROM osv_cache").get() as { c: number }).c;
  }

  lastQueryAt(): string | null {
    const value = this.settings.get<{ at?: unknown } | null>(LAST_QUERY_KEY, null);
    return typeof value?.at === "string" ? value.at : null;
  }
}

// ───────────────────────────── dependency audit over an inventory ─────────────────────────────

export interface DependencyAuditResult {
  candidates: CandidateFinding[];
  /** Distinct (ecosystem, name, version) triples sent to OSV. */
  packagesAudited: number;
  /** Inventory entries without an OSV ecosystem or version (not queryable). */
  packagesSkipped: number;
  vulnerablePackages: number;
  /** Distinct package/vulnerability pairs; aliased records count once (withdrawn records excluded). */
  vulnerabilities: number;
  withdrawnSkipped: number;
  fetchedRecords: number;
  cachedRecords: number;
  queriedAt: string;
}

/**
 * Ecosystems the core inventory can emit that OSV indexes. Anything else (e.g. Deno "JSR"
 * packages) is never sent to OSV and is counted as skipped instead of reported as clean.
 */
export const OSV_QUERYABLE_ECOSYSTEMS: ReadonlySet<string> = new Set(["crates.io", "npm", "PyPI", "Go", "Packagist", "NuGet", "RubyGems"]);

function isQueryable(pkg: DependencyPackageView): pkg is DependencyPackageView & { ecosystem: string } {
  return !!pkg.ecosystem && !!pkg.version && OSV_QUERYABLE_ECOSYSTEMS.has(pkg.ecosystem);
}

/** Queries OSV for every queryable inventory package and builds dependency candidates. */
export async function auditDependencies(client: OsvClient, packages: DependencyPackageView[]): Promise<DependencyAuditResult> {
  const queryIndex = new Map<string, number>();
  const queries: OsvPackageQuery[] = [];
  let skipped = 0;
  for (const pkg of packages) {
    if (!isQueryable(pkg)) {
      skipped += 1;
      continue;
    }
    const key = `${pkg.ecosystem}\u0000${pkg.name}\u0000${pkg.version}`;
    if (!queryIndex.has(key)) {
      queryIndex.set(key, queries.length);
      queries.push({ name: pkg.name, ecosystem: pkg.ecosystem, version: pkg.version });
    }
  }
  const lookup = await client.lookup(queries);
  const candidates: CandidateFinding[] = [];
  const vulnerable = new Set<string>();
  const pairs = new Set<string>();
  let withdrawnSkipped = 0;
  for (const pkg of packages) {
    if (!isQueryable(pkg)) continue;
    const key = `${pkg.ecosystem}\u0000${pkg.name}\u0000${pkg.version}`;
    const records = lookup.perQuery[queryIndex.get(key) as number] ?? [];
    const active = records.filter((record) => !record.withdrawn);
    withdrawnSkipped += records.length - active.length;
    // Aliased records (e.g. a GHSA and a RUSTSEC entry for one CVE) become one finding.
    for (const group of groupAliases(active, pkg.ecosystem)) {
      const advisory = dependencyAdvisory(group, { ...pkg, ecosystem: pkg.ecosystem });
      candidates.push(dependencyCandidate(advisory.details, advisory.severity, advisory.cwes));
      vulnerable.add(key);
      pairs.add(`${key}\u0000${advisory.details.advisoryId}`);
    }
  }
  return {
    candidates,
    packagesAudited: queries.length,
    packagesSkipped: skipped,
    vulnerablePackages: vulnerable.size,
    vulnerabilities: pairs.size,
    withdrawnSkipped,
    fetchedRecords: lookup.fetchedRecords,
    cachedRecords: lookup.cachedRecords,
    queriedAt: lookup.queriedAt,
  };
}

// ───────────────────────────── service ─────────────────────────────

export interface OsvServiceDeps {
  settings: SettingsStore;
  client: OsvClient;
  /** Runs `sentra inventory --workspace <dir> --json` and returns its parsed JSON. */
  runInventory: (workspace: string, signal?: AbortSignal) => Promise<unknown>;
}

export function osvDisabledError(): HttpError {
  return new HttpError(
    412,
    "osv_disabled",
    "OSV lookups are disabled by policy. An admin can enable them under Settings > Threat intelligence.",
  );
}

export function createOsvServiceFrom(deps: OsvServiceDeps): OsvService {
  const enabled = () => deps.settings.get<{ enabled?: unknown }>(SETTING_KEY, { enabled: false }).enabled === true;
  const status = (): IntelStatusView => {
    const meta = deps.settings.meta(SETTING_KEY);
    return {
      osvEnabled: enabled(),
      changedBy: meta?.updatedBy ?? null,
      changedAt: meta?.updatedAt ?? null,
      endpoint: OSV_ENDPOINT,
      cachedAdvisories: deps.client.cachedCount(),
      lastQueryAt: deps.client.lastQueryAt(),
      privacyNote: OSV_PRIVACY_NOTE,
    };
  };
  return {
    enabled,
    status,
    setEnabled(value: boolean, actor: ActorRef): IntelStatusView {
      deps.settings.set(SETTING_KEY, { enabled: value }, actor.label);
      return status();
    },
    async query(pkg: string, ecosystem: string, version: string | null): Promise<OsvQueryResponse> {
      if (!enabled()) throw osvDisabledError();
      const lookup = await deps.client.lookup([{ name: pkg, ecosystem, version }]);
      const vulnerabilities = (lookup.perQuery[0] ?? [])
        .map((record) => toVulnerabilityView(record, { name: pkg, ecosystem, version }))
        .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id));
      return { package: pkg, ecosystem, version, vulnerabilities, queriedAt: lookup.queriedAt };
    },
    async inventory(workspace: string, signal?: AbortSignal): Promise<DependencyInventoryView> {
      return mapInventory(await deps.runInventory(workspace, signal));
    },
  };
}

/**
 * Runs the core lockfile inventory (read-only). Exposed with the `truncated` flag so the
 * scan pipeline can report an incomplete inventory; the public view does not carry it yet.
 */
export async function readInventory(
  app: Pick<AppContext, "cli" | "config">,
  workspace: string,
  signal?: AbortSignal,
): Promise<DependencyInventoryView & { truncated: boolean }> {
  const json = await app.cli.runJson(["inventory", "--workspace", cliValue(workspace, "workspace"), "--json"], {
    timeoutMs: app.config.cliLongTimeoutMs,
    signal,
  });
  return mapInventory(json);
}

/** Read views reuse one inventory run per workspace for this long (scans always run their own). */
export const INVENTORY_VIEW_TTL_MS = 30_000;

export function createOsvService(app: Omit<AppContext, "osv" | "scans">): OsvService {
  return createOsvServiceFrom({
    settings: app.settings,
    client: new OsvClient(app.db, app.settings),
    runInventory: async (workspace, signal) =>
      requireJson(
        "inventory",
        await app.cli.runShared(["inventory", "--workspace", cliValue(workspace, "workspace"), "--json"], {
          ttlMs: INVENTORY_VIEW_TTL_MS,
          timeoutMs: app.config.cliLongTimeoutMs,
          signal,
        }),
      ),
  });
}
