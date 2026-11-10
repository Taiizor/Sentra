import type { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openWebDb } from "../db.ts";
import { HttpError } from "../http-error.ts";
import { cvss3BaseScore, cvssRating, cvssRoundup } from "../services/cvss.ts";
import {
  allFixedVersions,
  auditDependencies,
  createOsvServiceFrom,
  dependencyAdvisory,
  deriveSeverity,
  fixedVersionsFor,
  groupAliases,
  mapInventory,
  OSV_PRIVACY_NOTE,
  OsvClient,
  sanitizeOsvRecord,
  toVulnerabilityView,
  type OsvFetcher,
  type OsvRecord,
} from "../services/osv.ts";
import { DEPENDENCY_CATEGORY } from "../services/findings.ts";
import { comparePep440, compareSemver, evaluateRange } from "../services/osv-versions.ts";
import { SettingsStore } from "../services/settings-store.ts";

const cleanup: { dirs: string[]; dbs: Database[] } = { dirs: [], dbs: [] };

afterAll(() => {
  for (const db of cleanup.dbs) {
    try {
      db.close();
    } catch {
      // already closed
    }
  }
  for (const dir of cleanup.dirs) fs.rmSync(dir, { recursive: true, force: true });
});

function tempDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentra-osv-"));
  const db = openWebDb(path.join(dir, "web.db"));
  cleanup.dirs.push(dir);
  cleanup.dbs.push(db);
  return { db, settings: new SettingsStore(db) };
}

function record(partial: Partial<OsvRecord> & { id: string }): OsvRecord {
  return sanitizeOsvRecord(partial) as OsvRecord;
}

/** In-memory OSV double: querybatch answers from `vulnsFor`, vulns/{id} from `records`. */
function fakeOsv(options: {
  vulnsFor: (query: { name: string; ecosystem: string; version?: string; page_token?: string }) => {
    vulns?: { id: string; modified?: string }[];
    next_page_token?: string;
  };
  records: Record<string, unknown>;
  delayMs?: number;
}) {
  const calls = { batch: [] as number[], vuln: [] as string[], maxInFlight: 0 };
  let inFlight = 0;
  const fetcher: OsvFetcher = async (url, init) => {
    if (url.endsWith("/v1/querybatch")) {
      const body = JSON.parse(init.body ?? "{}") as { queries: { package: { name: string; ecosystem: string }; version?: string; page_token?: string }[] };
      calls.batch.push(body.queries.length);
      const results = body.queries.map((query) =>
        options.vulnsFor({ name: query.package.name, ecosystem: query.package.ecosystem, version: query.version, page_token: query.page_token }),
      );
      return { status: 200, text: JSON.stringify({ results }) };
    }
    const id = decodeURIComponent(url.slice(url.lastIndexOf("/") + 1));
    calls.vuln.push(id);
    inFlight += 1;
    calls.maxInFlight = Math.max(calls.maxInFlight, inFlight);
    await new Promise((resolve) => setTimeout(resolve, options.delayMs ?? 1));
    inFlight -= 1;
    const found = options.records[id];
    return found ? { status: 200, text: JSON.stringify(found) } : { status: 404, text: "{}" };
  };
  return { fetcher, calls };
}

describe("CVSS v3.1 base score", () => {
  test("matches the reference scores from the specification examples", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.score).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")?.score).toBe(6.1);
    expect(cvss3BaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")?.score).toBe(7.8);
  });

  test("handles scope change, zero impact and v3.0 vectors", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")?.score).toBe(10);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")?.score).toBe(0);
    const v30 = cvss3BaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(v30).toEqual({ version: "3.0", score: 9.8, vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" });
    // Temporal metrics are accepted and ignored for the base score.
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O")?.score).toBe(9.8);
  });

  test("rejects malformed vectors", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull();
    expect(cvss3BaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeNull();
  });

  test("Roundup and qualitative rating follow the specification", () => {
    expect(cvssRoundup(4.0)).toBe(4.0);
    expect(cvssRoundup(4.02)).toBe(4.1);
    expect(cvssRoundup(4.000001)).toBe(4.0);
    expect(cvssRating(0)).toBe("Informational");
    expect(cvssRating(0.1)).toBe("Low");
    expect(cvssRating(3.9)).toBe("Low");
    expect(cvssRating(4.0)).toBe("Medium");
    expect(cvssRating(6.9)).toBe("Medium");
    expect(cvssRating(7.0)).toBe("High");
    expect(cvssRating(8.9)).toBe("High");
    expect(cvssRating(9.0)).toBe("Critical");
    expect(cvssRating(11)).toBe("Unknown");
  });
});

describe("OSV record mapping", () => {
  const ghsa = record({
    id: "GHSA-vh95-rmgr-6w4m",
    summary: "Prototype Pollution in minimist",
    aliases: ["CVE-2020-7598"],
    modified: "2024-01-01T00:00:00Z",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    affected: [
      {
        package: { name: "minimist", ecosystem: "npm" },
        ranges: [
          { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.2.1" }, { introduced: "1.0.0" }, { fixed: "1.2.3" }] },
        ],
      },
      { package: { name: "other", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
    ],
    references: [{ type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2020-7598" }, { type: "WEB", url: "javascript:alert(1)" }],
    database_specific: { severity: "MODERATE", cwe_ids: ["CWE-1321"] },
  });

  test("database_specific severity wins and the CVSS vector is still reported", () => {
    expect(deriveSeverity(ghsa)).toEqual({
      severity: "Medium",
      severitySource: "database_specific",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      cvssScore: 9.8,
    });
  });

  test("falls back to the CVSS v3 score, then Unknown with the vector kept", () => {
    const rustsec = record({
      id: "RUSTSEC-2020-0071",
      affected: [
        {
          package: { name: "time", ecosystem: "crates.io" },
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" }],
        },
      ],
    });
    expect(deriveSeverity(rustsec, { name: "time", ecosystem: "crates.io" })).toMatchObject({ severity: "High", severitySource: "cvss_v3", cvssScore: 7.8 });
    const v4 = record({ id: "X-1", severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }] });
    expect(deriveSeverity(v4)).toEqual({
      severity: "Unknown",
      severitySource: "none",
      cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      cvssScore: null,
    });
    expect(deriveSeverity(record({ id: "X-2" }))).toEqual({ severity: "Unknown", severitySource: "none", cvssVector: null, cvssScore: null });
  });

  test("fixed versions come only from affected entries of the same package", () => {
    expect(allFixedVersions(ghsa, "minimist", "npm")).toEqual(["0.2.1", "1.2.3"]);
    expect(allFixedVersions(ghsa, "minimist", "PyPI")).toEqual([]);
    const pypi = record({
      id: "PYSEC-1",
      affected: [{ package: { name: "Django_Rest", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }] }],
    });
    expect(fixedVersionsFor(pypi, "django-rest", "PyPI", "1.9")).toEqual({ fixedVersions: ["2.0"], note: null });
  });

  test("only the fix of the range that contains the installed version is offered", () => {
    expect(fixedVersionsFor(ghsa, "minimist", "npm", "1.2.0")).toEqual({ fixedVersions: ["1.2.3"], note: null });
    expect(fixedVersionsFor(ghsa, "minimist", "npm", "0.1.0")).toEqual({ fixedVersions: ["0.2.1"], note: null });
    // RUSTSEC-2020-0071 (time) as published: one range per patched 0.2.x release, then 0.2.7..0.2.23.
    const rustsec = record({
      id: "RUSTSEC-2020-0071",
      affected: [
        {
          package: { name: "time", ecosystem: "crates.io" },
          ranges: [
            {
              type: "SEMVER",
              events: [
                { introduced: "0.0.0-0" },
                { fixed: "0.2.0" },
                { introduced: "0.2.1-0" },
                { fixed: "0.2.1" },
                { introduced: "0.2.2-0" },
                { fixed: "0.2.2" },
                { introduced: "0.2.3-0" },
                { fixed: "0.2.3" },
                { introduced: "0.2.4-0" },
                { fixed: "0.2.4" },
                { introduced: "0.2.5-0" },
                { fixed: "0.2.5" },
                { introduced: "0.2.6-0" },
                { fixed: "0.2.6" },
                { introduced: "0.2.7-0" },
                { fixed: "0.2.23" },
              ],
            },
          ],
        },
      ],
    });
    expect(fixedVersionsFor(rustsec, "time", "crates.io", "0.2.10")).toEqual({ fixedVersions: ["0.2.23"], note: null });
    expect(fixedVersionsFor(rustsec, "time", "crates.io", "0.1.43")).toEqual({ fixedVersions: ["0.2.0"], note: null });
    // GHSA-xvch-5gv4-984h (minimist): one ECOSYSTEM range per release line.
    const minimist = record({
      id: "GHSA-xvch-5gv4-984h",
      affected: [
        { package: { name: "minimist", ecosystem: "npm" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "0.2.4" }] }] },
        { package: { name: "minimist", ecosystem: "npm" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "1.2.6" }] }] },
      ],
    });
    expect(fixedVersionsFor(minimist, "minimist", "npm", "1.2.0")).toEqual({ fixedVersions: ["1.2.6"], note: null });
  });

  test("an interval closed by last_affected has no fix; unorderable versions are flagged, not guessed", () => {
    const lastAffected = record({
      id: "GHSA-last",
      affected: [{ package: { name: "pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { last_affected: "1.4.0" }] }] }],
    });
    expect(fixedVersionsFor(lastAffected, "pkg", "npm", "1.2.0")).toEqual({ fixedVersions: [], note: null });
    const maven = record({
      id: "GHSA-maven",
      affected: [
        { package: { name: "g:a", ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0.0.Final" }] }] },
      ],
    });
    const result = fixedVersionsFor(maven, "g:a", "Maven", "1.0.0.Final");
    expect(result.fixedVersions).toEqual(["2.0.0.Final"]);
    expect(result.note).toContain("cannot order");
    // Listed only by exact version: the fixes are shown, newer than the installed version, with the caveat.
    const enumerated = record({
      id: "GHSA-enum",
      affected: [
        {
          package: { name: "pkg", ecosystem: "npm" },
          versions: ["1.0.5"],
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.9.0" }, { introduced: "2.0.0" }, { fixed: "2.1.0" }] }],
        },
      ],
    });
    const listed = fixedVersionsFor(enumerated, "pkg", "npm", "1.0.5");
    expect(listed.fixedVersions).toEqual(["2.1.0"]);
    expect(listed.note).toContain("none of the advisory's ranges contains it");
  });

  test("version ordering follows SemVer 2.0.0 and PEP 440", () => {
    expect(compareSemver("1.0.0-alpha", "1.0.0")).toBe(-1);
    expect(compareSemver("1.0.0-alpha.1", "1.0.0-alpha.beta")).toBe(-1);
    expect(compareSemver("1.0.0-beta.11", "1.0.0-beta.2")).toBe(1);
    expect(compareSemver("v1.2.3", "1.2.3+build.5")).toBe(0);
    expect(compareSemver("0.0.0-0", "0.0.0")).toBe(-1);
    expect(compareSemver("1.2", "1.2.0")).toBe(0);
    expect(compareSemver("not-a-version", "1.0.0")).toBeNull();
    expect(comparePep440("1.0.dev1", "1.0a1")).toBe(-1);
    expect(comparePep440("1.0a1", "1.0rc1")).toBe(-1);
    expect(comparePep440("1.0rc1", "1.0")).toBe(-1);
    expect(comparePep440("1.0", "1.0.post1")).toBe(-1);
    expect(comparePep440("1.0", "1.0.0")).toBe(0);
    expect(comparePep440("1!0.5", "2.0")).toBe(1);
    expect(comparePep440("2.0+local", "2.0")).toBeNull();
    expect(evaluateRange([{ introduced: "0" }, { fixed: "2.0" }], "2.0rc1", comparePep440)).toEqual({ evaluable: true, affected: true, fix: "2.0" });
    expect(evaluateRange([{ introduced: "1.0" }, { limit: "1.5" }], "1.6", comparePep440)).toEqual({ evaluable: true, affected: false });
  });

  test("vulnerability view pairs range events and filters non-http references", () => {
    const view = toVulnerabilityView(ghsa, { name: "minimist", ecosystem: "npm" });
    expect(view.affected[0].ranges).toEqual([
      { type: "SEMVER", introduced: "0", fixed: "0.2.1", lastAffected: null },
      { type: "SEMVER", introduced: "1.0.0", fixed: "1.2.3", lastAffected: null },
    ]);
    expect(view.references).toEqual([{ type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2020-7598" }]);
    expect(view.cwes).toEqual(["CWE-1321"]);
    // Without a version every range's fix is listed, and the view says so.
    expect(view.fixedVersions).toEqual(["0.2.1", "1.2.3"]);
    expect(view.fixedVersionsNote).toContain("No version was given");
    const forVersion = toVulnerabilityView(ghsa, { name: "minimist", ecosystem: "npm", version: "1.2.0" });
    expect(forVersion.fixedVersions).toEqual(["1.2.3"]);
    expect(forVersion.fixedVersionsNote).toBeNull();
    expect(view.withdrawn).toBeNull();
  });

  test("aliased records are grouped under the ecosystem-native advisory", () => {
    const github = record({
      id: "GHSA-wcg3-cvx6-7396",
      aliases: ["CVE-2020-26235", "RUSTSEC-2020-0071"],
      summary: "Segmentation fault in time",
      database_specific: { severity: "MODERATE" },
      affected: [{ package: { name: "time", ecosystem: "crates.io" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0.2.7" }, { fixed: "0.2.23" }] }] }],
    });
    const rustsec = record({
      id: "RUSTSEC-2020-0071",
      aliases: ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
      summary: "Potential segfault in the time crate",
      published: "2020-11-18T12:00:00Z",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
      affected: [{ package: { name: "time", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0.2.7-0" }, { fixed: "0.2.23" }] }] }],
    });
    const unrelated = record({ id: "RUSTSEC-2099-0001", affected: [{ package: { name: "time", ecosystem: "crates.io" } }] });
    const groups = groupAliases([github, rustsec, unrelated], "crates.io");
    expect(groups.map((group) => group.map((entry) => entry.id))).toEqual([["RUSTSEC-2020-0071", "GHSA-wcg3-cvx6-7396"], ["RUSTSEC-2099-0001"]]);
    const advisory = dependencyAdvisory(groups[0], { name: "time", version: "0.2.10", ecosystem: "crates.io", lockfile: "Cargo.lock" });
    expect(advisory.details).toMatchObject({
      advisoryId: "RUSTSEC-2020-0071",
      aliases: ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
      summary: "Potential segfault in the time crate",
      fixedVersions: ["0.2.23"],
      fixedVersionsNote: null,
      severitySource: "cvss_v3",
      published: "2020-11-18T12:00:00Z",
    });
    // Records joined only through a shared CVE alias are one vulnerability as well.
    const viaCve = groupAliases(
      [record({ id: "GHSA-a", aliases: ["CVE-1"] }), record({ id: "GHSA-b", aliases: ["CVE-1"] }), record({ id: "GHSA-c" })],
      "npm",
    );
    expect(viaCve.map((group) => group.map((entry) => entry.id))).toEqual([["GHSA-a", "GHSA-b"], ["GHSA-c"]]);
  });

  test("sanitizer rejects documents without an id", () => {
    expect(sanitizeOsvRecord({ summary: "x" })).toBeNull();
    expect(sanitizeOsvRecord("nope")).toBeNull();
  });
});

describe("inventory mapping", () => {
  test("maps the core snake_case contract", () => {
    const view = mapInventory(
      {
        schema_version: 1,
        command: "inventory",
        workspace: "C:/ws",
        lockfiles: [
          { path: "web/bun.lock", kind: "Bun", ecosystem: "npm", packages: 2, parse_error: null },
          { path: "broken/Cargo.lock", kind: "Cargo", ecosystem: "crates.io", packages: 0, parse_error: "unexpected token" },
        ],
        packages: [
          { name: "react", version: "19.3.1", ecosystem: "npm", lockfile: "web/bun.lock" },
          { name: "mystery", version: "1.0.0", ecosystem: null, lockfile: "web/bun.lock" },
        ],
        total_packages: 2,
        truncated: false,
        untrusted_execution: false,
      },
      "2026-11-10T00:00:00.000Z",
    );
    expect(view).toEqual({
      lockfiles: [
        { path: "web/bun.lock", kind: "Bun", ecosystem: "npm", packages: 2, parseError: null },
        { path: "broken/Cargo.lock", kind: "Cargo", ecosystem: "crates.io", packages: 0, parseError: "unexpected token" },
      ],
      packages: [
        { name: "react", version: "19.3.1", ecosystem: "npm", lockfile: "web/bun.lock" },
        { name: "mystery", version: "1.0.0", ecosystem: null, lockfile: "web/bun.lock" },
      ],
      totalPackages: 2,
      generatedAt: "2026-11-10T00:00:00.000Z",
      truncated: false,
    });
    expect(() => mapInventory({ error: "invalid_workspace" })).toThrow(HttpError);
  });
});

describe("OSV client", () => {
  test("chunks querybatch at 1000 queries and follows next_page_token per query", async () => {
    const { db, settings } = tempDb();
    const { fetcher, calls } = fakeOsv({
      vulnsFor: (query) => {
        if (query.name === "pkg-0" && !query.page_token) return { vulns: [{ id: "OSV-A", modified: "2024-01-01T00:00:00Z" }], next_page_token: "p2" };
        if (query.name === "pkg-0" && query.page_token === "p2") return { vulns: [{ id: "OSV-B", modified: "2024-01-01T00:00:00Z" }] };
        return {};
      },
      records: {},
    });
    const client = new OsvClient(db, settings, fetcher);
    const queries = Array.from({ length: 1001 }, (_, index) => ({ name: `pkg-${index}`, ecosystem: "npm", version: "1.0.0" }));
    const refs = await client.queryBatch(queries);
    expect(calls.batch).toEqual([1000, 1, 1]);
    expect(refs[0].map((ref) => ref.id)).toEqual(["OSV-A", "OSV-B"]);
    expect(refs[1]).toEqual([]);
    expect(client.lastQueryAt()).not.toBeNull();
  });

  test("fetches records with at most 8 concurrent requests and reuses the cache", async () => {
    const { db, settings } = tempDb();
    const ids = Array.from({ length: 20 }, (_, index) => `OSV-${index}`);
    const records = Object.fromEntries(ids.map((id) => [id, { id, modified: "2024-01-01T00:00:00Z", summary: `summary ${id}` }]));
    const { fetcher, calls } = fakeOsv({ vulnsFor: () => ({}), records, delayMs: 5 });
    const client = new OsvClient(db, settings, fetcher);
    const first = await client.records(ids.map((id) => ({ id, modified: "2024-01-01T00:00:00Z" })));
    expect(first.fetched).toBe(20);
    expect(first.records.get("OSV-3")?.summary).toBe("summary OSV-3");
    expect(calls.maxInFlight).toBeLessThanOrEqual(8);
    expect(calls.maxInFlight).toBeGreaterThan(1);
    expect(client.cachedCount()).toBe(20);

    const second = await client.records([{ id: "OSV-1", modified: "2024-01-01T00:00:00Z" }]);
    expect(second).toMatchObject({ fetched: 0, cached: 1 });

    records["OSV-1"] = { id: "OSV-1", modified: "2025-06-01T00:00:00Z", summary: "updated" };
    const third = await client.records([{ id: "OSV-1", modified: "2025-06-01T00:00:00Z" }]);
    expect(third.fetched).toBe(1);
    expect(third.records.get("OSV-1")?.summary).toBe("updated");
  });

  test("upstream errors fail loudly instead of reporting no vulnerabilities", async () => {
    const { db, settings } = tempDb();
    const failing: OsvFetcher = async () => ({ status: 503, text: "unavailable" });
    const client = new OsvClient(db, settings, failing);
    await expect(client.queryBatch([{ name: "a", ecosystem: "npm", version: "1.0.0" }])).rejects.toMatchObject({ status: 502, code: "osv_unavailable" });
    const { fetcher } = fakeOsv({ vulnsFor: () => ({ vulns: [{ id: "OSV-GONE" }] }), records: {} });
    const missing = new OsvClient(db, settings, fetcher);
    await expect(missing.lookup([{ name: "a", ecosystem: "npm", version: "1.0.0" }])).rejects.toBeInstanceOf(HttpError);
  });
});

describe("dependency audit", () => {
  test("builds candidates per lockfile package, skips withdrawn and unqueryable entries", async () => {
    const { db, settings } = tempDb();
    const { fetcher } = fakeOsv({
      vulnsFor: (query) =>
        query.name === "minimist" ? { vulns: [{ id: "GHSA-vh95-rmgr-6w4m" }, { id: "GHSA-old" }] } : query.name === "time" ? { vulns: [{ id: "RUSTSEC-2020-0071" }] } : {},
      records: {
        "GHSA-vh95-rmgr-6w4m": {
          id: "GHSA-vh95-rmgr-6w4m",
          summary: "Prototype Pollution in minimist",
          affected: [{ package: { name: "minimist", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }] }],
          database_specific: { severity: "MODERATE", cwe_ids: ["CWE-1321"] },
        },
        "GHSA-old": { id: "GHSA-old", withdrawn: "2023-01-01T00:00:00Z" },
        "RUSTSEC-2020-0071": {
          id: "RUSTSEC-2020-0071",
          summary: "Potential segfault in the time crate",
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
          affected: [{ package: { name: "time", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0.2.7" }, { fixed: "0.2.23" }] }] }],
        },
      },
    });
    const client = new OsvClient(db, settings, fetcher);
    const result = await auditDependencies(client, [
      { name: "minimist", version: "1.2.0", ecosystem: "npm", lockfile: "package-lock.json" },
      { name: "minimist", version: "1.2.0", ecosystem: "npm", lockfile: "web/package-lock.json" },
      { name: "time", version: "0.2.10", ecosystem: "crates.io", lockfile: "Cargo.lock" },
      { name: "serde", version: "1.0.0", ecosystem: "crates.io", lockfile: "Cargo.lock" },
      { name: "unknown", version: "1.0.0", ecosystem: null, lockfile: "weird.lock" },
    ]);
    expect(result.packagesAudited).toBe(3);
    expect(result.packagesSkipped).toBe(1);
    expect(result.vulnerablePackages).toBe(2);
    expect(result.vulnerabilities).toBe(2);
    expect(result.withdrawnSkipped).toBe(2);
    expect(result.candidates).toHaveLength(3);
    const minimist = result.candidates.find((candidate) => candidate.filePath === "package-lock.json");
    expect(minimist).toMatchObject({
      source: "dependency",
      ruleId: "GHSA-vh95-rmgr-6w4m",
      ruleName: "Prototype Pollution in minimist",
      category: DEPENDENCY_CATEGORY,
      line: null,
      snippet: "minimist@1.2.0",
      severity: "Medium",
      cwe: "CWE-1321",
    });
    expect(minimist?.dependency).toMatchObject({ packageName: "minimist", lockfile: "package-lock.json", fixedVersions: ["1.2.3"], severitySource: "database_specific" });
    const other = result.candidates.find((candidate) => candidate.filePath === "web/package-lock.json");
    expect(other?.fingerprint).not.toBe(minimist?.fingerprint);
    const time = result.candidates.find((candidate) => candidate.ruleId === "RUSTSEC-2020-0071");
    expect(time).toMatchObject({ severity: "Medium", dependency: { cvssScore: 5.9, severitySource: "cvss_v3", fixedVersions: ["0.2.23"] } });
  });

  test("aliased advisories for one package become one finding and one counted vulnerability", async () => {
    const { db, settings } = tempDb();
    const { fetcher } = fakeOsv({
      vulnsFor: () => ({ vulns: [{ id: "GHSA-wcg3-cvx6-7396" }, { id: "RUSTSEC-2020-0071" }] }),
      records: {
        "GHSA-wcg3-cvx6-7396": {
          id: "GHSA-wcg3-cvx6-7396",
          aliases: ["CVE-2020-26235", "RUSTSEC-2020-0071"],
          database_specific: { severity: "MODERATE" },
          affected: [{ package: { name: "time", ecosystem: "crates.io" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0.2.7" }, { fixed: "0.2.23" }] }] }],
        },
        "RUSTSEC-2020-0071": {
          id: "RUSTSEC-2020-0071",
          aliases: ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
          affected: [{ package: { name: "time", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0.2.7-0" }, { fixed: "0.2.23" }] }] }],
        },
      },
    });
    const result = await auditDependencies(new OsvClient(db, settings, fetcher), [
      { name: "time", version: "0.2.10", ecosystem: "crates.io", lockfile: "Cargo.lock" },
    ]);
    expect(result.vulnerabilities).toBe(1);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]).toMatchObject({ ruleId: "RUSTSEC-2020-0071", dependency: { aliases: ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"] } });
  });
});

describe("OSV service policy", () => {
  function service(fetcher?: OsvFetcher) {
    const { db, settings } = tempDb();
    const client = new OsvClient(db, settings, fetcher ?? (async () => ({ status: 500, text: "" })));
    return createOsvServiceFrom({ settings, client, runInventory: async () => ({ lockfiles: [], packages: [], total_packages: 0, truncated: true }) });
  }

  test("is disabled by default and states what enabling discloses", () => {
    const status = service().status();
    expect(status).toMatchObject({ osvEnabled: false, changedBy: null, endpoint: "https://api.osv.dev", cachedAdvisories: 0, lastQueryAt: null });
    expect(status.privacyNote).toBe(OSV_PRIVACY_NOTE);
  });

  test("refuses queries while disabled and records who changed the switch", async () => {
    const osv = service();
    await expect(osv.query("minimist", "npm", "1.2.0")).rejects.toMatchObject({ status: 412, code: "osv_disabled" });
    const status = osv.setEnabled(true, { label: "alice", role: "admin" });
    expect(status).toMatchObject({ osvEnabled: true, changedBy: "alice" });
    expect(osv.enabled()).toBe(true);
  });

  test("query maps and sorts vulnerabilities by severity", async () => {
    const { fetcher } = fakeOsv({
      vulnsFor: () => ({ vulns: [{ id: "LOW-1" }, { id: "CRIT-1" }] }),
      records: {
        "LOW-1": { id: "LOW-1", database_specific: { severity: "LOW" } },
        "CRIT-1": { id: "CRIT-1", database_specific: { severity: "CRITICAL" } },
      },
    });
    const osv = service(fetcher);
    osv.setEnabled(true, { label: "alice", role: "admin" });
    const response = await osv.query("minimist", "npm", null);
    expect(response.vulnerabilities.map((vuln) => [vuln.id, vuln.severity])).toEqual([
      ["CRIT-1", "Critical"],
      ["LOW-1", "Low"],
    ]);
    expect(response.version).toBeNull();
    expect(osv.status().lastQueryAt).not.toBeNull();
  });

  test("inventory view exposes exactly the contract fields, including truncation", async () => {
    const view = await service().inventory("C:/ws");
    expect(Object.keys(view).sort()).toEqual(["generatedAt", "lockfiles", "packages", "totalPackages", "truncated"]);
    expect(typeof view.truncated).toBe("boolean");
  });
});
