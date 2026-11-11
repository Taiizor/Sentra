import fs from "node:fs";
import type { Severity } from "../../src/types/api.ts";
import type { StoredFinding } from "./findings.ts";

/**
 * SARIF 2.1.0 export of stored findings (OASIS SARIF v2.1.0). Only facts the bridge holds are
 * emitted: dependency findings point at their lockfile without an invented region, SAST and
 * CodeQL findings carry the line that was reported (CodeQL results keep their origin as a
 * property), and every result is labelled a candidate.
 */

export const SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
export const SARIF_FINGERPRINT_KEY = "sentra/v1";

export type SarifLevel = "error" | "warning" | "note";

interface SarifMessage {
  text: string;
}

interface SarifPhysicalLocation {
  artifactLocation: { uri: string; uriBaseId: string };
  region?: { startLine: number };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: SarifMessage;
  locations: { physicalLocation: SarifPhysicalLocation }[];
  partialFingerprints: Record<string, string>;
  codeFlows?: {
    threadFlows: { locations: { location: { physicalLocation: SarifPhysicalLocation; message: SarifMessage } }[] }[];
  }[];
  properties: {
    findingId: string;
    severity: Severity;
    source: StoredFinding["source"];
    /** CodeQL findings only: host_analysis, sarif_import or github_code_scanning. */
    origin?: NonNullable<StoredFinding["origin"]>;
    triage: string | null;
    status: "candidate";
    firstSeenAt: string;
    lastSeenAt: string;
  };
}

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription: SarifMessage;
  helpUri?: string;
  properties: { tags: string[]; category: string | null; "security-severity"?: string };
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: {
    tool: { driver: { name: "Sentra"; version?: string; informationUri?: string; rules: SarifRule[] } };
    results: SarifResult[];
    properties: { tenantId: string; generatedAt: string; note: string };
  }[];
}

export function sarifLevel(severity: Severity): SarifLevel {
  if (severity === "Critical" || severity === "High") return "error";
  if (severity === "Medium") return "warning";
  return "note";
}

/** Percent-encodes each segment of a workspace-relative path for use as a URI reference. */
export function relativeUri(filePath: string): string {
  return filePath
    .replace(/\\/g, "/")
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

/**
 * Reads `repository = "..."` from the `[workspace.package]` or `[package]` table of a
 * Cargo.toml. Returns null when the file or the key is missing or not an http(s) URL.
 */
export function readRepositoryUrl(cargoTomlPath: string): string | null {
  let text: string;
  try {
    text = fs.readFileSync(cargoTomlPath, "utf8");
  } catch {
    return null;
  }
  let section = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1].trim();
      continue;
    }
    if (section !== "workspace.package" && section !== "package") continue;
    const match = /^repository\s*=\s*"([^"]+)"/.exec(line);
    if (match && /^https?:\/\/[^\s"]+$/.test(match[1])) return match[1];
  }
  return null;
}

function location(filePath: string, line: number | null): SarifPhysicalLocation {
  const physical: SarifPhysicalLocation = { artifactLocation: { uri: relativeUri(filePath), uriBaseId: "%SRCROOT%" } };
  if (line !== null && line >= 1) physical.region = { startLine: line };
  return physical;
}

function message(finding: StoredFinding): string {
  if (finding.source === "dependency" && finding.dependency) {
    const dep = finding.dependency;
    const fixed =
      (dep.fixedVersions.length > 0 ? ` Fixed in: ${dep.fixedVersions.join(", ")}.` : " No fixed version is listed.") +
      (dep.fixedVersionsNote ? ` ${dep.fixedVersionsNote}` : "");
    return `${dep.packageName}@${dep.packageVersion} (${dep.ecosystem}) is listed as affected by ${dep.advisoryId}${dep.summary ? `: ${dep.summary}` : "."}${fixed}`;
  }
  if (finding.rationale) return `${finding.ruleName}: ${finding.rationale}`;
  if (finding.taintTrace) return `${finding.ruleName}: pattern-based taint trace with ${finding.taintTrace.length} step(s) reported by the core.`;
  return finding.ruleName;
}

export interface SarifToolInfo {
  version: string | null;
  informationUri: string | null;
}

/** Builds the SARIF log from findings that the caller already filtered (open, not rejected). */
export function buildSarif(findings: StoredFinding[], tool: SarifToolInfo, tenantId: string, generatedAt: string): SarifLog {
  const rules: SarifRule[] = [];
  const ruleIndex = new Map<string, number>();
  const results: SarifResult[] = [];
  for (const finding of findings) {
    let index = ruleIndex.get(finding.ruleId);
    if (index === undefined) {
      index = rules.length;
      ruleIndex.set(finding.ruleId, index);
      const tags = ["security", finding.source];
      if (finding.cwe) tags.push(...finding.cwe.split(",").map((cwe) => cwe.trim()).filter(Boolean));
      const rule: SarifRule = {
        id: finding.ruleId,
        shortDescription: { text: finding.ruleName },
        properties: { tags, category: finding.category },
      };
      if (finding.source === "sast" || finding.source === "codeql") rule.name = finding.ruleName;
      if (finding.source === "codeql" && finding.codeql) {
        if (finding.codeql.helpUri) rule.helpUri = finding.codeql.helpUri;
        if (typeof finding.codeql.securitySeverity === "number") rule.properties["security-severity"] = finding.codeql.securitySeverity.toFixed(1);
      }
      if (finding.source === "dependency") {
        rule.helpUri = `https://osv.dev/vulnerability/${encodeURIComponent(finding.ruleId)}`;
        const score = finding.dependency?.cvssScore;
        if (typeof score === "number") rule.properties["security-severity"] = score.toFixed(1);
      }
      rules.push(rule);
    }
    const result: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex: index,
      level: sarifLevel(finding.severity),
      message: { text: message(finding) },
      locations: finding.filePath
        ? [{ physicalLocation: location(finding.filePath, finding.source === "dependency" ? null : finding.line) }]
        : [],
      partialFingerprints: { [SARIF_FINGERPRINT_KEY]: finding.fingerprint },
      properties: {
        findingId: finding.findingId,
        severity: finding.severity,
        source: finding.source,
        triage: finding.triage?.verdict ?? null,
        status: "candidate",
        firstSeenAt: finding.firstSeenAt,
        lastSeenAt: finding.lastSeenAt,
      },
    };
    if (finding.source === "codeql" && finding.origin) result.properties.origin = finding.origin;
    if (finding.source === "sast" && finding.taintTrace && finding.taintTrace.length > 0 && finding.filePath) {
      const filePath = finding.filePath;
      result.codeFlows = [
        {
          threadFlows: [
            {
              locations: finding.taintTrace.map((step) => ({
                location: {
                  physicalLocation: location(filePath, step.line),
                  message: { text: `${step.role}${step.variable ? ` ${step.variable}` : ""}${step.code ? `: ${step.code}` : ""}` },
                },
              })),
            },
          ],
        },
      ];
    }
    results.push(result);
  }
  const driver: SarifLog["runs"][number]["tool"]["driver"] = { name: "Sentra", rules };
  if (tool.version) driver.version = tool.version;
  if (tool.informationUri) driver.informationUri = tool.informationUri;
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: { driver },
        results,
        properties: {
          tenantId,
          generatedAt,
          note: "Exported from stored Sentra findings that are open and not triaged as rejected. Results are unvalidated scanner/advisory candidates; CodeQL results are re-exported as stored (see properties.origin); each origin is stored on its own, so a result reported by host analysis, a SARIF import and GitHub code scanning appears once per origin.",
        },
      },
    ],
  };
}
