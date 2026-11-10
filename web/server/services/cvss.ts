import type { Severity } from "../../src/types/api.ts";

/**
 * CVSS v3.x base score calculator, implemented from the FIRST CVSS v3.1 specification
 * (https://www.first.org/cvss/v3.1/specification-document, sections 7.1 and 7.4 plus
 * Appendix A for Roundup). Only the eight base metrics are evaluated; temporal and
 * environmental metrics in a vector are accepted but ignored.
 *
 * v3.0 vectors use the same base equations; the v3.1 Roundup is the floating-point-safe
 * form of the v3.0 "round up to one decimal" rule, so it is applied to both versions.
 */

export interface CvssBaseScore {
  version: "3.0" | "3.1";
  score: number;
  /** The vector as received (trimmed). */
  vector: string;
}

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const SCOPE = new Set(["U", "C"]);

const BASE_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;

/** CVSS v3.1 Appendix A Roundup: smallest number with one decimal >= input. */
export function cvssRoundup(value: number): number {
  const intInput = Math.round(value * 100_000);
  if (intInput % 10_000 === 0) return intInput / 100_000;
  return (Math.floor(intInput / 10_000) + 1) / 10;
}

/** Computes the base score of a `CVSS:3.0/...` or `CVSS:3.1/...` vector; null when invalid. */
export function cvss3BaseScore(rawVector: string): CvssBaseScore | null {
  if (typeof rawVector !== "string") return null;
  const vector = rawVector.trim();
  const parts = vector.split("/");
  const prefix = parts.shift();
  if (prefix !== "CVSS:3.0" && prefix !== "CVSS:3.1") return null;
  const metrics = new Map<string, string>();
  for (const part of parts) {
    const match = /^([A-Za-z]{1,3}):([A-Za-z])$/.exec(part);
    if (!match) return null;
    const [, key, value] = match;
    if (metrics.has(key)) return null;
    metrics.set(key, value);
  }
  for (const key of BASE_METRICS) {
    if (!metrics.has(key)) return null;
  }
  const scope = metrics.get("S") as string;
  if (!SCOPE.has(scope)) return null;
  const changed = scope === "C";
  const av = AV[metrics.get("AV") as string];
  const ac = AC[metrics.get("AC") as string];
  const pr = (changed ? PR_CHANGED : PR_UNCHANGED)[metrics.get("PR") as string];
  const ui = UI[metrics.get("UI") as string];
  const c = CIA[metrics.get("C") as string];
  const i = CIA[metrics.get("I") as string];
  const a = CIA[metrics.get("A") as string];
  if ([av, ac, pr, ui, c, i, a].some((value) => value === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (changed) {
    score = cvssRoundup(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    score = cvssRoundup(Math.min(impact + exploitability, 10));
  }
  return { version: prefix === "CVSS:3.0" ? "3.0" : "3.1", score, vector };
}

/**
 * Qualitative rating from CVSS v3.1 section 5. The spec's "None" (0.0) has no counterpart in
 * the Sentra severity scale and is reported as Informational.
 */
export function cvssRating(score: number): Severity {
  if (!Number.isFinite(score) || score < 0 || score > 10) return "Unknown";
  if (score === 0) return "Informational";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}
