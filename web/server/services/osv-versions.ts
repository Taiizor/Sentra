/**
 * Version ordering and OSV range evaluation, used to pick the fix that applies to an installed
 * version. Only orderings that can be implemented exactly from their specification are
 * supported; anything else returns null, and callers say that the fix list was not filtered
 * instead of guessing.
 *
 * - SEMVER ranges and the semver-ordered ecosystems (npm, crates.io, Go, NuGet, Packagist):
 *   SemVer 2.0.0 precedence (a leading `v` is accepted; a fourth numeric part is accepted for
 *   NuGet-style versions; build metadata is ignored).
 * - PyPI: PEP 440 public versions (epoch, release, a/b/rc, post, dev).
 * - RubyGems: purely numeric dotted versions only.
 */

type Comparator = (a: string, b: string) => number | null;

// ───────────────────────────── SemVer ─────────────────────────────

interface SemverParts {
  release: number[];
  pre: string[] | null;
}

const SEMVER = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseSemver(value: string): SemverParts | null {
  const match = value.trim().match(SEMVER);
  if (!match) return null;
  const release = [match[1], match[2], match[3], match[4]].map((part) => (part === undefined ? 0 : Number(part)));
  if (release.some((part) => !Number.isSafeInteger(part))) return null;
  return { release, pre: match[5] ? match[5].split(".") : null };
}

function compareIdentifiers(a: string, b: string): number {
  const numericA = /^\d+$/.test(a);
  const numericB = /^\d+$/.test(b);
  if (numericA && numericB) return Math.sign(Number(a) - Number(b));
  if (numericA) return -1;
  if (numericB) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareSemver(a: string, b: string): number | null {
  const left = parseSemver(a);
  const right = parseSemver(b);
  if (!left || !right) return null;
  for (let index = 0; index < 4; index += 1) {
    if (left.release[index] !== right.release[index]) return Math.sign(left.release[index] - right.release[index]);
  }
  if (!left.pre && !right.pre) return 0;
  if (!left.pre) return 1;
  if (!right.pre) return -1;
  const length = Math.max(left.pre.length, right.pre.length);
  for (let index = 0; index < length; index += 1) {
    if (left.pre[index] === undefined) return -1;
    if (right.pre[index] === undefined) return 1;
    const result = compareIdentifiers(left.pre[index], right.pre[index]);
    if (result !== 0) return result;
  }
  return 0;
}

// ───────────────────────────── PEP 440 ─────────────────────────────

// The public-version part of the PEP 440 grammar (local versions are not accepted).
// Groups: 1 epoch, 2 release, 3 pre label, 4 pre number, 5 implicit post number, 6 post label,
// 7 post number, 8 dev label, 9 dev number.
const PEP440 =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?$/i;

const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

/** Sort key per PEP 440 (as in `packaging`): epoch, release, pre, post, dev. */
function pep440Key(value: string): { epoch: number; release: number[]; pre: [number, number]; post: number; dev: number } | null {
  const match = value.trim().match(PEP440);
  if (!match) return null;
  const [, epoch, release, preLabel, preNumber, postImplicit, postLabel, postNumber, devLabel, devNumber] = match;
  const hasPost = postImplicit !== undefined || postLabel !== undefined;
  const hasDev = devLabel !== undefined;
  let pre: [number, number];
  if (preLabel) pre = [PRE_RANK[preLabel.toLowerCase()], Number(preNumber ?? 0)];
  // A dev release without pre or post sorts before every pre-release of the same version.
  else if (hasDev && !hasPost) pre = [-1, 0];
  else pre = [3, 0];
  return {
    epoch: Number(epoch ?? 0),
    release: release.split(".").map(Number),
    pre,
    post: hasPost ? Number(postImplicit ?? postNumber ?? 0) : -1,
    dev: hasDev ? Number(devNumber ?? 0) : Number.POSITIVE_INFINITY,
  };
}

export function comparePep440(a: string, b: string): number | null {
  const left = pep440Key(a);
  const right = pep440Key(b);
  if (!left || !right) return null;
  if (left.epoch !== right.epoch) return Math.sign(left.epoch - right.epoch);
  const length = Math.max(left.release.length, right.release.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left.release[index] ?? 0) - (right.release[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  for (const [x, y] of [
    [left.pre[0], right.pre[0]],
    [left.pre[1], right.pre[1]],
    [left.post, right.post],
    [left.dev, right.dev],
  ]) {
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// ───────────────────────────── numeric (RubyGems subset) ─────────────────────────────

export function compareNumericDotted(a: string, b: string): number | null {
  if (!/^\d+(\.\d+)*$/.test(a.trim()) || !/^\d+(\.\d+)*$/.test(b.trim())) return null;
  const left = a.trim().split(".").map(Number);
  const right = b.trim().split(".").map(Number);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

const ECOSYSTEM_COMPARATORS: Record<string, Comparator> = {
  npm: compareSemver,
  "crates.io": compareSemver,
  Go: compareSemver,
  NuGet: compareSemver,
  Packagist: compareSemver,
  PyPI: comparePep440,
  RubyGems: compareNumericDotted,
};

/** The comparator for an OSV range type in an ecosystem, or null when Sentra cannot order it. */
export function comparatorFor(rangeType: string | undefined, ecosystem: string): Comparator | null {
  if (rangeType === "SEMVER") return compareSemver;
  if (rangeType === "ECOSYSTEM") return ECOSYSTEM_COMPARATORS[ecosystem.split(":")[0]] ?? null;
  return null;
}

// ───────────────────────────── range evaluation ─────────────────────────────

export interface RangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export type RangeVerdict =
  | { evaluable: false }
  | { evaluable: true; affected: false }
  /** `fix` is the fixed event closing the interval that holds the version; null when none is published. */
  | { evaluable: true; affected: true; fix: string | null };

function eventVersion(event: RangeEvent): string | null {
  return event.introduced ?? event.fixed ?? event.last_affected ?? event.limit ?? null;
}

/**
 * Evaluates one SEMVER/ECOSYSTEM range for `version` as described by the OSV schema: events
 * sorted by version, `introduced` opens an affected interval, `fixed` closes it before that
 * version, `last_affected` closes it after that version, and `limit` caps the range.
 */
export function evaluateRange(events: readonly RangeEvent[], version: string, compare: Comparator): RangeVerdict {
  if (compare(version, version) === null) return { evaluable: false };
  const keyed: { event: RangeEvent; value: string; zero: boolean }[] = [];
  for (const event of events) {
    const value = eventVersion(event);
    if (value === null) continue;
    const zero = event.introduced === "0";
    if (!zero && compare(value, value) === null) return { evaluable: false };
    keyed.push({ event, value, zero });
  }
  if (keyed.length === 0) return { evaluable: false };
  keyed.sort((x, y) => (x.zero && y.zero ? 0 : x.zero ? -1 : y.zero ? 1 : (compare(x.value, y.value) ?? 0)));
  for (const { event, value } of keyed) {
    if (event.limit !== undefined && (compare(version, value) ?? 0) >= 0) return { evaluable: true, affected: false };
  }
  let affected = false;
  for (const { event, value, zero } of keyed) {
    if (event.introduced !== undefined) {
      if (zero || (compare(version, value) ?? -1) >= 0) affected = true;
    } else if (event.fixed !== undefined) {
      if ((compare(version, value) ?? -1) >= 0) affected = false;
    } else if (event.last_affected !== undefined) {
      if ((compare(version, value) ?? -1) > 0) affected = false;
    }
  }
  if (!affected) return { evaluable: true, affected: false };
  // The interval holding the version ends at the first closing event above it.
  for (const { event, value } of keyed) {
    if (event.fixed !== undefined && (compare(version, value) ?? 0) < 0) return { evaluable: true, affected: true, fix: event.fixed };
    if (event.last_affected !== undefined && (compare(version, value) ?? 0) <= 0) return { evaluable: true, affected: true, fix: null };
  }
  return { evaluable: true, affected: true, fix: null };
}

/** Sorts versions ascending with `compare`; the input order is kept when they cannot be ordered. */
export function sortVersions(versions: readonly string[], compare: Comparator | null): string[] {
  if (!compare || versions.some((version) => compare(version, version) === null)) return [...versions];
  return [...versions].sort((a, b) => compare(a, b) ?? 0);
}
