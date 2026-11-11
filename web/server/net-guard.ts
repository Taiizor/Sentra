import dns from "node:dns/promises";
import net from "node:net";
import { HttpError } from "./http-error.ts";

/**
 * Outbound URL guard for operator-configurable endpoints (custom LLM base URLs).
 * Blocks non-HTTP(S) schemes, embedded credentials, and destinations that resolve to
 * private, link-local, metadata, or loopback ranges unless loopback was explicitly allowed
 * (local model runtimes such as Ollama). DNS is resolved at check time; a resolver that
 * changes answers between the check and the request (rebinding) is a documented residual risk.
 */

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function inV4(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

const BLOCKED_V4 = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
];

/**
 * Parses an IPv6 literal (with `::` compression, an optional trailing dotted IPv4 part and an
 * optional `%zone`) into eight 16-bit groups; null when it is not valid IPv6.
 */
export function parseIPv6(ip: string): number[] | null {
  const bare = ip.replace(/%.*$/, "");
  if (!net.isIPv6(bare)) return null;
  let text = bare.toLowerCase();
  const dotted = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const octets = dotted[2].split(".").map(Number);
    text = `${dotted[1]}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const [head, tail] = text.includes("::") ? text.split("::") : [text, null];
  const parse = (part: string) => (part ? part.split(":").map((group) => Number.parseInt(group, 16)) : []);
  const left = parse(head);
  const right = tail === null ? [] : parse(tail);
  const groups = tail === null ? left : [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
  return groups.length === 8 && groups.every((group) => Number.isInteger(group) && group >= 0 && group <= 0xffff) ? groups : null;
}

function v4FromGroups(high: number, low: number): string {
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

/**
 * The IPv4 address an IPv6 address carries and a router would deliver to: IPv4-mapped
 * (::ffff:0:0/96), IPv4-compatible (::/96), IPv4-translated (::ffff:0:0:0/96), NAT64
 * (64:ff9b::/96) and 6to4 (2002::/16). Null for other addresses.
 */
export function embeddedIPv4(groups: readonly number[]): string | null {
  const zero = (from: number, to: number) => groups.slice(from, to).every((group) => group === 0);
  if (zero(0, 5) && (groups[5] === 0xffff || groups[5] === 0)) return v4FromGroups(groups[6], groups[7]);
  if (zero(0, 4) && groups[4] === 0xffff && groups[5] === 0) return v4FromGroups(groups[6], groups[7]);
  if (groups[0] === 0x64 && groups[1] === 0xff9b && zero(2, 6)) return v4FromGroups(groups[6], groups[7]);
  if (groups[0] === 0x2002) return v4FromGroups(groups[1], groups[2]);
  return null;
}

/** IPv6 ranges that never name a public unicast destination (embedded IPv4 is handled separately). */
function blockedV6(groups: readonly number[]): boolean {
  const [first, second] = groups;
  return (
    (first & 0xfe00) === 0xfc00 || // fc00::/7 unique local
    (first & 0xffc0) === 0xfe80 || // fe80::/10 link local
    (first & 0xffc0) === 0xfec0 || // fec0::/10 site local (deprecated)
    (first & 0xff00) === 0xff00 || // ff00::/8 multicast
    (first === 0x2001 && second === 0x0db8) || // 2001:db8::/32 documentation
    (first === 0x2001 && second === 0x0000) || // 2001::/32 Teredo (tunnels to an embedded IPv4 peer)
    (first === 0x0064 && second === 0xff9b && groups[2] === 0x0001) || // 64:ff9b:1::/48 local-use NAT64
    (first === 0x0100 && groups.slice(1, 4).every((group) => group === 0)) // 100::/64 discard-only
  );
}

export function isLoopbackAddress(ip: string): boolean {
  if (net.isIPv4(ip)) return inV4(ip, "127.0.0.0/8");
  const groups = parseIPv6(ip);
  if (!groups) return false;
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return true;
  const v4 = embeddedIPv4(groups);
  return v4 !== null && inV4(v4, "127.0.0.0/8");
}

export function isBlockedAddress(ip: string): boolean {
  if (net.isIPv4(ip)) return BLOCKED_V4.some((cidr) => inV4(ip, cidr));
  const groups = parseIPv6(ip);
  // Anything that is neither IPv4 nor parseable IPv6 is refused rather than guessed at.
  if (!groups) return true;
  // ::/96 covers the unspecified address (::) and loopback (::1) through 0.0.0.0/8.
  const v4 = embeddedIPv4(groups);
  if (v4 !== null) return isBlockedAddress(v4);
  return blockedV6(groups);
}

export interface OutboundCheckOptions {
  /** Permit loopback destinations (only for explicitly local model runtimes). */
  allowLoopback?: boolean;
  /** Permit plain http (only meaningful together with loopback). */
  allowHttp?: boolean;
}

export async function assertSafeOutboundUrl(raw: string, options: OutboundCheckOptions = {}): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new HttpError(400, "invalid_endpoint", "Endpoint is not a valid URL");
  }
  if (url.username || url.password) {
    throw new HttpError(400, "invalid_endpoint", "Endpoint URLs must not embed credentials");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && options.allowHttp)) {
    throw new HttpError(400, "invalid_endpoint", "Endpoint must use https");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  let addresses: string[];
  if (net.isIP(hostname)) {
    addresses = [hostname];
  } else {
    try {
      addresses = (await dns.lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address);
    } catch {
      throw new HttpError(400, "invalid_endpoint", "Endpoint host could not be resolved");
    }
  }
  if (addresses.length === 0) {
    throw new HttpError(400, "invalid_endpoint", "Endpoint host could not be resolved");
  }
  for (const address of addresses) {
    if (options.allowLoopback && isLoopbackAddress(address)) continue;
    if (isBlockedAddress(address)) {
      throw new HttpError(
        400,
        "endpoint_blocked",
        options.allowLoopback
          ? "Local endpoints must resolve to a loopback address"
          : "Endpoint resolves to a private, loopback or link-local address",
      );
    }
    if (options.allowLoopback && url.protocol === "http:" && !isLoopbackAddress(address)) {
      throw new HttpError(400, "endpoint_blocked", "Plain http is only allowed for loopback endpoints");
    }
  }
  return url;
}

/** fetch() with a hard timeout and a cap on the response body size. */
export async function fetchWithLimits(
  input: string | URL,
  init: RequestInit & { timeoutMs?: number; maxResponseBytes?: number } = {},
): Promise<{ status: number; ok: boolean; headers: Headers; text: string }> {
  const { timeoutMs = 60_000, maxResponseBytes = 4 * 1024 * 1024, ...rest } = init;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(input, { ...rest, redirect: rest.redirect ?? "error", signal: controller.signal });
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader) {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxResponseBytes) {
          await reader.cancel().catch(() => {});
          throw new HttpError(502, "upstream_too_large", "Upstream response exceeded the size limit");
        }
        chunks.push(value);
      }
    }
    const text = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
    return { status: response.status, ok: response.ok, headers: response.headers, text };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    if (controller.signal.aborted) throw new HttpError(504, "upstream_timeout", "Upstream request timed out");
    throw new HttpError(502, "upstream_unreachable", "Upstream request failed");
  } finally {
    clearTimeout(timer);
  }
}
