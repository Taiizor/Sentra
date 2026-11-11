import type { Database } from "bun:sqlite";
import crypto from "node:crypto";
import { sha256, type Role, type ServerConfig, type TokenGrant } from "./config.ts";
import { nowIso } from "./db.ts";
import { HttpError } from "./http-error.ts";
import type { Principal } from "./http.ts";

export const SESSION_COOKIE = "sentra_session";

interface SessionRow {
  id_hash: string;
  role: Role;
  label: string;
  expires_at: string;
  grant_fingerprint: string;
}

/** Fixed-window limiter keyed by an arbitrary string (client address, principal). */
export class AttemptLimiter {
  private readonly buckets = new Map<string, { count: number; resetAt: number }>();
  private readonly limit: number;
  private readonly windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  hit(key: string): boolean {
    const now = Date.now();
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + this.windowMs });
      if (this.buckets.size > 10_000) this.prune(now);
      return true;
    }
    bucket.count += 1;
    return bucket.count <= this.limit;
  }

  private prune(now: number) {
    for (const [key, bucket] of this.buckets) if (bucket.resetAt <= now) this.buckets.delete(key);
  }
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name && !(name in out)) out[name] = value;
  }
  return out;
}

export class AuthService {
  private readonly loginLimiter = new AttemptLimiter(10, 60_000);
  private lastPurge = 0;
  private readonly db: Database;
  private readonly config: ServerConfig;
  private readonly fingerprintKey: Buffer;
  /** Configured grants by fingerprint; a session is valid only while its grant is in here. */
  private readonly grantsByFingerprint = new Map<string, TokenGrant>();

  constructor(db: Database, config: ServerConfig) {
    this.db = db;
    this.config = config;
    this.fingerprintKey = Buffer.from(crypto.hkdfSync("sha256", config.secretKey, Buffer.alloc(0), "sentra-web-session-grant-v1", 32));
    for (const grant of config.tokenGrants) this.grantsByFingerprint.set(this.fingerprint(grant), grant);
  }

  /**
   * Keyed fingerprint of one grant (role, label and token digest). Stored with each session so a
   * session ends when the token that created it is rotated or removed, even if another token
   * with the same role and label is configured. Keyed, so the table never holds a plain token hash.
   */
  private fingerprint(grant: TokenGrant): string {
    return crypto.createHmac("sha256", this.fingerprintKey).update(`${grant.role}\n${grant.label}\n`).update(grant.digest).digest("hex");
  }

  /** Constant-time lookup of a presented token among configured grants. */
  private findGrant(token: string): TokenGrant | null {
    const digest = sha256(token);
    let match: TokenGrant | null = null;
    for (const grant of this.config.tokenGrants) {
      if (crypto.timingSafeEqual(digest, grant.digest)) match = grant;
    }
    return match;
  }

  login(token: string, ip: string): { principal: Principal; sessionId: string; expiresAt: string } {
    if (!this.loginLimiter.hit(ip)) {
      throw new HttpError(429, "too_many_attempts", "Too many login attempts. Try again in a minute.");
    }
    const grant = this.findGrant(token);
    if (!grant) {
      throw new HttpError(401, "invalid_token", "The access token is not valid.");
    }
    const sessionId = crypto.randomBytes(32).toString("base64url");
    const idHash = sha256(sessionId).toString("hex");
    const now = nowIso();
    const expiresAt = new Date(Date.now() + this.config.sessionTtlMs).toISOString();
    this.db
      .query(
        "INSERT INTO web_sessions (id_hash, role, label, created_at, expires_at, last_seen_at, grant_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(idHash, grant.role, grant.label, now, expiresAt, now, this.fingerprint(grant));
    return { principal: { role: grant.role, label: grant.label, via: "session", sessionIdHash: idHash }, sessionId, expiresAt };
  }

  logout(principal: Principal): void {
    if (principal.sessionIdHash) {
      this.db.query("DELETE FROM web_sessions WHERE id_hash = ?").run(principal.sessionIdHash);
    }
  }

  /** Resolves the caller from `Authorization: Bearer` (API clients) or the session cookie. */
  authenticate(req: Request): Principal | null {
    this.purgeExpired();
    const authorization = req.headers.get("authorization");
    if (authorization) {
      const match = authorization.match(/^Bearer\s+(\S+)$/i);
      if (!match) return null;
      const grant = this.findGrant(match[1]);
      return grant ? { role: grant.role, label: grant.label, via: "bearer" } : null;
    }
    const sessionId = parseCookies(req.headers.get("cookie"))[SESSION_COOKIE];
    if (!sessionId || !/^[A-Za-z0-9_-]{20,100}$/.test(sessionId)) return null;
    const idHash = sha256(sessionId).toString("hex");
    const row = this.db
      .query("SELECT id_hash, role, label, expires_at, grant_fingerprint FROM web_sessions WHERE id_hash = ?")
      .get(idHash) as SessionRow | null;
    if (!row) return null;
    if (row.expires_at <= nowIso()) {
      this.db.query("DELETE FROM web_sessions WHERE id_hash = ?").run(idHash);
      return null;
    }
    // A session lives only as long as the exact grant (token) that created it is configured;
    // a rotated or removed token ends its sessions even when the role and label stay the same.
    const grant = this.grantsByFingerprint.get(row.grant_fingerprint);
    if (!grant || grant.role !== row.role || grant.label !== row.label) {
      this.db.query("DELETE FROM web_sessions WHERE id_hash = ?").run(idHash);
      return null;
    }
    this.db.query("UPDATE web_sessions SET last_seen_at = ? WHERE id_hash = ?").run(nowIso(), idHash);
    return { role: grant.role, label: grant.label, via: "session", sessionIdHash: idHash };
  }

  sessionCookie(sessionId: string, expiresAt: string, secure: boolean): string {
    const maxAge = Math.max(0, Math.floor((Date.parse(expiresAt) - Date.now()) / 1000));
    return `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
  }

  clearedCookie(secure: boolean): string {
    return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;
  }

  private purgeExpired(): void {
    const now = Date.now();
    if (now - this.lastPurge < 60_000) return;
    this.lastPurge = now;
    this.db.query("DELETE FROM web_sessions WHERE expires_at <= ?").run(nowIso());
  }
}

/**
 * Cross-site request forgery / DNS-rebinding guard. State-changing cookie-authenticated
 * requests must originate from an allowed origin; every request must target an allowed Host.
 */
export function checkHost(req: Request, config: ServerConfig): boolean {
  const host = (req.headers.get("host") ?? "").toLowerCase();
  return config.allowedHosts.has(host);
}

export function checkOrigin(req: Request, config: ServerConfig): boolean {
  const origin = req.headers.get("origin");
  if (origin) return config.allowedOrigins.has(origin);
  const fetchSite = req.headers.get("sec-fetch-site");
  if (fetchSite) return fetchSite === "same-origin" || fetchSite === "none";
  // Non-browser clients (no Origin, no Sec-Fetch-*) are only accepted with bearer tokens,
  // which the dispatcher verifies separately.
  return false;
}
