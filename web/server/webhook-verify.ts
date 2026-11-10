import crypto from "node:crypto";

/** Verifies GitHub's `X-Hub-Signature-256: sha256=<hex>` header over the raw request body. */
export function verifyGitHubSignature(secret: string, rawBody: string, header: string | null): boolean {
  if (!header) return false;
  const match = header.match(/^sha256=([0-9a-f]{64})$/i);
  if (!match) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest();
  const presented = Buffer.from(match[1], "hex");
  return presented.length === expected.length && crypto.timingSafeEqual(presented, expected);
}

/** Verifies GitLab's shared `X-Gitlab-Token` header in constant time. */
export function verifyGitLabToken(expected: string, header: string | null): boolean {
  if (!header) return false;
  const a = crypto.createHash("sha256").update(expected).digest();
  const b = crypto.createHash("sha256").update(header).digest();
  return crypto.timingSafeEqual(a, b);
}

/** GitHub delivery ids are GUIDs; GitLab sends an `X-Gitlab-Event-UUID` / `X-Gitlab-Webhook-UUID`. */
export function normalizeDeliveryId(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  return /^[A-Za-z0-9-]{8,80}$/.test(trimmed) ? trimmed : null;
}
