import { HttpError } from "./http-error.ts";

/**
 * Minimal, dependency-free request validators. Every accessor throws a 400 HttpError
 * naming the offending field so handlers never operate on unchecked input.
 */

export type JsonObject = Record<string, unknown>;

export function asObject(value: unknown, field = "body"): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_request", `${field} must be a JSON object`);
  }
  return value as JsonObject;
}

interface StringRules {
  min?: number;
  max?: number;
  pattern?: RegExp;
  trim?: boolean;
}

export function requiredString(obj: JsonObject, field: string, rules: StringRules = {}): string {
  const value = obj[field];
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `'${field}' is required and must be a string`);
  }
  return checkString(value, field, rules);
}

export function optionalString(obj: JsonObject, field: string, rules: StringRules = {}): string | undefined {
  const value = obj[field];
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `'${field}' must be a string`);
  }
  return checkString(value, field, rules);
}

function checkString(raw: string, field: string, rules: StringRules): string {
  const value = rules.trim === false ? raw : raw.trim();
  const min = rules.min ?? 1;
  const max = rules.max ?? 4096;
  if (value.length < min || value.length > max) {
    throw new HttpError(400, "invalid_request", `'${field}' must be between ${min} and ${max} characters`);
  }
  if (value.includes("\u0000")) {
    throw new HttpError(400, "invalid_request", `'${field}' contains a NUL byte`);
  }
  if (rules.pattern && !rules.pattern.test(value)) {
    throw new HttpError(400, "invalid_request", `'${field}' has an invalid format`);
  }
  return value;
}

export function optionalBoolean(obj: JsonObject, field: string): boolean | undefined {
  const value = obj[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "boolean") {
    throw new HttpError(400, "invalid_request", `'${field}' must be a boolean`);
  }
  return value;
}

export function optionalInt(obj: JsonObject, field: string, min: number, max: number): number | undefined {
  const value = obj[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new HttpError(400, "invalid_request", `'${field}' must be an integer between ${min} and ${max}`);
  }
  return value;
}

export function oneOf<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    throw new HttpError(400, "invalid_request", `'${field}' must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

export function optionalStringArray(
  obj: JsonObject,
  field: string,
  rules: StringRules & { maxItems?: number } = {},
): string[] | undefined {
  const value = obj[field];
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) {
    throw new HttpError(400, "invalid_request", `'${field}' must be an array of strings`);
  }
  const maxItems = rules.maxItems ?? 100;
  if (value.length > maxItems) {
    throw new HttpError(400, "invalid_request", `'${field}' accepts at most ${maxItems} items`);
  }
  return value.map((item, index) => {
    if (typeof item !== "string") {
      throw new HttpError(400, "invalid_request", `'${field}[${index}]' must be a string`);
    }
    return checkString(item, `${field}[${index}]`, rules);
  });
}

/** Tenant identifiers follow the core TenantId rules: 1-64 chars of [a-z0-9_-]. */
export const TENANT_ID_PATTERN = /^[a-z0-9_-]{1,64}$/;

export function tenantIdParam(value: string | null, field = "tenant"): string {
  if (!value || !TENANT_ID_PATTERN.test(value)) {
    throw new HttpError(400, "invalid_request", `'${field}' must be a tenant id (1-64 chars of a-z, 0-9, '-', '_')`);
  }
  return value;
}
