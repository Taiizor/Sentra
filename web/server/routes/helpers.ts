import type { AppContext } from "../app-context.ts";
import { markAuditHandled, type AuditEntryInput } from "../audit-log.ts";
import { HttpError } from "../http-error.ts";
import type { AuthedContext, Principal } from "../http.ts";
import type { ActorRef } from "../services/types.ts";
import type { TenantRecord } from "../services/workspaces.ts";

export function actorOf(principal: Principal): ActorRef {
  return { label: principal.label, role: principal.role };
}

/** Resolves `:tenantId` from the route to a registered tenant (404 otherwise). */
export function tenantParam(app: AppContext, ctx: AuthedContext): TenantRecord {
  const tenantId = ctx.params.tenantId;
  if (!tenantId) throw new HttpError(400, "invalid_request", "Missing tenant id");
  return app.workspaces.get(tenantId);
}

/**
 * Runs a state-changing operation and records its outcome on the audit chain, including
 * failures. A 403 raised by the operation (a path or policy refusal) is recorded as `denied`.
 * The error is rethrown unchanged after it has been recorded.
 */
export async function audited<T>(
  app: Pick<AppContext, "audit">,
  principal: Principal,
  entry: Omit<AuditEntryInput, "outcome">,
  operation: () => Promise<T> | T,
  successDetails?: (result: T) => Record<string, unknown>,
): Promise<T> {
  try {
    const result = await operation();
    app.audit.append(principal, {
      ...entry,
      outcome: "success",
      details: { ...(entry.details ?? {}), ...(successDetails ? successDetails(result) : {}) },
    });
    return result;
  } catch (error) {
    app.audit.append(principal, {
      ...entry,
      outcome: error instanceof HttpError && error.status === 403 ? "denied" : "failure",
      details: {
        ...(entry.details ?? {}),
        error: error instanceof HttpError ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : String(error),
      },
    });
    throw markAuditHandled(error);
  }
}

export function intParam(value: string | null | undefined, field: string, min: number, max: number, fallback: number): number {
  if (value === null || value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new HttpError(400, "invalid_request", `'${field}' must be an integer between ${min} and ${max}`);
  }
  return parsed;
}
