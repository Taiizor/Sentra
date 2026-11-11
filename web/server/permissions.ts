import { PERMISSION_MIN_ROLE, ROLE_LABELS, type Permission } from "../src/types/api.ts";
import type { Role } from "./config.ts";

/**
 * Server-enforced permissions. Roles are derived from the authenticated credential, never
 * from request bodies. Publication to remote repositories (PR creation) and public
 * disclosure (PR comments / commit statuses) are deliberately distinct permissions.
 *
 * The matrix is defined once in the shared contract (PERMISSION_MIN_ROLE) so the console's
 * explanations can never drift from what the bridge enforces.
 */
export type { Permission };

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

export const PERMISSIONS = Object.keys(PERMISSION_MIN_ROLE) as Permission[];

export function hasPermission(role: Role, permission: Permission): boolean {
  const minimum = PERMISSION_MIN_ROLE[permission];
  return minimum !== undefined && RANK[role] >= RANK[minimum];
}

export function permissionsFor(role: Role): Permission[] {
  return PERMISSIONS.filter((permission) => hasPermission(role, permission));
}

/** Display names used by the existing UI vocabulary. */
export const ROLE_LABEL = ROLE_LABELS;
