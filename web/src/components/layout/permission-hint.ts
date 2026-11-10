import { PERMISSION_MIN_ROLE, ROLE_LABELS, permissionHint as sharedPermissionHint, type Permission, type RoleLabel } from '@/types/api'

export function minimumRoleFor(permission: Permission): RoleLabel {
  return ROLE_LABELS[PERMISSION_MIN_ROLE[permission]]
}

/** Display-only explanation derived from the shared role matrix (PERMISSION_MIN_ROLE); the server enforces. */
export function permissionHint(permission: Permission): string {
  return sharedPermissionHint(permission)
}

export function roleBadgeClass(role: RoleLabel): string {
  switch (role) {
    case 'SecurityAdmin':
      return 'bg-purple-500/15 text-purple-300 border-purple-500/30'
    case 'Operator':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30'
    default:
      return 'bg-zinc-800/60 text-zinc-300 border-zinc-700'
  }
}
