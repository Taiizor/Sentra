import { UserRound } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useConsole } from '@/lib/console-context'
import { formatDateTime } from './settings-format'
import { TimeAgo } from './settings-kit'

/** The authenticated session as reported by the bridge. Read-only. */
export function SettingsSession() {
  const { session } = useConsole()
  return (
    <div className="flex flex-col gap-3">
      <div className="p-3 rounded-lg border border-border/60 bg-card/40 grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="flex flex-col gap-0.5 min-w-0">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1">
            <UserRound className="size-3" />
            Principal
          </span>
          <span className="font-mono text-xs text-foreground break-all">{session.principal}</span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground">Role</span>
          <span className="text-xs text-foreground">{session.roleLabel}</span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground">Signed in via</span>
          <span className="text-xs text-foreground">{session.via === 'session' ? 'Console session cookie' : 'Bearer token'}</span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground">Session expires</span>
          <span className="text-xs text-foreground" title={session.expiresAt ? formatDateTime(session.expiresAt) : undefined}>
            {session.expiresAt ? <TimeAgo iso={session.expiresAt} /> : 'not reported'}
          </span>
        </div>
      </div>

      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground">Permissions granted to this session ({session.permissions.length})</span>
        <div className="flex flex-wrap gap-1.5">
          {session.permissions.map((permission) => (
            <Badge key={permission} variant="outline" className="text-[10px] font-mono">
              {permission}
            </Badge>
          ))}
        </div>
        <span className="text-[11px] text-muted-foreground">
          The role is bound to the token you signed in with and is enforced by the bridge on every request. Roles are assigned on the bridge
          host through <code className="font-mono">SENTRA_WEB_TOKENS</code> (or the generated local admin token); the console cannot change
          them.
        </span>
      </div>
    </div>
  )
}
