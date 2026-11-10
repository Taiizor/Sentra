import { FolderGit2, Plus, UserRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { useConsole } from '@/lib/console-context'
import { minimumRoleFor } from './console-format'

interface OnboardingPanelProps {
  onRegisterWorkspace: () => void
}

/** Shown in place of workspace-scoped views while no workspace (tenant) is registered. */
export function OnboardingPanel({ onRegisterWorkspace }: OnboardingPanelProps) {
  const { can, session } = useConsole()
  const canRegister = can('tenant:create')

  return (
    <Empty className="border border-dashed border-zinc-800 bg-zinc-900/30 py-12">
      <EmptyHeader>
        <EmptyMedia variant="icon" className="bg-primary/10 text-primary">
          <FolderGit2 />
        </EmptyMedia>
        <EmptyTitle className="text-zinc-100">No workspace registered</EmptyTitle>
        <EmptyDescription className="text-xs text-zinc-400">
          Sentra scans, findings, patches and research are scoped to a registered workspace: an existing directory on the bridge
          host with its own core store. Nothing is shown here until one exists.
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        {canRegister ? (
          <Button size="sm" onClick={onRegisterWorkspace} className="text-xs font-semibold">
            <Plus className="size-3.5" />
            Register workspace
          </Button>
        ) : (
          <p className="flex items-center gap-1.5 text-xs text-zinc-400">
            <UserRound className="size-3.5" />
            Ask someone with the {minimumRoleFor('tenant:create')} role to register a workspace. You are signed in as {session.roleLabel}.
          </p>
        )}
        <p className="text-[11px] text-zinc-500">
          Settings, the audit trail, webhook intake, plugins, snippet scans and OSV lookups remain available from the sidebar.
        </p>
      </EmptyContent>
    </Empty>
  )
}
