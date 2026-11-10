import { useEffect, useMemo } from 'react'
import { CircleAlert, Download, FileText, LoaderCircle, Plus, Terminal, TriangleAlert } from 'lucide-react'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { FindingView, Severity } from '@/types/api'
import { exportExecutiveReport, exportSarif } from './export-actions'
import { NAV_ITEMS } from './nav-items'

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onToggleConsole: () => void
  onRegisterWorkspace: () => void
}

const MAX_LISTED_FINDINGS = 300

const SEVERITY_ORDER: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4, Unknown: 5 }

const SEVERITY_ICON_CLASS: Record<Severity, string> = {
  Critical: 'text-rose-400',
  High: 'text-orange-400',
  Medium: 'text-amber-300',
  Low: 'text-sky-400',
  Informational: 'text-zinc-400',
  Unknown: 'text-zinc-500',
}

function findingLabel(finding: FindingView): { title: string; detail: string } {
  if (finding.source === 'dependency' && finding.dependency) {
    const dep = finding.dependency
    return {
      title: `${dep.advisoryId} · ${dep.packageName}@${dep.packageVersion}`,
      detail: `${finding.severity} · ${dep.ecosystem} · ${dep.lockfile}`,
    }
  }
  const location = finding.filePath ? `${finding.filePath}${finding.line !== null ? `:${finding.line}` : ''}` : 'no location'
  return { title: `[${finding.ruleId}] ${finding.ruleName}`, detail: `${finding.severity} · ${finding.cwe ?? 'no CWE'} · ${location}` }
}

export function CommandPalette({ open, onOpenChange, onToggleConsole, onRegisterWorkspace }: CommandPaletteProps) {
  const { navigate, tenant, session, can } = useConsole()
  const tenantId = tenant?.tenantId ?? null

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.key === 'k' || event.key === 'K') && (event.metaKey || event.ctrlKey)) {
        event.preventDefault()
        onOpenChange(!open)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, onOpenChange])

  const findings = useResource(open && tenantId ? `palette-findings:${tenantId}` : null, (signal) =>
    api.findings.list(tenantId ?? '', { state: 'open' }, signal),
  )

  const sortedFindings = useMemo(
    () =>
      [...(findings.data?.findings ?? [])].sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.ruleId.localeCompare(b.ruleId),
      ),
    [findings.data],
  )
  const listed = sortedFindings.slice(0, MAX_LISTED_FINDINGS)

  function run(action: () => void) {
    onOpenChange(false)
    action()
  }

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Search" description="Search console views and open findings">
      <CommandInput placeholder="Search views and open findings…" />
      <CommandList>
        <CommandEmpty>No matching view or finding.</CommandEmpty>

        <CommandGroup heading="Views">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon
            return (
              <CommandItem key={item.id} value={`view ${item.label} ${item.title}`} onSelect={() => run(() => navigate(item.id))}>
                <Icon data-icon="inline-start" />
                <span>{item.title}</span>
              </CommandItem>
            )
          })}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Actions">
          {can('console:run') && (
            <CommandItem value="action toggle cli console" onSelect={() => run(onToggleConsole)}>
              <Terminal data-icon="inline-start" />
              <span>Toggle CLI console</span>
            </CommandItem>
          )}
          {tenant && (
            <>
              <CommandItem value="action export sarif" onSelect={() => run(() => void exportSarif(tenant))}>
                <Download data-icon="inline-start" />
                <span>Export SARIF for {tenant.name}</span>
              </CommandItem>
              <CommandItem value="action executive report html" onSelect={() => run(() => void exportExecutiveReport(tenant, session))}>
                <FileText data-icon="inline-start" />
                <span>Download executive report for {tenant.name}</span>
              </CommandItem>
            </>
          )}
          {can('tenant:create') && (
            <CommandItem value="action register workspace tenant" onSelect={() => run(onRegisterWorkspace)}>
              <Plus data-icon="inline-start" />
              <span>Register workspace</span>
            </CommandItem>
          )}
        </CommandGroup>

        {tenant && (
          <>
            <CommandSeparator />
            <CommandGroup
              heading={
                findings.data
                  ? `Open candidate findings (unverified) · ${sortedFindings.length}${
                      sortedFindings.length > listed.length ? ` · first ${listed.length} by severity listed` : ''
                    }`
                  : 'Open candidate findings (unverified)'
              }
            >
              {findings.loading && !findings.data && (
                <CommandItem value="findings loading" disabled>
                  <LoaderCircle data-icon="inline-start" className="animate-spin" />
                  <span className="text-xs text-zinc-400">Loading findings for {tenant.name}…</span>
                </CommandItem>
              )}
              {findings.error && (
                <CommandItem value="findings error retry" onSelect={findings.reload}>
                  <CircleAlert data-icon="inline-start" className="text-rose-400" />
                  <span className="text-xs text-rose-300">Findings unavailable: {errorMessage(findings.error)} (select to retry)</span>
                </CommandItem>
              )}
              {findings.data && sortedFindings.length === 0 && (
                <CommandItem value="findings none open" disabled>
                  <span className="text-xs text-zinc-400">No open findings recorded for this workspace.</span>
                </CommandItem>
              )}
              {listed.map((finding) => {
                const label = findingLabel(finding)
                return (
                  <CommandItem
                    key={finding.findingId}
                    value={`finding ${finding.findingId} ${label.title} ${label.detail}`}
                    onSelect={() => run(() => navigate('findings', { findingId: finding.findingId }))}
                  >
                    <TriangleAlert data-icon="inline-start" className={`size-3.5 shrink-0 ${SEVERITY_ICON_CLASS[finding.severity]}`} />
                    <span className="flex flex-col min-w-0">
                      <span className="truncate text-xs font-medium text-zinc-200">{label.title}</span>
                      <span className="text-[10px] text-zinc-500 truncate">{label.detail}</span>
                    </span>
                  </CommandItem>
                )
              })}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  )
}
