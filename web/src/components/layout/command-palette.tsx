import { useEffect } from 'react'
import {
  Search,
  Code2,
  AlertTriangle,
  CheckCircle2,
  Globe,
  Brain,
  Server,
  History,
  FileDown,
  Terminal,
} from 'lucide-react'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import type { FindingView } from '@/types/sentra'

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSelectTab: (tab: string) => void
  onExportSarif: () => void
  onToggleConsole: () => void
  findings: FindingView[]
}

export function CommandPalette({
  open,
  onOpenChange,
  onSelectTab,
  onExportSarif,
  onToggleConsole,
  findings,
}: CommandPaletteProps) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        onOpenChange(!open)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, onOpenChange])

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Type a command or search findings, rules, CVEs..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        {/* Quick Actions */}
        <CommandGroup heading="Platform Quick Actions">
          <CommandItem
            onSelect={() => {
              onToggleConsole()
              onOpenChange(false)
            }}
          >
            <Terminal data-icon="inline-start" />
            <span>Open Interactive Scanner CLI Console</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onExportSarif()
              onOpenChange(false)
            }}
          >
            <FileDown data-icon="inline-start" />
            <span>Export OASIS SARIF v2.1.0 Security Report</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        {/* Navigation */}
        <CommandGroup heading="Navigation">
          <CommandItem
            onSelect={() => {
              onSelectTab('overview')
              onOpenChange(false)
            }}
          >
            <Search data-icon="inline-start" />
            <span>Executive Threat Posture &amp; Overview</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('studio')
              onOpenChange(false)
            }}
          >
            <Code2 data-icon="inline-start" />
            <span>Live SAST &amp; Taint Studio (Interactive Scanner)</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('findings')
              onOpenChange(false)
            }}
          >
            <AlertTriangle data-icon="inline-start" />
            <span>Vulnerability Findings &amp; Taint Call Graphs</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('remediation')
              onOpenChange(false)
            }}
          >
            <CheckCircle2 data-icon="inline-start" />
            <span>Automated Remediation &amp; Three-Tier Verified Patches</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('intel')
              onOpenChange(false)
            }}
          >
            <Globe data-icon="inline-start" />
            <span>Universal OSV Threat Intelligence Feed</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('research')
              onOpenChange(false)
            }}
          >
            <Brain data-icon="inline-start" />
            <span>Autonomous Research Campaigns &amp; Coverage Ledger</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('fleet')
              onOpenChange(false)
            }}
          >
            <Server data-icon="inline-start" />
            <span>Remote-Worker Fleet &amp; Isolation Sandboxes</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onSelectTab('audit')
              onOpenChange(false)
            }}
          >
            <History data-icon="inline-start" />
            <span>Tamper-Resistant Immutable Audit Trail</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        {/* Jump to Findings */}
        <CommandGroup heading="Active Security Findings">
          {findings.map((finding) => (
            <CommandItem
              key={finding.findingId}
              onSelect={() => {
                onSelectTab('findings')
                onOpenChange(false)
              }}
            >
              <AlertTriangle data-icon="inline-start" className="text-rose-400" />
              <span>
                [{finding.ruleId}] {finding.title} ({finding.cwe})
              </span>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}
