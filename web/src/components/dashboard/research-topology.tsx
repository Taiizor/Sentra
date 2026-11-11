import { useState, type ReactNode } from 'react'
import { Boxes, CheckCircle2, Loader2, Map as MapIcon, Network, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { TenantView, ToolAvailability, TopologyReportView } from '@/types/api'
import { EXECUTABLE_SOURCE_LABEL, formatDateTime, TOOL_USAGE_LABEL } from './console-format'
import { EmptyBlock, ErrorAlert, GatedButton, KeyValue, LoadingBlock, SectionCard } from './console-kit'
import { LockfileList } from './stream-summary'

/** Workspace topology computed by the bridge from the workspace's files (latest report). */
export function TopologyPanel({ tenant }: { tenant: TenantView }) {
  const { invalidate } = useConsole()
  const topology = useResource(`topology:${tenant.tenantId}`, (signal) => api.research.topology(tenant.tenantId, signal))
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState<unknown>(null)

  const run = async () => {
    setRunning(true)
    setRunError(null)
    try {
      const report = await api.research.runTopology(tenant.tenantId)
      topology.setData({ report })
      toast.success('Topology report created')
      invalidate()
    } catch (failure) {
      setRunError(failure)
    } finally {
      setRunning(false)
    }
  }

  const report = topology.data?.report ?? null

  return (
    <div className="flex flex-col gap-4">
      <SectionCard
        icon={<MapIcon className="size-4 text-emerald-400" />}
        title="Workspace topology"
        description={
          report
            ? `Report ${report.reportId} created ${formatDateTime(report.createdAt)} by ${report.createdBy}.`
            : 'Languages, manifests, subsystems, lockfiles and entry-point candidates derived from the workspace files.'
        }
        actions={
          <GatedButton
            permission="research:run"
            blockedReason={tenant.workspaceExists ? null : 'The workspace directory does not exist on the bridge host'}
            size="sm"
            disabled={running}
            onClick={() => void run()}
          >
            {running ? <Loader2 className="animate-spin" /> : <Network />}
            {report ? 'Map again' : 'Map topology'}
          </GatedButton>
        }
      >
        {runError !== null && <ErrorAlert error={runError} title="Topology mapping failed" />}
        {topology.error ? (
          <ErrorAlert error={topology.error} onRetry={topology.reload} title="Could not load the topology report" />
        ) : !topology.data ? (
          <LoadingBlock rows={3} />
        ) : !report ? (
          <EmptyBlock icon={<MapIcon />} title="No topology report for this workspace yet">
            Map topology builds a report from the workspace's files: languages by file extension, manifests, declared
            frameworks, lockfiles and entry-point candidates.
          </EmptyBlock>
        ) : (
          <KeyValue label="Workspace" mono>
            {report.workspace}
          </KeyValue>
        )}
      </SectionCard>

      {report && <TopologyDetails report={report} />}
    </div>
  )
}

function TopologyDetails({ report }: { report: TopologyReportView }) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <SectionCard title="Languages" description="Files per language, counted by extension.">
        {report.languages.length === 0 ? (
          <Muted>No recognised source files.</Muted>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {report.languages.map((entry) => (
              <Badge
                key={entry.language}
                variant="outline"
                className={entry.language === report.primaryLanguage ? 'border-primary/50 font-mono text-[10px] text-primary' : 'font-mono text-[10px]'}
              >
                {entry.language}: {entry.filesCount}
                {entry.language === report.primaryLanguage ? ' (primary)' : ''}
              </Badge>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title="Tools on the bridge host" description="Presence when the report was created, including paths set in the console. Tools are located, never run.">
        <div className="flex flex-wrap gap-1.5">
          {report.tools.map((tool) => (
            <span key={tool.name} className="inline-flex items-center gap-1 text-[11px]" title={topologyToolTitle(tool)}>
              {tool.available ? <CheckCircle2 className="size-3 text-emerald-400" /> : <XCircle className="size-3 text-zinc-600" />}
              <span className="font-mono">{tool.name}</span>
            </span>
          ))}
        </div>
      </SectionCard>

      <SectionCard title={`Manifests (${report.manifests.length})`}>
        <SimpleTable
          empty="No package manifests found."
          headers={['Path', 'Kind', 'Ecosystem']}
          rows={report.manifests.map((manifest) => [
            <Mono key="p">{manifest.path}</Mono>,
            manifest.kind,
            <Mono key="e">{manifest.ecosystem ?? 'unknown'}</Mono>,
          ])}
        />
      </SectionCard>

      <SectionCard title={`Frameworks declared in manifests (${report.frameworks.length})`}>
        <SimpleTable
          empty="No known framework dependency is declared."
          headers={['Name', 'Version', 'Manifest']}
          rows={report.frameworks.map((framework) => [
            <Mono key="n">{framework.name}</Mono>,
            <Mono key="v">{framework.version ?? 'unspecified'}</Mono>,
            <Mono key="m">{framework.manifest}</Mono>,
          ])}
        />
      </SectionCard>

      <SectionCard title={`Subsystems (${report.subsystems.length})`}>
        <SimpleTable
          empty="No subsystem was identified."
          headers={['Name', 'Path', 'Kind']}
          rows={report.subsystems.map((subsystem) => [subsystem.name, <Mono key="p">{subsystem.path}</Mono>, subsystem.kind])}
        />
      </SectionCard>

      <SectionCard
        icon={<Boxes className="size-4 text-sky-400" />}
        title={`Lockfiles (${report.lockfiles.length}) · ${report.packagesTotal.toLocaleString()} packages`}
      >
        <LockfileList lockfiles={report.lockfiles} />
      </SectionCard>

      <SectionCard
        className="xl:col-span-2"
        title={`Entry-point candidates (${report.entrypoints.length})`}
        description="Heuristic: files that look like entry points, with the evidence that matched. Nothing here is confirmed reachable or exposed."
      >
        <SimpleTable
          empty="No entry-point candidate was identified."
          headers={['Path', 'Kind', 'Evidence']}
          rows={report.entrypoints.map((entrypoint) => [
            <Mono key="p">{entrypoint.path}</Mono>,
            entrypoint.kind,
            <span key="e" className="font-mono text-[11px] text-zinc-400">
              {entrypoint.evidence}
            </span>,
          ])}
        />
      </SectionCard>

      {report.notes.length > 0 && (
        <SectionCard className="xl:col-span-2" title="Notes from the mapper">
          <ul className="flex list-disc flex-col gap-0.5 pl-4 text-xs text-zinc-300">
            {report.notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        </SectionCard>
      )}
    </div>
  )
}

function SimpleTable({ headers, rows, empty }: { headers: string[]; rows: ReactNode[][]; empty: string }) {
  if (rows.length === 0) return <Muted>{empty}</Muted>
  return (
    <div className="max-h-80 overflow-auto">
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            {headers.map((header) => (
              <TableHead key={header}>{header}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((cells, index) => (
            <TableRow key={index}>
              {cells.map((cell, cellIndex) => (
                <TableCell key={cellIndex} className="max-w-96 whitespace-normal break-all">
                  {cell}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[11px]">{children}</span>
}

function Muted({ children }: { children: ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>
}

/**
 * Reports persisted before the tool search recorded usage carry only name, availability and path,
 * and reports from before contract version 3 no source of a path set in the console.
 */
function topologyToolTitle(tool: ToolAvailability): string {
  const lines = [tool.path ?? 'not found']
  if (tool.path && tool.source) lines.push(`Found via: ${EXECUTABLE_SOURCE_LABEL[tool.source] ?? tool.source}`)
  if (tool.usage) lines.push(`Used by the bridge: ${TOOL_USAGE_LABEL[tool.usage]}`)
  return lines.join('\n')
}
