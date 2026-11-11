import type { ReactNode } from 'react'
import { ArrowRight, ExternalLink, ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { TenantView } from '@/types/api'
import { formatDateTime, osvUrl } from './console-format'
import { EmptyBlock, ErrorAlert, LoadingBlock, SectionCard, SeverityBadge } from './console-kit'

/** Open findings produced by dependency audits (OSV records matched to lockfile packages). */
export function DependencyFindings({ tenant, actions }: { tenant: TenantView; actions?: ReactNode }) {
  const { navigate } = useConsole()
  const findings = useResource(`dependency-findings:${tenant.tenantId}`, (signal) =>
    api.findings.list(tenant.tenantId, { source: 'dependency', state: 'open' }, signal),
  )
  const list = findings.data?.findings ?? []

  return (
    <SectionCard
      icon={<ShieldAlert className="size-4 text-rose-400" />}
      title={`Open dependency findings${findings.data ? ` (${list.length})` : ''}`}
      description="OSV records matched to package versions from this workspace's lockfiles by a dependency audit run."
      actions={actions}
    >
      {findings.error ? (
        <ErrorAlert error={findings.error} onRetry={findings.reload} title="Could not load dependency findings" />
      ) : !findings.data ? (
        <LoadingBlock rows={3} />
      ) : list.length === 0 ? (
        <EmptyBlock icon={<ShieldAlert />} title="No open dependency findings">
          Either no dependency audit has run for this workspace yet, or the last audit matched no OSV record to a locked
          package version. Run a dependency audit to refresh.
        </EmptyBlock>
      ) : (
        <Table className="text-xs">
          <TableHeader>
            <TableRow>
              <TableHead>Package</TableHead>
              <TableHead>Advisory</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Fixed in</TableHead>
              <TableHead>Lockfile</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.map((finding) => {
              const dep = finding.dependency
              return (
                <TableRow key={finding.findingId}>
                  <TableCell className="font-mono text-[11px]">
                    {dep ? (
                      <>
                        <span className="text-zinc-100">{dep.packageName}</span>
                        <span className="text-zinc-500">@{dep.packageVersion}</span>
                        <div className="text-[10px] text-zinc-500">{dep.ecosystem}</div>
                      </>
                    ) : (
                      <span className="text-zinc-400">{finding.ruleName}</span>
                    )}
                  </TableCell>
                  <TableCell className="max-w-72 whitespace-normal">
                    {dep ? (
                      <>
                        <a
                          href={osvUrl(dep.advisoryId)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-[11px] text-primary hover:underline"
                        >
                          {dep.advisoryId}
                          <ExternalLink className="size-3" />
                        </a>
                        {dep.aliases.length > 0 && (
                          <div className="font-mono text-[10px] text-zinc-500">{dep.aliases.join(', ')}</div>
                        )}
                        {dep.summary && <div className="text-[11px] text-zinc-300">{dep.summary}</div>}
                      </>
                    ) : (
                      <span className="font-mono text-[11px]">{finding.ruleId}</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-0.5">
                      <SeverityBadge severity={finding.severity} />
                      {dep && (
                        <span className="text-[10px] text-zinc-500">
                          {dep.severitySource === 'none' ? 'no rating published' : dep.severitySource}
                          {dep.cvssScore !== null ? ` · CVSS ${dep.cvssScore.toFixed(1)}` : ''}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="max-w-40 whitespace-normal font-mono text-[11px]">
                    {dep && dep.fixedVersions.length > 0 ? dep.fixedVersions.join(', ') : dep?.fixedVersionsNote ? 'none listed' : 'none published'}
                    {dep?.fixedVersionsNote && (
                      <details className="mt-0.5 font-sans text-[10px] text-amber-300/90">
                        <summary className="cursor-pointer select-none">caveat</summary>
                        {dep.fixedVersionsNote}
                      </details>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-zinc-400">{dep?.lockfile ?? finding.filePath ?? 'n/a'}</TableCell>
                  <TableCell className="text-[11px] text-zinc-400">{formatDateTime(finding.lastSeenAt)}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="xs" onClick={() => navigate('findings', { findingId: finding.findingId })}>
                      Open
                      <ArrowRight />
                    </Button>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  )
}
