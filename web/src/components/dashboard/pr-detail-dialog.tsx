import { useState } from 'react'
import { ExternalLink, GitBranch, GitCommit } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { api } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { PullRequestView } from '@/types/api'
import { ChecksSummary, SecurityStatusBadge } from './pr-badges'
import { PrPublishPanel } from './pr-publish-panel'
import { PrScanPanel } from './pr-scan-panel'
import { PrWorkflows } from './pr-workflows'
import { shortSha } from './settings-format'
import { LoadingRows, TimeAgo } from './settings-kit'

type DetailTab = 'scan' | 'workflows' | 'publish'

export function PrDetailDialog({
  tenantId,
  repository,
  pr,
  viewerLogin,
  onClose,
}: {
  tenantId: string
  repository: { owner: string; repo: string }
  pr: PullRequestView
  viewerLogin: string | null
  onClose: () => void
}) {
  const [tab, setTab] = useState<DetailTab>('scan')
  const latest = useResource(`gh-pr-scan:${tenantId}:${pr.number}`, (signal) => api.github.latestScan(tenantId, pr.number, signal))
  const scan = latest.data?.scan

  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className="sm:max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-sm font-semibold flex items-start gap-2 pr-6">
            <span className="font-mono text-muted-foreground">#{pr.number}</span>
            <span className="break-words">{pr.title}</span>
          </DialogTitle>
          <DialogDescription render={<div />} className="text-[11px] flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              by <span className="font-mono text-foreground">@{pr.author.login}</span>
            </span>
            <span className="inline-flex items-center gap-1 font-mono">
              <GitBranch className="size-3" />
              {pr.headRef} → {pr.baseRef}
            </span>
            <span className="inline-flex items-center gap-1 font-mono">
              <GitCommit className="size-3" />
              {shortSha(pr.headSha)}
            </span>
            {pr.isDraft && (
              <Badge variant="outline" className="text-[10px]">
                Draft
              </Badge>
            )}
            <span>
              {pr.filesCount} files · <span className="text-emerald-400">+{pr.additions}</span> / <span className="text-rose-400">-{pr.deletions}</span>
            </span>
            <span>
              updated <TimeAgo iso={pr.updatedAt} />
            </span>
            <a href={pr.htmlUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-0.5 hover:text-foreground">
              Open on GitHub <ExternalLink className="size-3" />
            </a>
          </DialogDescription>
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <SecurityStatusBadge security={pr.security} />
            <ChecksSummary checks={pr.checks} />
          </div>
        </DialogHeader>

        <Tabs value={tab} onValueChange={(value) => setTab(value as DetailTab)}>
          <TabsList>
            <TabsTrigger value="scan" className="text-xs">
              Sentra scan
            </TabsTrigger>
            <TabsTrigger value="workflows" className="text-xs">
              CI workflows
            </TabsTrigger>
            <TabsTrigger value="publish" className="text-xs">
              Comment &amp; status
            </TabsTrigger>
          </TabsList>
          <TabsContent value="scan" className="pt-2">
            <PrScanPanel
              tenantId={tenantId}
              pr={pr}
              scan={scan}
              loading={latest.loading}
              error={latest.error}
              onRetry={latest.reload}
              onScanned={(result) => latest.setData({ scan: result })}
            />
          </TabsContent>
          <TabsContent value="workflows" className="pt-2">
            <PrWorkflows tenantId={tenantId} pr={pr} />
          </TabsContent>
          <TabsContent value="publish" className="pt-2">
            {latest.error ? (
              <p className="text-xs text-rose-400">The last scan could not be loaded; see the Sentra scan tab.</p>
            ) : scan === undefined ? (
              <LoadingRows rows={2} />
            ) : (
              <PrPublishPanel
                key={scan ? `${scan.headSha}:${scan.scannedAt}` : 'none'}
                tenantId={tenantId}
                repository={repository}
                pr={pr}
                scan={scan}
                viewerLogin={viewerLogin}
              />
            )}
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
