import { useRef, useState } from 'react'
import { FileUp, GitPullRequest, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { GatedButton } from '@/components/dashboard/findings-shared'
import type { CodeqlIngestView } from '@/types/api'

/** Mirrors the bridge's limit for one SARIF upload (CODEQL_IMPORT_MAX_BYTES). */
export const MAX_SARIF_UPLOAD_BYTES = 64 * 1024 * 1024

function describeIngest(view: CodeqlIngestView): string {
  const counts = view.findings
  const parts = [
    `${view.resultsTotal} result(s) read`,
    `${counts.created} new, ${counts.reopened} reopened, ${counts.stillOpen} still open, ${counts.resolved} resolved`,
  ]
  if (view.resultsOutsideWorkspace > 0) parts.push(`${view.resultsOutsideWorkspace} outside the workspace not stored`)
  if (view.truncated) parts.push('list truncated')
  return `${parts.join('; ')}. ${view.note}${view.warnings.length > 0 ? ` ${view.warnings.join(' ')}` : ''}`
}

/**
 * "Import CodeQL SARIF" (a file produced elsewhere, read in the browser and posted as JSON) and
 * "Sync GitHub code scanning" (open CodeQL alerts of the workspace's repository, read-only on
 * GitHub). Both need scan:run; neither runs CodeQL.
 */
export function CodeqlIngestActions({ tenantId, hasRepository }: { tenantId: string; hasRepository: boolean }) {
  const { invalidate } = useConsole()
  const input = useRef<HTMLInputElement>(null)
  const [importing, setImporting] = useState(false)
  const [syncing, setSyncing] = useState(false)

  async function importFile(file: File) {
    if (file.size > MAX_SARIF_UPLOAD_BYTES) {
      toast.error('SARIF file too large', { description: `${file.name} is larger than the ${MAX_SARIF_UPLOAD_BYTES / (1024 * 1024)} MiB import limit.` })
      return
    }
    setImporting(true)
    try {
      const view = await api.codeql.importSarif(tenantId, await file.text())
      invalidate()
      toast.success(`CodeQL SARIF imported (${view.sourceTool?.name ?? 'CodeQL'}${view.sourceTool?.version ? ` ${view.sourceTool.version}` : ''})`, {
        description: describeIngest(view),
        duration: 12_000,
      })
    } catch (error) {
      toast.error('CodeQL SARIF import failed', { description: errorMessage(error) })
    } finally {
      setImporting(false)
      if (input.current) input.current.value = ''
    }
  }

  async function sync() {
    setSyncing(true)
    try {
      const view = await api.codeql.githubSync(tenantId)
      invalidate()
      toast.success(`GitHub code scanning synced (${view.repository ?? 'repository'})`, { description: describeIngest(view), duration: 12_000 })
    } catch (error) {
      toast.error('GitHub code scanning sync failed', { description: errorMessage(error) })
    } finally {
      setSyncing(false)
    }
  }

  return (
    <>
      <input
        ref={input}
        type="file"
        accept=".sarif,.json,application/json,application/sarif+json"
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) void importFile(file)
        }}
      />
      <GatedButton permission="scan:run" variant="outline" size="sm" disabled={importing} onClick={() => input.current?.click()}>
        {importing ? <Loader2 className="animate-spin" /> : <FileUp />} Import CodeQL SARIF
      </GatedButton>
      <GatedButton
        permission="scan:run"
        variant="outline"
        size="sm"
        disabled={syncing}
        disabledReason={hasRepository ? null : 'No GitHub repository is configured or detected for this workspace.'}
        onClick={() => void sync()}
      >
        {syncing ? <Loader2 className="animate-spin" /> : <GitPullRequest />} Sync GitHub code scanning
      </GatedButton>
    </>
  )
}
