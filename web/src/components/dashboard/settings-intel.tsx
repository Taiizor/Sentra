import { useState } from 'react'
import { Database, Globe } from 'lucide-react'
import { toast } from 'sonner'
import { Switch } from '@/components/ui/switch'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { permissionHint } from './settings-format'
import { ConfirmDialog, ErrorState, LoadingRows, TimeAgo } from './settings-kit'

/** OSV.dev lookups for dependency findings: off by default, enabled only by an explicit admin choice. */
export function SettingsIntel() {
  const { can, invalidate } = useConsole()
  const status = useResource('settings:intel', (signal) => api.intel.status(signal))
  const [confirmEnable, setConfirmEnable] = useState(false)
  const [saving, setSaving] = useState(false)

  async function apply(enabled: boolean) {
    setSaving(true)
    try {
      const next = await api.intel.setOsvEnabled(enabled)
      status.setData(next)
      invalidate()
      toast.success(enabled ? 'OSV lookups enabled' : 'OSV lookups disabled')
    } catch (error) {
      toast.error('OSV setting was not changed', { description: errorMessage(error) })
      throw error
    } finally {
      setSaving(false)
    }
  }

  if (status.error) return <ErrorState title="Could not load the threat intelligence settings" error={status.error} onRetry={status.reload} />
  if (!status.data) return <LoadingRows rows={1} className="h-28" />

  const intel = status.data
  const canWrite = can('settings:write')
  const toggle = (
    <Switch
      checked={intel.osvEnabled}
      disabled={!canWrite || saving}
      onCheckedChange={(checked) => {
        if (checked) setConfirmEnable(true)
        else void apply(false).catch(() => undefined)
      }}
      aria-label="Enable OSV lookups"
    />
  )

  return (
    <div className="flex flex-col gap-3">
      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
        <div className="flex items-center justify-between gap-3">
          <div className="flex flex-col gap-0.5">
            <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Globe className="size-3.5 text-muted-foreground" />
              OSV.dev advisory lookups
            </span>
            <span className="font-mono text-[10px] text-muted-foreground break-all">{intel.endpoint}</span>
          </div>
          {canWrite ? (
            toggle
          ) : (
            <Tooltip>
              <TooltipTrigger render={<span className="inline-flex cursor-not-allowed" tabIndex={0} />}>{toggle}</TooltipTrigger>
              <TooltipContent>{permissionHint('settings:write')}</TooltipContent>
            </Tooltip>
          )}
        </div>
        <span className={`text-xs ${intel.osvEnabled ? 'text-emerald-400' : 'text-muted-foreground'}`}>
          {intel.osvEnabled ? 'Enabled' : 'Disabled — dependency scans skip advisory lookups and say so in the scan result.'}
        </span>
        <p className="text-[11px] text-muted-foreground">{intel.privacyNote}</p>
        {intel.changedAt && (
          <span className="text-[11px] text-muted-foreground">
            Last changed <TimeAgo iso={intel.changedAt} />
            {intel.changedBy ? ` by ${intel.changedBy}` : ''}.
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-0.5">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
            <Database className="size-3" />
            Cached advisories
          </span>
          <span className="font-mono text-lg font-bold text-foreground">{intel.cachedAdvisories}</span>
          <span className="text-[11px] text-muted-foreground">OSV records stored by the bridge from earlier lookups.</span>
        </div>
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-0.5">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground">Last query</span>
          <span className="text-sm text-foreground">
            <TimeAgo iso={intel.lastQueryAt} />
          </span>
          <span className="text-[11px] text-muted-foreground">{intel.lastQueryAt ? 'Most recent request to OSV.dev.' : 'OSV.dev has not been queried yet.'}</span>
        </div>
      </div>

      <ConfirmDialog
        open={confirmEnable}
        onOpenChange={setConfirmEnable}
        title="Enable OSV.dev lookups?"
        confirmLabel="Enable lookups"
        onConfirm={() => apply(true)}
      >
        <p>
          Dependency scans and advisory queries will send package names, versions and ecosystems from workspace lockfiles to{' '}
          <span className="font-mono text-foreground">{intel.endpoint}</span>.
        </p>
        <p>{intel.privacyNote}</p>
      </ConfirmDialog>
    </div>
  )
}
