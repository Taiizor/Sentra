import { useEffect } from 'react'
import { Inbox, RefreshCw, ShieldAlert, Webhook } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { api } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { WebhookConfigView } from '@/types/api'
import { WebhookDeliveriesTable } from './webhook-deliveries'
import { WebhookCiExample, WebhookSetupSteps } from './webhook-setup'
import { ErrorState, LoadingRows, TimeAgo } from './settings-kit'

const POLL_INTERVAL_MS = 15_000
const DELIVERY_LIMIT = 100

export function WebhookTab() {
  const config = useResource('webhooks:config', (signal) => api.webhooks.config(signal))
  const deliveries = useResource('webhooks:deliveries', (signal) => api.webhooks.deliveries(DELIVERY_LIMIT, signal))
  const { reload: reloadDeliveries } = deliveries
  const { reload: reloadConfig } = config

  // Poll while the page is visible; refresh immediately when it becomes visible again.
  useEffect(() => {
    const tick = () => {
      if (document.visibilityState !== 'visible') return
      reloadDeliveries()
      reloadConfig()
    }
    const timer = window.setInterval(tick, POLL_INTERVAL_MS)
    document.addEventListener('visibilitychange', tick)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', tick)
    }
  }, [reloadDeliveries, reloadConfig])

  const refreshing = config.loading || deliveries.loading

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Webhook className="size-4 text-violet-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">Webhooks</h2>
          </div>
          <p className="text-xs text-muted-foreground">
            Push deliveries from GitHub (HMAC-SHA256 signature) and GitLab (shared token) received by this bridge, and what it did with
            them. Refreshes every 15 seconds while this page is visible.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            reloadConfig()
            reloadDeliveries()
          }}
          disabled={refreshing}
          className="h-8 text-xs gap-1.5 self-start sm:self-auto"
        >
          <RefreshCw className={`size-3 ${refreshing ? 'animate-spin text-primary' : ''}`} />
          Refresh
        </Button>
      </div>

      {config.error ? (
        <ErrorState title="Could not read the webhook configuration" error={config.error} onRetry={reloadConfig} />
      ) : !config.data ? (
        <LoadingRows rows={1} className="h-24" />
      ) : (
        <WebhookStatusRibbon config={config.data} />
      )}

      <Card className="border-border/60 bg-card/40">
        <CardHeader className="py-2.5 px-4 border-b border-border/40">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-xs font-medium text-foreground flex items-center gap-2">
              <Inbox className="size-3.5 text-muted-foreground" />
              Recorded deliveries
              {deliveries.data && <span className="text-[11px] text-muted-foreground font-normal">(latest {deliveries.data.deliveries.length})</span>}
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {deliveries.error ? (
            <div className="p-4">
              <ErrorState title="Could not load deliveries" error={deliveries.error} onRetry={reloadDeliveries} />
            </div>
          ) : !deliveries.data ? (
            <div className="p-4">
              <LoadingRows rows={3} className="h-10" />
            </div>
          ) : deliveries.data.deliveries.length === 0 ? (
            <div className="p-8 text-center text-xs text-muted-foreground flex flex-col items-center gap-2">
              <Inbox className="size-6" />
              <span className="text-foreground font-medium">No authenticated deliveries recorded yet</span>
              <span className="max-w-md">
                Deliveries appear here once GitHub or GitLab can reach this bridge and sign requests with the configured secret. Follow the
                setup steps below.
              </span>
            </div>
          ) : (
            <WebhookDeliveriesTable deliveries={deliveries.data.deliveries} />
          )}
        </CardContent>
      </Card>

      {config.data && <WebhookSetupSteps config={config.data} />}
      <WebhookCiExample />
    </div>
  )
}

function Endpoint({ provider, path, configured, envName, mechanism }: { provider: string; path: string; configured: boolean; envName: string; mechanism: string }) {
  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1 min-w-0">
      <span className="text-[10px] uppercase font-semibold text-muted-foreground">{provider} endpoint</span>
      <span className="font-mono text-xs text-foreground truncate">POST {path}</span>
      <span className="text-[11px] text-muted-foreground">{mechanism}</span>
      {configured ? (
        <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-400 bg-emerald-500/5 w-fit">
          {envName} configured
        </Badge>
      ) : (
        <Badge variant="outline" className="text-[10px] font-mono border-amber-500/30 text-amber-400 bg-amber-500/5 w-fit" title={`Set ${envName} in the bridge environment and restart it.`}>
          not configured — set {envName}
        </Badge>
      )}
    </div>
  )
}

function WebhookStatusRibbon({ config }: { config: WebhookConfigView }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Endpoint
          provider="GitHub"
          path={config.github.path}
          configured={config.github.secretConfigured}
          envName="SENTRA_GITHUB_WEBHOOK_SECRET"
          mechanism="X-Hub-Signature-256 (HMAC-SHA256 of the body)"
        />
        <Endpoint
          provider="GitLab"
          path={config.gitlab.path}
          configured={config.gitlab.tokenConfigured}
          envName="SENTRA_GITLAB_WEBHOOK_TOKEN"
          mechanism="X-Gitlab-Token (shared token)"
        />
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1 min-w-0">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
            <ShieldAlert className="size-3" />
            Rejected since bridge start
          </span>
          <span className={`font-mono text-lg font-bold ${config.rejectedSinceStart > 0 ? 'text-rose-400' : 'text-foreground'}`}>
            {config.rejectedSinceStart}
          </span>
          <span className="text-[11px] text-muted-foreground">
            {config.lastRejectedAt ? (
              <>
                last <TimeAgo iso={config.lastRejectedAt} />
              </>
            ) : (
              'none'
            )}{' '}
            · counted in memory only, reset on restart
          </span>
        </div>
      </div>
      <div className="rounded-md border border-border/50 bg-muted/20 p-2.5 text-[11px] text-muted-foreground flex flex-col gap-1">
        <span>
          Bridge bind address: <span className="font-mono text-foreground">{config.bindHost}</span>. GitHub and GitLab must reach the bridge
          through a public HTTPS reverse proxy or tunnel.
        </span>
        {config.note && <span>{config.note}</span>}
      </div>
    </div>
  )
}
