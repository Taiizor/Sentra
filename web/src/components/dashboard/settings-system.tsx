import type { ReactNode } from 'react'
import { Cpu, HardDrive, Lock, Plug, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { api } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { SystemStatus, ToolAvailability } from '@/types/api'
import {
  CANNOT_RUN_HERE_LABEL,
  cannotRunHere,
  describeCannotRun,
  describeToolPath,
  hasCurrentToolShape,
  TOOL_USAGE_LABEL,
  toolDetectionSummary,
  toolStatus,
  type ToolSearchContext,
  type ToolStatusKind,
} from './console-format'
import { CREDENTIAL_SOURCE_LABEL } from './settings-format'
import { ErrorState, LoadingRows } from './settings-kit'
import { ViewErrorBoundary } from './view-error-boundary'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-0.5 sm:gap-3 py-1 border-b border-border/20 last:border-b-0">
      <span className="text-[11px] text-muted-foreground sm:w-44 shrink-0">{label}</span>
      <span className="text-[11px] text-foreground min-w-0 break-all">{children}</span>
    </div>
  )
}

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1.5 min-w-0">
      <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
        {icon}
        {title}
      </span>
      <div className="flex flex-col">{children}</div>
    </div>
  )
}

function YesNo({ value, yes = 'yes', no = 'no' }: { value: boolean; yes?: string; no?: string }) {
  return <span className={value ? 'text-emerald-400' : 'text-amber-400'}>{value ? yes : no}</span>
}

export function SettingsSystem() {
  const status = useResource('settings:system', (signal) => api.system.status(signal))
  if (status.error) return <ErrorState title="Could not load the bridge status" error={status.error} onRetry={status.reload} />
  if (!status.data) return <LoadingRows rows={3} className="h-24" />
  // A rendering failure here (for example a response shape this console does not expect) stays in
  // this section; the other settings sections keep working.
  return (
    <ViewErrorBoundary title="The bridge status could not be shown">
      <SystemDetails system={status.data} />
    </ViewErrorBoundary>
  )
}

function SystemDetails({ system }: { system: SystemStatus }) {
  const { core, auth, integrations } = system
  // A bridge running older code (contract version 1) sends no tool search details.
  const currentTools = hasCurrentToolShape(system)
  const search: ToolSearchContext | null = currentTools ? { toolSearch: system.toolSearch, platform: system.host.platform } : null
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
      <Section icon={<Cpu className="size-3" />} title="Sentra core">
        <Row label="Bridge mode">{system.mode}</Row>
        <Row label="Core binary">
          <span className="font-mono">{core.binaryPath}</span>
        </Row>
        <Row label="Binary present">
          {core.present && core.binary && cannotRunHere(core.binary) ? (
            <span className="text-rose-400" title={describeCannotRun(core.binary)}>
              {CANNOT_RUN_HERE_LABEL}
            </span>
          ) : (
            <YesNo value={core.present} />
          )}
        </Row>
        <Row label="Version">{core.version ? <span className="font-mono">{core.version}</span> : <span className="text-muted-foreground">unknown</span>}</Row>
        {core.error && (
          <Row label="Version check error">
            <span className="text-rose-400">{core.error}</span>
          </Row>
        )}
      </Section>

      <Section icon={<HardDrive className="size-3" />} title="Storage">
        <Row label="Data directory">
          <span className="font-mono">{system.dataDir}</span>
        </Row>
        <Row label="Remote workers">
          <span className="text-muted-foreground">{system.remoteWorkers.note}</span>
        </Row>
      </Section>

      <Section icon={<Lock className="size-3" />} title="Access">
        <Row label="Bind address">
          <span className="font-mono">{auth.bindHost}</span>{' '}
          {auth.loopbackOnly ? (
            <span className="text-muted-foreground">(loopback only: reachable from this machine)</span>
          ) : (
            <span className="text-amber-400">(not loopback: reachable from the network)</span>
          )}
        </Row>
        <Row label="Configured token grants">
          {auth.configuredGrants}{' '}
          <span className="text-muted-foreground">
            from SENTRA_WEB_TOKENS
            {auth.configuredGrants === 0 && auth.generatedLocalToken ? ' (not set; the generated local admin token is in use)' : ''}
          </span>
        </Row>
        <Row label="Generated local admin token">
          {auth.generatedLocalToken ? 'yes (web-admin.token in the data directory)' : 'no'}
        </Row>
      </Section>

      <Section icon={<Plug className="size-3" />} title="Integrations">
        <Row label="GitHub credential">
          {integrations.githubCredentialSource ? CREDENTIAL_SOURCE_LABEL[integrations.githubCredentialSource] : <YesNo value={false} no="not configured" />}
        </Row>
        <Row label="OSV.dev lookups">
          <YesNo value={integrations.osvEnabled} yes="enabled" no="disabled" />
        </Row>
        <Row label="Default AI provider">{integrations.aiDefaultProvider ?? <span className="text-muted-foreground">none</span>}</Row>
        <Row label="Configured AI providers">
          {integrations.aiReadyProviders.length > 0 ? integrations.aiReadyProviders.join(', ') : <span className="text-muted-foreground">none</span>}
        </Row>
        <Row label="GitHub webhook secret">
          <YesNo value={integrations.githubWebhookSecretConfigured} yes="configured" no="not configured" />
        </Row>
        <Row label="GitLab webhook token">
          <YesNo value={integrations.gitlabWebhookTokenConfigured} yes="configured" no="not configured" />
        </Row>
      </Section>

      <div className="xl:col-span-2">
        <Section icon={<Wrench className="size-3" />} title="Tools on the bridge host">
          {search ? (
            <>
              <div className="flex flex-wrap gap-1.5 py-1">
                {system.tools.map((tool) => {
                  const toolState = toolStatus(tool)
                  return (
                    <Badge
                      key={tool.name}
                      variant="outline"
                      title={toolTitle(tool, search)}
                      className={`text-[10px] font-mono ${TOOL_STATUS_BADGE_CLASS[toolState.kind]}`}
                    >
                      {tool.name}: {toolState.kind === 'cannot_run' ? 'cannot run here' : toolState.label} · {TOOL_USAGE_LABEL[tool.usage]}
                    </Badge>
                  )
                })}
              </div>
              <span className="text-[10px] text-muted-foreground">
                {toolDetectionSummary(search.toolSearch, search.platform)} The second label says how the bridge uses the tool; hover
                a tool for its path, or open Host &amp; workers for details and to set a tool&apos;s path.
              </span>
            </>
          ) : (
            <span className="text-[11px] text-amber-400 py-1">
              The bridge did not send the tool search details: it is running older code than this console. Restart the bridge (for
              example stop and rerun <span className="font-mono">bun run dev</span>).
            </span>
          )}
        </Section>
      </div>
    </div>
  )
}

const TOOL_STATUS_BADGE_CLASS: Record<ToolStatusKind, string> = {
  found: 'border-emerald-500/30 text-emerald-400',
  not_found: 'text-muted-foreground',
  configured_broken: 'border-amber-500/30 text-amber-400',
  cannot_run: 'border-rose-500/30 text-rose-400',
}

function toolTitle(tool: ToolAvailability, search: ToolSearchContext): string {
  const status = toolStatus(tool)
  // The path details already describe a broken chosen path (and whether the file shown instead can
  // run here); a found file that cannot run here is added.
  const lines = [describeToolPath(tool, search)]
  if (status.kind === 'cannot_run') lines.unshift(status.title)
  lines.push(`Used by the bridge: ${TOOL_USAGE_LABEL[tool.usage]}${tool.usageNote ? ` (${tool.usageNote})` : ''}`)
  return lines.join('\n')
}
