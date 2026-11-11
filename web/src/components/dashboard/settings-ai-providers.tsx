import { useMemo, useState } from 'react'
import { Bot, KeyRound, ListFilter, Server } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { AiSettingsView, ListModelsResponse, ProviderId, ProviderStatusView, UpdateProviderRequest } from '@/types/api'
import { permissionHint } from './settings-format'
import { ConfirmDialog, ErrorState, GatedButton, LoadingRows, TimeAgo } from './settings-kit'

const NO_DEFAULT = '__none__'

export function SettingsAiProviders() {
  const settings = useResource('settings:ai', (signal) => api.ai.settings(signal))

  if (settings.error) return <ErrorState title="Could not load AI provider settings" error={settings.error} onRetry={settings.reload} />
  if (!settings.data) return <LoadingRows rows={3} className="h-28" />

  const view = settings.data
  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs text-muted-foreground">
        Model providers are used for candidate patches and reconnaissance notes. Everything a model returns is unverified output. A provider is <span className="text-foreground">configured</span> when it has a model and, where required, a stored
        API key; that does not test connectivity — use <span className="text-foreground">Fetch models</span> for a live check against the
        provider.
      </p>
      <DefaultProviderSelect view={view} onChange={(next) => settings.setData(next)} />
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
        {view.providers.map((provider) => (
          <ProviderCard
            // Remount (dropping drafts) only when this provider's saved state changes.
            key={`${provider.id}:${provider.model ?? ''}:${provider.endpoint}:${provider.keyUpdatedAt ?? ''}:${provider.keyConfigured}`}
            provider={provider}
            onSaved={(next) => settings.setData(next)}
          />
        ))}
      </div>
      {view.updatedAt && (
        <span className="text-[11px] text-muted-foreground">
          Last changed <TimeAgo iso={view.updatedAt} />
          {view.updatedBy ? ` by ${view.updatedBy}` : ''}.
        </span>
      )}
    </div>
  )
}

function DefaultProviderSelect({ view, onChange }: { view: AiSettingsView; onChange: (next: AiSettingsView) => void }) {
  const { can, invalidate } = useConsole()
  const [saving, setSaving] = useState(false)
  const ready = view.providers.filter((provider) => provider.ready)
  const current = view.providers.find((provider) => provider.id === view.defaultProvider) ?? null
  const labels = new Map<string, string>(view.providers.map((provider) => [provider.id, `${provider.label}${provider.model ? ` · ${provider.model}` : ''}`]))
  labels.set(NO_DEFAULT, 'No default provider')

  async function choose(value: string) {
    const provider = value === NO_DEFAULT ? null : (value as ProviderId)
    if (provider === view.defaultProvider) return
    setSaving(true)
    try {
      const next = await api.ai.setDefault(provider)
      onChange(next)
      invalidate()
      toast.success(provider ? `Default provider set to ${labels.get(provider)}` : 'Default provider cleared')
    } catch (error) {
      toast.error('Default provider was not changed', { description: errorMessage(error) })
    } finally {
      setSaving(false)
    }
  }

  const disabled = saving || !can('settings:write')
  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div className="flex flex-col gap-0.5">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground">Default provider</span>
        <span className="text-xs text-foreground">
          {current ? labels.get(current.id) : 'None — features that need a model report “not configured”.'}
        </span>
        {current && !current.ready && (
          <span className="text-[11px] text-amber-400">This provider is no longer configured (missing model or API key).</span>
        )}
        {ready.length === 0 && <span className="text-[11px] text-muted-foreground">No provider is configured yet.</span>}
      </div>
      <Select value={view.defaultProvider ?? NO_DEFAULT} onValueChange={(value) => {
          if (value) void choose(String(value))
        }} disabled={disabled}>
        <SelectTrigger size="sm" className="w-full sm:w-72 text-xs" title={!can('settings:write') ? permissionHint('settings:write') : undefined}>
          <SelectValue>{(value: string | null) => labels.get(value ?? NO_DEFAULT) ?? value}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NO_DEFAULT}>No default provider</SelectItem>
          {ready.map((provider) => (
            <SelectItem key={provider.id} value={provider.id}>
              {labels.get(provider.id)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

function ProviderCard({ provider, onSaved }: { provider: ProviderStatusView; onSaved: (next: AiSettingsView) => void }) {
  const { can, invalidate } = useConsole()
  const savedEndpoint = provider.usesCustomEndpoint ? provider.endpoint : ''
  const [model, setModel] = useState(provider.model ?? '')
  const [endpoint, setEndpoint] = useState(savedEndpoint)
  const [apiKey, setApiKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [clearOpen, setClearOpen] = useState(false)
  const [listing, setListing] = useState(false)
  const [models, setModels] = useState<ListModelsResponse | null>(null)
  const [modelFilter, setModelFilter] = useState('')

  const canWrite = can('settings:write')
  const modelChanged = model.trim() !== (provider.model ?? '')
  const endpointChanged = provider.customEndpointAllowed && endpoint.trim() !== savedEndpoint
  const keyEntered = apiKey.length > 0
  const dirty = modelChanged || endpointChanged || keyEntered

  const visibleModels = useMemo(() => {
    if (!models) return []
    const needle = modelFilter.trim().toLowerCase()
    return needle ? models.models.filter((id) => id.toLowerCase().includes(needle)) : models.models
  }, [models, modelFilter])

  async function save() {
    const body: UpdateProviderRequest = {}
    if (modelChanged) body.model = model.trim() || null
    if (endpointChanged) body.endpoint = endpoint.trim() || null
    if (keyEntered) body.apiKey = apiKey
    setSaving(true)
    try {
      const next = await api.ai.updateProvider(provider.id, body)
      onSaved(next)
      invalidate()
      toast.success(`${provider.label} settings saved`)
    } catch (error) {
      toast.error(`${provider.label} settings were not saved`, { description: errorMessage(error) })
    } finally {
      setSaving(false)
    }
  }

  async function clearKey() {
    try {
      const next = await api.ai.updateProvider(provider.id, { clearKey: true })
      onSaved(next)
      invalidate()
      toast.success(`${provider.label} API key removed`)
    } catch (error) {
      toast.error('API key was not removed', { description: errorMessage(error) })
      throw error
    }
  }

  async function fetchModels() {
    setListing(true)
    try {
      const result = await api.ai.listModels(provider.id)
      setModels(result)
      setModelFilter('')
      toast.success(`${provider.label}: ${result.models.length} models listed`, { description: `Provider answered in ${result.latencyMs} ms.` })
    } catch (error) {
      setModels(null)
      toast.error(`${provider.label}: model listing failed`, { description: errorMessage(error) })
    } finally {
      setListing(false)
    }
  }

  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-3 min-w-0">
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-col gap-0.5 min-w-0">
          <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
            <Bot className="size-3.5 text-muted-foreground" />
            {provider.label}
          </span>
          <span className="font-mono text-[10px] text-muted-foreground break-all">
            {provider.endpoint}
            {provider.usesCustomEndpoint ? ' (custom)' : ' (default)'}
          </span>
        </div>
        {provider.ready ? (
          <Badge variant="outline" className="text-[10px] border-emerald-500/30 text-emerald-400 bg-emerald-500/5 shrink-0">
            configured
          </Badge>
        ) : (
          <Badge variant="outline" className="text-[10px] text-muted-foreground shrink-0">
            not configured
          </Badge>
        )}
      </div>

      {/* Model */}
      <div className="flex flex-col gap-1">
        <label className="text-[10px] uppercase font-semibold text-muted-foreground" htmlFor={`model-${provider.id}`}>
          Model
        </label>
        <div className="flex gap-2">
          <Input
            id={`model-${provider.id}`}
            value={model}
            onChange={(event) => setModel(event.target.value)}
            placeholder="Model identifier (use Fetch models to list them)"
            className="h-7 text-xs font-mono"
            disabled={!canWrite}
            spellCheck={false}
            autoComplete="off"
          />
          <GatedButton
            permission="ai:test"
            size="sm"
            onClick={() => void fetchModels()}
            busy={listing}
            disabled={provider.requiresKey && !provider.keyConfigured}
            className="text-xs shrink-0"
          >
            <ListFilter className="size-3" />
            Fetch models
          </GatedButton>
        </div>
        {provider.requiresKey && !provider.keyConfigured && (
          <span className="text-[11px] text-muted-foreground">Store an API key before fetching the model list.</span>
        )}
        {dirty && <span className="text-[11px] text-muted-foreground">Fetch models uses the saved key and endpoint, not unsaved edits.</span>}
        {models && (
          <div className="flex flex-col gap-1.5 rounded-md border border-border/50 bg-zinc-950/40 p-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] text-muted-foreground">
                {models.models.length} models from {provider.label} ({models.latencyMs} ms) — click one to use it
              </span>
              <Input
                value={modelFilter}
                onChange={(event) => setModelFilter(event.target.value)}
                placeholder="Filter"
                className="h-6 w-32 text-[11px]"
              />
            </div>
            {visibleModels.length === 0 ? (
              <span className="text-[11px] text-muted-foreground">No model matches.</span>
            ) : (
              <ul className="max-h-40 overflow-y-auto flex flex-col">
                {visibleModels.map((id) => (
                  <li key={id}>
                    <button
                      type="button"
                      disabled={!canWrite}
                      onClick={() => setModel(id)}
                      className={`w-full text-left font-mono text-[11px] px-1.5 py-0.5 rounded hover:bg-muted/40 disabled:cursor-not-allowed ${
                        id === model ? 'text-primary' : 'text-zinc-300'
                      }`}
                    >
                      {id}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* API key */}
      {provider.requiresKey ? (
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1" htmlFor={`key-${provider.id}`}>
            <KeyRound className="size-3" />
            API key
          </label>
          <div className="text-[11px] text-muted-foreground flex items-center gap-2 flex-wrap">
            {provider.keyConfigured ? (
              <>
                <span>
                  Stored: <span className="font-mono text-foreground">{provider.maskedKey}</span>
                </span>
                {provider.keyUpdatedAt && (
                  <span>
                    updated <TimeAgo iso={provider.keyUpdatedAt} />
                  </span>
                )}
                <GatedButton permission="settings:write" size="xs" variant="ghost" onClick={() => setClearOpen(true)} className="text-rose-400">
                  Clear key
                </GatedButton>
              </>
            ) : (
              <span>No key stored.</span>
            )}
          </div>
          <Input
            id={`key-${provider.id}`}
            type="password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder={provider.keyConfigured ? 'Enter a new key to replace the stored one' : 'Paste an API key'}
            className="h-7 text-xs font-mono"
            autoComplete="new-password"
            disabled={!canWrite}
            spellCheck={false}
          />
          <span className="text-[10px] text-muted-foreground">
            Write-only: the key is sent to the bridge once and never returned; only its last four characters are shown.
          </span>
        </div>
      ) : (
        <span className="text-[11px] text-muted-foreground">No API key is needed for this provider.</span>
      )}

      {/* Endpoint */}
      {provider.customEndpointAllowed && (
        <div className="flex flex-col gap-1">
          <label className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1" htmlFor={`endpoint-${provider.id}`}>
            <Server className="size-3" />
            Custom endpoint
          </label>
          <Input
            id={`endpoint-${provider.id}`}
            value={endpoint}
            onChange={(event) => setEndpoint(event.target.value)}
            placeholder={provider.loopbackOnly ? 'http://127.0.0.1:11434/v1' : 'https://… (leave empty for the default)'}
            className="h-7 text-xs font-mono"
            disabled={!canWrite}
            spellCheck={false}
            autoComplete="off"
          />
          <span className="text-[10px] text-muted-foreground">
            {provider.loopbackOnly
              ? 'Loopback only: the bridge accepts 127.0.0.1, localhost or [::1] (for example Ollama or LM Studio on the bridge host). Plain HTTP is allowed for loopback.'
              : `An OpenAI-compatible HTTPS endpoint. The stored ${provider.label} key is sent to this endpoint. Leave empty to use the default.`}
          </span>
        </div>
      )}

      <div className="flex items-center justify-end gap-2">
        {dirty && (
          <button
            type="button"
            className="text-[11px] text-muted-foreground hover:text-foreground"
            onClick={() => {
              setModel(provider.model ?? '')
              setEndpoint(savedEndpoint)
              setApiKey('')
            }}
          >
            Discard changes
          </button>
        )}
        <GatedButton permission="settings:write" variant="default" size="sm" onClick={() => void save()} busy={saving} disabled={!dirty} className="text-xs">
          Save
        </GatedButton>
      </div>

      <ConfirmDialog
        open={clearOpen}
        onOpenChange={setClearOpen}
        title={`Remove the ${provider.label} API key?`}
        confirmLabel="Remove key"
        destructive
        onConfirm={clearKey}
      >
        <p>
          Deletes the stored {provider.label} key ({provider.maskedKey}) from the bridge. Features that use this provider will report it as not
          configured until a new key is stored.
        </p>
      </ConfirmDialog>
    </div>
  )
}
