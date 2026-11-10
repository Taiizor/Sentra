import { useState, useEffect } from 'react'
import {
  Settings,
  Key,
  Cpu,
  CheckCircle2,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
  Save,
  ShieldCheck,
  Lock,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { UserRole } from '@/types/sentra'
import { toast } from 'sonner'

interface SettingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  currentRole: UserRole
}

interface ProviderState {
  apiKey: string
  model: string
  endpoint?: string
  isConfigured: boolean
  maskedKey: string
}

export function SettingsDialog({
  open,
  onOpenChange,
  currentRole,
}: SettingsDialogProps) {
  const [activeTab, setActiveTab] = useState('providers')
  const [defaultProvider, setDefaultProvider] = useState('anthropic')
  const [defaultModel, setDefaultModel] = useState('claude-3-7-sonnet-20250219')

  const [providers, setProviders] = useState<Record<string, ProviderState>>({
    anthropic: { apiKey: '', model: 'claude-3-7-sonnet-20250219', isConfigured: false, maskedKey: '' },
    openai: { apiKey: '', model: 'o3-mini', isConfigured: false, maskedKey: '' },
    gemini: { apiKey: '', model: 'gemini-2.5-flash', isConfigured: false, maskedKey: '' },
    xai: { apiKey: '', model: 'grok-3', isConfigured: false, maskedKey: '' },
    deepseek: { apiKey: '', model: 'deepseek-chat', isConfigured: false, maskedKey: '' },
    openrouter: { apiKey: '', model: 'anthropic/claude-3.7-sonnet', isConfigured: false, maskedKey: '' },
  })

  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({})
  const [testing, setTesting] = useState<Record<string, boolean>>({})
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; message: string }>>({})
  const [saving, setSaving] = useState(false)

  // Load configured settings on open
  useEffect(() => {
    if (!open) return
    async function loadSettings() {
      try {
        const res = await fetch('/api/settings/ai')
        if (res.ok) {
          const data = await res.json()
          if (data.defaultProvider) setDefaultProvider(data.defaultProvider)
          if (data.defaultModel) setDefaultModel(data.defaultModel)
          if (data.providers) {
            setProviders((prev) => {
              const updated = { ...prev }
              for (const [k, v] of Object.entries(data.providers) as any[]) {
                if (updated[k]) {
                  updated[k] = {
                    ...updated[k],
                    model: v.model || updated[k].model,
                    endpoint: v.endpoint || '',
                    isConfigured: v.isConfigured || false,
                    maskedKey: v.maskedKey || '',
                    apiKey: v.isConfigured ? v.maskedKey : '',
                  }
                }
              }
              return updated
            })
          }
        }
      } catch (err) {
        console.error('Failed to load settings:', err)
      }
    }
    loadSettings()
  }, [open])

  function handleKeyChange(provider: string, val: string) {
    setProviders((prev) => ({
      ...prev,
      [provider]: {
        ...prev[provider],
        apiKey: val,
      },
    }))
    // Clear test result on edit
    setTestResults((prev) => {
      const copy = { ...prev }
      delete copy[provider]
      return copy
    })
  }

  function handleModelChange(provider: string, val: string) {
    setProviders((prev) => ({
      ...prev,
      [provider]: {
        ...prev[provider],
        model: val,
      },
    }))
  }

  async function handleTestConnection(provider: string) {
    const p = providers[provider]
    if (!p) return

    setTesting((prev) => ({ ...prev, [provider]: true }))
    setTestResults((prev) => {
      const copy = { ...prev }
      delete copy[provider]
      return copy
    })

    try {
      const res = await fetch('/api/ai/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          apiKey: p.apiKey,
          model: p.model,
          endpoint: p.endpoint,
        }),
      })

      const data = await res.json()
      if (data.ok) {
        setTestResults((prev) => ({
          ...prev,
          [provider]: { ok: true, message: `Connected (${data.latencyMs}ms)` },
        }))
        toast.success(`${provider.toUpperCase()} Connection Verified`, {
          description: `Latency: ${data.latencyMs}ms • Model responding correctly.`,
        })
      } else {
        setTestResults((prev) => ({
          ...prev,
          [provider]: { ok: false, message: data.error || 'Connection Failed' },
        }))
        toast.error(`${provider.toUpperCase()} Connection Failed`, {
          description: data.error,
        })
      }
    } catch (err: any) {
      setTestResults((prev) => ({
        ...prev,
        [provider]: { ok: false, message: err.message || 'Network error' },
      }))
    } finally {
      setTesting((prev) => ({ ...prev, [provider]: false }))
    }
  }

  async function handleSave() {
    if (currentRole === 'Viewer') {
      toast.error('Viewer Restricted', {
        description: 'Viewer role cannot update API settings. Switch to Operator or Admin.',
      })
      return
    }

    setSaving(true)
    try {
      const res = await fetch('/api/settings/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          defaultProvider,
          defaultModel,
          providers,
          role: currentRole,
        }),
      })

      const data = await res.json()
      if (res.ok) {
        toast.success('AI Settings Saved', {
          description: 'Provider configurations and API credentials stored in SQLite WAL.',
        })
        onOpenChange(false)
      } else {
        throw new Error(data.error || 'Failed to save settings.')
      }
    } catch (err: any) {
      toast.error('Save Failed', { description: err.message })
    } finally {
      setSaving(false)
    }
  }

  const isViewer = currentRole === 'Viewer'

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl border-border/80 bg-background/95 text-foreground shadow-2xl backdrop-blur-md">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <div className="flex size-7 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
              <Settings className="size-3.5" />
            </div>
            <div>
              <DialogTitle className="text-sm font-semibold text-foreground">
                Platform Settings & Frontier AI Providers
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground mt-0.5">
                Configure frontier LLM API keys for autonomous patch synthesis, code triage, and verification.
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-2">
          <TabsList className="bg-card/60 border border-border/60 w-full justify-start h-8 p-0.5">
            <TabsTrigger value="providers" className="text-xs flex items-center gap-1.5 h-7">
              <Key className="size-3" />
              <span>AI Providers</span>
            </TabsTrigger>
            <TabsTrigger value="policy" className="text-xs flex items-center gap-1.5 h-7">
              <ShieldCheck className="size-3" />
              <span>Security & Policy</span>
            </TabsTrigger>
          </TabsList>

          {/* AI Providers Tab */}
          <TabsContent value="providers" className="flex flex-col gap-4 py-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-zinc-900/60 border border-zinc-800/80 p-3 rounded-lg text-xs">
              <div className="flex items-center gap-2">
                <Cpu className="size-4 text-primary shrink-0" />
                <div>
                  <span className="font-semibold text-zinc-200">Default Remediation Model:</span>
                  <p className="text-[11px] text-zinc-400">Used for autonomous three-tier verified patch synthesis</p>
                </div>
              </div>

              <select
                value={`${defaultProvider}:${defaultModel}`}
                onChange={(e) => {
                  const [p, m] = e.target.value.split(':')
                  setDefaultProvider(p)
                  setDefaultModel(m)
                }}
                disabled={isViewer}
                className="bg-zinc-950 border border-zinc-800 text-zinc-100 text-xs rounded-md px-2.5 py-1.5 focus:border-primary outline-none w-full sm:w-auto"
              >
                <option value="anthropic:claude-3-7-sonnet-20250219">Anthropic — Claude 3.7 Sonnet</option>
                <option value="openai:o3-mini">OpenAI — o3-mini (High Reasoning)</option>
                <option value="openai:gpt-4.5-preview">OpenAI — GPT-4.5 Preview</option>
                <option value="gemini:gemini-2.5-flash">Google Gemini — 2.5 Flash</option>
                <option value="gemini:gemini-2.5-pro">Google Gemini — 2.5 Pro</option>
                <option value="xai:grok-3">xAI — Grok 3</option>
                <option value="deepseek:deepseek-chat">DeepSeek — DeepSeek V3</option>
                <option value="openrouter:anthropic/claude-3.7-sonnet">OpenRouter — Universal Routing</option>
              </select>
            </div>

            {/* Provider List with shadcn ScrollArea */}
            <ScrollArea className="h-[340px] pr-2">
              <div className="flex flex-col gap-3">
              {[
                { id: 'anthropic', name: 'Anthropic Claude', defaultModel: 'claude-3-7-sonnet-20250219', placeholder: 'sk-ant-api03-...' },
                { id: 'openai', name: 'OpenAI (o3-mini / GPT-4.5)', defaultModel: 'o3-mini', placeholder: 'sk-proj-...' },
                { id: 'gemini', name: 'Google Gemini (Flash/Pro)', defaultModel: 'gemini-2.5-flash', placeholder: 'AIzaSy...' },
                { id: 'xai', name: 'xAI (Grok 3)', defaultModel: 'grok-3', placeholder: 'xai-...' },
                { id: 'deepseek', name: 'DeepSeek (V3)', defaultModel: 'deepseek-chat', placeholder: 'sk-...' },
                { id: 'openrouter', name: 'OpenRouter (Universal)', defaultModel: 'anthropic/claude-3.7-sonnet', placeholder: 'sk-or-v1-...' },
              ].map((p) => {
                const state = providers[p.id] || { apiKey: '', model: p.defaultModel, isConfigured: false, maskedKey: '' }
                const isShow = showKeys[p.id]
                const isTestingThis = testing[p.id]
                const result = testResults[p.id]

                return (
                  <div key={p.id} className="border border-zinc-800/80 bg-zinc-900/40 rounded-lg p-3 flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-zinc-200">{p.name}</span>
                        {state.isConfigured && (
                          <Badge variant="outline" className="text-[10px] py-0 border-emerald-900 text-emerald-400 bg-emerald-950/40">
                            Configured
                          </Badge>
                        )}
                      </div>

                      {result && (
                        <div className={`text-[11px] flex items-center gap-1 ${result.ok ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {result.ok ? <CheckCircle2 className="size-3" /> : <XCircle className="size-3" />}
                          <span>{result.message}</span>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <div className="sm:col-span-2 relative">
                        <Input
                          type={isShow ? 'text' : 'password'}
                          value={state.apiKey}
                          onChange={(e) => handleKeyChange(p.id, e.target.value)}
                          placeholder={p.placeholder}
                          disabled={isViewer || saving}
                          className="h-8 text-xs font-mono bg-zinc-950 border-zinc-800 pr-8"
                        />
                        <button
                          type="button"
                          onClick={() => setShowKeys((prev) => ({ ...prev, [p.id]: !prev[p.id] }))}
                          className="absolute right-2.5 top-2 text-zinc-500 hover:text-zinc-300"
                        >
                          {isShow ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                        </button>
                      </div>

                      <div className="flex items-center gap-2">
                        <Input
                          value={state.model}
                          onChange={(e) => handleModelChange(p.id, e.target.value)}
                          placeholder="Model ID"
                          disabled={isViewer || saving}
                          className="h-8 text-xs font-mono bg-zinc-950 border-zinc-800 flex-1"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => handleTestConnection(p.id)}
                          disabled={isTestingThis || isViewer || (!state.apiKey && !state.isConfigured)}
                          className="h-8 text-[11px] px-2.5 border-zinc-800 bg-zinc-900 text-zinc-300 hover:text-zinc-100"
                        >
                          {isTestingThis ? <Loader2 className="size-3 animate-spin" /> : 'Test'}
                        </Button>
                      </div>
                    </div>
                  </div>
                )
              })}
              </div>
            </ScrollArea>
          </TabsContent>

          {/* Policy Tab */}
          <TabsContent value="policy" className="flex flex-col gap-3 py-3">
            <div className="border border-zinc-800 bg-zinc-900/40 rounded-lg p-3.5 flex flex-col gap-2.5 text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Lock className="size-4 text-primary" />
                  <span className="font-semibold text-zinc-200">Fail-Closed Host Execution Protection</span>
                </div>
                <Badge variant="outline" className="text-emerald-400 border-emerald-900 bg-emerald-950/40">
                  Enforced Permanently
                </Badge>
              </div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Sentra policy strictly forbids the direct execution of untrusted target scripts, build commands, and procedural macros on the host control plane.
              </p>
            </div>

            <div className="border border-zinc-800 bg-zinc-900/40 rounded-lg p-3.5 flex flex-col gap-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-zinc-200">Multi-Tenant Cross-Boundary Fencing</span>
                <Badge variant="outline" className="text-emerald-400 border-emerald-900 bg-emerald-950/40">
                  MultiTenantIsolated
                </Badge>
              </div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Zero cross-tenant context bleed. Findings, taint call graphs, and audit history are partitioned by tenant namespace.
              </p>
            </div>

            <div className="border border-zinc-800 bg-zinc-900/40 rounded-lg p-3.5 flex flex-col gap-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-zinc-200">Maximum Scan Ingestion Ceiling</span>
                <span className="font-mono text-zinc-400">5.0 MB / file</span>
              </div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Prevents denial-of-service from oversized binaries or log archives during AST parsing.
              </p>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter className="mt-2 pt-2 border-t border-border/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <CheckCircle2 className="size-3 text-emerald-400" />
            <span>Encrypted SQLite WAL Storage</span>
          </div>

          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onOpenChange(false)}
              className="h-7 text-xs border-border/70 text-muted-foreground hover:text-foreground"
            >
              Cancel
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={handleSave}
              disabled={isViewer || saving}
              className="h-7 text-xs font-medium gap-1.5"
            >
              {saving ? (
                <>
                  <Loader2 className="size-3 animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Save className="size-3" />
                  <span>Save Settings</span>
                </>
              )}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
