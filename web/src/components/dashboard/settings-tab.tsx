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
  Database,
  Sparkles,
  Server,
  UserCheck,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { UserRole } from '@/types/sentra'
import { toast } from 'sonner'

interface SettingsTabProps {
  currentRole: UserRole
}

interface ProviderState {
  apiKey: string
  model: string
  endpoint?: string
  isConfigured: boolean
  maskedKey: string
}

export function SettingsTab({ currentRole }: SettingsTabProps) {
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

  // Load configured settings on mount
  useEffect(() => {
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
  }, [])

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
  const configuredCount = Object.values(providers).filter((p) => p.isConfigured).length

  return (
    <div className="flex flex-col gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border/60">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20 shrink-0">
            <Settings className="size-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-foreground">
              Platform Settings & AI Providers
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              Frontier LLM credentials for autonomous patch synthesis, security enforcement policies, and SQLite WAL storage.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <Badge variant="outline" className="text-[11px] font-mono border-emerald-500/30 text-emerald-400 bg-emerald-500/10 gap-1 py-1">
            <CheckCircle2 className="size-3" />
            <span>SQLite WAL Encrypted</span>
          </Badge>

          <Button
            type="button"
            size="sm"
            onClick={handleSave}
            disabled={isViewer || saving}
            className="h-8 text-xs font-semibold gap-1.5 shadow-sm"
          >
            {saving ? (
              <>
                <Loader2 className="size-3.5 animate-spin" />
                <span>Saving...</span>
              </>
            ) : (
              <>
                <Save className="size-3.5" />
                <span>Save Changes</span>
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Metrics / Status Banner Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] font-medium text-muted-foreground">Active Synthesis Engine</span>
            <div className="text-sm font-semibold text-foreground truncate max-w-[180px]">
              {defaultProvider.toUpperCase()}
            </div>
            <span className="text-[10px] font-mono text-muted-foreground truncate block">
              {defaultModel}
            </span>
          </div>
          <Cpu className="size-5 text-primary shrink-0 opacity-80" />
        </div>

        <div className="p-3.5 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] font-medium text-muted-foreground">Configured Providers</span>
            <div className="text-sm font-semibold text-foreground">
              {configuredCount} / {Object.keys(providers).length} Active
            </div>
            <span className="text-[10px] font-mono text-emerald-400">
              Frontier LLM Ready
            </span>
          </div>
          <Sparkles className="size-5 text-emerald-400 shrink-0 opacity-80" />
        </div>

        <div className="p-3.5 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] font-medium text-muted-foreground">Isolation & Boundary</span>
            <div className="text-sm font-semibold text-foreground">MultiTenantIsolated</div>
            <span className="text-[10px] font-mono text-muted-foreground">Zero Cross-Tenant Leakage</span>
          </div>
          <Lock className="size-5 text-primary shrink-0 opacity-80" />
        </div>

        <div className="p-3.5 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] font-medium text-muted-foreground">Effective Role</span>
            <div className="text-sm font-semibold text-foreground">{currentRole}</div>
            <span className="text-[10px] font-mono text-muted-foreground">
              {isViewer ? 'Read-Only Mode' : 'Policy Modification Granted'}
            </span>
          </div>
          <UserCheck className="size-5 text-purple-400 shrink-0 opacity-80" />
        </div>
      </div>

      {/* Main Settings Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-card/60 border border-border/60 w-full sm:w-auto justify-start h-9 p-0.5">
          <TabsTrigger value="providers" className="text-xs flex items-center gap-1.5 h-8 px-3">
            <Key className="size-3.5" />
            <span>AI Model Providers</span>
          </TabsTrigger>
          <TabsTrigger value="policy" className="text-xs flex items-center gap-1.5 h-8 px-3">
            <ShieldCheck className="size-3.5" />
            <span>Security & Governance Policy</span>
          </TabsTrigger>
        </TabsList>

        {/* AI Model Providers Tab */}
        <TabsContent value="providers" className="space-y-4 focus-visible:outline-none">
          {/* Default Model Selector Card */}
          <div className="p-4 rounded-lg border border-border/60 bg-card/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="size-9 rounded-md bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
                <Cpu className="size-4" />
              </div>
              <div>
                <span className="text-sm font-semibold text-foreground">Default Remediation Model</span>
                <p className="text-xs text-muted-foreground">
                  Primary model invoked for automated three-tier verified patch synthesis (Baseline Fails → Patched Passes → Zero Regressions).
                </p>
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
              className="bg-background border border-border/70 text-foreground text-xs rounded-md px-3 py-2 focus:border-primary outline-none w-full sm:w-72"
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

          {/* Provider List Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3.5">
            {[
              {
                id: 'anthropic',
                name: 'Anthropic Claude',
                subtitle: 'Claude 3.7 Sonnet / Claude 3.5 Haiku',
                defaultModel: 'claude-3-7-sonnet-20250219',
                placeholder: 'sk-ant-api03-...',
              },
              {
                id: 'openai',
                name: 'OpenAI',
                subtitle: 'o3-mini / GPT-4.5 / GPT-4o',
                defaultModel: 'o3-mini',
                placeholder: 'sk-proj-...',
              },
              {
                id: 'gemini',
                name: 'Google Gemini',
                subtitle: 'Gemini 2.5 Flash / Gemini 2.5 Pro',
                defaultModel: 'gemini-2.5-flash',
                placeholder: 'AIzaSy...',
              },
              {
                id: 'xai',
                name: 'xAI Grok',
                subtitle: 'Grok 3 Reasoning Engine',
                defaultModel: 'grok-3',
                placeholder: 'xai-...',
              },
              {
                id: 'deepseek',
                name: 'DeepSeek',
                subtitle: 'DeepSeek V3 / DeepSeek R1',
                defaultModel: 'deepseek-chat',
                placeholder: 'sk-...',
              },
              {
                id: 'openrouter',
                name: 'OpenRouter',
                subtitle: 'Universal Multi-Provider Fallback Routing',
                defaultModel: 'anthropic/claude-3.7-sonnet',
                placeholder: 'sk-or-v1-...',
              },
            ].map((p) => {
              const state = providers[p.id] || { apiKey: '', model: p.defaultModel, isConfigured: false, maskedKey: '' }
              const isShow = showKeys[p.id]
              const isTestingThis = testing[p.id]
              const result = testResults[p.id]

              return (
                <div
                  key={p.id}
                  className="p-4 rounded-lg border border-border/60 bg-card/30 flex flex-col justify-between gap-3"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-foreground">{p.name}</span>
                        {state.isConfigured ? (
                          <Badge variant="outline" className="text-[10px] py-0 border-emerald-500/30 text-emerald-400 bg-emerald-500/10 font-mono">
                            Configured
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] py-0 border-border text-muted-foreground font-mono">
                            Not Set
                          </Badge>
                        )}
                      </div>
                      <span className="text-[11px] text-muted-foreground">{p.subtitle}</span>
                    </div>

                    {result && (
                      <div
                        className={`text-[11px] font-mono flex items-center gap-1 ${
                          result.ok ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {result.ok ? <CheckCircle2 className="size-3" /> : <XCircle className="size-3" />}
                        <span>{result.message}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col sm:flex-row gap-2">
                    <div className="relative flex-1">
                      <Input
                        type={isShow ? 'text' : 'password'}
                        value={state.apiKey}
                        onChange={(e) => handleKeyChange(p.id, e.target.value)}
                        placeholder={p.placeholder}
                        disabled={isViewer || saving}
                        className="h-8 text-xs font-mono bg-background/80 border-border/70 pr-8"
                      />
                      <button
                        type="button"
                        onClick={() => setShowKeys((prev) => ({ ...prev, [p.id]: !prev[p.id] }))}
                        className="absolute right-2.5 top-2 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
                        title={isShow ? 'Hide Key' : 'Show Key'}
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
                        className="h-8 text-xs font-mono bg-background/80 border-border/70 w-32 sm:w-36"
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => handleTestConnection(p.id)}
                        disabled={isTestingThis || isViewer || (!state.apiKey && !state.isConfigured)}
                        className="h-8 text-xs px-2.5 border-border/70 hover:border-primary/50 shrink-0"
                      >
                        {isTestingThis ? <Loader2 className="size-3 animate-spin" /> : 'Test'}
                      </Button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </TabsContent>

        {/* Security & Policy Tab */}
        <TabsContent value="policy" className="space-y-3.5 focus-visible:outline-none">
          <div className="p-4 rounded-lg border border-border/60 bg-card/30 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Lock className="size-4 text-primary" />
                <span className="text-xs font-semibold text-foreground">
                  Fail-Closed Host Execution Protection
                </span>
              </div>
              <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                Enforced Permanently
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Sentra policy strictly forbids the direct execution of untrusted target scripts, build commands, and procedural macros on the host control plane. All AST parsing and AST pattern searches are executed in memory via pure-Rust tree-sitter without triggering target build files.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/60 bg-card/30 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Server className="size-4 text-primary" />
                <span className="text-xs font-semibold text-foreground">
                  Multi-Tenant Cross-Boundary Fencing
                </span>
              </div>
              <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                MultiTenantIsolated
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Zero cross-tenant context bleed. Findings, taint call graphs, synthetic patch proposals, and audit logs are strictly partitioned by tenant ID in SQLite WAL and session caches.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/60 bg-card/30 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Database className="size-4 text-primary" />
                <span className="text-xs font-semibold text-foreground">
                  Maximum Scan Ingestion Ceiling
                </span>
              </div>
              <Badge variant="outline" className="text-[10px] font-mono border-border text-foreground">
                5.0 MB / file
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Prevents denial-of-service from oversized binaries, database dumps, or log archives during AST parsing. Files exceeding 5.0 MB are safely skipped and reported in the scanner session diagnostics.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/60 bg-card/30 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="size-4 text-primary" />
                <span className="text-xs font-semibold text-foreground">
                  Role-Based Access Control (RBAC) Governance
                </span>
              </div>
              <Badge variant="outline" className="text-[10px] font-mono border-purple-500/30 text-purple-300 bg-purple-500/10">
                {currentRole} Session Active
              </Badge>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
              <div className="p-2.5 rounded border border-border/40 bg-background/40">
                <div className="font-semibold text-xs text-foreground">Viewer</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  Read-only view of posture, findings, and SARIF exports. No scan or configuration dispatch.
                </div>
              </div>
              <div className="p-2.5 rounded border border-border/40 bg-background/40">
                <div className="font-semibold text-xs text-foreground">Operator</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  Execute live scans, synthesize AI patches, audit dependencies, and trigger webhooks.
                </div>
              </div>
              <div className="p-2.5 rounded border border-border/40 bg-background/40">
                <div className="font-semibold text-xs text-foreground">Security Admin</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  Full administrative permissions. Configure frontier LLM credentials and register tenants.
                </div>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
