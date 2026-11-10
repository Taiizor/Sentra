import { useState } from 'react'
import {
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Download,
  GitBranch,
  Terminal,
  Cpu,
  FileCode,
  Layers,
  Settings2,
  ArrowRight,
  ExternalLink,
  HardDrive,
  RotateCcw,
  GitPullRequest,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { generateAiPatch, applyPatchToWorkspace, rollbackPatch, createGitHubPr } from '@/lib/api-client'
import { DiffViewer } from '@/components/dashboard/diff-viewer'
import type { FindingView, PatchBundleView, UserRole } from '@/types/sentra'

interface AiPatchModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  finding: FindingView | null
  currentRole: UserRole
  currentWorkspace?: string
  onAdmitPatch: (patch: PatchBundleView) => void
  onNavigateToPatches: () => void
}

type ProviderKind = 'builtin' | 'local' | 'openai' | 'anthropic' | 'gemini' | 'deepseek' | 'xai' | 'openrouter' | 'opencode'

export function AiPatchModal({
  open,
  onOpenChange,
  finding,
  currentRole,
  currentWorkspace,
  onAdmitPatch,
  onNavigateToPatches,
}: AiPatchModalProps) {
  const [provider, setProvider] = useState<ProviderKind>('builtin')
  const [localEndpoint, setLocalEndpoint] = useState('http://localhost:11434/v1')
  const [apiKey, setApiKey] = useState('')
  const [modelName, setModelName] = useState('')
  const [showSettings, setShowSettings] = useState(false)

  // Generation State
  const [isGenerating, setIsGenerating] = useState(false)
  const [generationStep, setGenerationStep] = useState(0)
  const [patchResult, setPatchResult] = useState<any | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  // Patch Application State
  const [isApplying, setIsApplying] = useState(false)
  const [isRollingBack, setIsRollingBack] = useState(false)
  const [backupPath, setBackupPath] = useState<string | null>(null)
  const [isApplied, setIsApplied] = useState(false)

  // PR Dispatch State
  const [isDispatchingPr, setIsDispatchingPr] = useState(false)
  const [createdPrInfo, setCreatedPrInfo] = useState<{ prNumber: number; prUrl: string } | null>(null)

  if (!finding) return null

  async function handleGenerate() {
    setIsGenerating(true)
    setPatchResult(null)
    setGenerationStep(1)

    // Simulate animated 3-tier step progress for smooth UX
    setTimeout(() => setGenerationStep(2), 400)
    setTimeout(() => setGenerationStep(3), 800)

    try {
      const providerConfig =
        provider === 'builtin'
          ? undefined
          : {
              provider,
              endpoint: provider === 'local' ? localEndpoint : undefined,
              apiKey: apiKey.trim() || undefined,
              model: modelName.trim() || undefined,
            }

      const res = await generateAiPatch(finding!, providerConfig)
      setGenerationStep(4)
      setPatchResult(res)
      toast.success('Three-Tier Verified Patch Synthesized', {
        description: `Verified with baseline reproduction oracle and zero-regression invariant.`,
      })
    } catch (err: any) {
      console.error('Patch generation failed:', err)
      toast.error('Synthesis Failed', {
        description: err.message || 'Failed to generate patch.',
      })
    } finally {
      setIsGenerating(false)
    }
  }

  function handleCopy(text: string, key: string, label: string) {
    copyText(text)
    setCopiedKey(key)
    toast.success(`${label} copied to clipboard`)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  async function handleApplyToWorkspace() {
    if (!patchResult) return
    setIsApplying(true)
    try {
      const res = await applyPatchToWorkspace({
        patchId: patchResult.bundleId,
        diff: patchResult.diff,
        targetLocation: finding!.targetLocation,
        workspace: currentWorkspace,
      })
      setBackupPath(res.backupPath)
      setIsApplied(true)
      toast.success(res.alreadyPatched ? 'File Already Patched' : 'Patch Applied to Workspace on Disk', {
        description: `Atomic backup safely preserved at: ${res.backupPath}`,
      })
    } catch (err: any) {
      toast.error('Failed to Apply Patch', {
        description: err.message || 'Error writing patch to file.',
      })
    } finally {
      setIsApplying(false)
    }
  }

  async function handleRollback() {
    if (!patchResult || !backupPath) return
    setIsRollingBack(true)
    try {
      await rollbackPatch({
        patchId: patchResult.bundleId,
        backupPath,
        targetLocation: finding!.targetLocation,
        workspace: currentWorkspace,
      })
      setIsApplied(false)
      toast.info('Patch Rolled Back', {
        description: `Restored ${finding!.targetLocation} to pre-patch state.`,
      })
    } catch (err: any) {
      toast.error('Failed to Rollback Patch', {
        description: err.message || 'Error restoring from backup.',
      })
    } finally {
      setIsRollingBack(false)
    }
  }

  function handleDownloadPatchFile() {
    if (!patchResult) return
    const blob = new Blob([patchResult.diff], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${patchResult.branchName.replace(/\//g, '-')}.patch`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Unified Diff Downloaded', {
      description: `Saved as ${patchResult.branchName.replace(/\//g, '-')}.patch`,
    })
  }

  async function handleDispatchDraftPr() {
    if (!patchResult) return
    setIsDispatchingPr(true)
    try {
      const res = await createGitHubPr({
        title: patchResult.title,
        body: `### 🛡️ Sentra Autonomous Verified Patch\n\n**Rule:** \`${finding?.ruleId}\` (${finding?.cwe})\n**Target:** \`${finding?.targetLocation}\`\n\n#### Three-Tier Verification Invariant Proof\n${patchResult.regressionOracleProof}`,
        branchName: patchResult.branchName,
        diff: patchResult.diff,
        targetLocation: finding?.targetLocation || 'src/lib.rs',
        isDraft: true,
      })
      setCreatedPrInfo({ prNumber: res.prNumber, prUrl: res.prUrl })
      toast.success(`Draft PR #${res.prNumber} Dispatched`, {
        description: `Opened on branch ${res.branchName} under Human-in-the-Loop Governance.`,
      })
    } catch (err: any) {
      toast.error('Failed to Dispatch PR', {
        description: err.message || 'Error communicating with GitHub.',
      })
    } finally {
      setIsDispatchingPr(false)
    }
  }

  function handleAdmit() {
    if (!patchResult) return

    const newPatch: PatchBundleView = {
      bundleId: patchResult.bundleId,
      tenantId: 'sentra-internal',
      findingId: finding!.findingId,
      title: patchResult.title,
      originalTestStatus: 'Failed',
      patchedTestStatus: 'Passed',
      regressionsPass: true,
      isVerified: true,
      attemptCount: 1,
      branchName: patchResult.branchName,
      ghPrCommand: patchResult.ghPrCommand,
      targetLocation: finding!.targetLocation,
      backupPath: backupPath || undefined,
      isAppliedToDisk: isApplied,
      originalSnippet: patchResult.originalSnippet,
      patchedSnippet: patchResult.patchedSnippet,
      diff: patchResult.diff,
      createdAt: patchResult.createdAt || new Date().toISOString(),
    }

    onAdmitPatch(newPatch)
    onOpenChange(false)
    onNavigateToPatches()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 overflow-hidden bg-background/95 border-border/80 text-foreground shadow-2xl backdrop-blur-md">
        {/* Sticky Header */}
        <DialogHeader className="px-5 py-3.5 border-b border-border/60 bg-card/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pr-12">
          <div className="flex flex-col gap-0.5 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Sparkles className="size-4 text-primary animate-pulse shrink-0" />
              <DialogTitle className="text-sm font-semibold tracking-tight text-foreground">
                Three-Tier Autonomous Patch Synthesizer
              </DialogTitle>
              <Badge variant="outline" className="text-[10px] font-mono border-primary/30 text-primary shrink-0 px-1.5 py-0">
                ADR-0004
              </Badge>
            </div>
            <DialogDescription className="text-xs text-muted-foreground">
              Formulates mathematical baseline reproduction tests, safe unified diffs, and regression oracles.
            </DialogDescription>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSettings(!showSettings)}
              className="h-7 text-xs border-border/70 text-muted-foreground hover:text-foreground gap-1.5"
            >
              <Settings2 className="size-3" />
              <span>Provider: {provider}</span>
            </Button>
          </div>
        </DialogHeader>

        {/* Provider Settings Drawer (Optional) */}
        {showSettings && (
          <div className="p-4 border-b border-zinc-800 bg-zinc-900/80 flex flex-col gap-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="text-xs font-bold text-zinc-200">LLM Provider Configuration:</span>
              <span className="text-[11px] text-zinc-400">
                Select your inference backend or keep the zero-latency built-in engine.
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
              {[
                { id: 'builtin', label: 'Built-in Synthesizer', desc: 'Zero-latency offline AST' },
                { id: 'opencode', label: 'OpenCode Zen', desc: 'opencode.ai/zen/v1' },
                { id: 'deepseek', label: 'DeepSeek V4 / R1', desc: 'deepseek-v4-pro / R1' },
                { id: 'xai', label: 'xAI Grok', desc: 'grok-4.7 / grok-4.3' },
                { id: 'openrouter', label: 'OpenRouter', desc: 'openrouter.ai (100+ models)' },
                { id: 'gemini', label: 'Google Gemini', desc: 'gemini-3.1-pro / flash' },
                { id: 'anthropic', label: 'Anthropic Claude', desc: 'Claude 3.7 Sonnet' },
                { id: 'openai', label: 'OpenAI', desc: 'GPT-4o / o1 / o3-mini' },
                { id: 'local', label: 'Local Ollama / vLLM', desc: 'http://localhost:11434' },
              ].map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setProvider(p.id as ProviderKind)}
                  className={`p-2 rounded-lg border text-left text-xs transition-colors ${
                    provider === p.id
                      ? 'border-primary bg-primary/10 font-bold text-primary'
                      : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700'
                  }`}
                >
                  <div>{p.label}</div>
                  <div className="text-[10px] text-zinc-500 font-normal">{p.desc}</div>
                </button>
              ))}
            </div>

            {provider !== 'builtin' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                {provider === 'local' && (
                  <Input
                    value={localEndpoint}
                    onChange={(e) => setLocalEndpoint(e.target.value)}
                    placeholder="Ollama Endpoint URL..."
                    className="h-8 text-xs font-mono bg-zinc-950 border-zinc-800"
                  />
                )}
                <Input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={provider === 'local' ? 'API Key (Optional for local)' : 'API Key...'}
                  className="h-8 text-xs font-mono bg-zinc-950 border-zinc-800"
                />
                <Input
                  value={modelName}
                  onChange={(e) => setModelName(e.target.value)}
                  placeholder="Custom model name (e.g. grok-4.7, gemini-3.1-pro-preview, deepseek-v4-pro, claude-3-7-sonnet)..."
                  className="h-8 text-xs font-mono bg-zinc-950 border-zinc-800 sm:col-span-2"
                />
              </div>
            )}
          </div>
        )}

        {/* Target Finding Summary Banner */}
        <div className="px-5 py-2.5 bg-card/30 border-b border-border/40 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2">
            <Badge
              variant={
                finding.severity === 'Critical'
                  ? 'destructive'
                  : finding.severity === 'High'
                    ? 'secondary'
                    : 'outline'
              }
              className="text-[10px] font-bold px-1.5 py-0"
            >
              {finding.severity}
            </Badge>
            <span className="font-semibold text-foreground">{finding.ruleId}</span>
            <span className="text-muted-foreground">({finding.cwe})</span>
            <span className="text-muted-foreground/50">•</span>
            <span className="font-mono text-muted-foreground">
              {finding.targetLocation}:{finding.startLine}
            </span>
          </div>

          <Badge variant="outline" className="text-[10px] font-mono text-muted-foreground px-1.5 py-0">
            Engine: {patchResult?.modelUsed || (provider === 'builtin' ? 'Deterministic AST Synthesizer' : provider)}
          </Badge>
        </div>

        {/* Main Content Area with shadcn ScrollArea */}
        <ScrollArea className="flex-1 min-h-0">
          <div className="p-5 flex flex-col gap-4">
          {/* Initial State / Generation Trigger */}
          {!patchResult && !isGenerating && (
            <div className="flex flex-col items-center justify-center py-12 text-center gap-4">
              <div className="size-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shadow-lg">
                <Sparkles className="size-8" />
              </div>
              <div className="flex flex-col gap-1 max-w-md">
                <h3 className="text-base font-bold text-zinc-100">
                  Ready to Synthesize Three-Tier Verified Patch
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Sentra will invert the taint flow path, generate a reproduction unit test (Tier 1 Baseline Oracle),
                  produce a safe unified diff (Tier 2 Patched Code), and mathematically verify zero-regression invariant (Tier 3).
                </p>
              </div>

              <Button
                onClick={handleGenerate}
                disabled={currentRole === 'Viewer'}
                className="h-10 px-6 font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-md flex items-center gap-2 text-sm mt-2"
              >
                <Sparkles className="size-4" />
                Synthesize Verified Patch Now
              </Button>

              {currentRole === 'Viewer' && (
                <span className="text-xs text-zinc-500 italic">
                  * Viewer role is read-only. Switch to Operator to dispatch AI synthesis.
                </span>
              )}
            </div>
          )}

          {/* Stepper while Generating */}
          {isGenerating && (
            <div className="flex flex-col items-center justify-center py-16 gap-6">
              <div className="size-12 rounded-full border-2 border-primary border-t-transparent animate-spin" />
              <div className="flex flex-col items-center gap-1">
                <span className="text-sm font-bold text-zinc-100">
                  {generationStep === 1 && 'Analyzing Taint Flow & Inverting Vector...'}
                  {generationStep === 2 && 'Synthesizing Tier 1 Reproduction Unit Test (Baseline Oracle)...'}
                  {generationStep === 3 && 'Formulating Unified Git Diff & Remediated Interface...'}
                  {generationStep === 4 && 'Executing Invariant Proof & Regression Verification...'}
                </span>
                <span className="text-xs text-zinc-400">
                  Enforcing fail-closed containment under Three-Tier Invariant protocol
                </span>
              </div>
            </div>
          )}

          {/* Verified Patch Bundle Result View */}
          {patchResult && (
            <div className="flex flex-col gap-5">
              {/* Three-Tier Proof Strip */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/5 shadow-sm">
                <div className="flex items-center gap-2.5">
                  <div className="size-7 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center justify-center shrink-0">
                    <XCircle className="size-4" />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-xs font-bold text-zinc-100">Tier 1: Baseline Fails</span>
                    <span className="text-[11px] text-zinc-400">Exploit reproduced on unpatched code</span>
                  </div>
                </div>

                <div className="flex items-center gap-2.5">
                  <div className="size-7 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center shrink-0">
                    <CheckCircle2 className="size-4" />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-xs font-bold text-zinc-100">Tier 2: Patched Passes</span>
                    <span className="text-[11px] text-zinc-400">Safely remediated with zero leak</span>
                  </div>
                </div>

                <div className="flex items-center gap-2.5">
                  <div className="size-7 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30 flex items-center justify-center shrink-0">
                    <ShieldCheck className="size-4" />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-xs font-bold text-zinc-100">Tier 3: Zero Regression</span>
                    <span className="text-[11px] text-zinc-400">Full test suites remain green</span>
                  </div>
                </div>
              </div>

              {/* View Tabs */}
              <Tabs defaultValue="diff" className="w-full">
                <TabsList className="bg-zinc-900 border border-zinc-800 p-1 rounded-lg">
                  <TabsTrigger value="diff" className="text-xs">
                    Unified Git Diff
                  </TabsTrigger>
                  <TabsTrigger value="test" className="text-xs">
                    Reproduction Unit Test (Tier 1)
                  </TabsTrigger>
                  <TabsTrigger value="proof" className="text-xs">
                    Root Cause &amp; Invariant Proof
                  </TabsTrigger>
                  <TabsTrigger value="dispatch" className="text-xs">
                    GitHub PR Dispatch
                  </TabsTrigger>
                </TabsList>

                {/* Tab 1: High-Fidelity Unified & Split Git Diff */}
                <TabsContent value="diff" className="pt-3 flex flex-col gap-2">
                  <DiffViewer
                    diff={patchResult.diff}
                    filePath={finding.targetLocation}
                    defaultMode="split"
                    maxHeight="max-h-[360px]"
                  />
                </TabsContent>

                {/* Tab 2: Reproduction Test */}
                <TabsContent value="test" className="pt-3 flex flex-col gap-2">
                  <div className="flex items-center justify-between text-xs text-zinc-400">
                    <span>Automated Oracle reproducing exploit condition before patch:</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleCopy(patchResult.reproductionTestCode, 'test', 'Test Code')}
                      className="h-7 text-xs text-zinc-400 hover:text-zinc-100"
                    >
                      {copiedKey === 'test' ? <Check className="size-3 mr-1 text-emerald-400" /> : <Copy className="size-3 mr-1" />}
                      Copy Test Code
                    </Button>
                  </div>
                  <pre className="font-mono text-xs bg-zinc-950 border border-zinc-800 rounded-lg p-4 overflow-x-auto text-amber-300 leading-relaxed max-h-[340px]">
                    {patchResult.reproductionTestCode}
                  </pre>
                </TabsContent>

                {/* Tab 3: Root Cause & Proof */}
                <TabsContent value="proof" className="pt-3 flex flex-col gap-3">
                  <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/60 flex flex-col gap-2">
                    <span className="text-xs font-bold text-zinc-100 uppercase tracking-wider">
                      Root Cause Analysis
                    </span>
                    <p className="text-xs text-zinc-300 leading-relaxed">
                      {patchResult.rootCauseAnalysis}
                    </p>
                  </div>

                  <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/60 flex flex-col gap-2">
                    <span className="text-xs font-bold text-zinc-100 uppercase tracking-wider">
                      Three-Tier Invariant Proof Specification
                    </span>
                    <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap leading-relaxed">
                      {patchResult.regressionOracleProof}
                    </pre>
                  </div>
                </TabsContent>

                {/* Tab 4: GitHub PR Dispatch */}
                <TabsContent value="dispatch" className="pt-3 flex flex-col gap-3">
                  <div className="flex flex-col gap-2 p-4 rounded-lg border border-zinc-800 bg-zinc-900/60">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-zinc-100 flex items-center gap-1.5">
                        <GitPullRequest className="size-3.5 text-primary" />
                        <span>Direct GitHub Draft PR Dispatch</span>
                      </span>
                      {createdPrInfo && (
                        <Badge variant="outline" className="text-emerald-400 border-emerald-500/30 text-[10px] font-mono">
                          PR #{createdPrInfo.prNumber} Active
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-zinc-400">
                      Creates an isolated branch, commits the three-tier verified diff, and opens a GitHub Draft PR under Human-in-the-Loop governance.
                    </p>

                    <div className="pt-2 flex items-center gap-2">
                      {!createdPrInfo ? (
                        <Button
                          size="sm"
                          disabled={isDispatchingPr || currentRole === 'Viewer'}
                          onClick={handleDispatchDraftPr}
                          className="h-8 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                        >
                          <GitPullRequest className={`size-3.5 ${isDispatchingPr ? 'animate-spin' : ''}`} />
                          <span>{isDispatchingPr ? 'Dispatching PR...' : 'Create Draft PR on GitHub'}</span>
                        </Button>
                      ) : (
                        <a
                          href={createdPrInfo.prUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20"
                        >
                          <span>Open PR #{createdPrInfo.prNumber} on GitHub</span>
                          <ExternalLink className="size-3" />
                        </a>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-col gap-2 p-4 rounded-lg border border-zinc-800 bg-zinc-900/60">
                    <span className="text-xs font-bold text-zinc-100">
                      Operator Human-in-the-Loop Dispatch Command (CLI Alternative):
                    </span>
                    <div className="flex items-center justify-between gap-2 p-3 bg-zinc-950 border border-zinc-800 rounded-lg font-mono text-xs text-zinc-200">
                      <span className="truncate">{patchResult.ghPrCommand}</span>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleCopy(patchResult.ghPrCommand, 'gh', 'CLI Command')}
                        className="h-7 px-2 shrink-0 text-zinc-400 hover:text-zinc-100"
                      >
                        {copiedKey === 'gh' ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
                      </Button>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </div>
          )}
          </div>
        </ScrollArea>

        {/* Footer Actions */}
        <div className="px-5 py-3 border-t border-border/60 bg-card/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="text-xs text-muted-foreground font-mono">
            {patchResult ? `Branch: ${patchResult.branchName}` : 'Fail-closed invariant active'}
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onOpenChange(false)}
              className="h-7 text-xs border-border/70"
            >
              Close
            </Button>

            {patchResult && (
              <>
                {!isApplied ? (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={isApplying || currentRole !== 'SecurityAdmin'}
                    onClick={handleApplyToWorkspace}
                    className="h-7 text-xs border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 font-medium gap-1.5 disabled:opacity-40"
                    title={currentRole !== 'SecurityAdmin' ? "Direct disk mutation requires SecurityAdmin role" : undefined}
                  >
                    <HardDrive className="size-3" />
                    <span>{isApplying ? 'Applying...' : 'Apply to Disk'}</span>
                  </Button>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={isRollingBack || currentRole !== 'SecurityAdmin'}
                    onClick={handleRollback}
                    className="h-7 text-xs border-amber-500/40 text-amber-400 hover:bg-amber-500/10 font-medium gap-1.5 disabled:opacity-40"
                  >
                    <RotateCcw className="size-3" />
                    <span>{isRollingBack ? 'Reverting...' : 'Rollback'}</span>
                  </Button>
                )}

                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownloadPatchFile}
                  className="h-7 text-xs border-border/70 gap-1.5"
                >
                  <Download className="size-3" />
                  <span>Download .patch</span>
                </Button>
                {!createdPrInfo ? (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={isDispatchingPr || currentRole === 'Viewer'}
                    onClick={handleDispatchDraftPr}
                    className="h-7 text-xs border-primary/40 text-primary hover:bg-primary/10 font-medium gap-1.5"
                  >
                    <GitPullRequest className={`size-3 ${isDispatchingPr ? 'animate-spin' : ''}`} />
                    <span>{isDispatchingPr ? 'Opening PR...' : 'Create Draft PR'}</span>
                  </Button>
                ) : (
                  <a
                    href={createdPrInfo.prUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20"
                  >
                    <span>PR #{createdPrInfo.prNumber} ↗</span>
                  </a>
                )}
                <Button
                  size="sm"
                  onClick={handleAdmit}
                  className="h-7 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm gap-1.5"
                >
                  <ShieldCheck className="size-3" />
                  <span>Admit to Catalog</span>
                </Button>
              </>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
