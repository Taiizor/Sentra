import { useState } from 'react'
import {
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  GitPullRequestDraft,
  ShieldCheck,
  RotateCcw,
  Download,
  Terminal,
  Sparkles,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { applyPatchToWorkspace, rollbackPatch } from '@/lib/api-client'
import { DiffViewer } from '@/components/dashboard/diff-viewer'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import type { PatchBundleView, UserRole } from '@/types/sentra'

interface RemediationTabProps {
  patches: PatchBundleView[]
  currentRole: UserRole
}

export function RemediationTab({ patches, currentRole }: RemediationTabProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [patchStates, setPatchStates] = useState<
    Record<string, { applied: boolean; backupPath?: string; loading?: boolean }>
  >({})

  function copyToClipboard(text: string, id: string) {
    copyText(text)
    setCopiedId(id)
    toast.success('GitHub Draft PR Command Copied', {
      description: 'Run in terminal to submit three-tier verified remediation patch.',
    })
    setTimeout(() => setCopiedId(null), 2500)
  }

  function handleDownloadPatch(patch: PatchBundleView) {
    const blob = new Blob([patch.diff], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${patch.branchName.replace(/\//g, '-')}.patch`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Unified Diff Downloaded', {
      description: `Saved as ${patch.branchName.replace(/\//g, '-')}.patch`,
    })
  }

  async function handleApply(patch: PatchBundleView) {
    const loc = patch.targetLocation || 'crates/sentra-cli/src/lib.rs'
    setPatchStates((prev) => ({ ...prev, [patch.bundleId]: { ...prev[patch.bundleId], loading: true, applied: false } }))
    try {
      const res = await applyPatchToWorkspace({
        patchId: patch.bundleId,
        diff: patch.diff,
        targetLocation: loc,
      })
      setPatchStates((prev) => ({
        ...prev,
        [patch.bundleId]: { applied: true, backupPath: res.backupPath, loading: false },
      }))
      toast.success(res.alreadyPatched ? 'File Already Remediated' : 'Patch Applied to Workspace on Disk', {
        description: `Target: ${res.targetLocation}. Backup: ${res.backupPath}`,
      })
    } catch (err: any) {
      setPatchStates((prev) => ({ ...prev, [patch.bundleId]: { applied: false, loading: false } }))
      toast.error('Failed to Apply Patch', {
        description: err.message || 'Error modifying source code on disk.',
      })
    }
  }

  async function handleRollback(patch: PatchBundleView) {
    const state = patchStates[patch.bundleId]
    const backup = state?.backupPath || patch.backupPath
    const loc = patch.targetLocation || 'crates/sentra-cli/src/lib.rs'
    if (!backup) return

    setPatchStates((prev) => ({ ...prev, [patch.bundleId]: { ...prev[patch.bundleId], loading: true } }))
    try {
      await rollbackPatch({
        patchId: patch.bundleId,
        backupPath: backup,
        targetLocation: loc,
      })
      setPatchStates((prev) => ({
        ...prev,
        [patch.bundleId]: { applied: false, backupPath: undefined, loading: false },
      }))
      toast.info('Patch Rolled Back', {
        description: `Restored ${loc} to original state.`,
      })
    } catch (err: any) {
      setPatchStates((prev) => ({ ...prev, [patch.bundleId]: { ...prev[patch.bundleId], loading: false } }))
      toast.error('Rollback Failed', {
        description: err.message || 'Error restoring file.',
      })
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Streamlined Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="size-5 text-emerald-400" />
            <h2 className="text-base sm:text-lg font-bold tracking-tight text-zinc-100">
              Automated Remediation &amp; Verified Patches
            </h2>
            <Badge variant="outline" className="text-[10px] font-mono border-zinc-800 text-emerald-400 bg-emerald-500/10">
              {patches.length} Verified
            </Badge>
          </div>
          <p className="text-xs text-zinc-400">
            Dual-state oracle verified patch candidates with mathematical and regression sound execution gates.
          </p>
        </div>
      </div>

      {/* Verified Patch Bundles */}
      {patches.length === 0 ? (
        <Card className="border-zinc-800/80 bg-zinc-900/40 shadow-xs">
          <CardContent className="p-0">
            <Empty className="py-12">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <ShieldCheck className="size-8 text-emerald-400" />
                </EmptyMedia>
                <EmptyTitle>No Pending Remediation Bundles</EmptyTitle>
                <EmptyDescription>
                  All confirmed findings are either clean or have not yet had a patch synthesized.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          </CardContent>
        </Card>
      ) : (
        <div className="flex flex-col gap-4">
          {patches.map((patch) => {
            const isApplied = patchStates[patch.bundleId]?.applied || patch.isAppliedToDisk
            const isLoading = patchStates[patch.bundleId]?.loading

            return (
              <Card key={patch.bundleId} className="border-zinc-800/80 bg-zinc-900/40 shadow-xs">
                <CardHeader className="py-3 px-4 sm:px-5 border-b border-zinc-800/80 bg-zinc-950/40">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    {/* Patch Identity & Title */}
                    <div className="flex flex-col gap-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className="font-mono text-[10px] border-zinc-800 text-zinc-400">
                          {patch.bundleId}
                        </Badge>
                        <Badge variant="secondary" className="text-[10px] flex items-center gap-1 font-mono text-emerald-400 bg-emerald-500/10 border-emerald-500/20">
                          <CheckCircle2 className="size-3 text-emerald-400" />
                          Verified Fix
                        </Badge>
                        <span className="text-[11px] text-zinc-500 font-mono truncate max-w-[240px] sm:max-w-none" title={patch.branchName}>
                          Branch: {patch.branchName}
                        </span>
                      </div>
                      <CardTitle className="text-sm font-bold text-zinc-100 mt-0.5">
                        {patch.title}
                      </CardTitle>
                      <CardDescription className="text-xs text-zinc-400">
                        Linked Finding: <span className="font-mono text-zinc-300 font-medium">{patch.findingId}</span> • Verified in {patch.attemptCount} attempt(s)
                      </CardDescription>
                    </div>

                    {/* Action Controls */}
                    <div className="flex items-center gap-1.5 flex-wrap w-full sm:w-auto">
                      {!isApplied ? (
                        <Button
                          size="sm"
                          disabled={isLoading || currentRole !== 'SecurityAdmin'}
                          onClick={() => handleApply(patch)}
                          className="h-7.5 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-xs disabled:opacity-40 cursor-pointer"
                          title={currentRole !== 'SecurityAdmin' ? "Direct workspace patch application requires SecurityAdmin role" : undefined}
                        >
                          <CheckCircle2 className="size-3.5 mr-1" />
                          {isLoading ? 'Applying...' : 'Apply to Workspace'}
                        </Button>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={isLoading || currentRole !== 'SecurityAdmin'}
                          onClick={() => handleRollback(patch)}
                          className="h-7.5 text-xs border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 font-semibold disabled:opacity-40 cursor-pointer"
                          title={currentRole !== 'SecurityAdmin' ? "Rollback requires SecurityAdmin role" : undefined}
                        >
                          <RotateCcw className="size-3.5 mr-1" />
                          {isLoading ? 'Rolling back...' : 'Rollback Disk'}
                        </Button>
                      )}

                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7.5 text-xs border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-300 cursor-pointer"
                        onClick={() => handleDownloadPatch(patch)}
                        title="Download unified .patch file"
                      >
                        <Download className="size-3.5 mr-1" />
                        .patch
                      </Button>

                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7.5 text-xs border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-300 cursor-pointer"
                        onClick={() => copyToClipboard(patch.ghPrCommand, patch.bundleId)}
                        title="Copy GitHub CLI draft PR command"
                      >
                        {copiedId === patch.bundleId ? (
                          <Check className="text-emerald-400 size-3.5 mr-1" />
                        ) : (
                          <Copy className="size-3.5 mr-1" />
                        )}
                        {copiedId === patch.bundleId ? 'Copied' : 'Draft PR'}
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="p-4 sm:p-5 flex flex-col gap-4">
                  {/* Three-Tier Verification Invariant Proof Strip */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 p-2.5 rounded-lg border border-zinc-800/80 bg-zinc-950/60 text-xs">
                    {/* 1. Baseline Fails */}
                    <div className="flex items-center gap-2">
                      {patch.originalTestStatus === 'Failed' ? (
                        <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      ) : (
                        <XCircle className="size-4 text-rose-500 shrink-0" />
                      )}
                      <div className="flex flex-col min-w-0">
                        <span className="font-semibold text-zinc-200 text-[11px]">1. Baseline Fails</span>
                        <span className="text-[10px] text-zinc-400 font-mono truncate">
                          Original Test: {patch.originalTestStatus} (Confirms Bug)
                        </span>
                      </div>
                    </div>

                    {/* 2. Patched Passes */}
                    <div className="flex items-center gap-2">
                      {patch.patchedTestStatus === 'Passed' ? (
                        <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      ) : (
                        <XCircle className="size-4 text-rose-500 shrink-0" />
                      )}
                      <div className="flex flex-col min-w-0">
                        <span className="font-semibold text-zinc-200 text-[11px]">2. Patched Passes</span>
                        <span className="text-[10px] text-zinc-400 font-mono truncate">
                          Patched Test: {patch.patchedTestStatus} (Confirms Fix)
                        </span>
                      </div>
                    </div>

                    {/* 3. Regressions Pass */}
                    <div className="flex items-center gap-2">
                      {patch.regressionsPass ? (
                        <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      ) : (
                        <XCircle className="size-4 text-rose-500 shrink-0" />
                      )}
                      <div className="flex flex-col min-w-0">
                        <span className="font-semibold text-zinc-200 text-[11px]">3. Zero Regressions</span>
                        <span className="text-[10px] text-zinc-400 font-mono truncate">
                          Existing Suites: {patch.regressionsPass ? 'Zero Regressions' : 'Regression Found'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* High-Fidelity Unified & Split Diff Viewer */}
                  <div className="flex flex-col gap-1.5">
                    <DiffViewer
                      diff={patch.diff}
                      filePath={patch.targetLocation}
                      defaultMode="unified"
                      maxHeight="max-h-[360px]"
                    />
                  </div>

                  {/* GitHub Draft PR Dispatch Command Box */}
                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center justify-between text-xs text-zinc-400">
                      <span className="font-semibold flex items-center gap-1.5">
                        <Terminal className="size-3.5 text-zinc-400" />
                        <span>Human-in-the-Loop CLI Dispatch:</span>
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2 bg-zinc-950/80 px-3 py-2 rounded-lg border border-zinc-800 font-mono text-[11px] min-w-0 text-zinc-300">
                      <span className="truncate min-w-0 flex-1">{patch.ghPrCommand}</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-xs px-2 shrink-0 hover:text-zinc-100 text-zinc-400 cursor-pointer"
                        onClick={() => copyToClipboard(patch.ghPrCommand, patch.bundleId)}
                      >
                        {copiedId === patch.bundleId ? <Check className="size-3 text-emerald-400 mr-1" /> : <Copy className="size-3 mr-1" />}
                        {copiedId === patch.bundleId ? 'Copied' : 'Copy'}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
