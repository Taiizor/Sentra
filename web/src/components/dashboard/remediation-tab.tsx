import { useState } from 'react'
import {
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  GitPullRequestDraft,
  ShieldCheck,
  FileCode,
  HardDrive,
  RotateCcw,
  Download,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { applyPatchToWorkspace, rollbackPatch } from '@/lib/api-client'
import { DiffViewer } from '@/components/dashboard/diff-viewer'
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
    <div className="flex flex-col gap-6">
      {/* Three-Tier Invariant Header Card */}
      <Alert>
        <ShieldCheck className="size-5 text-primary" />
        <AlertTitle className="text-sm font-semibold">
          Sentra Three-Tier Verification Invariant
        </AlertTitle>
        <AlertDescription className="text-xs text-muted-foreground mt-1">
          A patch candidate is never accepted based on LLM assertion alone.
          Verification requires mathematical and experimental proof: (1) Baseline fails on unpatched code,
          (2) Target passes on patched code, and (3) Zero regression across existing test suites.
        </AlertDescription>
      </Alert>

      {/* Verified Patch Bundles */}
      <div className="flex flex-col gap-4">
        {patches.map((patch) => (
          <Card key={patch.bundleId} className="border-border/80">
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-col gap-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline" className="font-mono text-xs">
                      {patch.bundleId}
                    </Badge>
                    <Badge variant="secondary" className="text-xs flex items-center gap-1">
                      <CheckCircle2 className="size-3 text-primary" />
                      Verified Remediated
                    </Badge>
                    <span className="text-xs text-muted-foreground font-mono truncate max-w-[240px] sm:max-w-none" title={patch.branchName}>
                      Branch: {patch.branchName}
                    </span>
                  </div>
                  <CardTitle className="text-base font-bold mt-1">
                    {patch.title}
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Linked Finding ID: <span className="font-mono font-semibold">{patch.findingId}</span> • Verified in {patch.attemptCount} attempt(s)
                  </CardDescription>
                </div>

                <div className="flex items-center gap-2 flex-wrap w-full sm:w-auto">
                  {/* Disk Patch Application State (Restricted to SecurityAdmin) */}
                  {!(patchStates[patch.bundleId]?.applied || patch.isAppliedToDisk) ? (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={patchStates[patch.bundleId]?.loading || currentRole !== 'SecurityAdmin'}
                      onClick={() => handleApply(patch)}
                      className="h-8 text-xs border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 font-semibold disabled:opacity-40"
                      title={currentRole !== 'SecurityAdmin' ? "Direct disk mutation requires SecurityAdmin role" : undefined}
                    >
                      <HardDrive className="size-3.5 mr-1" />
                      {patchStates[patch.bundleId]?.loading ? 'Applying...' : 'Apply to Workspace'}
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={patchStates[patch.bundleId]?.loading || currentRole !== 'SecurityAdmin'}
                      onClick={() => handleRollback(patch)}
                      className="h-8 text-xs border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 font-semibold disabled:opacity-40"
                      title={currentRole !== 'SecurityAdmin' ? "Rollback requires SecurityAdmin role" : undefined}
                    >
                      <RotateCcw className="size-3.5 mr-1" />
                      {patchStates[patch.bundleId]?.loading ? 'Rolling back...' : 'Rollback Disk'}
                    </Button>
                  )}

                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs border-zinc-700 bg-zinc-900 hover:bg-zinc-800 text-zinc-300"
                    onClick={() => handleDownloadPatch(patch)}
                  >
                    <Download className="size-3.5 mr-1" />
                    .patch
                  </Button>

                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs border-zinc-700 bg-zinc-900 hover:bg-zinc-800 text-zinc-300"
                    onClick={() => copyToClipboard(patch.ghPrCommand, patch.bundleId)}
                  >
                    {copiedId === patch.bundleId ? (
                      <Check data-icon="inline-start" className="text-primary size-3.5 mr-1" />
                    ) : (
                      <Copy data-icon="inline-start" className="size-3.5 mr-1" />
                    )}
                    {copiedId === patch.bundleId ? 'Copied' : 'Draft PR Command'}
                  </Button>
                </div>
              </div>
            </CardHeader>

            <CardContent className="flex flex-col gap-4">
              {/* Three-Tier Verification Invariant Proof Strip */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded-lg border bg-muted/20">
                {/* 1. Baseline Fails */}
                <div className="flex items-center gap-2.5">
                  {patch.originalTestStatus === 'Failed' ? (
                    <CheckCircle2 className="size-4 text-primary" />
                  ) : (
                    <XCircle className="size-4 text-destructive" />
                  )}
                  <div className="flex flex-col">
                    <span className="text-xs font-medium">1. Baseline Fails (Vulnerable)</span>
                    <span className="text-[11px] text-muted-foreground font-mono">
                      Original Test: {patch.originalTestStatus} (Confirms Bug)
                    </span>
                  </div>
                </div>

                {/* 2. Patched Passes */}
                <div className="flex items-center gap-2.5">
                  {patch.patchedTestStatus === 'Passed' ? (
                    <CheckCircle2 className="size-4 text-primary" />
                  ) : (
                    <XCircle className="size-4 text-destructive" />
                  )}
                  <div className="flex flex-col">
                    <span className="text-xs font-medium">2. Patched Passes (Remediated)</span>
                    <span className="text-[11px] text-muted-foreground font-mono">
                      Patched Test: {patch.patchedTestStatus} (Confirms Fix)
                    </span>
                  </div>
                </div>

                {/* 3. Regressions Pass */}
                <div className="flex items-center gap-2.5">
                  {patch.regressionsPass ? (
                    <CheckCircle2 className="size-4 text-primary" />
                  ) : (
                    <XCircle className="size-4 text-destructive" />
                  )}
                  <div className="flex flex-col">
                    <span className="text-xs font-medium">3. Regressions Pass (Soundness)</span>
                    <span className="text-[11px] text-muted-foreground font-mono">
                      Existing Suites: {patch.regressionsPass ? 'Zero Regressions' : 'Defect Detected'}
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
                <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                  <GitPullRequestDraft className="size-3.5" />
                  Operator Human-in-the-Loop CLI Dispatch
                </span>
                <div className="flex items-center justify-between gap-2 bg-muted/40 p-2.5 rounded-md border font-mono text-xs min-w-0">
                  <span className="truncate min-w-0 flex-1">{patch.ghPrCommand}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 text-xs px-2 shrink-0"
                    onClick={() => copyToClipboard(patch.ghPrCommand, patch.bundleId)}
                  >
                    Copy
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
