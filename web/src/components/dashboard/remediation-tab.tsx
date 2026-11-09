import { useState } from 'react'
import {
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  GitPullRequestDraft,
  ShieldCheck,
  FileCode,
} from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import type { PatchBundleView, UserRole } from '@/types/sentra'

interface RemediationTabProps {
  patches: PatchBundleView[]
  currentRole: UserRole
}

export function RemediationTab({ patches, currentRole }: RemediationTabProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null)

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2500)
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
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="font-mono text-xs">
                      {patch.bundleId}
                    </Badge>
                    <Badge variant="secondary" className="text-xs flex items-center gap-1">
                      <CheckCircle2 className="size-3 text-primary" />
                      Verified Remediated
                    </Badge>
                    <span className="text-xs text-muted-foreground font-mono">
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

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs"
                    onClick={() => copyToClipboard(patch.ghPrCommand, patch.bundleId)}
                  >
                    {copiedId === patch.bundleId ? (
                      <Check data-icon="inline-start" className="text-primary" />
                    ) : (
                      <Copy data-icon="inline-start" />
                    )}
                    {copiedId === patch.bundleId ? 'Copied GH PR CLI' : 'Copy Draft PR Command'}
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

              {/* Code Diff Display */}
              <div className="flex flex-col gap-1.5">
                <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                  <FileCode className="size-3.5" />
                  Isolated Unified Patch Diff
                </span>
                <pre className="font-mono text-xs bg-muted/60 p-3 rounded-md overflow-x-auto border text-foreground leading-relaxed">
                  {patch.diff}
                </pre>
              </div>

              {/* GitHub Draft PR Dispatch Command Box */}
              <div className="flex flex-col gap-1.5">
                <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                  <GitPullRequestDraft className="size-3.5" />
                  Operator Human-in-the-Loop CLI Dispatch
                </span>
                <div className="flex items-center justify-between gap-2 bg-muted/40 p-2.5 rounded-md border font-mono text-xs">
                  <span className="truncate">{patch.ghPrCommand}</span>
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
