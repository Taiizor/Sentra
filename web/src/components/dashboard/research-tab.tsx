import { Brain, Coins, Shield, Target } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import type { CampaignLedgerView } from '@/types/sentra'

interface ResearchTabProps {
  campaigns: CampaignLedgerView[]
}

export function ResearchTab({ campaigns }: ResearchTabProps) {
  return (
    <div className="flex flex-col gap-6">
      {/* Intro Description */}
      <div className="flex flex-col gap-1">
        <h2 className="text-base font-bold flex items-center gap-2">
          <Brain className="size-5 text-primary" />
          Autonomous Deep Research Campaigns & Coverage Ledger
        </h2>
        <p className="text-xs text-muted-foreground">
          Autonomous multi-role agent campaigns (Scout, Analyst, Validator, Independent Verifier)
          with hard monetary token budgets, hypothesis tree deduplication, and strictly tracked exploration coverage.
        </p>
      </div>

      {/* Campaigns Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {campaigns.map((cmp) => {
          const spendPercent = Math.min(
            100,
            Math.round((cmp.spentBudgetMicroUsd / cmp.maxBudgetMicroUsd) * 100)
          )

          return (
            <Card key={cmp.campaignId} className="flex flex-col justify-between">
              <CardHeader>
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="outline" className="font-mono text-xs">
                    {cmp.campaignId}
                  </Badge>
                  <Badge
                    variant={cmp.status === 'ACTIVE' ? 'secondary' : 'outline'}
                    className="text-xs"
                  >
                    {cmp.status}
                  </Badge>
                </div>
                <CardTitle className="text-sm font-bold mt-2">{cmp.title}</CardTitle>
                <CardDescription className="text-xs">
                  {cmp.taskCount} dispatched research tasks • Anti-collusion barriers enforced
                </CardDescription>
              </CardHeader>

              <CardContent className="flex flex-col gap-4">
                {/* Budget Spend Bar */}
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-1">
                      <Coins className="size-3.5" />
                      Budget Utilization:
                    </span>
                    <span className="font-mono font-medium">
                      ${(cmp.spentBudgetMicroUsd / 1_000_000).toFixed(2)} / $
                      {(cmp.maxBudgetMicroUsd / 1_000_000).toFixed(2)} ({spendPercent}%)
                    </span>
                  </div>
                  <Progress value={spendPercent} className="h-2" />
                </div>

                {/* Exploration Coverage Ledger */}
                <div className="grid grid-cols-2 gap-2 p-3 rounded-lg border bg-muted/20">
                  <div className="flex items-center gap-2">
                    <Target className="size-4 text-primary" />
                    <div className="flex flex-col">
                      <span className="text-xs font-semibold">{cmp.coveredRegions} Regions</span>
                      <span className="text-[11px] text-muted-foreground">Explored & Fingerprinted</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Shield className="size-4 text-muted-foreground" />
                    <div className="flex flex-col">
                      <span className="text-xs font-semibold">{cmp.skippedRegions} Regions</span>
                      <span className="text-[11px] text-muted-foreground">Excluded with Reason</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
