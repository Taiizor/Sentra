import {
  Server,
  Cpu,
  HardDrive,
  ShieldAlert,
  ShieldCheck,
  Lock,
  RotateCw,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import type { WorkerNodeView } from '@/types/sentra'

interface WorkerFleetTabProps {
  workers: WorkerNodeView[]
}

export function WorkerFleetTab({ workers }: WorkerFleetTabProps) {
  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <Server className="size-5 text-primary" />
          <h2 className="text-lg font-bold tracking-tight">
            Remote-Worker Fleet Coordinator & Isolation Sandboxes
          </h2>
          <Badge variant="outline" className="text-xs">
            Phase 6 Enterprise Gate
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">
          Single-tenant exclusive worker leasing, fail-closed cross-tenant fencing,
          mandatory quarantine-and-reset lifecycle, and zero-egress network enforcement.
        </p>
      </div>

      {/* 5-Gate Multi-User Security Audit Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 p-4 rounded-lg border bg-card/60">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <ShieldCheck className="size-4" />
            Gate 1: Tenant Fencing
          </div>
          <span className="text-[11px] text-muted-foreground">
            Fail-closed cross-tenant boundary verified
          </span>
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <Lock className="size-4" />
            Gate 2: Worker Egress
          </div>
          <span className="text-[11px] text-muted-foreground">
            StrictlyDenied egress policy enforced
          </span>
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <RotateCw className="size-4" />
            Gate 3: Zero Reuse
          </div>
          <span className="text-[11px] text-muted-foreground">
            Mandatory quarantine before sanitization
          </span>
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <ShieldAlert className="size-4" />
            Gate 4: Secret Canaries
          </div>
          <span className="text-[11px] text-muted-foreground">
            Zero secret inheritance across tasks
          </span>
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <HardDrive className="size-4" />
            Gate 5: Immutable CAS
          </div>
          <span className="text-[11px] text-muted-foreground">
            Content-addressed tamper-resistant store
          </span>
        </div>
      </div>

      {/* Worker Nodes Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {workers.map((worker) => (
          <Card key={worker.workerId} className="flex flex-col justify-between border-border/80">
            <CardHeader className="pb-3 border-b bg-muted/20">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="size-4 text-muted-foreground" />
                  <span className="font-mono text-xs font-bold">{worker.hostname}</span>
                </div>
                <Badge
                  variant={
                    worker.state === 'AVAILABLE'
                      ? 'secondary'
                      : worker.state === 'LEASED'
                        ? 'destructive'
                        : 'outline'
                  }
                  className="text-xs"
                >
                  {worker.state}
                </Badge>
              </div>
              <CardDescription className="text-xs font-mono mt-1">
                {worker.workerId} • {worker.architecture}
              </CardDescription>
            </CardHeader>

            <CardContent className="pt-4 flex flex-col gap-4">
              {/* Lease info */}
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Tenant Lease:</span>
                <span className="font-mono font-medium">
                  {worker.tenantLease ?? 'None (Unassigned)'}
                </span>
              </div>

              {/* CPU utilization */}
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground flex items-center gap-1">
                    <Cpu className="size-3.5" /> CPU Load:
                  </span>
                  <span className="font-mono font-medium">{worker.cpuUsagePercent}%</span>
                </div>
                <Progress value={worker.cpuUsagePercent} className="h-1.5" />
              </div>

              {/* Memory usage */}
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground flex items-center gap-1">
                  <HardDrive className="size-3.5" /> RSS Memory:
                </span>
                <span className="font-mono font-medium">{worker.memoryUsageMb} MiB / 2048 MiB</span>
              </div>

              {/* Active Job */}
              <div className="p-2.5 rounded bg-muted/30 border text-xs flex flex-col gap-1">
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">
                  Dispatched Workload
                </span>
                <span className="font-mono text-xs truncate">
                  {worker.activeJob ?? 'Idle (Awaiting Lease Allocation)'}
                </span>
              </div>

              {/* Egress Gate */}
              <div className="flex items-center justify-between text-xs border-t pt-3">
                <span className="text-muted-foreground">Egress Boundary:</span>
                <Badge variant="outline" className="text-xs font-mono flex items-center gap-1">
                  <Lock className="size-3 text-primary" />
                  {worker.egressPolicy}
                </Badge>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
