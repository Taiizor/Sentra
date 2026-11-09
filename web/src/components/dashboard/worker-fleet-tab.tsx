import { useState, useMemo } from 'react'
import {
  Server,
  Cpu,
  HardDrive,
  ShieldAlert,
  ShieldCheck,
  Lock,
  RotateCw,
  Terminal,
  Activity,
  Layers,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import type { WorkerNodeView } from '@/types/sentra'

interface WorkerFleetTabProps {
  workers: WorkerNodeView[]
}

const FIVE_GATES = [
  { id: 'g1', name: 'Tenant Fencing', desc: 'Fail-closed isolation', icon: ShieldCheck },
  { id: 'g2', name: 'Zero Egress', desc: 'StrictlyDenied outbound', icon: Lock },
  { id: 'g3', name: 'Quarantine Cycle', desc: 'Zero host task reuse', icon: RotateCw },
  { id: 'g4', name: 'Secret Canaries', desc: 'Zero credential bleed', icon: ShieldAlert },
  { id: 'g5', name: 'Immutable CAS', desc: 'Content-addressed store', icon: HardDrive },
]

export function WorkerFleetTab({ workers }: WorkerFleetTabProps) {
  const [filterState, setFilterState] = useState<'ALL' | WorkerNodeView['state']>('ALL')

  const stats = useMemo(() => {
    const total = workers.length
    const available = workers.filter((w) => w.state === 'AVAILABLE').length
    const leased = workers.filter((w) => w.state === 'LEASED').length
    const quarantined = workers.filter((w) => w.state === 'QUARANTINED' || w.state === 'RESETTING').length
    const avgCpu = total > 0 ? Math.round(workers.reduce((acc, w) => acc + w.cpuUsagePercent, 0) / total) : 0
    const totalMemMb = workers.reduce((acc, w) => acc + w.memoryUsageMb, 0)

    return { total, available, leased, quarantined, avgCpu, totalMemMb }
  }, [workers])

  const filteredWorkers = useMemo(() => {
    if (filterState === 'ALL') return workers
    return workers.filter((w) => w.state === filterState)
  }, [workers, filterState])

  function getStateBadge(state: WorkerNodeView['state']) {
    switch (state) {
      case 'AVAILABLE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
            AVAILABLE
          </span>
        )
      case 'LEASED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <span className="size-1.5 rounded-full bg-amber-400" />
            LEASED
          </span>
        )
      case 'QUARANTINED':
      case 'RESETTING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold font-mono bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <span className="size-1.5 rounded-full bg-rose-400" />
            {state}
          </span>
        )
    }
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Sleek Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Server className="size-4 text-amber-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              Worker Fleet & Sandboxes
            </h2>
            <Badge variant="outline" className="text-[11px] px-2 py-0 border-amber-500/30 text-amber-400 bg-amber-500/5">
              Phase 6 Enclaves
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Isolated execution nodes with single-tenant leasing, fail-closed fencing, and zero-egress enforcement.
          </p>
        </div>

        {/* Live Status Indicator */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5 bg-card/60 border border-border/60 px-2.5 py-1 rounded-md">
            <Activity className="size-3.5 text-emerald-400" />
            <span className="text-muted-foreground">Avg Load:</span>
            <span className="font-semibold text-foreground">{stats.avgCpu}%</span>
          </div>
          <div className="flex items-center gap-1.5 bg-card/60 border border-border/60 px-2.5 py-1 rounded-md">
            <HardDrive className="size-3.5 text-sky-400" />
            <span className="text-muted-foreground">Memory:</span>
            <span className="font-semibold text-foreground">{stats.totalMemMb} MiB</span>
          </div>
        </div>
      </div>

      {/* 5-Gate Enterprise Governance Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 bg-card/40 border border-border/60 rounded-lg p-2.5">
        {FIVE_GATES.map((gate, i) => {
          const Icon = gate.icon
          return (
            <div
              key={gate.id}
              className="flex items-center gap-2 p-1.5 rounded-md bg-background/40 border border-border/40"
            >
              <div className="size-6 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
                <Icon className="size-3" />
              </div>
              <div className="flex flex-col min-w-0">
                <span className="text-[11px] font-semibold text-foreground truncate">
                  Gate {i + 1}: {gate.name}
                </span>
                <span className="text-[10px] text-muted-foreground truncate">
                  {gate.desc}
                </span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Filter Toolbar */}
      <div className="flex items-center justify-between gap-3 bg-card/60 border border-border/60 rounded-lg p-2">
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setFilterState('ALL')}
            className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              filterState === 'ALL'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
            }`}
          >
            <span>All Nodes</span>
            <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
              filterState === 'ALL' ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
            }`}>
              {stats.total}
            </span>
          </button>
          <button
            onClick={() => setFilterState('AVAILABLE')}
            className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              filterState === 'AVAILABLE'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
            }`}
          >
            <span>Available</span>
            <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
              filterState === 'AVAILABLE' ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
            }`}>
              {stats.available}
            </span>
          </button>
          <button
            onClick={() => setFilterState('LEASED')}
            className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
              filterState === 'LEASED'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
            }`}
          >
            <span>Leased</span>
            <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
              filterState === 'LEASED' ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
            }`}>
              {stats.leased}
            </span>
          </button>
        </div>

        <span className="text-[11px] text-muted-foreground font-mono hidden sm:inline">
          Fail-Closed Hardware Enclaves
        </span>
      </div>

      {/* Worker Nodes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {filteredWorkers.map((worker) => {
          const memPercent = Math.min(100, Math.round((worker.memoryUsageMb / 2048) * 100))
          return (
            <Card key={worker.workerId} className="border-border/60 bg-card/40 flex flex-col justify-between">
              <CardHeader className="p-3 pb-2.5 border-b border-border/40">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <Server className="size-3.5 text-muted-foreground shrink-0" />
                    <span className="font-mono text-xs font-semibold text-foreground truncate">
                      {worker.hostname}
                    </span>
                  </div>
                  {getStateBadge(worker.state)}
                </div>

                <div className="flex items-center justify-between mt-1 text-[11px] font-mono text-muted-foreground">
                  <span>{worker.workerId}</span>
                  <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                    {worker.architecture}
                  </Badge>
                </div>
              </CardHeader>

              <CardContent className="p-3 flex flex-col gap-3">
                {/* Lease status */}
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Tenant Lease:</span>
                  <span className={`font-mono text-xs font-medium ${
                    worker.tenantLease ? 'text-amber-400' : 'text-muted-foreground'
                  }`}>
                    {worker.tenantLease ?? 'None (Unassigned)'}
                  </span>
                </div>

                {/* Telemetry metrics */}
                <div className="flex flex-col gap-2 p-2.5 rounded bg-background/40 border border-border/40">
                  {/* CPU load */}
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-muted-foreground flex items-center gap-1">
                        <Cpu className="size-3" /> CPU Load
                      </span>
                      <span className="font-mono font-medium text-foreground">{worker.cpuUsagePercent}%</span>
                    </div>
                    <Progress
                      value={worker.cpuUsagePercent}
                      className="h-1 bg-muted"
                    />
                  </div>

                  {/* Memory usage */}
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-muted-foreground flex items-center gap-1">
                        <HardDrive className="size-3" /> Memory ({memPercent}%)
                      </span>
                      <span className="font-mono font-medium text-foreground">{worker.memoryUsageMb} / 2048 MiB</span>
                    </div>
                    <Progress
                      value={memPercent}
                      className="h-1 bg-muted"
                    />
                  </div>
                </div>

                {/* Active Dispatched Workload */}
                <div className="p-2 rounded bg-background/50 border border-border/40 text-xs flex flex-col gap-1">
                  <span className="text-[10px] text-muted-foreground uppercase font-semibold flex items-center gap-1">
                    <Terminal className="size-2.5 text-primary" /> Workload:
                  </span>
                  <span className="font-mono text-[11px] text-foreground/90 truncate">
                    {worker.activeJob ?? 'Idle (Awaiting Task)'}
                  </span>
                </div>

                {/* Footer Egress Boundary */}
                <div className="flex items-center justify-between text-xs pt-1 border-t border-border/40">
                  <span className="text-[11px] text-muted-foreground">Egress Boundary:</span>
                  <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-400 bg-emerald-500/5 flex items-center gap-1 px-1.5 py-0">
                    <Lock className="size-2.5" />
                    {worker.egressPolicy}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
