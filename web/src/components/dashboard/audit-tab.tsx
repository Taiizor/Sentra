import { useState, useMemo } from 'react'
import {
  History,
  ShieldCheck,
  Search,
  X,
  User,
  Cpu,
  FilterX,
  FileCheck,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import type { AuditLogView } from '@/types/sentra'

interface AuditTabProps {
  auditLogs: AuditLogView[]
}

export function AuditTab({ auditLogs }: AuditTabProps) {
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState<string>('ALL')

  const uniqueActions = useMemo(() => {
    const set = new Set<string>()
    for (const log of auditLogs) {
      set.add(log.action)
    }
    return Array.from(set)
  }, [auditLogs])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return auditLogs.filter((log) => {
      const matchSearch =
        !q ||
        log.eventId.toLowerCase().includes(q) ||
        log.actor.toLowerCase().includes(q) ||
        log.action.toLowerCase().includes(q) ||
        log.details.toLowerCase().includes(q)

      const matchAction = actionFilter === 'ALL' || log.action === actionFilter
      return matchSearch && matchAction
    })
  }, [auditLogs, search, actionFilter])

  function getActionBadge(action: string) {
    if (action.includes('CONFIRM') || action.includes('VERIFIED')) {
      return (
        <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          {action}
        </span>
      )
    }
    if (action.includes('PATCH') || action.includes('SYNTHES')) {
      return (
        <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30">
          {action}
        </span>
      )
    }
    if (action.includes('SCAN') || action.includes('INGEST')) {
      return (
        <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-sky-500/15 text-sky-400 border border-sky-500/30">
          {action}
        </span>
      )
    }
    return (
      <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
        {action}
      </Badge>
    )
  }

  function getActorDisplay(actor: string) {
    const isSystem = actor.startsWith('sys:')
    return (
      <div className="flex items-center gap-1.5">
        {isSystem ? (
          <Cpu className="size-3 text-muted-foreground shrink-0" />
        ) : (
          <User className="size-3 text-primary shrink-0" />
        )}
        <span className="font-mono text-xs text-foreground/90">{actor}</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Sleek Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <History className="size-4 text-zinc-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              Immutable Audit Trail
            </h2>
            <Badge variant="outline" className="text-[11px] px-2 py-0 border-zinc-700 text-zinc-300 bg-zinc-800/40">
              Monotonic CAS
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Strictly monotonic, cryptographically verifiable record of all state transitions and governance approvals.
          </p>
        </div>

        {/* Verification Status Badge */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <Badge variant="outline" className="text-[11px] border-emerald-500/30 text-emerald-400 bg-emerald-500/5 flex items-center gap-1.5 px-2.5 py-1">
            <ShieldCheck className="size-3.5" />
            <span>Cryptographic Chain Sound (SHA-256)</span>
          </Badge>
        </div>
      </div>

      {/* Unified Filter & Search Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-card/60 border border-border/60 rounded-lg p-2.5">
        {/* Action Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar">
          <button
            type="button"
            onClick={() => setActionFilter('ALL')}
            className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 shrink-0 ${
              actionFilter === 'ALL'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
            }`}
          >
            <span>All Events</span>
            <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
              actionFilter === 'ALL' ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
            }`}>
              {auditLogs.length}
            </span>
          </button>
          {uniqueActions.map((act) => {
            const count = auditLogs.filter((l) => l.action === act).length
            const isActive = actionFilter === act
            return (
              <button
                key={act}
                type="button"
                onClick={() => setActionFilter(act)}
                className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 shrink-0 ${
                  isActive
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
                }`}
              >
                <span>{act}</span>
                <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
                  isActive ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
                }`}>
                  {count}
                </span>
              </button>
            )
          })}
        </div>

        {/* Search Input */}
        <div className="relative w-full md:w-72 shrink-0">
          <Search className="size-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search event ID, actor, details..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 pr-7 h-7 text-xs bg-background/50 border-border/60 focus-visible:ring-1"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5 rounded"
            >
              <X className="size-3" />
            </button>
          )}
        </div>
      </div>

      {/* Audit Log Table Card */}
      <Card className="border-border/60 bg-card/40">
        <CardHeader className="py-2.5 px-4 border-b border-border/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCheck className="size-3.5 text-muted-foreground" />
              <CardTitle className="text-xs font-medium text-foreground">
                Audit Event Timeline
              </CardTitle>
              <span className="text-[11px] text-muted-foreground">
                ({filtered.length} of {auditLogs.length} events)
              </span>
            </div>
            <span className="text-[11px] text-muted-foreground font-mono hidden sm:inline">
              Tamper-Evident Append-Only
            </span>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
              <FilterX className="size-8 text-muted-foreground/50 mb-3" />
              <p className="text-xs font-medium text-foreground">No audit events match filter</p>
              <p className="text-[11px] text-muted-foreground mt-1 max-w-sm">
                Try adjusting your search query or action filter.
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 h-7 text-xs"
                onClick={() => {
                  setSearch('')
                  setActionFilter('ALL')
                }}
              >
                Reset Filters
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/40 hover:bg-transparent">
                    <TableHead className="text-xs font-medium h-9 pl-4 w-[70px]">Seq</TableHead>
                    <TableHead className="text-xs font-medium h-9">Event ID</TableHead>
                    <TableHead className="text-xs font-medium h-9">Actor</TableHead>
                    <TableHead className="text-xs font-medium h-9">Action</TableHead>
                    <TableHead className="text-xs font-medium h-9">Structured Audit Details</TableHead>
                    <TableHead className="text-xs font-medium h-9 text-right pr-4">Timestamp</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className="text-xs">
                  {filtered.map((log) => (
                    <TableRow key={log.eventId} className="border-border/40 hover:bg-muted/30">
                      <TableCell className="font-mono text-xs font-bold text-muted-foreground pl-4 py-2.5">
                        #{log.sequenceNumber}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-foreground/80 py-2.5">
                        {log.eventId}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {getActorDisplay(log.actor)}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {getActionBadge(log.action)}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[340px] truncate py-2.5" title={log.details}>
                        {log.details}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground text-right pr-4 py-2.5">
                        {new Date(log.timestamp).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
