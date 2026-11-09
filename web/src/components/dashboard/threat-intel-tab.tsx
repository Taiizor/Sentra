import { useState, useMemo } from 'react'
import {
  Globe,
  Search,
  ExternalLink,
  RefreshCw,
  Database,
  X,
  FilterX,
  ShieldAlert,
} from 'lucide-react'
import { toast } from 'sonner'
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
import type { OsvAdvisoryView, UserRole } from '@/types/sentra'

interface ThreatIntelTabProps {
  advisories: OsvAdvisoryView[]
  currentRole: UserRole
  onSyncAdvisories: () => void
}

const ECOSYSTEM_OPTIONS = [
  { id: 'ALL', label: 'All Feeds' },
  { id: 'npm', label: 'npm' },
  { id: 'crates.io', label: 'crates.io' },
  { id: 'PyPI', label: 'PyPI' },
  { id: 'Go', label: 'Go' },
]

export function ThreatIntelTab({ advisories, currentRole, onSyncAdvisories }: ThreatIntelTabProps) {
  const [search, setSearch] = useState('')
  const [ecosystem, setEcosystem] = useState('ALL')
  const [isSyncing, setIsSyncing] = useState(false)

  const ecosystemCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: advisories.length }
    for (const a of advisories) {
      counts[a.ecosystem] = (counts[a.ecosystem] || 0) + 1
    }
    return counts
  }, [advisories])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return advisories.filter((a) => {
      const matchQuery =
        !q ||
        a.id.toLowerCase().includes(q) ||
        a.package.toLowerCase().includes(q) ||
        a.vulnerability.toLowerCase().includes(q)

      const matchEco = ecosystem === 'ALL' || a.ecosystem === ecosystem
      return matchQuery && matchEco
    })
  }, [advisories, search, ecosystem])

  function handleSync() {
    if (currentRole === 'Viewer') return
    setIsSyncing(true)
    setTimeout(() => {
      setIsSyncing(false)
      onSyncAdvisories()
      toast.success('OSV Mirror Synchronized', {
        description: 'Updated local in-memory threat cache with 250k+ universal security advisories.',
      })
    }, 800)
  }

  function getSeverityBadge(severity: string) {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <Badge className="bg-rose-500/15 text-rose-400 border-rose-500/30 text-xs">Critical</Badge>
      case 'high':
        return <Badge className="bg-orange-500/15 text-orange-400 border-orange-500/30 text-xs">High</Badge>
      case 'medium':
        return <Badge className="bg-amber-500/15 text-amber-400 border-amber-500/30 text-xs">Medium</Badge>
      default:
        return <Badge variant="outline" className="text-xs text-muted-foreground">{severity}</Badge>
    }
  }

  function getAdvisoryUrl(advisory: OsvAdvisoryView): string {
    if (advisory.url) return advisory.url
    const id = advisory.id
    if (id.startsWith('RUSTSEC-')) {
      return `https://rustsec.org/advisories/${id}.html`
    }
    if (id.startsWith('GHSA-')) {
      return `https://github.com/advisories/${id}`
    }
    if (id.startsWith('CVE-')) {
      return `https://nvd.nist.gov/vuln/detail/${id}`
    }
    if (id.startsWith('GO-')) {
      return `https://pkg.go.dev/vuln/${id}`
    }
    return `https://osv.dev/vulnerability/${id}`
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Sleek Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-1 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Globe className="size-4 text-sky-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              OSV Threat Intelligence
            </h2>
            <Badge variant="outline" className="text-[11px] px-2 py-0 border-sky-500/30 text-sky-400 bg-sky-500/5">
              Local Mirror
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Zero-latency offline vulnerability mirror synchronized across npm, crates.io, PyPI, and Go.
          </p>
        </div>

        <Button
          size="sm"
          variant="outline"
          disabled={isSyncing || currentRole === 'Viewer'}
          onClick={handleSync}
          className="h-8 text-xs font-medium gap-2 shrink-0 border-border/80 hover:bg-accent self-start sm:self-auto"
        >
          <RefreshCw className={`size-3.5 text-muted-foreground ${isSyncing ? 'animate-spin text-primary' : ''}`} />
          <span>{isSyncing ? 'Syncing Feeds...' : 'Sync Mirror'}</span>
        </Button>
      </div>

      {/* Unified Filter & Search Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-card/60 border border-border/60 rounded-lg p-2.5">
        {/* Ecosystem Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar">
          {ECOSYSTEM_OPTIONS.map((eco) => {
            const count = ecosystemCounts[eco.id] ?? 0
            const isActive = ecosystem === eco.id
            return (
              <button
                key={eco.id}
                onClick={() => setEcosystem(eco.id)}
                className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 shrink-0 ${
                  isActive
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
                }`}
              >
                <span>{eco.label}</span>
                <span
                  className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
                    isActive ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
                  }`}
                >
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
            placeholder="Search CVE, package, summary..."
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

      {/* Database Table Card */}
      <Card className="border-border/60 bg-card/40">
        <CardHeader className="py-3 px-4 border-b border-border/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="size-3.5 text-muted-foreground" />
              <CardTitle className="text-xs font-medium text-foreground">
                Vulnerability Database
              </CardTitle>
              <span className="text-[11px] text-muted-foreground">
                ({filtered.length} of {advisories.length})
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[11px] text-muted-foreground hidden sm:inline">
                Storage: In-Memory WAL
              </span>
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono text-muted-foreground">
                OSV v1.6
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
              <FilterX className="size-8 text-muted-foreground/50 mb-3" />
              <p className="text-xs font-medium text-foreground">No matching advisories</p>
              <p className="text-[11px] text-muted-foreground mt-1 max-w-sm">
                No security advisories matched your filter criteria. Try adjusting the search query or ecosystem.
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 h-7 text-xs"
                onClick={() => {
                  setSearch('')
                  setEcosystem('ALL')
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
                    <TableHead className="text-xs font-medium h-9">Advisory</TableHead>
                    <TableHead className="text-xs font-medium h-9">Package</TableHead>
                    <TableHead className="text-xs font-medium h-9">Ecosystem</TableHead>
                    <TableHead className="text-xs font-medium h-9">Vulnerability</TableHead>
                    <TableHead className="text-xs font-medium h-9">Affected</TableHead>
                    <TableHead className="text-xs font-medium h-9">Fixed</TableHead>
                    <TableHead className="text-xs font-medium h-9">Severity</TableHead>
                    <TableHead className="text-xs font-medium h-9 text-right pr-4">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((item) => (
                    <TableRow key={item.id} className="border-border/40 hover:bg-muted/30">
                      <TableCell className="font-mono text-xs font-semibold text-foreground py-2.5">
                        <div className="flex items-center gap-1.5">
                          <ShieldAlert className="size-3 text-muted-foreground shrink-0" />
                          <span>{item.id}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-medium text-foreground/90 py-2.5">
                        {item.package}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                          {item.ecosystem}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs max-w-[280px] truncate text-muted-foreground py-2.5" title={item.vulnerability}>
                        {item.vulnerability}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-rose-400 py-2.5">
                        {item.affectedRange}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-emerald-400 font-semibold py-2.5">
                        {item.fixedVersion}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {getSeverityBadge(item.severity)}
                      </TableCell>
                      <TableCell className="text-right py-2.5 pr-4">
                        <a
                          href={getAdvisoryUrl(item)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300 transition-colors"
                        >
                          Details
                          <ExternalLink className="size-3" />
                        </a>
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
