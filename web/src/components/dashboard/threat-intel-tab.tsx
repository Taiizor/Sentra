import { useState } from 'react'
import {
  Globe,
  Search,
  ExternalLink,
  RefreshCw,
  Database,
  CheckCircle2,
  Sparkles,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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

const ECOSYSTEM_PILLS = ['ALL', 'npm', 'crates.io', 'PyPI', 'Go']

export function ThreatIntelTab({ advisories, currentRole, onSyncAdvisories }: ThreatIntelTabProps) {
  const [search, setSearch] = useState('')
  const [ecosystem, setEcosystem] = useState('ALL')
  const [isSyncing, setIsSyncing] = useState(false)

  const filtered = advisories.filter((a) => {
    const matchQuery =
      a.id.toLowerCase().includes(search.toLowerCase()) ||
      a.package.toLowerCase().includes(search.toLowerCase()) ||
      a.vulnerability.toLowerCase().includes(search.toLowerCase())

    const matchEco = ecosystem === 'ALL' || a.ecosystem === ecosystem
    return matchQuery && matchEco
  })

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

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <Globe className="size-5 text-primary" />
            <h2 className="text-lg font-bold tracking-tight">
              Universal OSV Threat Intelligence & Feed Sync
            </h2>
            <Badge variant="outline" className="text-xs">
              Live Feed Ingestion
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Search universal OSV v1.6 advisory feeds (Google OSV, RustSec, GHSA, PyPI, Go) synchronized
            directly into Sentra’s local memory database without external API dependencies.
          </p>
        </div>

        <Button
          size="sm"
          disabled={isSyncing || currentRole === 'Viewer'}
          onClick={handleSync}
          className="h-8 text-xs w-full sm:w-auto"
        >
          <RefreshCw data-icon="inline-start" className={isSyncing ? 'animate-spin' : ''} />
          <span className="hidden sm:inline">{isSyncing ? 'Syncing OSV Mirror...' : 'Sync Advisories (sentra sync-advisories)'}</span>
          <span className="inline sm:hidden">{isSyncing ? 'Syncing...' : 'Sync Advisories'}</span>
        </Button>
      </div>

      {/* Quick Ecosystem Pills */}
      <div className="flex items-center gap-2 overflow-x-auto no-scrollbar py-0.5 max-w-full">
        <span className="text-xs font-medium text-zinc-400 mr-2 flex items-center gap-1.5 shrink-0">
          <Sparkles className="size-3.5 text-primary" />
          Filter by Ecosystem:
        </span>
        {ECOSYSTEM_PILLS.map((eco) => {
          const isActive = ecosystem === eco
          return (
            <Button
              key={eco}
              variant={isActive ? 'default' : 'outline'}
              size="sm"
              className={`h-7 text-xs rounded-full px-3 transition-all shrink-0 ${
                isActive
                  ? 'font-semibold shadow-sm'
                  : 'bg-zinc-900 border-zinc-800 hover:border-zinc-700 text-zinc-300'
              }`}
              onClick={() => setEcosystem(eco)}
            >
              {eco === 'ALL' ? 'All Feeds' : eco}
            </Button>
          )
        })}
      </div>

      {/* Filter Bar */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="size-4 absolute left-3 top-2.5 text-muted-foreground" />
              <Input
                placeholder="Search advisories by CVE, GHSA, package name, or vulnerability..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 h-9 text-xs"
              />
            </div>

            <Select value={ecosystem} onValueChange={(val) => setEcosystem(val ?? 'ALL')}>
              <SelectTrigger className="w-full sm:w-[160px] h-9 text-xs">
                <SelectValue placeholder="Ecosystem">
                  {(val: string | null) => {
                    if (val === 'ALL' || !val) return 'All Ecosystems'
                    if (val === 'npm') return 'npm / Node.js'
                    if (val === 'crates.io') return 'crates.io (Rust)'
                    if (val === 'PyPI') return 'PyPI (Python)'
                    if (val === 'Go') return 'Go Modules'
                    return val
                  }}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="ALL">All Ecosystems</SelectItem>
                  <SelectItem value="npm">npm / Node.js</SelectItem>
                  <SelectItem value="crates.io">crates.io (Rust)</SelectItem>
                  <SelectItem value="PyPI">PyPI (Python)</SelectItem>
                  <SelectItem value="Go">Go Modules</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold">Synchronized Vulnerability Database</CardTitle>
              <CardDescription className="text-xs">
                Showing {filtered.length} of {advisories.length} advisory records in memory
              </CardDescription>
            </div>
            <Badge variant="secondary" className="text-xs flex items-center gap-1 font-mono">
              <Database className="size-3 text-primary" />
              SQLite Persistent Store
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Advisory ID</TableHead>
                  <TableHead className="text-xs">Package</TableHead>
                  <TableHead className="text-xs">Ecosystem</TableHead>
                  <TableHead className="text-xs">Vulnerability Summary</TableHead>
                  <TableHead className="text-xs">Affected Range</TableHead>
                  <TableHead className="text-xs">Fixed Version</TableHead>
                  <TableHead className="text-xs">Severity</TableHead>
                  <TableHead className="text-xs text-right">Upstream Link</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-mono text-xs font-bold text-foreground">
                      {item.id}
                    </TableCell>
                    <TableCell className="font-mono text-xs font-semibold">
                      {item.package}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {item.ecosystem}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs max-w-[300px] truncate">
                      {item.vulnerability}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-rose-400">
                      {item.affectedRange}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-emerald-400 font-bold">
                      {item.fixedVersion}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={item.severity === 'Critical' || item.severity === 'High' ? 'destructive' : 'outline'}
                        className="text-xs"
                      >
                        {item.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <a
                        href={`https://github.com/advisories/${item.id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                      >
                        View
                        <ExternalLink className="size-3" />
                      </a>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
