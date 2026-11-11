import { useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, FileLock2, PackageSearch, Search, TriangleAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { DependencyPackageView, TenantView } from '@/types/api'
import { formatDateTime } from './console-format'
import { EmptyBlock, ErrorAlert, LoadingBlock, SectionCard } from './console-kit'

const PAGE_SIZE = 50
const ALL = '__all__'

/**
 * Lockfiles and packages parsed by the core (`sentra inventory`). This is a local, read-only
 * listing: it does not query any advisory source.
 */
export function DependencyInventory({
  tenant,
  onLookup,
  lookupBlockedReason,
}: {
  tenant: TenantView
  onLookup: (pkg: DependencyPackageView) => void
  /** Why OSV lookups from a row are unavailable, or null when they are available. */
  lookupBlockedReason: string | null
}) {
  const inventory = useResource(`dependencies:${tenant.tenantId}`, (signal) => api.dependencies(tenant.tenantId, signal))
  const [search, setSearch] = useState('')
  const [ecosystem, setEcosystem] = useState<string>(ALL)
  const [page, setPage] = useState(0)

  const ecosystems = useMemo(() => {
    const values = new Set<string>()
    for (const pkg of inventory.data?.packages ?? []) values.add(pkg.ecosystem ?? 'unknown')
    return [...values].sort()
  }, [inventory.data])

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return (inventory.data?.packages ?? []).filter((pkg) => {
      if (ecosystem !== ALL && (pkg.ecosystem ?? 'unknown') !== ecosystem) return false
      if (!needle) return true
      return pkg.name.toLowerCase().includes(needle) || pkg.version.toLowerCase().includes(needle)
    })
  }, [inventory.data, search, ecosystem])

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, pageCount - 1)
  const visible = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE)

  return (
    <SectionCard
      icon={<FileLock2 className="size-4 text-sky-400" />}
      title="Dependency inventory"
      description={
        inventory.data
          ? `Parsed from workspace lockfiles by the Sentra core at ${formatDateTime(inventory.data.generatedAt)}.`
          : 'Lockfiles and packages parsed by the Sentra core from the workspace.'
      }
      actions={
        <Button variant="outline" size="xs" onClick={inventory.reload} disabled={inventory.loading}>
          Refresh
        </Button>
      }
    >
      {inventory.data?.truncated && !inventory.error && (
        <Alert className="border-amber-500/30 bg-amber-500/5 text-amber-200">
          <TriangleAlert />
          <AlertTitle className="text-xs">Incomplete inventory</AlertTitle>
          <AlertDescription className="text-xs text-amber-200/90">
            The core inventory hit a limit; the list is incomplete. The core stops at fixed bounds on directory entries walked,
            lockfiles recorded and package rows returned, so some lockfiles or packages are missing here and dependency audit runs
            do not query them.
          </AlertDescription>
        </Alert>
      )}
      {inventory.error ? (
        <ErrorAlert error={inventory.error} onRetry={inventory.reload} title="Could not read the dependency inventory" />
      ) : !inventory.data ? (
        <LoadingBlock rows={4} />
      ) : inventory.data.lockfiles.length === 0 ? (
        <EmptyBlock icon={<PackageSearch />} title="No lockfiles found">
          The core found no supported lockfile in this workspace (it skips dependency and build directories such as
          node_modules, target and vendor). Dependency auditing needs a lockfile with pinned versions.
        </EmptyBlock>
      ) : (
        <>
          <Table className="text-xs">
            <TableHeader>
              <TableRow>
                <TableHead>Lockfile</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Ecosystem</TableHead>
                <TableHead className="text-right">Packages</TableHead>
                <TableHead>Parse result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {inventory.data.lockfiles.map((lockfile) => (
                <TableRow key={lockfile.path}>
                  <TableCell className="font-mono text-[11px]">{lockfile.path}</TableCell>
                  <TableCell>{lockfile.kind}</TableCell>
                  <TableCell className="font-mono text-[11px]">{lockfile.ecosystem ?? 'unknown'}</TableCell>
                  <TableCell className="text-right font-mono">{lockfile.packages.toLocaleString()}</TableCell>
                  <TableCell className="max-w-80 whitespace-normal">
                    {lockfile.parseError ? (
                      <span className="text-rose-300">{lockfile.parseError}</span>
                    ) : (
                      <span className="text-zinc-500">parsed</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-1 items-center gap-2">
              <div className="relative max-w-xs flex-1">
                <Search className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-zinc-500" />
                <Input
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value)
                    setPage(0)
                  }}
                  placeholder="Filter packages by name or version"
                  className="h-7 pl-7 text-xs"
                  aria-label="Filter packages"
                />
              </div>
              <Select
                value={ecosystem}
                onValueChange={(value) => {
                  setEcosystem(value ?? ALL)
                  setPage(0)
                }}
              >
                <SelectTrigger size="sm" className="w-40 text-xs">
                  <SelectValue>{(value: string | null) => (!value || value === ALL ? 'All ecosystems' : value)}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All ecosystems</SelectItem>
                  {ecosystems.map((value) => (
                    <SelectItem key={value} value={value}>
                      {value}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <span className="text-[11px] text-muted-foreground">
              {filtered.length.toLocaleString()} of {inventory.data.totalPackages.toLocaleString()} packages
              {inventory.data.packages.length < inventory.data.totalPackages &&
                ` (${inventory.data.packages.length.toLocaleString()} rows returned by the core)`}
            </span>
          </div>

          {filtered.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted-foreground">No package matches the current filter.</p>
          ) : (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Package</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Ecosystem</TableHead>
                  <TableHead>Lockfile</TableHead>
                  <TableHead className="text-right">OSV</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((pkg) => (
                  <TableRow key={`${pkg.lockfile}:${pkg.ecosystem}:${pkg.name}@${pkg.version}`}>
                    <TableCell className="font-mono text-[11px] text-zinc-100">{pkg.name}</TableCell>
                    <TableCell className="font-mono text-[11px]">{pkg.version}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {pkg.ecosystem ?? 'unknown'}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-zinc-400">{pkg.lockfile}</TableCell>
                    <TableCell className="text-right">
                      <span title={lookupBlockedReason ?? (!pkg.ecosystem ? 'Ecosystem unknown for this package' : undefined)}>
                        <Button
                          variant="ghost"
                          size="xs"
                          disabled={lookupBlockedReason !== null || !pkg.ecosystem}
                          onClick={() => onLookup(pkg)}
                        >
                          Look up
                        </Button>
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {pageCount > 1 && (
            <div className="flex items-center justify-end gap-2 text-[11px] text-muted-foreground">
              <Button
                variant="outline"
                size="icon-xs"
                disabled={currentPage === 0}
                onClick={() => setPage(currentPage - 1)}
                aria-label="Previous page"
              >
                <ChevronLeft />
              </Button>
              Page {currentPage + 1} of {pageCount}
              <Button
                variant="outline"
                size="icon-xs"
                disabled={currentPage >= pageCount - 1}
                onClick={() => setPage(currentPage + 1)}
                aria-label="Next page"
              >
                <ChevronRight />
              </Button>
            </div>
          )}
        </>
      )}
    </SectionCard>
  )
}
