import { useImperativeHandle, useRef, useState, type FormEvent, type ReactNode, type Ref } from 'react'
import { ExternalLink, Loader2, Search, ShieldQuestion } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { MarkdownView } from '@/components/ui/markdown-view'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { api } from '@/lib/api'
import type { OsvQueryRequest, OsvQueryResponse, OsvVulnerabilityView } from '@/types/api'
import { formatDateTime, isSafeHttpUrl, osvUrl } from './console-format'
import { EmptyBlock, ErrorAlert, GatedButton, SectionCard, SeverityBadge } from './console-kit'

/**
 * OSV ecosystem identifiers (https://ossf.github.io/osv-schema/#affectedpackage-field) accepted by
 * the bridge, whose pattern does not allow spaces in the base name.
 */
const OSV_ECOSYSTEMS = [
  'crates.io',
  'npm',
  'PyPI',
  'Go',
  'Maven',
  'NuGet',
  'RubyGems',
  'Packagist',
  'Pub',
  'Hex',
  'SwiftURL',
  'Hackage',
  'CRAN',
] as const

const SEVERITY_SOURCE_LABEL: Record<OsvVulnerabilityView['severitySource'], string> = {
  database_specific: 'database-specific rating',
  cvss_v3: 'CVSS v3',
  cvss_v2: 'CVSS v2',
  none: 'no severity published',
}

export interface OsvLookupHandle {
  /** Fills the form with `request` and runs the query (when lookups are allowed). */
  lookup: (request: OsvQueryRequest) => void
}

/** On-demand OSV.dev query for a single package (sends the package name to OSV). */
export function OsvLookup({ blockedReason, ref }: { blockedReason: string | null; ref?: Ref<OsvLookupHandle> }) {
  const [pkg, setPkg] = useState('')
  const [ecosystem, setEcosystem] = useState<string>('npm')
  const [version, setVersion] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [result, setResult] = useState<OsvQueryResponse | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)

  const runQuery = async (request: OsvQueryRequest) => {
    setBusy(true)
    setError(null)
    try {
      setResult(await api.intel.query(request))
    } catch (failure) {
      setResult(null)
      setError(failure)
    } finally {
      setBusy(false)
    }
  }

  useImperativeHandle(
    ref,
    () => ({
      lookup: (request: OsvQueryRequest) => {
        setPkg(request.package)
        setEcosystem(request.ecosystem)
        setVersion(request.version ?? '')
        containerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
        if (blockedReason === null) void runQuery(request)
      },
    }),
    [blockedReason],
  )

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const name = pkg.trim()
    if (!name || blockedReason !== null) return
    void runQuery({ package: name, ecosystem, version: version.trim() || undefined })
  }

  const ecosystemOptions: string[] = OSV_ECOSYSTEMS.includes(ecosystem as (typeof OSV_ECOSYSTEMS)[number])
    ? [...OSV_ECOSYSTEMS]
    : [ecosystem, ...OSV_ECOSYSTEMS]

  return (
    <div ref={containerRef} className="scroll-mt-4">
      <SectionCard
        icon={<ShieldQuestion className="size-4 text-violet-400" />}
        title="OSV package lookup"
        description="Queries OSV.dev for one package. The package name, ecosystem and version are sent to OSV."
      >
        <form onSubmit={submit} className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_11rem_9rem_auto] sm:items-end">
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Package
            <Input
              value={pkg}
              onChange={(event) => setPkg(event.target.value)}
              placeholder="e.g. lodash"
              className="h-8 font-mono text-xs"
              maxLength={256}
              required
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Ecosystem
            <Select value={ecosystem} onValueChange={(value) => value && setEcosystem(value)}>
              <SelectTrigger className="w-full text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ecosystemOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Version (optional)
            <Input
              value={version}
              onChange={(event) => setVersion(event.target.value)}
              placeholder="any version"
              className="h-8 font-mono text-xs"
              maxLength={128}
            />
          </label>
          <GatedButton
            permission="intel:query"
            blockedReason={blockedReason}
            type="submit"
            size="default"
            disabled={busy || !pkg.trim()}
          >
            {busy ? <Loader2 className="animate-spin" /> : <Search />}
            Query OSV
          </GatedButton>
        </form>

        {error !== null && <ErrorAlert error={error} title="OSV query failed" />}

        {result && (
          <div className="flex flex-col gap-2">
            <p className="text-[11px] text-muted-foreground">
              {result.vulnerabilities.length} record(s) for <span className="font-mono text-zinc-300">{result.package}</span> (
              {result.ecosystem}
              {result.version ? ` ${result.version}` : ', all versions'}) · queried {formatDateTime(result.queriedAt)}
            </p>
            {result.vulnerabilities.length === 0 ? (
              <EmptyBlock icon={<ShieldQuestion />} title="OSV returned no records">
                OSV has no vulnerability record matching this query at query time. That reflects OSV's coverage; it is not
                proof that the package is free of vulnerabilities.
              </EmptyBlock>
            ) : (
              result.vulnerabilities.map((vulnerability) => <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} queriedVersion={result.version} />)
            )}
          </div>
        )}
      </SectionCard>
    </div>
  )
}

function VulnerabilityCard({ vulnerability, queriedVersion }: { vulnerability: OsvVulnerabilityView; queriedVersion: string | null }) {
  const [showAllRefs, setShowAllRefs] = useState(false)
  const [showDetails, setShowDetails] = useState(false)
  const references = vulnerability.references.filter((reference) => isSafeHttpUrl(reference.url))
  const visibleRefs = showAllRefs ? references : references.slice(0, 5)
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border/60 bg-background/40 p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <a
          href={osvUrl(vulnerability.id)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 font-mono text-[12px] font-semibold text-primary hover:underline"
        >
          {vulnerability.id}
          <ExternalLink className="size-3" />
        </a>
        <SeverityBadge severity={vulnerability.severity} />
        <span className="text-[11px] text-zinc-500">{SEVERITY_SOURCE_LABEL[vulnerability.severitySource]}</span>
        {vulnerability.cvssScore !== null && (
          <span className="font-mono text-[11px] text-zinc-300">CVSS {vulnerability.cvssScore.toFixed(1)}</span>
        )}
        {vulnerability.withdrawn && (
          <Badge variant="outline" className="border-amber-500/40 text-amber-300">
            withdrawn {formatDateTime(vulnerability.withdrawn)}
          </Badge>
        )}
      </div>
      {vulnerability.summary && <p className="text-zinc-200">{vulnerability.summary}</p>}
      {vulnerability.cvssVector && <code className="break-all font-mono text-[10px] text-zinc-500">{vulnerability.cvssVector}</code>}

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <Field label="Aliases">
          {vulnerability.aliases.length > 0 ? vulnerability.aliases.join(', ') : 'none'}
        </Field>
        <Field label="Fixed versions">
          {vulnerability.fixedVersions.length > 0
            ? vulnerability.fixedVersions.join(', ')
            : vulnerability.fixedVersionsNote
              ? 'none listed'
              : queriedVersion
                ? `no fixed version published for ${queriedVersion}`
                : 'no fixed version published'}
          {vulnerability.fixedVersionsNote && (
            <span className="mt-0.5 block text-[10px] text-amber-300/90">{vulnerability.fixedVersionsNote}</span>
          )}
        </Field>
        <Field label="Published / modified">
          {formatDateTime(vulnerability.published)} / {formatDateTime(vulnerability.modified)}
        </Field>
        <Field label="CWE">{vulnerability.cwes.length > 0 ? vulnerability.cwes.join(', ') : 'none listed'}</Field>
      </div>

      {vulnerability.affected.length > 0 && (
        <Field label="Affected ranges">
          <ul className="flex flex-col gap-0.5">
            {vulnerability.affected.map((affected, index) => (
              <li key={`${affected.ecosystem}:${affected.package}:${index}`} className="font-mono text-[11px]">
                {affected.ecosystem}/{affected.package}:{' '}
                {affected.ranges.length > 0
                  ? affected.ranges
                      .map(
                        (range) =>
                          `${range.type} ${range.introduced ?? '?'} → ${
                            range.fixed ? `fixed ${range.fixed}` : range.lastAffected ? `last affected ${range.lastAffected}` : 'no fix'
                          }`,
                      )
                      .join('; ')
                  : 'no ranges'}
                {affected.versions.length > 0 && ` (${affected.versions.length} explicit versions)`}
              </li>
            ))}
          </ul>
        </Field>
      )}

      {vulnerability.details && (
        <div>
          <button type="button" className="text-[11px] text-primary hover:underline" onClick={() => setShowDetails((v) => !v)}>
            {showDetails ? 'Hide details' : 'Show details'}
          </button>
          {showDetails && (
            <div className="mt-2 max-h-72 overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2">
              <MarkdownView content={vulnerability.details} />
            </div>
          )}
        </div>
      )}

      {references.length > 0 && (
        <Field label={`References (${references.length})`}>
          <ul className="flex flex-col gap-0.5">
            {visibleRefs.map((reference) => (
              <li key={`${reference.type}:${reference.url}`} className="flex gap-1.5 text-[11px]">
                <span className="w-16 shrink-0 font-mono text-zinc-500">{reference.type}</span>
                <a
                  href={reference.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="break-all text-sky-300 hover:underline"
                >
                  {reference.url}
                </a>
              </li>
            ))}
          </ul>
          {references.length > 5 && (
            <button type="button" className="mt-1 text-[11px] text-primary hover:underline" onClick={() => setShowAllRefs((v) => !v)}>
              {showAllRefs ? 'Show fewer' : `Show all ${references.length}`}
            </button>
          )}
        </Field>
      )}
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</span>
      <div className="min-w-0 break-words text-[11px] text-zinc-300">{children}</div>
    </div>
  )
}
