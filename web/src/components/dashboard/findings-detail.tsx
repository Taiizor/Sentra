import { useState, type ReactNode } from 'react'
import { ArrowRight, ExternalLink, FileLock2, KeyRound, Package, Search, Sparkles } from 'lucide-react'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { FINDING_ORIGIN_LABEL, findingSourceLabel, isSecretFinding } from '@/components/dashboard/findings-format'
import {
  CopyButton,
  DetailSection,
  GatedButton,
  RedactedText,
  SeverityBadge,
  Timestamp,
  TriageBadge,
} from '@/components/dashboard/findings-shared'
import { FindingTriageForm } from '@/components/dashboard/findings-triage-form'
import { PATCH_STATE_LABEL } from '@/components/dashboard/patch-format'
import { requestRemediationFocus } from '@/components/dashboard/remediation-focus'
import { SourceViewer } from '@/components/dashboard/source-viewer'
import type { CodeqlFindingDetails, DependencyFindingDetails, FindingView, TaintStepView } from '@/types/api'

const SEVERITY_SOURCE_LABEL: Record<DependencyFindingDetails['severitySource'], string> = {
  database_specific: 'Advisory database severity (database_specific)',
  cvss_v3: 'CVSS v3 vector',
  cvss_v2: 'CVSS v2 vector',
  none: 'The advisory carries no severity',
}

const ROLE_CLASS: Record<TaintStepView['role'], string> = {
  SOURCE: 'border-amber-500/40 text-amber-300',
  PROPAGATION: 'border-sky-500/40 text-sky-300',
  SANITIZER: 'border-emerald-500/40 text-emerald-300',
  SINK: 'border-rose-500/40 text-rose-300',
}

function cweUrl(cwe: string): string | null {
  const match = /^CWE-(\d+)$/i.exec(cwe.trim())
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : null
}

function ExternalAnchor({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-sky-300 hover:underline">
      {children}
      <ExternalLink className="size-3 shrink-0" />
    </a>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-zinc-500">{label}</dt>
      <dd className="min-w-0 break-words text-zinc-300">{children}</dd>
    </>
  )
}

function TaintTrace({ steps }: { steps: TaintStepView[] }) {
  return (
    <ol className="flex flex-col gap-1">
      {steps.map((step) => (
        <li key={step.step} className="flex items-start gap-2 rounded-md border border-zinc-800 bg-zinc-900/40 px-2 py-1.5 text-xs">
          <span className="w-5 shrink-0 text-right font-mono text-[10px] text-zinc-500">{step.step}</span>
          <Badge variant="outline" className={`shrink-0 text-[9px] ${ROLE_CLASS[step.role]}`}>
            {step.role}
          </Badge>
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="font-mono text-[11px] text-zinc-400">
              {step.line !== null ? `line ${step.line}` : 'line not reported'}
              {step.variable ? ` · ${step.variable}` : ''}
            </span>
            {step.code && (
              <code className="break-all font-mono text-[11px] text-zinc-300">
                <RedactedText text={step.code} />
              </code>
            )}
          </div>
        </li>
      ))}
    </ol>
  )
}

function DependencyDetails({ dependency }: { dependency: DependencyFindingDetails }) {
  return (
    <div className="flex flex-col gap-3">
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        <Field label="Advisory">
          <ExternalAnchor href={`https://osv.dev/vulnerability/${encodeURIComponent(dependency.advisoryId)}`}>
            <span className="font-mono">{dependency.advisoryId}</span>
          </ExternalAnchor>
        </Field>
        {dependency.aliases.length > 0 && (
          <Field label="Aliases">
            <span className="font-mono">{dependency.aliases.join(', ')}</span>
          </Field>
        )}
        <Field label="Package">
          <span className="font-mono">
            {dependency.packageName}@{dependency.packageVersion}
          </span>{' '}
          <span className="text-zinc-500">({dependency.ecosystem})</span>
        </Field>
        <Field label="Lockfile">
          <span className="font-mono">{dependency.lockfile}</span>
        </Field>
        <Field label="Fixed in">
          {dependency.fixedVersions.length > 0 ? (
            <span className="font-mono text-emerald-300">{dependency.fixedVersions.join(', ')}</span>
          ) : (
            <span className="text-amber-300">
              {dependency.fixedVersionsNote
                ? 'No fixed version listed'
                : dependency.packageVersion
                  ? `No fixed version is published for ${dependency.packageVersion}`
                  : 'The advisory lists no fixed version'}
            </span>
          )}
          {dependency.fixedVersionsNote && (
            <span className="mt-0.5 block text-[11px] text-amber-300/90">{dependency.fixedVersionsNote}</span>
          )}
        </Field>
        <Field label="Severity source">{SEVERITY_SOURCE_LABEL[dependency.severitySource]}</Field>
        {(dependency.cvssScore !== null || dependency.cvssVector) && (
          <Field label="CVSS">
            {dependency.cvssScore !== null && <span className="mr-2 font-semibold">{dependency.cvssScore.toFixed(1)}</span>}
            {dependency.cvssVector && <span className="break-all font-mono text-[11px] text-zinc-400">{dependency.cvssVector}</span>}
          </Field>
        )}
        <Field label="Published">
          <Timestamp value={dependency.published} />
        </Field>
        <Field label="Modified">
          <Timestamp value={dependency.modified} />
        </Field>
      </dl>
      {dependency.summary && <p className="text-xs font-medium text-zinc-200">{dependency.summary}</p>}
      {dependency.details && (
        <p className="max-h-48 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-900/40 p-2 text-[11px] leading-relaxed text-zinc-400">
          {dependency.details}
        </p>
      )}
      {dependency.references.length > 0 && (
        <ul className="flex flex-col gap-1 text-[11px]">
          {dependency.references.map((reference) => (
            <li key={`${reference.type}:${reference.url}`} className="flex min-w-0 items-center gap-2">
              <span className="w-20 shrink-0 font-mono text-[10px] uppercase text-zinc-500">{reference.type}</span>
              <span className="min-w-0 truncate">
                <ExternalAnchor href={reference.url}>{reference.url}</ExternalAnchor>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** What the operator can do next, based only on the finding's real fields. */
function RemediationGuidance({ finding, onGeneratePatch }: { finding: FindingView; onGeneratePatch: () => void }) {
  const { tenant, navigate } = useConsole()
  const tenantId = tenant?.tenantId ?? null
  const isSast = finding.source === 'sast'
  const patches = useResource(isSast && tenantId ? `patches:${tenantId}` : null, (signal) =>
    api.patches.list(tenantId as string, signal),
  )
  const related = (patches.data?.patches ?? [])
    .filter((patch) => patch.findingId === finding.findingId)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))

  if (finding.source === 'dependency') {
    const dependency = finding.dependency
    return (
      <div className="flex items-start gap-2 rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-xs text-zinc-300">
        <Package className="mt-0.5 size-3.5 shrink-0 text-zinc-400" />
        {dependency ? (
          dependency.fixedVersions.length > 0 ? (
            <span>
              Upgrade <code className="text-zinc-100">{dependency.packageName}</code> from{' '}
              <code>{dependency.packageVersion}</code> to a fixed version (
              <code className="text-emerald-300">{dependency.fixedVersions.join(', ')}</code>) with the package manager
              that owns <code>{dependency.lockfile}</code>, then re-run the dependency scan. Model patches are not
              offered for dependency findings.
              {dependency.fixedVersionsNote && (
                <span className="mt-1 block text-amber-300/90">
                  {dependency.fixedVersionsNote} Check the advisory for the fix that applies to your release line.
                </span>
              )}
            </span>
          ) : (
            <span>
              {dependency.fixedVersionsNote ? (
                <>
                  No fixed version is listed for <code className="text-zinc-100">{dependency.packageName}</code>{' '}
                  <code>{dependency.packageVersion}</code>. {dependency.fixedVersionsNote}{' '}
                </>
              ) : (
                <>
                  The advisory publishes no fixed version for <code className="text-zinc-100">{dependency.packageName}</code>{' '}
                  <code>{dependency.packageVersion}</code>.{' '}
                </>
              )}
              Review the advisory references for mitigations, or replace or remove the dependency.
            </span>
          )
        ) : (
          <span>The dependency details for this finding are unavailable.</span>
        )}
      </div>
    )
  }

  if (finding.source === 'codeql') {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-xs text-zinc-300">
        <Search className="mt-0.5 size-3.5 shrink-0 text-zinc-400" />
        <span>
          Review the query help{finding.codeql?.helpUri ? ' linked above' : ''} and fix the code. Model patch candidates are offered only for
          SAST findings. {finding.origin === 'host_analysis'
            ? 'The next scan with CodeQL host analysis resolves the finding when the same rule ran and no longer reports it (a rule left out by another query suite does not resolve it).'
            : finding.origin === 'sarif_import'
              ? 'A later import resolves it when that SARIF ran the same rule and no longer reports the result (CodeQL lists every query it ran, also those without results); a SARIF that did not run this rule leaves it open.'
              : 'Sync GitHub code scanning again after the alert is closed on GitHub to resolve it here.'}
        </span>
      </div>
    )
  }

  if (isSecretFinding(finding)) {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-zinc-300">
        <KeyRound className="mt-0.5 size-3.5 shrink-0 text-amber-400" />
        <span>
          Rotate or revoke the exposed credential at its issuer, then remove it from the source and from version
          control history. Editing the code cannot invalidate a leaked secret, so patch generation is not offered.
        </span>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-2">
      {finding.state === 'resolved' ? (
        <p className="text-xs text-zinc-500">
          This finding is resolved: the latest scan no longer reports it. Patch generation is offered only for open
          findings.
        </p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <GatedButton permission="ai:generate" size="sm" onClick={onGeneratePatch}>
            <Sparkles /> Generate patch candidate
          </GatedButton>
          <span className="text-[11px] text-zinc-500">Sends a source excerpt to a configured model provider.</span>
        </div>
      )}
      {related.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
          <span>
            {related.length} existing patch candidate{related.length === 1 ? '' : 's'} (latest:{' '}
            {PATCH_STATE_LABEL[related[0].state].toLowerCase()})
          </span>
          <Button
            variant="ghost"
            size="xs"
            onClick={() => {
              requestRemediationFocus(related[0].bundleId)
              navigate('remediation')
            }}
          >
            Open in Remediation <ArrowRight />
          </Button>
        </div>
      )}
    </div>
  )
}

function CodeqlDetails({ details }: { details: CodeqlFindingDetails }) {
  const range =
    details.startLine !== null
      ? `line ${details.startLine}${details.endLine !== null && details.endLine !== details.startLine ? `-${details.endLine}` : ''}${details.startColumn !== null ? `, column ${details.startColumn}${details.endColumn !== null ? `-${details.endColumn}` : ''}` : ''}`
      : null
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
      <Field label="Origin">
        {FINDING_ORIGIN_LABEL[details.origin] ?? details.origin}
        {details.origin === 'host_analysis' && <span className="text-zinc-500"> (Sentra ran CodeQL on the bridge host, build mode none)</span>}
      </Field>
      {details.language && <Field label="Language">{details.language}</Field>}
      {details.securitySeverity !== null && <Field label="security-severity">{details.securitySeverity.toFixed(1)} (query metadata)</Field>}
      {details.problemSeverity && <Field label="Problem severity">{details.problemSeverity}</Field>}
      {details.precision && <Field label="Precision">{details.precision}</Field>}
      {range && <Field label="Range">{range}</Field>}
      {details.toolName && (
        <Field label="Tool">
          {details.toolName}
          {details.toolVersion ? ` ${details.toolVersion}` : ''}
        </Field>
      )}
      {details.repository && <Field label="Repository">{details.repository}</Field>}
      {details.alertUrl && (
        <Field label="GitHub alert">
          <ExternalAnchor href={details.alertUrl}>#{details.alertNumber ?? ''}</ExternalAnchor>
        </Field>
      )}
      {details.helpUri && (
        <Field label="Query help">
          <ExternalAnchor href={details.helpUri}>{details.helpUri}</ExternalAnchor>
        </Field>
      )}
      {details.tags.length > 0 && (
        <Field label="Tags">
          <span className="font-mono text-[11px]">{details.tags.join(', ')}</span>
        </Field>
      )}
      <Field label="Severity mapping">
        <span className="text-zinc-500">
          {details.origin === 'github_code_scanning'
            ? 'From the alert rule: security severity level when set, else error=Medium, warning=Low, note=Informational.'
            : 'security-severity >= 9.0 Critical, >= 7.0 High, >= 4.0 Medium, > 0 Low; without it problem.severity error=Medium, warning=Low, recommendation/note=Informational.'}
        </span>
      </Field>
    </dl>
  )
}

function SourceContext({ finding, tenantId }: { finding: FindingView; tenantId: string }) {
  const secret = isSecretFinding(finding)
  const [revealed, setRevealed] = useState(!secret)
  if (!finding.filePath) return null
  if (!revealed) {
    return (
      <div className="flex flex-col gap-2 rounded-lg border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-xs text-zinc-400">
        <span className="flex items-start gap-2">
          <FileLock2 className="mt-0.5 size-3.5 shrink-0 text-amber-400" />
          This finding reports a credential. The file may contain it in clear text; values are shown masked only
          where the bridge redacted them.
        </span>
        <Button variant="outline" size="xs" className="w-fit" onClick={() => setRevealed(true)}>
          Load source file
        </Button>
      </div>
    )
  }
  return <SourceViewer tenantId={tenantId} path={finding.filePath} line={finding.line} taintTrace={finding.taintTrace} />
}

export function FindingDetail({ finding, onGeneratePatch }: { finding: FindingView; onGeneratePatch: () => void }) {
  const { tenant } = useConsole()
  const cweLink = finding.cwe ? cweUrl(finding.cwe) : null
  const location =
    finding.filePath !== null ? `${finding.filePath}${finding.line !== null ? `:${finding.line}` : ''}` : null

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
            {findingSourceLabel(finding)}
          </Badge>
          <Badge
            variant="outline"
            className={
              finding.state === 'open'
                ? 'border-zinc-600 text-[10px] text-zinc-200'
                : 'border-emerald-500/30 text-[10px] text-emerald-300'
            }
          >
            {finding.state === 'open' ? 'Open' : 'Resolved'}
          </Badge>
          <TriageBadge triage={finding.triage} />
        </div>
        <div className="flex flex-col">
          <span className="font-mono text-xs text-zinc-400">{finding.ruleId}</span>
          <span className="text-sm font-semibold text-zinc-100">{finding.ruleName}</span>
        </div>
        <p className="text-[11px] text-zinc-500">
          Scanner output is an unverified candidate. A triage verdict records an operator decision; it is not a
          verification.
        </p>
      </div>

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        {finding.cwe && (
          <Field label="CWE">{cweLink ? <ExternalAnchor href={cweLink}>{finding.cwe}</ExternalAnchor> : finding.cwe}</Field>
        )}
        {finding.category && (
          <Field label="Category">
            <span className="font-mono">{finding.category}</span>
          </Field>
        )}
        {location && (
          <Field label="Location">
            <span className="inline-flex flex-wrap items-center gap-1">
              <span className="break-all font-mono">{location}</span>
              <CopyButton text={location} label="Copy" />
            </span>
          </Field>
        )}
        <Field label="First seen">
          <Timestamp value={finding.firstSeenAt} />{' '}
          <span className="font-mono text-[10px] text-zinc-500">run {finding.firstSeenRun}</span>
        </Field>
        <Field label="Last seen">
          <Timestamp value={finding.lastSeenAt} />{' '}
          <span className="font-mono text-[10px] text-zinc-500">run {finding.lastSeenRun}</span>
        </Field>
        {finding.resolvedAt && (
          <Field label="Resolved">
            <Timestamp value={finding.resolvedAt} />
          </Field>
        )}
        <Field label="Finding ID">
          <span className="break-all font-mono text-[11px] text-zinc-500">{finding.findingId}</span>
        </Field>
      </dl>

      {finding.snippet && (
        <DetailSection title="Matched code">
          <pre className="overflow-x-auto whitespace-pre rounded-lg border border-zinc-800 bg-zinc-950 p-2.5 font-mono text-[11px] leading-5 text-zinc-300">
            <RedactedText text={finding.snippet} />
          </pre>
          {isSecretFinding(finding) && (
            <p className="text-[10px] text-zinc-500">The core scanner redacts matched secret values in snippets.</p>
          )}
        </DetailSection>
      )}

      {finding.rationale && (
        <DetailSection title="Rule rationale">
          <p className="text-xs leading-relaxed text-zinc-300">{finding.rationale}</p>
        </DetailSection>
      )}

      {finding.taintTrace && finding.taintTrace.length > 0 && (
        <DetailSection title="Reported taint trace">
          <p className="text-[10px] text-zinc-500">As reported by the scanner; not independently verified.</p>
          <TaintTrace steps={finding.taintTrace} />
        </DetailSection>
      )}

      {finding.dependency && (
        <DetailSection title="Advisory">
          <DependencyDetails dependency={finding.dependency} />
        </DetailSection>
      )}

      {finding.codeql && (
        <DetailSection title="CodeQL result">
          <CodeqlDetails details={finding.codeql} />
        </DetailSection>
      )}

      {tenant && finding.filePath && finding.source !== 'dependency' && (
        <DetailSection title="Source context">
          <SourceContext key={finding.findingId} finding={finding} tenantId={tenant.tenantId} />
        </DetailSection>
      )}

      <DetailSection title="Remediation">
        <RemediationGuidance finding={finding} onGeneratePatch={onGeneratePatch} />
      </DetailSection>

      <DetailSection title="Triage">
        <FindingTriageForm key={`${finding.findingId}:${finding.triage?.at ?? 'none'}`} finding={finding} />
      </DetailSection>
    </div>
  )
}
