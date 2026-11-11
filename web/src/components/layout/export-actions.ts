import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { collectExecutiveReportData, renderExecutiveReportHtml, splitOpenFindings } from '@/lib/executive-report'
import type { SessionInfo, TenantView } from '@/types/api'

/** Saves text as a file through a temporary object URL. */
export function downloadTextFile(fileName: string, mimeType: string, content: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  anchor.rel = 'noopener'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function countSarifResults(document: Record<string, unknown>): number | null {
  const runs = document.runs
  if (!Array.isArray(runs)) return null
  let total = 0
  for (const run of runs) {
    const results = (run as { results?: unknown } | null)?.results
    if (Array.isArray(results)) total += results.length
  }
  return total
}

/** Downloads the server-generated SARIF 2.1.0 document for the tenant's open findings. */
export async function exportSarif(tenant: TenantView): Promise<void> {
  const toastId = toast.loading(`Requesting SARIF for ${tenant.name}…`)
  try {
    const document = await api.findings.sarif(tenant.tenantId)
    downloadTextFile(`sentra-${tenant.tenantId}.sarif`, 'application/sarif+json', `${JSON.stringify(document, null, 2)}\n`)
    const results = countSarifResults(document)
    toast.success('SARIF downloaded', {
      id: toastId,
      description: `${results === null ? 'Unknown number of' : results} result(s) from open findings. Results are unverified candidates.`,
    })
  } catch (error) {
    toast.error('SARIF export failed', { id: toastId, description: errorMessage(error) })
  }
}

/** Collects real data from the bridge and downloads a self-contained HTML report. */
export async function exportExecutiveReport(tenant: TenantView, session: SessionInfo): Promise<void> {
  const toastId = toast.loading(`Collecting report data for ${tenant.name}…`)
  try {
    const data = await collectExecutiveReportData(tenant, session)
    const html = renderExecutiveReportHtml(data)
    const { counted, rejected } = splitOpenFindings(data.openFindings)
    const stamp = data.generatedAt.slice(0, 10)
    downloadTextFile(`sentra-${tenant.tenantId}-report-${stamp}.html`, 'text/html;charset=utf-8', html)
    toast.success('Report downloaded', {
      id: toastId,
      description: `${counted.length} open candidate finding(s)${rejected.length > 0 ? ` (+${rejected.length} triaged as rejected)` : ''}, ${data.patches.length} patch candidate(s).`,
    })
  } catch (error) {
    toast.error('Report generation failed', { id: toastId, description: errorMessage(error) })
  }
}
