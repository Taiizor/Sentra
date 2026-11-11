import type { CodeqlPackStatus, CodeqlPackView, CodeqlPacksDownloadView, CodeqlProgressView, CodeqlRunningView } from '../../types/api'

/**
 * Console wording for CodeQL progress, query packs and stopping a scan. Kept free of React so the
 * bridge tests can check it.
 */

/** Where the prefetch action lives, as the console names it. */
export const PACKS_SETTINGS_PATH = 'Settings → CodeQL → Query packs → Download missing packs'

/**
 * What happens to the query packs when a download stops early. The core downloads each pack into a
 * staging directory and moves only a complete pack into the pack cache, so nothing partial is kept;
 * whether a later scan downloads the pack again depends on the allowPackDownload setting.
 */
export const INTERRUPTED_PACKS_TEXT = `Query packs that finished downloading stay in the pack cache. A pack that was still downloading is discarded (Sentra keeps no partial pack); download it again with ${PACKS_SETTINGS_PATH}, or let the next scan download it if pack download is allowed.`

/** Paragraphs of the confirmation shown before a running scan is stopped or its dialog closed. */
export const STOP_SCAN_PARAGRAPHS: readonly string[] = [
  'This cancels the event stream. The bridge then stops the running sentra process for this workspace.',
  `If the CodeQL stage is running, CodeQL stops as well, including a query pack download in progress. ${INTERRUPTED_PACKS_TEXT}`,
  'Stages that already finished may have been persisted; unfinished stages produce no results.',
]

/** Shown when a query pack download is stopped (Stop, or the page was left). */
export const PACKS_DOWNLOAD_STOP_TEXT = `Stopping closes the stream; the bridge then stops CodeQL. ${INTERRUPTED_PACKS_TEXT}`

/** Shown after Stop until the bridge confirms that the download has ended. */
export const PACKS_STOPPING_TEXT = 'Stopping: waiting for the bridge to stop CodeQL and release the CodeQL lock…'

/**
 * After the console closed a download stream, the bridge still holds the CodeQL lock until the core
 * has stopped CodeQL and exited. Re-reads the pack listing (fresh) until it no longer reports a
 * running pack download, at most `attempts` times `delayMs` apart, and returns the last listing read
 * (null when none could be read). Stops early when `signal` aborts.
 */
export async function waitForPackDownloadToEnd<T extends { running: Pick<CodeqlRunningView, 'operation'> | null }>(
  read: () => Promise<T>,
  options: { attempts?: number; delayMs?: number; signal?: AbortSignal; sleep?: (ms: number) => Promise<void> } = {},
): Promise<T | null> {
  const attempts = options.attempts ?? 30
  const delayMs = options.delayMs ?? 1000
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)))
  let last: T | null = null
  for (let attempt = 0; attempt < attempts && !options.signal?.aborted; attempt += 1) {
    try {
      last = await read()
      if (last.running?.operation !== 'pack_download') return last
    } catch {
      // A failed read is retried like a busy one.
    }
    if (attempt + 1 < attempts) await sleep(delayMs)
  }
  return last
}

/** Shown on the CodeQL stage while it runs. */
export const CODEQL_FIRST_RUN_HINT =
  'When host analysis is enabled with pack download allowed, the first analysis on this bridge downloads the CodeQL query packs it needs before analyzing: a pack is tens of MB, which can take several minutes on a slow connection. Progress and a heartbeat every 15 s appear below.'

/** Shown on the running CodeQL stage once the core started downloading a query pack. */
export const CODEQL_PREFETCH_HINT = `This scan is downloading query packs (first run only; completed packs stay in the pack cache). To download them ahead of scans next time, use ${PACKS_SETTINGS_PATH}.`

/** Shown on the CodeQL stage after it ended, when it had started downloading a query pack. */
export const CODEQL_PREFETCH_DONE_HINT = `This scan started downloading query packs; the packs that finished downloading stay in the pack cache (see the log for each pack). To download missing packs ahead of scans, use ${PACKS_SETTINGS_PATH}.`

/** The hint on the CodeQL stage card, or null when none applies. */
export function codeqlStageHint(state: { stageRunning: boolean; packDownloadSeen: boolean }): string | null {
  if (state.packDownloadSeen) return state.stageRunning ? CODEQL_PREFETCH_HINT : CODEQL_PREFETCH_DONE_HINT
  if (state.stageRunning) return CODEQL_FIRST_RUN_HINT
  return null
}

/** True for a progress event of a query pack download. */
export function isPackDownload(progress: Pick<CodeqlProgressView, 'step'>): boolean {
  return progress.step === 'pack_download'
}

export const PACK_STATUS_LABEL: Record<CodeqlPackStatus, string> = {
  present: 'present',
  missing: 'missing',
  downloaded: 'downloaded',
  failed: 'download failed',
  not_analysable: 'not analysed on the host',
}

/** "present (pack cache)", "missing", ... for one pack row. */
export function packStatusText(pack: Pick<CodeqlPackView, 'status' | 'source'>): string {
  const label = PACK_STATUS_LABEL[pack.status] ?? pack.status
  if ((pack.status === 'present' || pack.status === 'downloaded') && pack.source) {
    return `${label} (${pack.source === 'distribution' ? 'CodeQL distribution' : 'pack cache'})`
  }
  return label
}

/** Who or what holds the bridge-wide CodeQL lock, in words. */
export function runningText(running: CodeqlRunningView): string {
  return running.operation === 'pack_download'
    ? `A query pack download is running${running.actor ? ` (started by ${running.actor})` : ''}.`
    : `An analysis is running for workspace ${running.tenantId ?? 'unknown'}.`
}

/**
 * Why an exclude glob is refused, or null: the rules of the bridge (excludeGlobProblem in
 * server/services/codeql.ts) and the core (validate_exclude_glob), checked here before saving.
 * The length is counted in UTF-16 code units like the bridge (at least as many as the core's
 * characters), so a glob saved here is never refused when a scan passes it on.
 */
export function excludeGlobProblem(glob: string, maxChars = 200): string | null {
  if (glob.trim() === '') return 'must not be empty'
  if (glob.startsWith('-')) return "must not start with '-'"
  if (glob.length > maxChars) return `must be at most ${maxChars} characters long (characters outside the Basic Multilingual Plane, such as emoji, count twice)`
  // oxlint-disable-next-line no-control-regex -- intentional: refuses control characters in a glob
  if (/[\u0000-\u001f\u007f-\u009f]/.test(glob)) return 'must not contain control characters'
  if (glob.includes('\\')) return 'must use / as the path separator, not \\'
  if (glob.startsWith('/') || glob.includes(':')) return "must be relative to the workspace (no leading /, drive or ':')"
  if (glob.split('/').includes('..')) return "must not contain a '..' segment"
  return null
}

/** The globs of the exclude text box (one per line, blank lines ignored) and the first problem, if any. */
export function parseExcludeText(text: string, bounds: { maxEntries: number; maxChars: number }): { globs: string[]; problem: string | null } {
  const globs: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const glob = line.trim()
    if (glob === '' || globs.includes(glob)) continue
    const problem = excludeGlobProblem(glob, bounds.maxChars)
    if (problem) return { globs, problem: `"${glob.slice(0, 60)}" ${problem}` }
    globs.push(glob)
  }
  if (globs.length > bounds.maxEntries) return { globs, problem: `at most ${bounds.maxEntries} globs` }
  return { globs, problem: null }
}

/** Toast title for a finished download. */
export function downloadOutcomeTitle(result: Pick<CodeqlPacksDownloadView, 'outcome' | 'downloaded'>): string {
  switch (result.outcome) {
    case 'completed':
      return `Downloaded ${result.downloaded.length} query pack${result.downloaded.length === 1 ? '' : 's'}`
    case 'nothing_to_do':
      return 'Every requested query pack is already present'
    case 'partial':
      return 'Some query packs were downloaded, others failed'
    case 'cancelled':
      return 'Download stopped'
    default:
      return 'No query pack was downloaded'
  }
}
