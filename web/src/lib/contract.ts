import { API_CONTRACT_VERSION } from '../types/api'

/**
 * Comparison of the bridge's API contract version with the one this console was built against.
 * Kept free of React and path aliases so the bridge's unit tests can import it.
 */

export interface ContractMismatch {
  /** Version the bridge reported; 1 when it reported none (bridges older than version 2). */
  bridgeVersion: number
  expectedVersion: number
  /** Whether the bridge runs older or newer code than the console. */
  bridgeIs: 'older' | 'newer'
  message: string
}

/** Contract version from a /api/health or /api/system body; 1 when absent (pre-versioning bridges). */
export function reportedContractVersion(body: unknown): number {
  const value = body && typeof body === 'object' ? (body as { apiContractVersion?: unknown }).apiContractVersion : undefined
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : 1
}

/** Null when the versions match; otherwise what to tell the operator. */
export function contractMismatch(bridgeVersion: number, expectedVersion: number = API_CONTRACT_VERSION): ContractMismatch | null {
  if (bridgeVersion === expectedVersion) return null
  const bridgeIs = bridgeVersion < expectedVersion ? 'older' : 'newer'
  // Older bridge: it was not restarted after an update (or after `bun run build` in production).
  // Newer bridge: in production (`bun run start`) the console is the prebuilt web/dist, which a reload
  // serves again unchanged until it is rebuilt; in development the bridge was started from another
  // checkout, or the page predates a Vite reload.
  const restart =
    bridgeIs === 'older'
      ? 'Restart the bridge (stop it and rerun `bun run dev`, or `bun run start` in production).'
      : 'Reload this page. If this message stays: in production (`bun run start`), the console is the prebuilt web/dist, so rebuild it with `bun run build` and reload; in development, the bridge was started from another checkout, so restart it from this one (stop it and rerun `bun run dev`).'
  return {
    bridgeVersion,
    expectedVersion,
    bridgeIs,
    message: `The bridge is running ${bridgeIs} code than this console (contract v${bridgeVersion}, console expects v${expectedVersion}). ${restart} Until then some views may show placeholders.`,
  }
}
