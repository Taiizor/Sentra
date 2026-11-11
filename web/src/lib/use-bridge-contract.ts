import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { contractMismatch, reportedContractVersion, type ContractMismatch } from '@/lib/contract'

const HEALTH_POLL_MS = 30_000

/**
 * Watches the bridge's API contract version through the public /api/health route: on mount, every
 * 30 s while the page is visible, and when the window regains focus (a restarted bridge clears the
 * banner within that time). `systemBody`, when given, is a /api/system response already loaded by
 * the caller; it is used only until the first health answer arrives. Failed health requests change
 * nothing: an unreachable bridge is reported by the views themselves.
 */
export function useBridgeContract(systemBody?: unknown): ContractMismatch | null {
  const [healthVersion, setHealthVersion] = useState<number | null>(null)

  useEffect(() => {
    let active = true
    const check = () => {
      api.health().then(
        (health) => {
          if (active) setHealthVersion(reportedContractVersion(health))
        },
        () => undefined,
      )
    }
    check()
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') check()
    }, HEALTH_POLL_MS)
    window.addEventListener('focus', check)
    return () => {
      active = false
      window.clearInterval(timer)
      window.removeEventListener('focus', check)
    }
  }, [])

  // The latest health answer wins: it is re-read periodically, while systemBody may predate a restart.
  if (healthVersion !== null) return contractMismatch(healthVersion)
  return systemBody === undefined ? null : contractMismatch(reportedContractVersion(systemBody))
}
