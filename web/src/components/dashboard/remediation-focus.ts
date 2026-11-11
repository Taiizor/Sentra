/**
 * One-shot hand-off of the patch bundle the Remediation tab should select when it next mounts
 * (e.g. after "Open in Remediation" in the patch dialog). The URL has no patch parameter, so
 * this stays in memory. Reading does not consume it (StrictMode may initialise state twice);
 * the tab clears it from an effect after mounting.
 */
let pendingBundleId: string | null = null

export function requestRemediationFocus(bundleId: string): void {
  pendingBundleId = bundleId
}

export function peekRemediationFocus(): string | null {
  return pendingBundleId
}

export function clearRemediationFocus(): void {
  pendingBundleId = null
}
