import { api, ApiError, errorMessage } from '@/lib/api'
import type { SessionInfo } from '@/types/api'

export type BootstrapResult =
  | { kind: 'signed_in'; session: SessionInfo }
  | { kind: 'signed_out'; error: string | null }

/**
 * Reads a sign-in token from a `#token=<value>` URL fragment (printed by the bridge for the
 * local operator) and immediately removes the fragment from the address bar and history entry.
 * Fragments are never sent to the server, so the token only leaves the browser via the login
 * request body.
 */
export function readAndStripFragmentToken(): string | null {
  const hash = window.location.hash
  if (!hash || hash.length < 2) return null
  const params = new URLSearchParams(hash.slice(1))
  const token = params.get('token')
  if (token === null) return null
  window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}`)
  const trimmed = token.trim()
  return trimmed.length > 0 ? trimmed : null
}

let pendingBootstrap: Promise<BootstrapResult> | null = null

async function runBootstrap(): Promise<BootstrapResult> {
  const fragmentToken = readAndStripFragmentToken()
  if (fragmentToken) {
    try {
      return { kind: 'signed_in', session: await api.auth.login(fragmentToken) }
    } catch (error) {
      return { kind: 'signed_out', error: `Sign-in with the link token failed: ${errorMessage(error)}` }
    }
  }
  try {
    return { kind: 'signed_in', session: await api.auth.session() }
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return { kind: 'signed_out', error: null }
    return { kind: 'signed_out', error: errorMessage(error) }
  }
}

/**
 * Resolves the initial session exactly once per page load (StrictMode runs effects twice;
 * sharing the promise prevents a duplicate login request for a fragment token).
 */
export function bootstrapSession(): Promise<BootstrapResult> {
  pendingBootstrap ??= runBootstrap()
  return pendingBootstrap
}
