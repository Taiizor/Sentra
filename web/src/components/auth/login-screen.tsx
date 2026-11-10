import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { CircleAlert, CircleCheck, KeyRound, LoaderCircle, LogIn, Server } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SentraLogo } from '@/components/ui/sentra-logo'
import { api, errorMessage } from '@/lib/api'
import type { HealthResponse, SessionInfo } from '@/types/api'
import { readAndStripFragmentToken } from './session-bootstrap'

type HealthState = { kind: 'loading' } | { kind: 'ok'; health: HealthResponse } | { kind: 'error'; message: string }

interface LoginScreenProps {
  /** Message from the initial session probe or a failed link sign-in. */
  initialError: string | null
  onSignedIn: (session: SessionInfo) => void
}

export function LoginScreen({ initialError, onSignedIn }: LoginScreenProps) {
  const [token, setToken] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(initialError)
  const [health, setHealth] = useState<HealthState>({ kind: 'loading' })

  const loadHealth = useCallback(() => {
    api.health().then(
      (result) => setHealth({ kind: 'ok', health: result }),
      (failure: unknown) => setHealth({ kind: 'error', message: errorMessage(failure) }),
    )
  }, [])

  useEffect(() => {
    loadHealth()
  }, [loadHealth])

  const retryHealth = useCallback(() => {
    setHealth({ kind: 'loading' })
    loadHealth()
  }, [loadHealth])

  const signIn = useCallback(
    async (value: string) => {
      setSubmitting(true)
      setError(null)
      try {
        const session = await api.auth.login(value)
        setToken('')
        onSignedIn(session)
      } catch (failure) {
        setError(errorMessage(failure))
      } finally {
        setSubmitting(false)
      }
    },
    [onSignedIn],
  )

  // A sign-in link pasted into the address bar while this screen is open.
  useEffect(() => {
    const onHashChange = () => {
      const fragmentToken = readAndStripFragmentToken()
      if (fragmentToken) void signIn(fragmentToken)
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [signIn])

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const value = token.trim()
    if (value.length < 8) {
      setError('Enter the full access token (at least 8 characters).')
      return
    }
    void signIn(value)
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md flex flex-col gap-5">
        <SentraLogo size={40} />

        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5 flex flex-col gap-4">
          <div className="flex flex-col gap-1">
            <h1 className="text-sm font-semibold flex items-center gap-2">
              <KeyRound className="size-4 text-primary" />
              Sign in to the console
            </h1>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Your role (Viewer, Operator or SecurityAdmin) is assigned by the bridge from the access token you use. It cannot be
              changed from this page.
            </p>
          </div>

          {error && (
            <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
              <CircleAlert />
              <AlertTitle className="text-xs">Sign-in failed</AlertTitle>
              <AlertDescription className="text-xs break-words">{error}</AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <label className="flex flex-col gap-1.5 text-xs font-medium text-zinc-300">
              Access token
              <Input
                type="password"
                autoComplete="current-password"
                spellCheck={false}
                value={token}
                onChange={(event) => setToken(event.target.value)}
                placeholder="Paste your access token"
                className="h-9 font-mono text-xs bg-zinc-950/70 border-zinc-800"
                disabled={submitting}
                autoFocus
              />
            </label>
            <Button type="submit" disabled={submitting || token.trim().length === 0} className="h-9 text-xs font-semibold">
              {submitting ? <LoaderCircle className="size-3.5 animate-spin" /> : <LogIn className="size-3.5" />}
              {submitting ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>

          <div className="text-[11px] text-zinc-500 leading-relaxed border-t border-zinc-800 pt-3">
            Tokens are configured on the bridge host with <code className="font-mono text-zinc-400">SENTRA_WEB_TOKENS</code>{' '}
            (<code className="font-mono text-zinc-400">role:label:token</code>). When none are configured, the bridge prints a
            loopback-only admin sign-in link (token in the URL fragment) to its terminal and stores the token in{' '}
            <code className="font-mono text-zinc-400">web-admin.token</code> in its data directory.
          </div>
        </div>

        <BridgeHealth state={health} onRetry={retryHealth} />
      </div>
    </div>
  )
}

function BridgeHealth({ state, onRetry }: { state: HealthState; onRetry: () => void }) {
  if (state.kind === 'loading') {
    return (
      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <LoaderCircle className="size-3.5 animate-spin" />
        Checking the console bridge…
      </div>
    )
  }
  if (state.kind === 'error') {
    return (
      <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
        <Server />
        <AlertTitle className="text-xs">Bridge unreachable</AlertTitle>
        <AlertDescription className="text-xs flex flex-col gap-2 items-start">
          <span className="break-words">{state.message}</span>
          <Button size="xs" variant="outline" onClick={onRetry}>
            Retry
          </Button>
        </AlertDescription>
      </Alert>
    )
  }
  if (!state.health.coreAvailable) {
    return (
      <Alert className="border-amber-500/40 bg-amber-500/5 text-amber-200">
        <CircleAlert />
        <AlertTitle className="text-xs">Core binary not found</AlertTitle>
        <AlertDescription className="text-xs text-amber-200/80">
          The bridge is running but cannot find the <code className="font-mono">sentra</code> binary, so scans and core-store reads
          will fail. The bridge administrator can build it with{' '}
          <code className="font-mono">cargo build --release -p sentra-cli</code> or set <code className="font-mono">SENTRA_BIN</code>.
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <div className="flex items-center gap-2 text-xs text-zinc-500">
      <CircleCheck className="size-3.5 text-emerald-500" />
      Bridge reachable · core binary present
    </div>
  )
}
