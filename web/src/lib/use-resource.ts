import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { ApiError } from '@/lib/api'
import { useConsole } from '@/lib/console-context'

export interface Resource<T> {
  data: T | undefined
  error: ApiError | Error | null
  loading: boolean
  /** True after the first request finished (successfully or not). */
  loaded: boolean
  reload: () => void
  setData: (updater: T | ((current: T | undefined) => T)) => void
}

/** State written when a request settles (or by `setData`); everything else is derived from it. */
interface Settled<T> {
  /** Resource key the data belongs to. */
  key: string
  /** Request that produced this state, or null when `setData` stored data before any request settled. */
  request: string | null
  data: T | undefined
  error: ApiError | Error | null
  loaded: boolean
}

/** One request per key, reload counter and console data version. */
function requestId(key: string, nonce: number, dataVersion: number): string {
  return `${nonce}\u0000${dataVersion}\u0000${key}`
}

/**
 * Fetches `fetcher` whenever `key` changes, when `reload()` is called, or when the console's
 * data version is bumped (after scans, triage, patches, ...). Pass `key = null` to skip.
 * Stale responses are discarded; nothing is substituted when a request fails. Data is only
 * returned for the key it was fetched for, and state is only set once a request settles.
 */
export function useResource<T>(key: string | null, fetcher: (signal: AbortSignal) => Promise<T>): Resource<T> {
  const { dataVersion } = useConsole()
  const [nonce, setNonce] = useState(0)
  const [settled, setSettled] = useState<Settled<T> | null>(null)
  const fetcherRef = useRef(fetcher)
  const keyRef = useRef(key)
  // Layout effects run before the fetch effect below in the same commit, so it always calls the
  // fetcher from the latest render without listing it as a dependency.
  useLayoutEffect(() => {
    fetcherRef.current = fetcher
    keyRef.current = key
  })
  const request = key === null ? null : requestId(key, nonce, dataVersion)

  useEffect(() => {
    if (key === null || request === null) return
    const controller = new AbortController()
    fetcherRef.current(controller.signal).then(
      (value) => {
        if (controller.signal.aborted) return
        setSettled({ key, request, data: value, error: null, loaded: true })
      },
      (failure: unknown) => {
        if (controller.signal.aborted) return
        // An abort this hook did not request is neither an error nor a finished load.
        const aborted = failure instanceof DOMException && failure.name === 'AbortError'
        setSettled((current) => {
          const same = current !== null && current.key === key ? current : null
          return {
            key,
            request,
            data: same?.data,
            error: aborted ? null : failure instanceof Error ? failure : new Error(String(failure)),
            loaded: aborted ? (same?.loaded ?? false) : true,
          }
        })
      },
    )
    return () => controller.abort()
  }, [key, request])

  const reload = useCallback(() => setNonce((value) => value + 1), [])
  const setData = useCallback((updater: T | ((current: T | undefined) => T)) => {
    const target = keyRef.current
    if (target === null) return
    setSettled((current) => {
      const same = current !== null && current.key === target ? current : null
      const data = typeof updater === 'function' ? (updater as (c: T | undefined) => T)(same?.data) : updater
      return same ? { ...same, data } : { key: target, request: null, data, error: null, loaded: false }
    })
  }, [])

  const current = key !== null && settled !== null && settled.key === key ? settled : null
  return {
    data: current?.data,
    error: current !== null && current.request === request ? current.error : null,
    loading: request !== null && (current === null || current.request !== request),
    loaded: current?.loaded ?? false,
    reload,
    setData,
  }
}
