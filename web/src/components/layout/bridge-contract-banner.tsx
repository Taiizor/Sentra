import { AlertTriangle } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import type { ContractMismatch } from '@/lib/contract'

/** App-level notice that the bridge and this console were built from different API contracts. */
export function BridgeContractBanner({ mismatch }: { mismatch: ContractMismatch }) {
  // `code` spans in the message are rendered in a monospace font.
  const parts = mismatch.message.split('`')
  return (
    <Alert className="border-amber-500/40 bg-amber-500/5 text-amber-100" role="alert">
      <AlertTriangle className="text-amber-400" />
      <AlertTitle className="text-xs font-semibold">
        {mismatch.bridgeIs === 'older'
          ? 'Restart the bridge: it runs older code than this console'
          : 'Reload or rebuild the console: the bridge runs newer code'}
      </AlertTitle>
      <AlertDescription className="text-xs text-amber-200/90">
        <span>
          {parts.map((part, index) =>
            index % 2 === 1 ? (
              <span key={index} className="font-mono">
                {part}
              </span>
            ) : (
              <span key={index}>{part}</span>
            ),
          )}
        </span>
      </AlertDescription>
    </Alert>
  )
}
