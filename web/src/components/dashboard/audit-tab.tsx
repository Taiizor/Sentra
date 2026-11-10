import { History } from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { CoreStoreAudit } from './audit-tab-core'
import { OperatorAuditChain } from './audit-tab-operator'

/**
 * Two distinct records: the bridge's HMAC-chained operator log (verifiable from the console)
 * and the selected workspace's core store (read-only view; not verified by the console).
 */
export function AuditTab() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1 pb-2 border-b border-zinc-800/60">
        <h2 className="text-base font-semibold tracking-tight flex items-center gap-2">
          <History className="size-4 text-zinc-400" />
          Audit trail
        </h2>
        <p className="text-xs text-zinc-400">
          The operator audit chain records console actions; the core store holds what the Sentra core itself recorded for the
          selected workspace.
        </p>
      </div>
      <Tabs defaultValue="operator">
        <TabsList className="bg-zinc-900/60 border border-zinc-800">
          <TabsTrigger value="operator" className="text-xs px-3">
            Operator audit chain
          </TabsTrigger>
          <TabsTrigger value="core" className="text-xs px-3">
            Core store
          </TabsTrigger>
        </TabsList>
        <TabsContent value="operator">
          <OperatorAuditChain />
        </TabsContent>
        <TabsContent value="core">
          <CoreStoreAudit />
        </TabsContent>
      </Tabs>
    </div>
  )
}
