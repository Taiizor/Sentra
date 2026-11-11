import { useState } from 'react'
import { Bot, ClipboardList, Database, Map as MapIcon, Microscope } from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useConsole } from '@/lib/console-context'
import { NoTenantState, TabHeader } from './console-kit'
import { CoverageLedger } from './research-coverage'
import { ModelRecon } from './research-model-recon'
import { ResearchSessions } from './research-sessions'
import { TopologyPanel } from './research-topology'

type ResearchSection = 'sessions' | 'coverage' | 'topology' | 'model'

/**
 * Research workspace: the core session, an operator-maintained coverage ledger, a topology
 * report computed from the workspace files and stored model reconnaissance (unverified).
 */
export function ResearchTab() {
  const { tenant } = useConsole()
  const [section, setSection] = useState<ResearchSection>('sessions')

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<Microscope className="size-4 text-sky-400" />}
        title="Research"
        description="Core session state, review coverage recorded by operators, workspace topology and model-assisted reconnaissance. Coverage entries and model output are claims for a human to check; neither creates or verifies findings."
      />

      {!tenant ? (
        <NoTenantState feature="Research" />
      ) : (
        <Tabs value={section} onValueChange={(value) => setSection(value as ResearchSection)} className="gap-4">
          <TabsList className="h-auto flex-wrap">
            <TabsTrigger value="sessions" className="text-xs">
              <Database />
              Core session
            </TabsTrigger>
            <TabsTrigger value="coverage" className="text-xs">
              <ClipboardList />
              Coverage ledger
            </TabsTrigger>
            <TabsTrigger value="topology" className="text-xs">
              <MapIcon />
              Topology
            </TabsTrigger>
            <TabsTrigger value="model" className="text-xs">
              <Bot />
              Model reconnaissance
            </TabsTrigger>
          </TabsList>
          <TabsContent value="sessions">
            <ResearchSessions key={tenant.tenantId} tenant={tenant} />
          </TabsContent>
          <TabsContent value="coverage">
            <CoverageLedger key={tenant.tenantId} tenant={tenant} />
          </TabsContent>
          <TabsContent value="topology">
            <TopologyPanel key={tenant.tenantId} tenant={tenant} />
          </TabsContent>
          <TabsContent value="model">
            <ModelRecon key={tenant.tenantId} tenant={tenant} />
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
