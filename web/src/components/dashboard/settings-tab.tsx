import { useState } from 'react'
import { Bot, FolderGit2, GitPullRequest, Globe, Server, Settings, UserRound } from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SettingsAiProviders } from './settings-ai-providers'
import { SettingsGitHub } from './settings-github'
import { SettingsIntel } from './settings-intel'
import { SettingsSession } from './settings-session'
import { SettingsSystem } from './settings-system'
import { SettingsWorkspaces } from './settings-workspaces'

type SettingsSection = 'session' | 'workspaces' | 'ai' | 'github' | 'intel' | 'system'

const SECTIONS: { id: SettingsSection; label: string; icon: typeof Settings; description: string }[] = [
  { id: 'session', label: 'Session', icon: UserRound, description: 'Who you are signed in as and what this session may do.' },
  { id: 'workspaces', label: 'Workspaces', icon: FolderGit2, description: 'Registered workspaces and unregistering them.' },
  { id: 'ai', label: 'AI providers', icon: Bot, description: 'Model providers, write-only API keys and the default provider.' },
  { id: 'github', label: 'GitHub credential', icon: GitPullRequest, description: 'The credential the bridge uses for GitHub API calls.' },
  { id: 'intel', label: 'Threat intelligence', icon: Globe, description: 'Whether dependency scans may query OSV.dev.' },
  { id: 'system', label: 'System', icon: Server, description: 'Bridge, core binary, storage, access and tool status.' },
]

export function SettingsTab() {
  const [section, setSection] = useState<SettingsSection>('session')
  const active = SECTIONS.find((entry) => entry.id === section) ?? SECTIONS[0]

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1 pb-3 border-b border-border/40">
        <div className="flex items-center gap-2">
          <Settings className="size-5 text-primary" />
          <h2 className="text-base sm:text-lg font-bold tracking-tight text-foreground">Settings</h2>
        </div>
        <p className="text-xs text-muted-foreground">
          Bridge-wide configuration. Changes are applied by the bridge, which checks the permission named on each control for every
          request.
        </p>
      </div>

      <Tabs value={section} onValueChange={(value) => setSection(value as SettingsSection)}>
        <TabsList className="flex-wrap h-auto">
          {SECTIONS.map((entry) => {
            const Icon = entry.icon
            return (
              <TabsTrigger key={entry.id} value={entry.id} className="text-xs gap-1.5">
                <Icon className="size-3.5" />
                {entry.label}
              </TabsTrigger>
            )
          })}
        </TabsList>
        <p className="text-[11px] text-muted-foreground pt-1">{active.description}</p>
        <TabsContent value="session" className="pt-2">
          <SettingsSession />
        </TabsContent>
        <TabsContent value="workspaces" className="pt-2">
          <SettingsWorkspaces />
        </TabsContent>
        <TabsContent value="ai" className="pt-2">
          <SettingsAiProviders />
        </TabsContent>
        <TabsContent value="github" className="pt-2">
          <SettingsGitHub />
        </TabsContent>
        <TabsContent value="intel" className="pt-2">
          <SettingsIntel />
        </TabsContent>
        <TabsContent value="system" className="pt-2">
          <SettingsSystem />
        </TabsContent>
      </Tabs>
    </div>
  )
}
