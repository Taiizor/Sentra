import { useState } from 'react'
import { CheckCircle2, CircleAlert, FileCode2, ListChecks } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { WebhookConfigView } from '@/types/api'
import { CopyButton } from './settings-kit'

/**
 * Example CI pipelines. Every `sentra` invocation uses flags the CLI accepts today; installing
 * the binary on the runner is deliberately left to the operator (no release channel is assumed).
 */
const GITHUB_ACTIONS_EXAMPLE = `# Example only: adapt before use. Installing the sentra binary on the runner is up to you.
name: sentra-scan
on:
  push:
  pull_request:
permissions:
  contents: read
  security-events: write   # required by upload-sarif
jobs:
  sentra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>   # pin actions to a commit SHA
      - name: Install sentra
        run: |
          echo "Install a pinned sentra binary and add it to PATH" >&2
          exit 1
      - name: Heuristic SAST scan (SARIF)
        run: sentra scan --workspace . --sarif sentra.sarif --json
      - name: Dependency inventory
        run: sentra inventory --workspace . --json > sentra-inventory.json
      - uses: github/codeql-action/upload-sarif@<full-commit-sha>
        with:
          sarif_file: sentra.sarif
          category: sentra`

const SHELL_EXAMPLE = `# Example only: works in any CI that can run a shell step with sentra on PATH.
sentra scan --workspace . --sarif sentra.sarif --json
sentra inventory --workspace . --json > sentra-inventory.json
# Publish sentra.sarif and sentra-inventory.json as build artifacts.`

function ConfiguredFlag({ configured, label }: { configured: boolean; label: string }) {
  return configured ? (
    <span className="inline-flex items-center gap-1 text-emerald-400">
      <CheckCircle2 className="size-3" />
      {label} is set on the bridge
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-amber-400">
      <CircleAlert className="size-3" />
      {label} is not set
    </span>
  )
}

function Code({ children }: { children: string }) {
  return <code className="font-mono text-foreground bg-muted/40 rounded px-1 py-0.5 break-all">{children}</code>
}

export function WebhookSetupSteps({ config }: { config: WebhookConfigView }) {
  return (
    <Card className="border-border/60 bg-card/40">
      <CardHeader className="py-2.5 px-4 border-b border-border/40">
        <CardTitle className="text-xs font-medium text-foreground flex items-center gap-2">
          <ListChecks className="size-3.5 text-muted-foreground" />
          Setup
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4">
        <ol className="list-decimal pl-4 space-y-3 text-xs text-muted-foreground">
          <li className="space-y-1">
            <div className="text-foreground">Configure a shared secret in the bridge environment and restart the bridge.</div>
            <div className="flex flex-col gap-1">
              <span>
                GitHub: <Code>SENTRA_GITHUB_WEBHOOK_SECRET=&lt;long random value&gt;</Code> (without it the endpoint answers 503) —{' '}
                <ConfiguredFlag configured={config.github.secretConfigured} label="SENTRA_GITHUB_WEBHOOK_SECRET" />
              </span>
              <span>
                GitLab: <Code>SENTRA_GITLAB_WEBHOOK_TOKEN=&lt;long random value&gt;</Code> —{' '}
                <ConfiguredFlag configured={config.gitlab.tokenConfigured} label="SENTRA_GITLAB_WEBHOOK_TOKEN" />
              </span>
            </div>
          </li>
          <li className="space-y-1">
            <div className="text-foreground">Make the bridge reachable from GitHub or GitLab over HTTPS.</div>
            <div>
              The bridge listens on <Code>{config.bindHost}</Code>. GitHub and GitLab must reach it through a public HTTPS reverse proxy or
              tunnel that forwards to that address. The bridge only answers requests whose <Code>Host</Code> header is allowed: either let
              the proxy forward the bridge&apos;s own host, or add the public host name to <Code>SENTRA_WEB_ALLOWED_HOSTS</Code> (otherwise
              deliveries are refused with HTTP 421).
            </div>
          </li>
          <li className="space-y-1">
            <div className="text-foreground">GitHub: Repository → Settings → Webhooks → Add webhook.</div>
            <div className="flex flex-col gap-0.5">
              <span>
                Payload URL: <Code>{`https://<public-host>${config.github.path}`}</Code>
              </span>
              <span>
                Content type: <Code>application/json</Code>
              </span>
              <span>Secret: the value of SENTRA_GITHUB_WEBHOOK_SECRET</span>
              <span>
                Events: <span className="text-foreground">Just the push event</span>
              </span>
            </div>
          </li>
          <li className="space-y-1">
            <div className="text-foreground">GitLab: Project → Settings → Webhooks → Add new webhook.</div>
            <div className="flex flex-col gap-0.5">
              <span>
                URL: <Code>{`https://<public-host>${config.gitlab.path}`}</Code>
              </span>
              <span>Secret token: the value of SENTRA_GITLAB_WEBHOOK_TOKEN</span>
              <span>
                Trigger: <span className="text-foreground">Push events</span>
              </span>
            </div>
          </li>
          <li className="space-y-1">
            <div className="text-foreground">Bind the repository to a registered workspace.</div>
            <div>
              A push is matched to workspaces whose GitHub repository (or GitLab origin) is the pushed repository; unmatched pushes are
              recorded as <span className="font-mono">ignored</span>. A matched push starts a SAST scan of that workspace&apos;s local
              checkout. The bridge never fetches or pulls, so the checkout may differ from the pushed commit; each delivery&apos;s detail
              states whether it matched.
            </div>
          </li>
          <li>
            Push a commit. The delivery appears above with the outcome the bridge recorded; deliveries that fail authentication are only
            counted, not stored.
          </li>
        </ol>
      </CardContent>
    </Card>
  )
}

type CiTab = 'github' | 'shell'

export function WebhookCiExample() {
  const [tab, setTab] = useState<CiTab>('github')
  const snippet = tab === 'github' ? GITHUB_ACTIONS_EXAMPLE : SHELL_EXAMPLE
  return (
    <Card className="border-border/60 bg-card/40">
      <CardHeader className="py-2.5 px-4 border-b border-border/40">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <CardTitle className="text-xs font-medium text-foreground flex items-center gap-2">
            <FileCode2 className="size-3.5 text-muted-foreground" />
            CI example
          </CardTitle>
          <div className="flex items-center gap-1">
            {(['github', 'shell'] as const).map((id) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                  tab === id ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {id === 'github' ? 'GitHub Actions' : 'Any CI (shell)'}
              </button>
            ))}
            <CopyButton text={snippet} />
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-4 flex flex-col gap-2">
        <p className="text-[11px] text-muted-foreground">
          This is an example you must adapt. It runs Sentra inside your CI instead of through the webhook: <Code>sentra scan --sarif</Code>{' '}
          writes heuristic SAST candidates as SARIF, and <Code>sentra inventory</Code> lists lockfile packages. Installing a pinned{' '}
          <Code>sentra</Code> binary on the runner is up to you, and the action references must be pinned to commit SHAs you have reviewed.
          SARIF results uploaded to GitHub code scanning are unverified candidates.
        </p>
        <pre className="font-mono text-[11px] leading-relaxed bg-zinc-950/70 border border-border/40 rounded-md p-3 overflow-x-auto text-zinc-300">
          {snippet}
        </pre>
      </CardContent>
    </Card>
  )
}
