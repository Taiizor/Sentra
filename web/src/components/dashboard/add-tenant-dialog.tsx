import { useState, type FormEvent } from 'react'
import { CircleAlert, FolderGit2, LoaderCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { permissionHint } from '@/components/layout/permission-hint'
import { ApiError, api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { isTabId } from '@/lib/router'
import type { CreateTenantRequest, IsolationLevel } from '@/types/api'

interface AddTenantDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** Same grammar the bridge enforces (lowercase, starts with a letter or digit). */
const TENANT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/
const REPOSITORY_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/
const ABSOLUTE_PATH_RE = /^(?:[A-Za-z]:[\\/]|\\\\|\/)/

const ISOLATION_LABELS: Record<IsolationLevel, string> = {
  single_operator: 'Single operator',
  multi_tenant_isolated: 'Multi-tenant (declared)',
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
}

export function AddTenantDialog({ open, onOpenChange }: AddTenantDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg border-zinc-800 bg-zinc-950 text-zinc-100">
        {/* Mounted only while open, so every opening starts from an empty form. */}
        {open && <AddTenantForm onClose={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  )
}

function AddTenantForm({ onClose }: { onClose: () => void }) {
  const { can, refreshTenants, setTenantId, invalidate } = useConsole()
  const allowed = can('tenant:create')
  const [name, setName] = useState('')
  const [tenantId, setTenantIdInput] = useState('')
  const [autoSlug, setAutoSlug] = useState(true)
  const [description, setDescription] = useState('')
  const [workspace, setWorkspace] = useState('')
  const [isolationLevel, setIsolationLevel] = useState<IsolationLevel>('single_operator')
  const [repository, setRepository] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [error, setError] = useState<{ message: string; code: string | null } | null>(null)

  function validate(): string | null {
    if (!name.trim()) return 'Enter a display name.'
    if (!TENANT_ID_RE.test(tenantId)) {
      return 'Tenant id must be 1-64 characters of a-z, 0-9, "-" or "_", starting with a letter or digit.'
    }
    if (isTabId(tenantId)) return `"${tenantId}" is reserved for a console view; choose another tenant id.`
    if (!workspace.trim()) return 'Enter the workspace directory.'
    if (!ABSOLUTE_PATH_RE.test(workspace.trim())) return 'The workspace must be an absolute path on the bridge host.'
    if (repository.trim() && !REPOSITORY_RE.test(repository.trim())) return 'GitHub repository must look like owner/name.'
    return null
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!allowed || submitting) return
    const problem = validate()
    if (problem) {
      setError({ message: problem, code: null })
      return
    }
    setError(null)
    setConfirming(true)
  }

  async function register() {
    if (!allowed || submitting) return
    setSubmitting(true)
    setError(null)
    const body: CreateTenantRequest = {
      tenantId,
      name: name.trim(),
      workspace: workspace.trim(),
      isolationLevel,
      ...(description.trim() ? { description: description.trim() } : {}),
      ...(repository.trim() ? { githubRepository: repository.trim() } : {}),
    }
    try {
      const created = await api.tenants.create(body)
      await refreshTenants()
      setTenantId(created.tenantId)
      invalidate()
      onClose()
      if (created.coreStore.error) {
        toast.warning(`Registered ${created.name}`, { description: `Core store: ${created.coreStore.error}` })
      } else {
        toast.success(`Registered ${created.name}`, { description: created.workspace })
      }
    } catch (failure) {
      setError({ message: errorMessage(failure), code: failure instanceof ApiError ? failure.code : null })
      setConfirming(false)
    } finally {
      setSubmitting(false)
    }
  }

  const disabled = !allowed || submitting

  return (
    <>
        <DialogHeader>
          <DialogTitle className="text-sm font-semibold flex items-center gap-2">
            <FolderGit2 className="size-4 text-primary" />
            Register workspace
          </DialogTitle>
          <DialogDescription className="text-xs text-zinc-400">
            Adds a tenant record that points the console at an existing directory on the bridge host. The bridge initializes a
            separate core store for it in the bridge data directory (<code className="font-mono">sentra init</code>). This action is
            recorded in the operator audit log.
          </DialogDescription>
        </DialogHeader>

        {!allowed && (
          <Alert className="border-amber-500/30 bg-amber-500/5 text-amber-200">
            <CircleAlert />
            <AlertDescription className="text-xs text-amber-200/90">{permissionHint('tenant:create')}</AlertDescription>
          </Alert>
        )}

        {error && (
          <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
            <CircleAlert />
            <AlertTitle className="text-xs">Registration failed{error.code ? ` (${error.code})` : ''}</AlertTitle>
            <AlertDescription className="text-xs break-words">{error.message}</AlertDescription>
          </Alert>
        )}

        {confirming ? (
          <div className="flex flex-col gap-3">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3 text-xs flex flex-col gap-2">
              <span className="font-medium text-zinc-100">Confirm registration</span>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
                <dt className="text-zinc-500">Tenant id</dt>
                <dd className="font-mono text-zinc-200 break-all">{tenantId}</dd>
                <dt className="text-zinc-500">Name</dt>
                <dd className="text-zinc-200 break-words">{name.trim()}</dd>
                <dt className="text-zinc-500">Workspace</dt>
                <dd className="font-mono text-zinc-200 break-all">{workspace.trim()}</dd>
                <dt className="text-zinc-500">Isolation label</dt>
                <dd className="text-zinc-200">{ISOLATION_LABELS[isolationLevel]} (not enforced)</dd>
                <dt className="text-zinc-500">GitHub</dt>
                <dd className="font-mono text-zinc-200 break-all">{repository.trim() || 'detect from git remote'}</dd>
              </dl>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                The bridge will verify the directory, run <code className="font-mono">sentra init</code> to create a new core store
                for this tenant in its data directory, store the tenant record and append a{' '}
                <code className="font-mono">tenant_registered</code> entry to the operator audit log. Users with read access will
                be able to view this workspace's findings and files through the console.
              </p>
            </div>
            <DialogFooter className="pt-3 border-t border-zinc-800 flex flex-col-reverse sm:flex-row gap-2 sm:justify-end">
              <Button type="button" variant="outline" size="sm" onClick={() => setConfirming(false)} disabled={submitting} className="h-8 text-xs">
                Back
              </Button>
              <Button type="button" size="sm" onClick={() => void register()} disabled={disabled} className="h-8 text-xs font-semibold">
                {submitting && <LoaderCircle className="size-3.5 animate-spin" />}
                {submitting ? 'Registering…' : 'Confirm and register'}
              </Button>
            </DialogFooter>
          </div>
        ) : (
        <form onSubmit={handleSubmit} className="flex flex-col gap-3" noValidate>
          <label className="flex flex-col gap-1 text-xs font-medium text-zinc-200">
            Display name
            <Input
              value={name}
              maxLength={120}
              onChange={(event) => {
                setName(event.target.value)
                if (autoSlug) setTenantIdInput(slugify(event.target.value))
              }}
              placeholder="Payments service"
              className="h-8 text-xs bg-zinc-900/60 border-zinc-800"
              disabled={disabled}
            />
          </label>

          <label className="flex flex-col gap-1 text-xs font-medium text-zinc-200">
            <span className="flex items-center justify-between">
              Tenant id
              <span className="text-[10px] font-mono text-zinc-500">a-z 0-9 - _ · {tenantId.length}/64</span>
            </span>
            <Input
              value={tenantId}
              maxLength={64}
              onChange={(event) => {
                setAutoSlug(false)
                setTenantIdInput(event.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))
              }}
              placeholder="payments-service"
              className="h-8 text-xs font-mono bg-zinc-900/60 border-zinc-800"
              disabled={disabled}
            />
            <span className="text-[10px] font-normal text-zinc-500">Used in URLs and the core store file name; cannot be changed later.</span>
          </label>

          <label className="flex flex-col gap-1 text-xs font-medium text-zinc-200">
            Workspace directory (absolute path on the bridge host)
            <Input
              value={workspace}
              maxLength={1024}
              onChange={(event) => setWorkspace(event.target.value)}
              placeholder="E:/Projects/payments-service"
              className="h-8 text-xs font-mono bg-zinc-900/60 border-zinc-800"
              disabled={disabled}
              spellCheck={false}
            />
            <span className="text-[10px] font-normal text-zinc-500">
              Must exist and cannot be a filesystem root. When the bridge sets SENTRA_WEB_WORKSPACE_ROOTS, it must lie inside one of
              those roots.
            </span>
          </label>

          <div className="flex flex-col gap-1 text-xs font-medium text-zinc-200">
            <span>Isolation level</span>
            <Select value={isolationLevel} onValueChange={(value) => value && setIsolationLevel(value as IsolationLevel)} disabled={disabled}>
              <SelectTrigger className="h-8 w-full text-xs bg-zinc-900/60 border-zinc-800" aria-label="Isolation level">
                <SelectValue>{(value: IsolationLevel | null) => (value ? ISOLATION_LABELS[value] : 'Select')}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="single_operator">{ISOLATION_LABELS.single_operator}</SelectItem>
                <SelectItem value="multi_tenant_isolated">{ISOLATION_LABELS.multi_tenant_isolated}</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-[10px] font-normal text-amber-300/80">
              Declared label only — not enforced by this console. All workspaces share one bridge process and host.
            </span>
          </div>

          <label className="flex flex-col gap-1 text-xs font-medium text-zinc-200">
            GitHub repository (optional)
            <Input
              value={repository}
              maxLength={200}
              onChange={(event) => setRepository(event.target.value)}
              placeholder="owner/name"
              className="h-8 text-xs font-mono bg-zinc-900/60 border-zinc-800"
              disabled={disabled}
              spellCheck={false}
            />
            <span className="text-[10px] font-normal text-zinc-500">When empty, the bridge tries the workspace's git remote.</span>
          </label>

          <label className="flex flex-col gap-1 text-xs font-medium text-zinc-200">
            Description (optional)
            <Input
              value={description}
              maxLength={500}
              onChange={(event) => setDescription(event.target.value)}
              className="h-8 text-xs bg-zinc-900/60 border-zinc-800"
              disabled={disabled}
            />
          </label>

          <DialogFooter className="mt-1 pt-3 border-t border-zinc-800 flex flex-col-reverse sm:flex-row gap-2 sm:justify-end">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={submitting} className="h-8 text-xs">
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={disabled} className="h-8 text-xs font-semibold">
              Review registration
            </Button>
          </DialogFooter>
        </form>
        )}
    </>
  )
}
