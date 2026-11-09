import { useState, useEffect } from 'react'
import {
  Building2,
  ShieldCheck,
  FolderGit2,
  Lock,
  AlertTriangle,
  CheckCircle2,
  Loader2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import type { TenantView, UserRole } from '@/types/sentra'

interface AddTenantDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  currentRole: UserRole
  onTenantCreated: (newTenant: TenantView) => void
  currentWorkspace: string
}

export function AddTenantDialog({
  open,
  onOpenChange,
  currentRole,
  onTenantCreated,
  currentWorkspace,
}: AddTenantDialogProps) {
  const [name, setName] = useState('')
  const [tenantId, setTenantId] = useState('')
  const [autoSlug, setAutoSlug] = useState(true)
  const [workspace, setWorkspace] = useState(currentWorkspace)
  const [description, setDescription] = useState('')
  const [isolationLevel, setIsolationLevel] = useState<'multi_tenant_isolated' | 'single_operator'>('multi_tenant_isolated')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (open) {
      setName('')
      setTenantId('')
      setAutoSlug(true)
      setWorkspace(currentWorkspace)
      setDescription('')
      setIsolationLevel('multi_tenant_isolated')
      setError(null)
    }
  }, [open, currentWorkspace])

  function handleNameChange(val: string) {
    setName(val)
    if (autoSlug) {
      const slug = val
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 64)
      setTenantId(slug)
    }
  }

  function handleSlugChange(val: string) {
    setAutoSlug(false)
    const sanitized = val.toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 64)
    setTenantId(sanitized)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)

    if (currentRole === 'Viewer') {
      setError('Viewer role cannot register tenants. Switch to Operator or Admin in the top-right role selector.')
      return
    }

    if (!name.trim()) {
      setError('Organization name is required.')
      return
    }

    if (!tenantId.trim()) {
      setError('Tenant ID is required (1-64 alphanumeric chars).')
      return
    }

    setLoading(true)

    try {
      const res = await fetch('/api/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenantId: tenantId.trim(),
          name: name.trim(),
          description: description.trim(),
          defaultWorkspace: workspace.trim() || currentWorkspace,
          isolationLevel,
          role: currentRole,
        }),
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.error || 'Failed to register tenant workspace.')
      }

      onTenantCreated(data.tenant)
      onOpenChange(false)
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred while registering tenant.')
    } finally {
      setLoading(false)
    }
  }

  const isViewer = currentRole === 'Viewer'

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg border-zinc-800 bg-zinc-950 text-zinc-100 shadow-2xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Building2 className="size-4" />
            </div>
            <div>
              <DialogTitle className="text-base font-semibold text-zinc-100">
                Register New Organization / Tenant
              </DialogTitle>
              <DialogDescription className="text-xs text-zinc-400 mt-0.5">
                Provision a cryptographic workspace with strict multi-tenant boundary fencing (REQ-F19, ADR-0001).
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        {isViewer && (
          <div className="flex items-start gap-2.5 rounded-lg border border-amber-900/60 bg-amber-950/30 p-3 text-xs text-amber-300">
            <AlertTriangle className="size-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <span className="font-semibold">Viewer Role Restricted:</span> Tenant registration enforces policy mutation controls. Please switch to <span className="font-mono font-medium">Operator</span> or <span className="font-mono font-medium">Admin</span> in the header to register new organizations.
            </div>
          </div>
        )}

        {error && (
          <div className="rounded-lg border border-destructive/60 bg-destructive/10 p-3 text-xs text-destructive flex items-center gap-2">
            <AlertTriangle className="size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4 py-2">
          {/* Organization Name */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-zinc-300 flex items-center justify-between">
              <span>Organization / Workspace Name</span>
              <span className="text-[10px] text-zinc-500 font-normal">e.g. Fintech Global Security</span>
            </label>
            <Input
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="e.g. CyberDefense Systems"
              className="h-9 text-xs bg-zinc-900/80 border-zinc-800 text-zinc-100"
              disabled={isViewer || loading}
              required
            />
          </div>

          {/* Tenant Identifier (Slug) */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-zinc-300 flex items-center justify-between">
              <span>Unique Tenant ID (Cryptographic Namespace)</span>
              <span className="text-[10px] text-zinc-500 font-mono">1-64 chars: a-z, 0-9, -, _</span>
            </label>
            <div className="relative">
              <Input
                value={tenantId}
                onChange={(e) => handleSlugChange(e.target.value)}
                placeholder="cyberdefense-systems"
                className="h-9 text-xs font-mono bg-zinc-900/80 border-zinc-800 text-zinc-100 pr-16"
                disabled={isViewer || loading}
                required
              />
              <span className="absolute right-2.5 top-2.5 text-[10px] font-mono text-zinc-500">
                {tenantId.length}/64
              </span>
            </div>
          </div>

          {/* Target Workspace Directory */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-zinc-300 flex items-center gap-1.5">
              <FolderGit2 className="size-3.5 text-zinc-400" />
              <span>Default Target Workspace Directory</span>
            </label>
            <Input
              value={workspace}
              onChange={(e) => setWorkspace(e.target.value)}
              placeholder="E:/Projects/cyberdefense"
              className="h-9 text-xs font-mono bg-zinc-900/80 border-zinc-800 text-zinc-100"
              disabled={isViewer || loading}
            />
            <span className="text-[10px] text-zinc-500">
              Scans, SAST runs, and CodeQL probes for this tenant will default to this path.
            </span>
          </div>

          {/* Isolation Mode */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-zinc-300 flex items-center gap-1.5">
              <Lock className="size-3.5 text-zinc-400" />
              <span>Boundary Fencing & Isolation Level</span>
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setIsolationLevel('multi_tenant_isolated')}
                disabled={isViewer || loading}
                className={`flex flex-col items-start gap-1 p-2.5 rounded-lg border text-left transition-colors ${
                  isolationLevel === 'multi_tenant_isolated'
                    ? 'border-primary/60 bg-primary/10 text-zinc-100'
                    : 'border-zinc-800 bg-zinc-900/50 text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <div className="flex items-center gap-1.5 font-medium text-xs">
                  <ShieldCheck className="size-3.5 text-primary" />
                  <span>Strict Isolated</span>
                </div>
                <span className="text-[10px] text-zinc-400 leading-tight">
                  Cross-tenant queries fail closed with CrossTenantAccessDenied.
                </span>
              </button>

              <button
                type="button"
                onClick={() => setIsolationLevel('single_operator')}
                disabled={isViewer || loading}
                className={`flex flex-col items-start gap-1 p-2.5 rounded-lg border text-left transition-colors ${
                  isolationLevel === 'single_operator'
                    ? 'border-primary/60 bg-primary/10 text-zinc-100'
                    : 'border-zinc-800 bg-zinc-900/50 text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <div className="flex items-center gap-1.5 font-medium text-xs">
                  <span>Single Operator</span>
                </div>
                <span className="text-[10px] text-zinc-400 leading-tight">
                  Permissive boundary for solo developer local development.
                </span>
              </button>
            </div>
          </div>

          {/* Description */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-zinc-300">
              <span>Description / Notes (Optional)</span>
            </label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Production payment services and cloud infrastructure"
              className="h-9 text-xs bg-zinc-900/80 border-zinc-800 text-zinc-100"
              disabled={isViewer || loading}
            />
          </div>

          <DialogFooter className="mt-2 pt-2 border-t border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1 text-[11px] text-zinc-500">
              <CheckCircle2 className="size-3 text-primary" />
              <span>Immutable Audit Trail record will be signed</span>
            </div>

            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => onOpenChange(false)}
                disabled={loading}
                className="h-8 text-xs text-zinc-400 hover:text-zinc-100"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={isViewer || loading || !name.trim() || !tenantId.trim()}
                className="h-8 text-xs font-medium"
              >
                {loading ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin mr-1.5" />
                    Registering...
                  </>
                ) : (
                  'Register & Activate Workspace'
                )}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
