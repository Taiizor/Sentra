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
      <DialogContent className="max-w-lg border-border/80 bg-background/95 text-foreground shadow-2xl backdrop-blur-md">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <div className="flex size-7 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
              <Building2 className="size-3.5" />
            </div>
            <div>
              <DialogTitle className="text-sm font-semibold text-foreground">
                Register Organization / Tenant
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground mt-0.5">
                Provision a cryptographic workspace with multi-tenant boundary fencing.
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        {isViewer && (
          <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-300">
            <AlertTriangle className="size-3.5 shrink-0 text-amber-400 mt-0.5" />
            <span>Viewer role cannot register tenants. Switch to Operator or Admin.</span>
          </div>
        )}

        {error && (
          <div className="rounded-lg border border-destructive/60 bg-destructive/10 p-2.5 text-xs text-destructive flex items-center gap-2">
            <AlertTriangle className="size-3.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-3 py-1">
          {/* Organization Name */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-foreground flex items-center justify-between">
              <span>Organization Name</span>
              <span className="text-[10px] text-muted-foreground">e.g. Acme Corp</span>
            </label>
            <Input
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="e.g. CyberDefense Systems"
              className="h-8 text-xs bg-background/50 border-border/60"
              disabled={isViewer || loading}
              required
            />
          </div>

          {/* Tenant Identifier (Slug) */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-foreground flex items-center justify-between">
              <span>Unique Tenant ID</span>
              <span className="text-[10px] text-muted-foreground font-mono">1-64 chars: a-z, 0-9, -, _</span>
            </label>
            <div className="relative">
              <Input
                value={tenantId}
                onChange={(e) => handleSlugChange(e.target.value)}
                placeholder="cyberdefense-systems"
                className="h-8 text-xs font-mono bg-background/50 border-border/60 pr-14"
                disabled={isViewer || loading}
                required
              />
              <span className="absolute right-2.5 top-2 text-[10px] font-mono text-muted-foreground">
                {tenantId.length}/64
              </span>
            </div>
          </div>

          {/* Target Workspace Directory */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-foreground flex items-center gap-1.5">
              <FolderGit2 className="size-3 text-muted-foreground" />
              <span>Workspace Directory</span>
            </label>
            <Input
              value={workspace}
              onChange={(e) => setWorkspace(e.target.value)}
              placeholder="E:/Projects/target"
              className="h-8 text-xs font-mono bg-background/50 border-border/60"
              disabled={isViewer || loading}
            />
          </div>

          {/* Isolation Mode */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-foreground flex items-center gap-1.5">
              <Lock className="size-3 text-muted-foreground" />
              <span>Isolation Boundary Level</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setIsolationLevel('multi_tenant_isolated')}
                disabled={isViewer || loading}
                className={`flex flex-col items-start gap-0.5 p-2 rounded-md border text-left transition-colors ${
                  isolationLevel === 'multi_tenant_isolated'
                    ? 'border-primary bg-primary/10 text-foreground font-medium'
                    : 'border-border/60 bg-card/40 text-muted-foreground hover:text-foreground'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold">
                  <ShieldCheck className="size-3 text-primary" />
                  <span>Strict Isolated</span>
                </div>
                <span className="text-[10px] text-muted-foreground leading-tight">
                  Cross-tenant queries fail closed
                </span>
              </button>

              <button
                type="button"
                onClick={() => setIsolationLevel('single_operator')}
                disabled={isViewer || loading}
                className={`flex flex-col items-start gap-0.5 p-2 rounded-md border text-left transition-colors ${
                  isolationLevel === 'single_operator'
                    ? 'border-primary bg-primary/10 text-foreground font-medium'
                    : 'border-border/60 bg-card/40 text-muted-foreground hover:text-foreground'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold">
                  <span>Single Operator</span>
                </div>
                <span className="text-[10px] text-muted-foreground leading-tight">
                  Local solo developer development
                </span>
              </button>
            </div>
          </div>

          {/* Description */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-foreground">
              <span>Description / Notes (Optional)</span>
            </label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Production payment services and infrastructure"
              className="h-8 text-xs bg-background/50 border-border/60"
              disabled={isViewer || loading}
            />
          </div>

          <DialogFooter className="mt-2 pt-2 border-t border-border/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <CheckCircle2 className="size-3 text-emerald-400" />
              <span>Signed Audit Record</span>
            </div>

            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onOpenChange(false)}
                disabled={loading}
                className="h-7 text-xs border-border/70 text-muted-foreground hover:text-foreground"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={isViewer || loading || !name.trim() || !tenantId.trim()}
                className="h-7 text-xs font-medium"
              >
                {loading ? (
                  <>
                    <Loader2 className="size-3 animate-spin mr-1.5" />
                    Registering...
                  </>
                ) : (
                  'Register Tenant'
                )}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
