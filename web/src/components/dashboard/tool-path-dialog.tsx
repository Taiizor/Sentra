import { useEffect, useId, useRef, useState, type ComponentProps, type FormEvent, type RefObject } from 'react'
import { CircleAlert, FolderSearch, LoaderCircle, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { ApiError, api, errorMessage } from '@/lib/api'
import type { SetToolPathResponse, ToolAvailability } from '@/types/api'
import { EXECUTABLE_SOURCE_LABEL, hasConfiguredPath, toolPathPlaceholder, toolPathUsageText } from './console-format'

/** The bridge refuses longer paths; checked here only to answer before a round trip. */
const MAX_TOOL_PATH_LENGTH = 1024

const PLATFORM_NAME: Record<string, string> = { win32: 'Windows', darwin: 'macOS', linux: 'Linux' }

/**
 * Sets the path the bridge reports for one tool. The bridge validates the path (absolute, exists,
 * can run on this host) and never runs the file; only tools it does not execute can be set here.
 * Open while `tool` is set. `finalFocus` names the element that gets focus back on close (the row's
 * path button), since saving re-renders the row that opened the dialog.
 */
export function ToolPathDialog({
  tool,
  platform,
  onClose,
  onSaved,
  finalFocus,
}: {
  tool: ToolAvailability | null
  platform: string
  onClose: () => void
  onSaved: (tool: ToolAvailability) => void
  finalFocus?: ComponentProps<typeof DialogContent>['finalFocus']
}) {
  const [saving, setSaving] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  return (
    <Dialog open={tool !== null} onOpenChange={(next) => !next && !saving && onClose()}>
      {/* sm:max-w-lg, not max-w-lg: the base max-w-[calc(100%-2rem)] keeps a 1rem gutter on phones. */}
      <DialogContent className="border-border/80 bg-background sm:max-w-lg" initialFocus={inputRef} finalFocus={finalFocus}>
        {/* Mounted per opening and per tool, so every opening starts from the tool's current state. */}
        {tool && (
          <ToolPathForm
            key={tool.name}
            tool={tool}
            platform={platform}
            inputRef={inputRef}
            saving={saving}
            setSaving={setSaving}
            onClose={onClose}
            onSaved={onSaved}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function ToolPathForm({
  tool,
  platform,
  inputRef,
  saving,
  setSaving,
  onClose,
  onSaved,
}: {
  tool: ToolAvailability
  platform: string
  inputRef: RefObject<HTMLInputElement | null>
  saving: boolean
  setSaving: (saving: boolean) => void
  onClose: () => void
  onSaved: (tool: ToolAvailability) => void
}) {
  const [value, setValue] = useState(tool.configuredPath ?? '')
  const [error, setError] = useState<{ message: string; code: string | null } | null>(null)
  const [savedWithWarning, setSavedWithWarning] = useState<SetToolPathResponse | null>(null)
  const inputId = useId()
  const helpId = useId()
  const errorId = useId()
  const configured = hasConfiguredPath(tool)
  const platformName = PLATFORM_NAME[platform] ?? platform

  // Back to the field after a refusal, once it is enabled again (it is disabled while saving).
  useEffect(() => {
    if (error) inputRef.current?.focus()
  }, [error, inputRef])

  function fail(message: string, code: string | null) {
    setError({ message, code })
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (saving) return
    const path = value.trim()
    if (!path) return fail('Enter the absolute path of the executable or of the folder that contains it.', null)
    if (path.length > MAX_TOOL_PATH_LENGTH) return fail(`The path is longer than ${MAX_TOOL_PATH_LENGTH} characters.`, null)
    setSaving(true)
    setError(null)
    try {
      const response = await api.system.setToolPath(tool.name, path)
      onSaved(response.tool)
      if (response.warning) {
        // Keep the dialog open so the warning is read, not lost in a toast.
        setSavedWithWarning(response)
      } else {
        toast.success(`${tool.name}: path saved`, { description: response.tool.path ?? path })
        onClose()
      }
    } catch (failure) {
      fail(errorMessage(failure), failure instanceof ApiError ? failure.code : null)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2 text-sm font-semibold">
          <FolderSearch className="size-4 text-emerald-400" />
          {configured || tool.available ? `Change the ${tool.name} path` : `Set the ${tool.name} path`}
        </DialogTitle>
        <DialogDescription className="text-xs">
          Sentra finds {tool.name} automatically. Set a path when it is installed where automatic detection does not look, or to
          choose another installation. The change applies to the whole bridge and is recorded in the operator audit log.
        </DialogDescription>
      </DialogHeader>

      <CurrentState tool={savedWithWarning?.tool ?? tool} />

      {savedWithWarning ? (
        <>
          <Alert className="border-amber-500/30 bg-amber-500/5 text-amber-200">
            <TriangleAlert />
            <AlertTitle className="text-xs">Saved, with a warning</AlertTitle>
            <AlertDescription className="text-xs break-words text-amber-200/90">{savedWithWarning.warning}</AlertDescription>
          </Alert>
          <DialogFooter>
            <Button type="button" size="sm" onClick={onClose} autoFocus>
              Close
            </Button>
          </DialogFooter>
        </>
      ) : (
        <form onSubmit={(event) => void handleSubmit(event)} className="flex flex-col gap-3" noValidate>
          <div className="flex flex-col gap-1">
            <label htmlFor={inputId} className="text-xs font-medium text-foreground">
              Path on the bridge host ({platformName})
            </label>
            <Input
              id={inputId}
              ref={inputRef}
              value={value}
              onChange={(event) => {
                setValue(event.target.value)
                if (error) setError(null)
              }}
              placeholder={toolPathPlaceholder(tool.name, platform)}
              className="h-8 font-mono text-xs"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? `${helpId} ${errorId}` : helpId}
              disabled={saving}
            />
            <p id={helpId} className="text-[11px] leading-snug text-muted-foreground">
              Absolute path to the executable or to the folder that contains it. Sentra never runs this file; it only checks that it
              exists and can run on this machine.
            </p>
          </div>

          <p className="text-[11px] leading-snug text-muted-foreground">{toolPathUsageText(tool.name)}</p>

          {error && (
            <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5" id={errorId}>
              <CircleAlert />
              <AlertTitle className="text-xs">The bridge did not accept the path{error.code ? ` (${error.code})` : ''}</AlertTitle>
              <AlertDescription className="text-xs break-words">{error.message}</AlertDescription>
            </Alert>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={saving || !value.trim()}>
              {saving && <LoaderCircle className="animate-spin" />}
              {saving ? 'Checking…' : 'Save path'}
            </Button>
          </DialogFooter>
        </form>
      )}
    </>
  )
}

/** What the row shows now, so the administrator sees what the new path replaces. */
function CurrentState({ tool }: { tool: ToolAvailability }) {
  const broken = hasConfiguredPath(tool) && tool.configuredPathProblem
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border/60 bg-card/40 p-2.5 text-[11px]">
      <span className="text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">Now shown</span>
      {tool.path ? (
        <span className="flex flex-wrap items-baseline gap-x-1.5">
          <span className="font-mono break-all text-foreground">{tool.path}</span>
          {tool.source && <span className="text-muted-foreground">({EXECUTABLE_SOURCE_LABEL[tool.source] ?? tool.source})</span>}
        </span>
      ) : (
        <span className="text-muted-foreground">Not found by automatic detection.</span>
      )}
      {broken && (
        <span className="break-words text-amber-300">
          The path set in the console, <span className="font-mono break-all">{tool.configuredPath}</span>, cannot be used:{' '}
          {tool.configuredPathProblem}
        </span>
      )}
    </div>
  )
}
