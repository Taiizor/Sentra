import type { ReactElement, ReactNode } from 'react'
import { cn } from 'cn'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * Wraps a (disabled) control so a tooltip can explain why it is unavailable. Disabled buttons
 * do not emit pointer events, so the tooltip is attached to a wrapping span. When `reason` is
 * null the child is rendered unchanged.
 */
export function DisabledReason({
  reason,
  className,
  children,
}: {
  reason: ReactNode | null
  /** Classes for the wrapping span (e.g. responsive visibility matching the child). */
  className?: string
  children: ReactElement
}) {
  if (reason === null) return children
  return (
    <Tooltip>
      <TooltipTrigger render={<span className={cn('inline-flex', className)} tabIndex={0} />}>{children}</TooltipTrigger>
      <TooltipContent className="max-w-xs text-[11px]">{reason}</TooltipContent>
    </Tooltip>
  )
}
