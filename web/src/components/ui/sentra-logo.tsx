import { cn } from 'cn'

interface SentraLogoProps {
  className?: string
  size?: number | string
  /** Core version reported by the bridge (`sentra --version --json`); the badge is hidden when unknown. */
  version?: string | null
  glow?: boolean
}

/** Sentra monogram (same artwork as public/favicon.svg). */
export function SentraLogoIcon({ className, size = 36 }: { className?: string; size?: number | string }) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ width: size, height: size }}
      className={cn('shrink-0 select-none drop-shadow-sm', className)}
      role="img"
      aria-label="Sentra"
    >
      <rect x="5" y="5" width="90" height="90" rx="22" fill="#09090b" stroke="#27272a" strokeWidth="2" />
      <polygon points="50,20 76,35 76,47 62,40 50,33 38,40 38,52 24,44 24,35" fill="#00f0ff" />
      <polygon points="50,80 24,65 24,53 38,60 50,67 62,60 62,48 76,56 76,65" fill="#ffffff" />
      <circle cx="50" cy="50" r="4.5" fill="#10b981" />
    </svg>
  )
}

/** Sentra wordmark with an optional core-version badge. */
export function SentraLogo({ className, size = 36, version = null, glow = true }: SentraLogoProps) {
  return (
    <div className={cn('flex items-center gap-3 select-none group', className)}>
      <div className="relative">
        <SentraLogoIcon size={size} />
        {glow && (
          <div className="absolute inset-0 rounded-2xl bg-cyan-500/15 opacity-0 group-hover:opacity-100 transition-opacity -z-10 blur-sm" />
        )}
      </div>

      <div className="flex flex-col min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-black text-base tracking-tight text-white font-sans">SENTRA</span>
          {version && (
            <span
              className="text-[10px] font-mono px-1.5 py-0.5 leading-none rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 font-semibold tracking-wider"
              title="Version reported by the Sentra core binary"
            >
              v{version}
            </span>
          )}
        </div>
        <span className="text-[11px] text-zinc-400 font-medium tracking-tight">Security review console</span>
      </div>
    </div>
  )
}
