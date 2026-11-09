import { cn } from 'cn'

interface SentraLogoProps {
  className?: string
  size?: number | string
  showBadge?: boolean
  glow?: boolean
}

/**
 * Sentra Cyber Hex Monogram Icon
 * Isometric interlocking tech S inside a matte obsidian squircle.
 */
export function SentraLogoIcon({
  className,
  size = 36,
  glow = true,
}: {
  className?: string
  size?: number | string
  glow?: boolean
}) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ width: size, height: size }}
      className={cn(
        'shrink-0 select-none drop-shadow-sm transition-transform duration-200 hover:scale-105',
        className
      )}
      aria-label="Sentra Cyber Hex Logo"
    >
      {/* Matte Obsidian Squircle Frame */}
      <rect x="5" y="5" width="90" height="90" rx="22" fill="#09090b" stroke="#27272a" strokeWidth="2" />

      {/* Top Hex Segment (Electric Cyan #00F0FF) */}
      <polygon
        points="50,20 76,35 76,47 62,40 50,33 38,40 38,52 24,44 24,35"
        fill="#00f0ff"
      />

      {/* Bottom Hex Segment (Pure Crisp White #FFFFFF - Exact 180° Rotation) */}
      <polygon
        points="50,80 24,65 24,53 38,60 50,67 62,60 62,48 76,56 76,65"
        fill="#ffffff"
      />

      {/* Center Verification Nexus Dot (Emerald Mint #10B981) */}
      <circle cx="50" cy="50" r="4.5" fill="#10b981" />
    </svg>
  )
}

/**
 * Sentra Brand Logo with Typography & Badge
 */
export function SentraLogo({
  className,
  size = 36,
  showBadge = true,
  glow = true,
}: SentraLogoProps) {
  return (
    <div className={cn('flex items-center gap-3 select-none group', className)}>
      <div className="relative">
        <SentraLogoIcon size={size} glow={glow} />
        {glow && (
          <div className="absolute inset-0 rounded-2xl bg-cyan-500/15 opacity-0 group-hover:opacity-100 transition-opacity -z-10 blur-sm" />
        )}
      </div>

      <div className="flex flex-col">
        <div className="flex items-center gap-2">
          <span className="font-black text-base tracking-tight text-white font-sans">
            SENTRA
          </span>
          {showBadge && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 font-bold tracking-wider shadow-xs">
              v0.1.0
            </span>
          )}
        </div>
        <span className="text-[11px] text-zinc-400 font-medium tracking-tight">
          Autonomous AI Security Core
        </span>
      </div>
    </div>
  )
}
