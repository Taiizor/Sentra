import { cn } from 'cn'

interface SentraLogoProps {
  className?: string
  size?: number | string
  variant?: 'icon' | 'full' | 'compact'
  showBadge?: boolean
  glow?: boolean
}

export function SentraLogoIcon({
  className,
  size = 32,
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
      className={cn('shrink-0 transition-transform duration-300 hover:scale-105', className)}
      aria-label="Sentra Cyber Shield Logo"
    >
      <defs>
        {/* Background Shield Gradient */}
        <linearGradient id="sentra-shield-bg" x1="50" y1="8" x2="50" y2="92" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#0c1322" />
          <stop offset="50%" stop-color="#050811" />
          <stop offset="100%" stop-color="#020307" />
        </linearGradient>

        {/* Outer Rim Holographic Gradient */}
        <linearGradient id="sentra-rim" x1="12" y1="8" x2="88" y2="92" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#22d3ee" />
          <stop offset="35%" stop-color="#38bdf8" />
          <stop offset="70%" stop-color="#6366f1" />
          <stop offset="100%" stop-color="#10b981" />
        </linearGradient>

        {/* S-Monogram Flow */}
        <linearGradient id="sentra-s-grad" x1="30" y1="26" x2="70" y2="74" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#06b6d4" />
          <stop offset="45%" stop-color="#3b82f6" />
          <stop offset="75%" stop-color="#8b5cf6" />
          <stop offset="100%" stop-color="#10b981" />
        </linearGradient>

        {/* Central Sentinel Core Gradient */}
        <linearGradient id="sentra-core-grad" x1="41" y1="41" x2="59" y2="59" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#38bdf8" />
          <stop offset="100%" stop-color="#a855f7" />
        </linearGradient>

        {/* Luminous Glow */}
        <filter id="sentra-glow" x="-25%" y="-25%" width="150%" height="150%">
          <feGaussianBlur stdDeviation="2.2" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      {/* Outer Protective Shield Contour */}
      <path
        d="M 50 8 L 88 23 C 88 56 75 79 50 92 C 25 79 12 56 12 23 Z"
        fill="url(#sentra-shield-bg)"
        stroke="url(#sentra-rim)"
        stroke-width="2.5"
        stroke-linejoin="round"
      />

      {/* Inner Cyber Contour / Lattice Facet */}
      <path
        d="M 50 15 L 81 27 C 81 54 70 73 50 84 C 30 73 19 54 19 27 Z"
        stroke="url(#sentra-rim)"
        stroke-opacity="0.25"
        stroke-width="1"
        fill="none"
      />

      {/* Verification Network Traces */}
      <g opacity="0.35" stroke="#38bdf8" stroke-width="0.8" stroke-dasharray="2 3">
        <line x1="50" y1="18" x2="50" y2="36" />
        <line x1="50" y1="64" x2="50" y2="82" />
        <line x1="24" y1="50" x2="38" y2="50" />
        <line x1="62" y1="50" x2="76" y2="50" />
      </g>

      {/* Stylized "S" Monogram (Flow from Source through Invariant to Remediated Sink) */}
      <path
        d="M 68 31 C 68 27 63 25 50 25 C 36 25 33 29 33 34 C 33 42 41 45 52 48 C 64 51 68 56 68 64 C 68 70 63 74 50 74 C 36 74 32 71 32 67"
        stroke="url(#sentra-s-grad)"
        stroke-width="5"
        stroke-linecap="round"
        fill="none"
        filter={glow ? 'url(#sentra-glow)' : undefined}
      />

      {/* Central Autonomous Sentinel Eye / Verification Core (Diamond) */}
      <g filter={glow ? 'url(#sentra-glow)' : undefined}>
        <polygon
          points="50,42 58,50 50,58 42,50"
          fill="url(#sentra-core-grad)"
          stroke="#ffffff"
          stroke-width="1.2"
        />
        {/* Pure Center Core Light */}
        <circle cx="50" cy="50" r="2.2" fill="#ffffff" />
      </g>

      {/* Autonomous Invariant Verification Nodes (Vertices) */}
      <circle cx="50" cy="18" r="1.8" fill="#22d3ee" />
      <circle cx="81" cy="27" r="1.8" fill="#6366f1" />
      <circle cx="19" cy="27" r="1.8" fill="#06b6d4" />
      <circle cx="50" cy="82" r="1.8" fill="#10b981" />
    </svg>
  )
}

export function SentraLogo({
  className,
  size = 32,
  variant = 'compact',
  showBadge = true,
  glow = true,
}: SentraLogoProps) {
  if (variant === 'icon') {
    return <SentraLogoIcon size={size} className={className} glow={glow} />
  }

  return (
    <div className={cn('flex items-center gap-3 select-none', className)}>
      <div className="relative group">
        <SentraLogoIcon size={size} glow={glow} />
        {glow && (
          <div className="absolute inset-0 rounded-full bg-primary/20 blur-md -z-10 opacity-70 group-hover:opacity-100 transition-opacity" />
        )}
      </div>

      <div className="flex flex-col">
        <div className="flex items-center gap-1.5">
          <span className="font-extrabold text-base tracking-tight text-white font-sans bg-clip-text text-transparent bg-gradient-to-r from-zinc-100 via-zinc-200 to-zinc-400">
            Sentra
          </span>
          {showBadge && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 font-semibold shadow-xs">
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
