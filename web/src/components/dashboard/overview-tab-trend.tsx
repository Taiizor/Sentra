import { useState } from 'react'
import { TrendingUp } from 'lucide-react'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { TrendPoint } from '@/types/api'
import { LoadError } from './overview-tab-parts'

/** Two series on one count axis; colours validated for CVD separation on the zinc-900 surface. */
const SERIES = [
  { key: 'openAtEndOfDay', label: 'Open findings', color: '#3b82f6' },
  { key: 'openCriticalAtEndOfDay', label: 'Open critical', color: '#f43f5e' },
] as const

interface TrendCardProps {
  days: number
  points: TrendPoint[] | undefined
  loading: boolean
  error: unknown
  onRetry: () => void
}

function hasActivity(points: TrendPoint[]): boolean {
  return points.some(
    (point) => point.scans > 0 || point.openAtEndOfDay > 0 || point.newFindings > 0 || point.resolvedFindings > 0,
  )
}

function TrendTooltip({ point }: { point: TrendPoint | undefined }) {
  if (!point) return null
  return (
    <div className="rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-2 text-[11px] text-zinc-200 shadow-lg flex flex-col gap-0.5">
      <span className="font-mono text-zinc-400">{point.date}</span>
      {SERIES.map((series) => (
        <span key={series.key} className="flex items-center gap-1.5">
          <span className="size-2 rounded-full" style={{ backgroundColor: series.color }} />
          {series.label}: <span className="font-mono">{point[series.key]}</span>
        </span>
      ))}
      <span className="text-zinc-400">
        New <span className="font-mono text-zinc-200">{point.newFindings}</span> · resolved{' '}
        <span className="font-mono text-zinc-200">{point.resolvedFindings}</span> · scans{' '}
        <span className="font-mono text-zinc-200">{point.scans}</span>
      </span>
    </div>
  )
}

export function OverviewTrendCard({ days, points, loading, error, onRetry }: TrendCardProps) {
  const [showTable, setShowTable] = useState(false)
  const active = points ? hasActivity(points) : false

  return (
    <Card className="border-zinc-800/80 bg-zinc-900/40">
      <CardHeader className="pb-2 pt-4 px-4 sm:px-5">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
          <div className="flex flex-col gap-1">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="size-4 text-primary" />
              Open findings, last {days} days
            </CardTitle>
            <CardDescription className="text-xs text-zinc-400">
              Daily end-of-day counts computed by the bridge from this workspace's recorded scan runs.
            </CardDescription>
          </div>
          {points && active && (
            <Button variant="outline" size="xs" className="self-start text-[11px] border-zinc-800" onClick={() => setShowTable((value) => !value)}>
              {showTable ? 'Show chart' : 'Show table'}
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="pt-1 px-3 sm:px-4 pb-4">
        {error ? (
          <LoadError title="Trend data unavailable" error={error} onRetry={onRetry} />
        ) : !points ? (
          loading ? <Skeleton className="h-[220px] w-full bg-zinc-900" /> : null
        ) : !active ? (
          <div className="h-[220px] flex items-center justify-center text-center text-xs text-zinc-500 px-6">
            No scan activity or open findings recorded in the last {days} days.
          </div>
        ) : showTable ? (
          <div className="max-h-[260px] overflow-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Date</TableHead>
                  <TableHead className="text-xs text-right">Scans</TableHead>
                  <TableHead className="text-xs text-right">New</TableHead>
                  <TableHead className="text-xs text-right">Resolved</TableHead>
                  <TableHead className="text-xs text-right">Open</TableHead>
                  <TableHead className="text-xs text-right">Open critical</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {points.map((point) => (
                  <TableRow key={point.date}>
                    <TableCell className="font-mono text-[11px]">{point.date}</TableCell>
                    <TableCell className="font-mono text-[11px] text-right">{point.scans}</TableCell>
                    <TableCell className="font-mono text-[11px] text-right">{point.newFindings}</TableCell>
                    <TableCell className="font-mono text-[11px] text-right">{point.resolvedFindings}</TableCell>
                    <TableCell className="font-mono text-[11px] text-right">{point.openAtEndOfDay}</TableCell>
                    <TableCell className="font-mono text-[11px] text-right">{point.openCriticalAtEndOfDay}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-4 px-1 text-[11px] text-zinc-300" aria-hidden="true">
              {SERIES.map((series) => (
                <span key={series.key} className="flex items-center gap-1.5">
                  <span className="h-0.5 w-3 rounded-full" style={{ backgroundColor: series.color }} />
                  {series.label}
                </span>
              ))}
            </div>
            <div className="h-[220px] w-full min-w-0" role="img" aria-label={`Open findings over the last ${days} days`}>
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={200}>
                <LineChart data={points} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="date"
                    stroke="#71717a"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={(value: string) => value.slice(5)}
                    minTickGap={16}
                  />
                  <YAxis stroke="#71717a" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} width={40} />
                  <Tooltip
                    cursor={{ stroke: '#52525b', strokeWidth: 1 }}
                    content={(props) => <TrendTooltip point={props.active ? (props.payload?.[0]?.payload as TrendPoint | undefined) : undefined} />}
                  />
                  {SERIES.map((series) => (
                    <Line
                      key={series.key}
                      type="monotone"
                      dataKey={series.key}
                      name={series.label}
                      stroke={series.color}
                      strokeWidth={2}
                      dot={false}
                      activeDot={{ r: 4, strokeWidth: 2, stroke: '#18181b' }}
                      isAnimationActive={false}
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
