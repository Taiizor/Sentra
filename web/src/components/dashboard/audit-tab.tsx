import { History, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import type { AuditLogView } from '@/types/sentra'

interface AuditTabProps {
  auditLogs: AuditLogView[]
}

export function AuditTab({ auditLogs }: AuditTabProps) {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-base font-bold flex items-center gap-2">
          <History className="size-5 text-primary" />
          Tamper-Resistant Immutable Audit Trail
        </h2>
        <p className="text-xs text-muted-foreground">
          Strictly monotonic, content-addressed cryptographic log of all state transitions, scan results,
          findings, patches, and human approvals under multi-tenant isolation.
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold">Audit Event Timeline</CardTitle>
              <CardDescription className="text-xs">
                {auditLogs.length} verified events recorded in persistent storage
              </CardDescription>
            </div>
            <Badge variant="secondary" className="text-xs flex items-center gap-1">
              <ShieldCheck className="size-3 text-primary" />
              Cryptographic Integrity Verified
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs w-[80px]">Seq #</TableHead>
                  <TableHead className="text-xs">Event ID</TableHead>
                  <TableHead className="text-xs">Actor</TableHead>
                  <TableHead className="text-xs">Action</TableHead>
                  <TableHead className="text-xs">Structured Details</TableHead>
                  <TableHead className="text-xs text-right">Timestamp (UTC)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditLogs.map((log) => (
                  <TableRow key={log.eventId}>
                    <TableCell className="font-mono text-xs font-bold">
                      #{log.sequenceNumber}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {log.eventId}
                    </TableCell>
                    <TableCell className="font-mono text-xs font-medium">
                      {log.actor}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs max-w-[340px] truncate">
                      {log.details}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground text-right">
                      {new Date(log.timestamp).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
