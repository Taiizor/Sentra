import { Database } from "bun:sqlite";
import fs from "node:fs";
import type {
  CoreAuditEventView,
  CoreAuditView,
  CoreSessionView,
  CoreTaskView,
  ResearchSessionsView,
} from "../../src/types/api.ts";
import { parseJsonColumn } from "../db.ts";
import { log } from "../logger.ts";
import { cliFailure, type SentraCli } from "../sentra-cli.ts";
import type { TenantRecord, WorkspaceService } from "./workspaces.ts";

/** Read views reuse one `sentra status` result per core store for this long. */
export const STATUS_VIEW_TTL_MS = 5_000;

const EMPTY_SESSION: CoreSessionView = {
  initialized: false,
  sessionId: null,
  state: null,
  mode: null,
  classificationFloor: null,
  contextGeneration: null,
  createdAt: null,
  updatedAt: null,
  budgetLimitMicroUsd: null,
  budgetUsedMicroUsd: null,
  error: null,
};

/**
 * Read model over a tenant's core store. Session state comes from `sentra status` (the core's
 * own projection); tables the CLI does not expose (tasks, audit events, budget, approvals)
 * are read through a read-only SQLite connection. Nothing here writes to a core store.
 */
export class CoreStoreReader {
  private readonly cli: SentraCli;
  private readonly workspaces: WorkspaceService;

  constructor(cli: SentraCli, workspaces: WorkspaceService) {
    this.cli = cli;
    this.workspaces = workspaces;
  }

  private open(tenant: TenantRecord): Database | null {
    const store = this.workspaces.coreStorePath(tenant.tenantId);
    if (!fs.existsSync(store)) return null;
    try {
      return new Database(store, { readonly: true });
    } catch (error) {
      log.warn("core store could not be opened read-only", { tenant: tenant.tenantId, error: String(error) });
      return null;
    }
  }

  /**
   * Core session state from `sentra status`. Concurrent and repeated reads share one core run
   * for a few seconds (see SentraCli.runShared); `signal` only stops this caller from waiting.
   */
  async session(tenant: TenantRecord, signal?: AbortSignal): Promise<CoreSessionView> {
    const store = this.workspaces.coreStorePath(tenant.tenantId);
    if (!fs.existsSync(store)) return { ...EMPTY_SESSION, error: "core store not initialized" };
    let workspace: string;
    try {
      workspace = this.workspaces.workspaceRoot(tenant);
    } catch (error) {
      return { ...EMPTY_SESSION, error: error instanceof Error ? error.message : String(error) };
    }
    const result = await this.cli.runShared(["status", "--database", store, "--workspace", workspace, "--json"], {
      ttlMs: STATUS_VIEW_TTL_MS,
      signal,
    });
    const json = (result.json ?? {}) as Record<string, unknown>;
    if (result.code !== 0 || json.initialized !== true) {
      return { ...EMPTY_SESSION, error: result.code === 0 ? "core store reports not initialized" : cliFailure("status", result).message };
    }
    const db = this.open(tenant);
    let mode: string | null = null;
    let updatedAt: string | null = null;
    if (db) {
      try {
        const row = db.query("SELECT mode, updated_at FROM sessions WHERE session_id = ?").get(String(json.session_id)) as {
          mode: string;
          updated_at: string;
        } | null;
        mode = row?.mode ?? null;
        updatedAt = row?.updated_at ?? null;
      } finally {
        db.close();
      }
    }
    return {
      initialized: true,
      sessionId: typeof json.session_id === "string" ? json.session_id : null,
      state: typeof json.state === "string" ? json.state : null,
      mode,
      classificationFloor: typeof json.classification_floor === "string" ? json.classification_floor : null,
      contextGeneration: typeof json.context_generation === "number" ? json.context_generation : null,
      createdAt: typeof json.created_at === "string" ? json.created_at : null,
      updatedAt,
      budgetLimitMicroUsd: typeof json.budget_limit_micro_usd === "number" ? json.budget_limit_micro_usd : null,
      budgetUsedMicroUsd: typeof json.budget_used_micro_usd === "number" ? json.budget_used_micro_usd : null,
      error: null,
    };
  }

  counts(tenant: TenantRecord): { tasks: number | null; auditEvents: number | null } {
    const db = this.open(tenant);
    if (!db) return { tasks: null, auditEvents: null };
    try {
      const tasks = (db.query("SELECT COUNT(*) AS c FROM tasks").get() as { c: number }).c;
      const auditEvents = (db.query("SELECT COUNT(*) AS c FROM audit_events").get() as { c: number }).c;
      return { tasks, auditEvents };
    } catch {
      return { tasks: null, auditEvents: null };
    } finally {
      db.close();
    }
  }

  tasks(tenant: TenantRecord, limit: number): { tasks: CoreTaskView[]; total: number } {
    const db = this.open(tenant);
    if (!db) return { tasks: [], total: 0 };
    try {
      const total = (db.query("SELECT COUNT(*) AS c FROM tasks").get() as { c: number }).c;
      const rows = db
        .query("SELECT task_id, sequence_number, title, state, created_at, updated_at, completed_at FROM tasks ORDER BY created_at DESC, sequence_number DESC LIMIT ?")
        .all(limit) as {
        task_id: string;
        sequence_number: number;
        title: string;
        state: string;
        created_at: string;
        updated_at: string;
        completed_at: string | null;
      }[];
      return {
        total,
        tasks: rows.map((row) => ({
          taskId: row.task_id,
          sequenceNumber: row.sequence_number,
          title: row.title,
          state: row.state,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          completedAt: row.completed_at,
        })),
      };
    } finally {
      db.close();
    }
  }

  auditEvents(tenant: TenantRecord, limit: number): { events: CoreAuditEventView[]; total: number } {
    const db = this.open(tenant);
    if (!db) return { events: [], total: 0 };
    try {
      const total = (db.query("SELECT COUNT(*) AS c FROM audit_events").get() as { c: number }).c;
      const rows = db
        .query(
          "SELECT event_id, session_id, sequence_number, event_kind, classification, timestamp, action_digest, details_json FROM audit_events ORDER BY timestamp DESC, sequence_number DESC LIMIT ?",
        )
        .all(limit) as {
        event_id: string;
        session_id: string;
        sequence_number: number;
        event_kind: string;
        classification: string;
        timestamp: string;
        action_digest: string | null;
        details_json: string;
      }[];
      return {
        total,
        events: rows.map((row) => {
          const details = parseJsonColumn<Record<string, unknown>>(row.details_json, {});
          const envelope = typeof details.version === "number" && "event" in details;
          return {
            eventId: row.event_id,
            sessionId: row.session_id,
            sequenceNumber: row.sequence_number,
            eventKind: row.event_kind,
            classification: row.classification,
            timestamp: row.timestamp,
            actionDigest: row.action_digest,
            operatorId: typeof details.operator_id === "string" ? details.operator_id : null,
            policyId: typeof details.policy_id === "string" ? details.policy_id : null,
            event: envelope ? details.event : details,
            nonCoreEnvelope: !envelope,
          };
        }),
      };
    } finally {
      db.close();
    }
  }

  async audit(tenant: TenantRecord, limit: number, signal?: AbortSignal): Promise<CoreAuditView> {
    const session = await this.session(tenant, signal);
    const { events, total } = this.auditEvents(tenant, limit);
    const tasks = this.tasks(tenant, limit);
    return { session, events, totalEvents: total, tasks: tasks.tasks, totalTasks: tasks.total };
  }

  async research(tenant: TenantRecord, signal?: AbortSignal): Promise<ResearchSessionsView> {
    const session = await this.session(tenant, signal);
    const tasks = this.tasks(tenant, 200).tasks;
    const db = this.open(tenant);
    const view: ResearchSessionsView = { session, tasks, budgetReservations: [], approvals: [] };
    if (!db) return view;
    try {
      view.budgetReservations = (
        db
          .query(
            "SELECT reservation_id, model_id, reserved_cost_micro_usd, actual_cost_micro_usd, state, reserved_at, settled_at FROM budget_reservations ORDER BY reserved_at DESC LIMIT 200",
          )
          .all() as {
          reservation_id: string;
          model_id: string;
          reserved_cost_micro_usd: number;
          actual_cost_micro_usd: number | null;
          state: string;
          reserved_at: string;
          settled_at: string | null;
        }[]
      ).map((row) => ({
        reservationId: row.reservation_id,
        modelId: row.model_id,
        reservedMicroUsd: row.reserved_cost_micro_usd,
        actualMicroUsd: row.actual_cost_micro_usd,
        state: row.state,
        reservedAt: row.reserved_at,
        settledAt: row.settled_at,
      }));
      view.approvals = (
        db
          .query(
            "SELECT request_id, action_name, state, classification, display_summary, created_at, expires_at FROM approval_requests ORDER BY created_at DESC LIMIT 200",
          )
          .all() as {
          request_id: string;
          action_name: string;
          state: string;
          classification: string;
          display_summary: string;
          created_at: string;
          expires_at: string;
        }[]
      ).map((row) => ({
        requestId: row.request_id,
        actionName: row.action_name,
        state: row.state,
        classification: row.classification,
        displaySummary: row.display_summary,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
      }));
    } catch (error) {
      log.warn("core research read failed", { tenant: tenant.tenantId, error: String(error) });
    } finally {
      db.close();
    }
    return view;
  }
}
