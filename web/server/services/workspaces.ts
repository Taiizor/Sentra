import { Database } from "bun:sqlite";
import fs from "node:fs";
import path from "node:path";
import type { CoreStoreState, IsolationLevel, RepositoryRef, TenantView } from "../../src/types/api.ts";
import type { ServerConfig } from "../config.ts";
import { nowIso } from "../db.ts";
import { isValidRepoRef, parseGitHubRemote, readHead, readRemoteUrl } from "../git-meta.ts";
import { GITHUB_WEB_HOST } from "../github.ts";
import { HttpError } from "../http-error.ts";
import { log } from "../logger.ts";
import { isWithin, realDirectory } from "../paths.ts";
import { cliFailure, cliValue, type SentraCli } from "../sentra-cli.ts";
import { STATUS_VIEW_TTL_MS } from "./core-store.ts";
import type { ActorRef } from "./types.ts";

export interface TenantRecord {
  tenantId: string;
  name: string;
  description: string;
  workspace: string;
  isolationLevel: IsolationLevel;
  githubOwner: string | null;
  githubRepo: string | null;
  createdAt: string;
  createdBy: string;
  importedFrom: string | null;
}

interface TenantRow {
  tenant_id: string;
  name: string;
  description: string;
  workspace: string;
  isolation_level: IsolationLevel;
  github_owner: string | null;
  github_repo: string | null;
  created_at: string;
  created_by: string;
  imported_from: string | null;
}

export const TENANT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** Console page names; a tenant with one of these ids could not be addressed by URL. */
const RESERVED_TENANT_IDS = new Set([
  "overview",
  "studio",
  "findings",
  "remediation",
  "intel",
  "research",
  "fleet",
  "pull-requests",
  "webhooks",
  "plugins",
  "audit",
  "settings",
  "api",
  "assets",
]);

/** Demo rows that earlier dashboard builds seeded into SQLite; never imported. */
const LEGACY_DEMO_TENANT_IDS = new Set(["tenant-alpha", "acme-corp"]);

/**
 * The same builds also seeded a `sentra-internal` row pointing at the repository checkout. It
 * was written by the bridge on first start, not registered by an operator, so it is skipped
 * while it still carries the seeded name and description. A row an operator edited is imported.
 */
const LEGACY_SEEDED_ROWS: ReadonlyMap<string, { name: string; description: string }> = new Map([
  ["sentra-internal", { name: "Sentra Core (Internal)", description: "Core platform codebase and internal services" }],
]);

export function isLegacySeedRow(row: { tenantId: string; name: string | null; description: string | null }): boolean {
  if (LEGACY_DEMO_TENANT_IDS.has(row.tenantId)) return true;
  const seeded = LEGACY_SEEDED_ROWS.get(row.tenantId);
  return !!seeded && (row.name ?? "") === seeded.name && (row.description ?? "") === seeded.description;
}

function fromRow(row: TenantRow): TenantRecord {
  return {
    tenantId: row.tenant_id,
    name: row.name,
    description: row.description,
    workspace: row.workspace,
    isolationLevel: row.isolation_level,
    githubOwner: row.github_owner,
    githubRepo: row.github_repo,
    createdAt: row.created_at,
    createdBy: row.created_by,
    importedFrom: row.imported_from,
  };
}

export function parseRepositorySlug(value: string): { owner: string; repo: string } {
  const match = value.trim().match(/^([^/\s]+)\/([^/\s]+)$/);
  const ref = match ? { owner: match[1], repo: match[2].replace(/\.git$/, "") } : null;
  if (!ref || !isValidRepoRef(ref)) {
    throw new HttpError(400, "invalid_repository", "Repository must look like owner/name");
  }
  return ref;
}

/**
 * Registry of tenant workspaces (bridge-owned) plus the per-tenant core store, which is
 * created and inspected exclusively through the `sentra` CLI. Core stores live in
 * `<dataDir>/core-stores/<tenantId>.db`, outside every workspace.
 */
export class WorkspaceService {
  private readonly storeState = new Map<string, { state: CoreStoreState; at: number }>();
  private readonly storesDir: string;
  private readonly db: Database;
  private readonly cli: SentraCli;
  private readonly config: ServerConfig;

  constructor(db: Database, cli: SentraCli, config: ServerConfig) {
    this.db = db;
    this.cli = cli;
    this.config = config;
    this.storesDir = path.join(config.dataDir, "core-stores");
    fs.mkdirSync(this.storesDir, { recursive: true });
  }

  list(): TenantRecord[] {
    return (this.db.query("SELECT * FROM tenants ORDER BY created_at ASC").all() as TenantRow[]).map(fromRow);
  }

  find(tenantId: string): TenantRecord | null {
    const row = this.db.query("SELECT * FROM tenants WHERE tenant_id = ?").get(tenantId) as TenantRow | null;
    return row ? fromRow(row) : null;
  }

  get(tenantId: string): TenantRecord {
    if (!TENANT_ID_RE.test(tenantId)) throw new HttpError(400, "invalid_tenant", "Invalid tenant id");
    const tenant = this.find(tenantId);
    if (!tenant) throw new HttpError(404, "tenant_not_found", `Tenant '${tenantId}' is not registered`);
    return tenant;
  }

  coreStorePath(tenantId: string): string {
    return path.join(this.storesDir, `${tenantId}.db`);
  }

  /** Returns the canonical workspace root, failing when it is missing or unsafe. */
  workspaceRoot(tenant: TenantRecord): string {
    try {
      return realDirectory(tenant.workspace, "workspace");
    } catch {
      throw new HttpError(409, "workspace_missing", `The workspace for '${tenant.tenantId}' no longer exists: ${tenant.workspace}`);
    }
  }

  validateWorkspace(raw: string): string {
    // realDirectory refuses UNC/device paths (in any separator form) before touching the disk.
    const root = realDirectory(raw, "workspace");
    if (path.parse(root).root === root) {
      throw new HttpError(400, "invalid_workspace", "A filesystem root cannot be registered as a workspace");
    }
    if (isWithin(root, this.config.dataDir) || isWithin(this.config.dataDir, root)) {
      throw new HttpError(400, "invalid_workspace", "The workspace must not contain, or be inside, the Sentra data directory");
    }
    if (this.config.workspaceRoots.length > 0 && !this.config.workspaceRoots.some((allowed) => isWithin(allowed, root))) {
      throw new HttpError(403, "workspace_not_allowed", "The workspace is outside SENTRA_WEB_WORKSPACE_ROOTS");
    }
    return root;
  }

  async create(
    input: {
      tenantId: string;
      name: string;
      description: string;
      workspace: string;
      isolationLevel: IsolationLevel;
      githubRepository: string | null;
    },
    actor: ActorRef,
  ): Promise<TenantRecord> {
    if (!TENANT_ID_RE.test(input.tenantId)) {
      throw new HttpError(400, "invalid_tenant", "Tenant id must be 1-64 chars of a-z, 0-9, '-', '_' and start with a letter or digit");
    }
    if (RESERVED_TENANT_IDS.has(input.tenantId)) {
      throw new HttpError(400, "invalid_tenant", `'${input.tenantId}' is reserved by the console (it names a page)`);
    }
    if (this.find(input.tenantId)) throw new HttpError(409, "tenant_exists", `Tenant '${input.tenantId}' already exists`);
    const workspace = this.validateWorkspace(input.workspace);
    const repo = input.githubRepository ? parseRepositorySlug(input.githubRepository) : null;
    const store = this.coreStorePath(input.tenantId);
    if (fs.existsSync(store)) {
      throw new HttpError(409, "core_store_exists", `A core store already exists for '${input.tenantId}'; remove ${store} or choose another id`);
    }
    await this.initCoreStore(workspace, store);
    const record: TenantRecord = {
      tenantId: input.tenantId,
      name: input.name,
      description: input.description,
      workspace,
      isolationLevel: input.isolationLevel,
      githubOwner: repo?.owner ?? null,
      githubRepo: repo?.repo ?? null,
      createdAt: nowIso(),
      createdBy: actor.label,
      importedFrom: null,
    };
    this.insert(record);
    this.storeState.delete(record.tenantId);
    return record;
  }

  update(tenantId: string, input: { name?: string; description?: string; githubRepository?: string | null }): TenantRecord {
    const tenant = this.get(tenantId);
    const next = { ...tenant };
    if (input.name !== undefined) next.name = input.name;
    if (input.description !== undefined) next.description = input.description;
    if (input.githubRepository !== undefined) {
      const repo = input.githubRepository ? parseRepositorySlug(input.githubRepository) : null;
      next.githubOwner = repo?.owner ?? null;
      next.githubRepo = repo?.repo ?? null;
    }
    this.db
      .query("UPDATE tenants SET name = ?, description = ?, github_owner = ?, github_repo = ? WHERE tenant_id = ?")
      .run(next.name, next.description, next.githubOwner, next.githubRepo, tenantId);
    return next;
  }

  /** Unregisters a tenant. Its core store and history stay on disk for forensics. */
  remove(tenantId: string): TenantRecord {
    const tenant = this.get(tenantId);
    this.db.query("DELETE FROM tenants WHERE tenant_id = ?").run(tenantId);
    this.storeState.delete(tenantId);
    return tenant;
  }

  private insert(record: TenantRecord): void {
    this.db
      .query(
        `INSERT INTO tenants (tenant_id, name, description, workspace, isolation_level, github_owner, github_repo, created_at, created_by, imported_from)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.tenantId,
        record.name,
        record.description,
        record.workspace,
        record.isolationLevel,
        record.githubOwner,
        record.githubRepo,
        record.createdAt,
        record.createdBy,
        record.importedFrom,
      );
  }

  private async initCoreStore(workspace: string, store: string): Promise<void> {
    const result = await this.cli.run(["init", "--workspace", cliValue(workspace, "workspace"), "--database", cliValue(store, "database"), "--json"]);
    if (result.code !== 0) throw cliFailure("init", result);
  }

  /**
   * Ensures the tenant's core store exists and opens cleanly (`sentra status`). The result
   * is cached for 30 seconds to keep list views cheap.
   */
  async coreStoreState(tenant: TenantRecord, refresh = false): Promise<CoreStoreState> {
    const cached = this.storeState.get(tenant.tenantId);
    if (!refresh && cached && Date.now() - cached.at < 30_000) return cached.state;
    let state: CoreStoreState;
    try {
      const workspace = this.workspaceRoot(tenant);
      const store = this.coreStorePath(tenant.tenantId);
      if (!fs.existsSync(store)) {
        await this.initCoreStore(workspace, store);
      }
      // Shared with concurrent readers (CoreStoreReader.session runs the same argv); a refresh
      // still joins an in-flight run but never reuses a completed one.
      const status = await this.cli.runShared(["status", "--database", store, "--workspace", workspace, "--json"], {
        ttlMs: refresh ? 0 : STATUS_VIEW_TTL_MS,
      });
      state = status.code === 0 ? { initialized: true, error: null } : { initialized: false, error: cliFailure("status", status).message };
    } catch (error) {
      state = { initialized: false, error: error instanceof Error ? error.message : String(error) };
    }
    this.storeState.set(tenant.tenantId, { state, at: Date.now() });
    return state;
  }

  repository(tenant: TenantRecord): RepositoryRef | null {
    if (tenant.githubOwner && tenant.githubRepo) {
      return { owner: tenant.githubOwner, repo: tenant.githubRepo, source: "configured" };
    }
    if (!fs.existsSync(tenant.workspace)) return null;
    const remote = readRemoteUrl(tenant.workspace);
    const parsed = remote ? parseGitHubRemote(remote, GITHUB_WEB_HOST) : null;
    return parsed ? { ...parsed, source: "git_remote" } : null;
  }

  async view(tenant: TenantRecord, refreshStore = false): Promise<TenantView> {
    const workspaceExists = fs.existsSync(tenant.workspace) && fs.statSync(tenant.workspace).isDirectory();
    const head = workspaceExists ? readHead(tenant.workspace) : null;
    return {
      tenantId: tenant.tenantId,
      name: tenant.name,
      description: tenant.description,
      workspace: tenant.workspace,
      workspaceExists,
      isolationLevel: tenant.isolationLevel,
      githubRepository: workspaceExists ? this.repository(tenant) : null,
      gitHead: head ? { branch: head.branch, sha: head.sha } : null,
      createdAt: tenant.createdAt,
      createdBy: tenant.createdBy,
      coreStore: workspaceExists
        ? await this.coreStoreState(tenant, refreshStore)
        : { initialized: false, error: "workspace directory is missing" },
    };
  }

  /**
   * One-time, read-only import of tenant registrations from the legacy dashboard store
   * (`<dataDir>/sentra.db`). Demo seed rows and registrations whose workspace does not exist
   * are skipped. The legacy file is never modified.
   */
  importLegacyTenants(settingsDone: () => boolean, markDone: (summary: unknown) => void): void {
    if (settingsDone()) return;
    const legacy = path.join(this.config.dataDir, "sentra.db");
    const summary: { imported: string[]; skipped: { tenantId: string; reason: string }[]; source: string } = {
      imported: [],
      skipped: [],
      source: legacy,
    };
    if (fs.existsSync(legacy)) {
      let source: Database | null = null;
      try {
        source = new Database(legacy, { readonly: true });
        const hasTable = source.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'tenants'").get();
        if (hasTable) {
          const rows = source.query("SELECT tenant_id, name, description, default_workspace, isolation_level, created_at FROM tenants").all() as {
            tenant_id: string;
            name: string;
            description: string | null;
            default_workspace: string | null;
            isolation_level: string | null;
            created_at: string;
          }[];
          for (const row of rows) {
            const tenantId = String(row.tenant_id).toLowerCase();
            const skip = (reason: string) => summary.skipped.push({ tenantId, reason });
            if (isLegacySeedRow({ tenantId, name: row.name, description: row.description })) {
              skip("seeded by an earlier dashboard build, not registered by an operator; register the workspace manually if it is needed");
              continue;
            }
            if (!TENANT_ID_RE.test(tenantId)) {
              skip("invalid tenant id");
              continue;
            }
            if (this.find(tenantId)) {
              skip("already registered");
              continue;
            }
            const workspaceRaw = row.default_workspace ?? "";
            let workspace: string;
            try {
              workspace = this.validateWorkspace(workspaceRaw);
            } catch (error) {
              skip(`workspace rejected: ${error instanceof Error ? error.message : String(error)}`);
              continue;
            }
            this.insert({
              tenantId,
              name: String(row.name || tenantId).slice(0, 120),
              description: String(row.description ?? "").slice(0, 500),
              workspace,
              isolationLevel: row.isolation_level === "single_operator" ? "single_operator" : "multi_tenant_isolated",
              githubOwner: null,
              githubRepo: null,
              createdAt: row.created_at,
              createdBy: "legacy-import",
              importedFrom: legacy,
            });
            summary.imported.push(tenantId);
          }
        }
      } catch (error) {
        log.warn("legacy tenant import failed", { error: error instanceof Error ? error.message : String(error) });
      } finally {
        source?.close();
      }
    }
    markDone(summary);
    if (summary.imported.length || summary.skipped.length) {
      log.info("legacy tenant registrations imported", summary);
    }
  }
}
