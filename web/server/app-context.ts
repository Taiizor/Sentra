import type { Database } from "bun:sqlite";
import type { AuditLog } from "./audit-log.ts";
import type { AuthService } from "./auth.ts";
import type { ServerConfig } from "./config.ts";
import type { GitHubService } from "./github.ts";
import type { LlmGateway } from "./llm.ts";
import type { SecretStore } from "./secrets.ts";
import type { SentraCli } from "./sentra-cli.ts";
import type { CoreStoreReader } from "./services/core-store.ts";
import type { SettingsStore } from "./services/settings-store.ts";
import type { OsvService, ScanService } from "./services/types.ts";
import type { WorkspaceService } from "./services/workspaces.ts";

/** Everything a route module may use. Built once in main.ts#createApp. */
export interface AppContext {
  config: ServerConfig;
  /** Bridge-owned SQLite store (never a core store). */
  db: Database;
  auth: AuthService;
  audit: AuditLog;
  secrets: SecretStore;
  settings: SettingsStore;
  cli: SentraCli;
  llm: LlmGateway;
  github: GitHubService;
  workspaces: WorkspaceService;
  coreStore: CoreStoreReader;
  osv: OsvService;
  scans: ScanService;
}
