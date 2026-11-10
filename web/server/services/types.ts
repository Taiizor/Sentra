import type {
  DependencyInventoryView,
  IntelStatusView,
  OsvQueryResponse,
  ScanKind,
  ScanRunView,
  ScanStreamEvent,
  ScanTrigger,
} from "../../src/types/api.ts";

/** A principal or named system actor recorded on audit entries and scan runs. */
export interface ActorRef {
  label: string;
  role: string;
}

export const SYSTEM_ACTOR: ActorRef = { label: "system", role: "system" };

export interface ScanRunInput {
  tenantId: string;
  kind: ScanKind;
  trigger: ScanTrigger;
  actor: ActorRef;
  signal?: AbortSignal;
  onEvent?: (event: ScanStreamEvent) => void;
}

/**
 * Runs real scans through the core CLI (SAST, CodeQL language probe) and the OSV API
 * (dependency vulnerabilities over the core's lockfile inventory), persists the run and
 * reconciles findings (new / still open / resolved). Implemented in services/scans.ts.
 */
export interface ScanService {
  run(input: ScanRunInput): Promise<ScanRunView>;
  isRunning(tenantId: string): boolean;
}

/** OSV.dev access, gated by an admin policy switch because it discloses package inventories. */
export interface OsvService {
  enabled(): boolean;
  status(): IntelStatusView;
  setEnabled(enabled: boolean, actor: ActorRef): IntelStatusView;
  query(pkg: string, ecosystem: string, version: string | null): Promise<OsvQueryResponse>;
  /**
   * Package inventory from `sentra inventory --workspace <dir> --json` (core lockfile parsers).
   * Concurrent and repeated reads of one workspace share a single core run for a short time;
   * `signal` only stops the caller from waiting.
   */
  inventory(workspace: string, signal?: AbortSignal): Promise<DependencyInventoryView>;
}
