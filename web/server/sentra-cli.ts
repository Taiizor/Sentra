import fs from "node:fs";
import { HttpError } from "./http-error.ts";
import { log } from "./logger.ts";

/**
 * The only way the bridge executes the Rust core. Arguments are passed as an argv vector
 * (no shell), values are validated so they can never be parsed as flags, and every run has
 * a timeout, an output cap and a global concurrency limit.
 */

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
  /** Parsed stdout when it is a JSON document. */
  json: unknown;
  timedOut: boolean;
  durationMs: number;
}

export interface CliRunOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
  stdin?: string;
  signal?: AbortSignal;
  /** Called with each decoded stdout/stderr chunk while the process runs. */
  onOutput?: (stream: "stdout" | "stderr", text: string) => void;
}

export function cancelledBeforeStart(): HttpError {
  return new HttpError(499, "aborted", "The request was cancelled before the core process started");
}

/**
 * Counting semaphore with a bounded, abortable wait queue. A released slot passes directly to
 * the next waiter, so the limit holds even while waiters resume. When the queue is full a new
 * caller is refused (503) instead of waiting behind an unbounded backlog, and a caller whose
 * request was cancelled leaves the queue immediately.
 */
export class Semaphore {
  private active = 0;
  private readonly waiters: { grant: () => void }[] = [];
  private readonly limit: number;
  private readonly maxQueued: number;

  constructor(limit: number, maxQueued: number) {
    this.limit = limit;
    this.maxQueued = maxQueued;
  }

  acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) return Promise.reject(cancelledBeforeStart());
    if (this.active < this.limit) {
      this.active += 1;
      return Promise.resolve(this.releaser());
    }
    if (this.waiters.length >= this.maxQueued) {
      return Promise.reject(
        new HttpError(503, "core_busy", `The sentra core is busy (${this.active} running, ${this.waiters.length} queued). Try again shortly.`),
      );
    }
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) {
          this.waiters.splice(index, 1);
          reject(cancelledBeforeStart());
        }
      };
      const waiter = {
        grant: () => {
          signal?.removeEventListener("abort", onAbort);
          resolve(this.releaser());
        },
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  private releaser(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = this.waiters.shift();
      if (next) next.grant();
      else this.active -= 1;
    };
  }

  get pending(): number {
    return this.waiters.length;
  }

  get running(): number {
    return this.active;
  }
}

/** Resolves with `promise`, or rejects as soon as `signal` aborts (the promise keeps running). */
function untilAborted<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(cancelledBeforeStart());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(cancelledBeforeStart());
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/** Rejects values that the CLI parser could interpret as a flag or that carry control bytes. */
export function cliValue(value: string, field: string, maxLength = 4096): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, "invalid_request", `'${field}' must not be empty`);
  }
  if (value.length > maxLength) {
    throw new HttpError(400, "invalid_request", `'${field}' exceeds ${maxLength} characters`);
  }
  if (value.startsWith("-")) {
    throw new HttpError(400, "invalid_request", `'${field}' must not start with '-'`);
  }
  // oxlint-disable-next-line no-control-regex -- intentional: rejects control characters other than tab and line breaks in CLI arguments
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) {
    throw new HttpError(400, "invalid_request", `'${field}' contains control characters`);
  }
  return value;
}

/** Environment variables forwarded to the core (and through it, to plugin adapters). */
const ENV_ALLOWLIST = [
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "WINDIR",
  "COMSPEC",
  "TEMP",
  "TMP",
  "TMPDIR",
  "HOME",
  "USERPROFILE",
  "LOCALAPPDATA",
  "APPDATA",
  "PROGRAMDATA",
  "LANG",
  "LC_ALL",
];

function childEnv(): Record<string, string> {
  const env: Record<string, string> = { NO_COLOR: "1" };
  for (const name of ENV_ALLOWLIST) {
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  return env;
}

/** Waiting runs allowed per concurrent slot before new callers are refused with 503. */
const QUEUE_PER_SLOT = 16;
const MIN_QUEUE = 32;
const MAX_SHARED_ENTRIES = 256;

export class SentraCli {
  private readonly semaphore: Semaphore;
  readonly binaryPath: string;
  private readonly cwd: string;
  private readonly defaultTimeoutMs: number;
  private readonly shared = new Map<string, { promise: Promise<CliResult>; settledAt: number | null }>();

  constructor(binaryPath: string, cwd: string, defaultTimeoutMs: number, maxConcurrency: number) {
    this.binaryPath = binaryPath;
    this.cwd = cwd;
    this.defaultTimeoutMs = defaultTimeoutMs;
    this.semaphore = new Semaphore(maxConcurrency, Math.max(MIN_QUEUE, maxConcurrency * QUEUE_PER_SLOT));
  }

  available(): boolean {
    return fs.existsSync(this.binaryPath);
  }

  get queued(): number {
    return this.semaphore.pending;
  }

  /**
   * Runs a read-only command once for all concurrent callers with the same argv and reuses a
   * completed result for `ttlMs`. Read views (status, inventory, plugin and skill listings) use
   * this so repeated or parallel page loads cannot each start a core process. The shared process
   * is not tied to one caller: a caller's `signal` only stops that caller from waiting, and the
   * run itself is bounded by its timeout. Failures to start (busy, missing binary) are not cached.
   */
  async runShared(args: string[], options: { ttlMs: number; timeoutMs?: number; signal?: AbortSignal }): Promise<CliResult> {
    const key = args.join("\u0000");
    const now = Date.now();
    const existing = this.shared.get(key);
    if (existing && (existing.settledAt === null || now - existing.settledAt < options.ttlMs)) {
      return untilAborted(existing.promise, options.signal);
    }
    if (this.shared.size >= MAX_SHARED_ENTRIES) {
      for (const [entryKey, entry] of this.shared) {
        if (entry.settledAt !== null) this.shared.delete(entryKey);
      }
    }
    const entry: { promise: Promise<CliResult>; settledAt: number | null } = {
      promise: this.run(args, { timeoutMs: options.timeoutMs }),
      settledAt: null,
    };
    entry.promise = entry.promise.then(
      (result) => {
        entry.settledAt = Date.now();
        return result;
      },
      (error: unknown) => {
        if (this.shared.get(key) === entry) this.shared.delete(key);
        throw error;
      },
    );
    this.shared.set(key, entry);
    return untilAborted(entry.promise, options.signal);
  }

  async run(args: string[], options: CliRunOptions = {}): Promise<CliResult> {
    if (!this.available()) {
      throw new HttpError(503, "core_unavailable", "The sentra core binary was not found. Build it with `cargo build --release -p sentra-cli` or set SENTRA_BIN.");
    }
    if (args.length > 64) {
      throw new HttpError(400, "invalid_request", "Too many CLI arguments");
    }
    const release = await this.semaphore.acquire(options.signal);
    const started = performance.now();
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const maxOutput = options.maxOutputBytes ?? 32 * 1024 * 1024;
    try {
      // The caller may have gone away while the run waited for a slot.
      if (options.signal?.aborted) throw cancelledBeforeStart();
      const child = Bun.spawn([this.binaryPath, ...args], {
        cwd: this.cwd,
        stdin: options.stdin !== undefined ? "pipe" : "ignore",
        stdout: "pipe",
        stderr: "pipe",
        windowsHide: true,
        // Credentials (GitHub tokens, provider keys) never reach the core or plugin adapters.
        env: childEnv(),
      });
      if (options.stdin !== undefined && child.stdin) {
        child.stdin.write(options.stdin);
        await child.stdin.end();
      }
      let timedOut = false;
      let overflow = false;
      const kill = () => {
        try {
          child.kill();
        } catch {
          // process already exited
        }
      };
      const timer = setTimeout(() => {
        timedOut = true;
        kill();
      }, timeoutMs);
      const onAbort = () => kill();
      options.signal?.addEventListener("abort", onAbort, { once: true });

      const collect = async (stream: ReadableStream<Uint8Array>, name: "stdout" | "stderr"): Promise<string> => {
        const decoder = new TextDecoder();
        const reader = stream.getReader();
        let text = "";
        let bytes = 0;
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes > maxOutput) {
            overflow = true;
            kill();
            await reader.cancel().catch(() => {});
            break;
          }
          const chunk = decoder.decode(value, { stream: true });
          text += chunk;
          options.onOutput?.(name, chunk);
        }
        return text + decoder.decode();
      };

      const [stdout, stderr] = await Promise.all([collect(child.stdout, "stdout"), collect(child.stderr, "stderr")]);
      const code = await child.exited;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      const durationMs = Math.round(performance.now() - started);

      if (overflow) {
        throw new HttpError(502, "core_output_too_large", "The sentra core produced more output than the bridge accepts");
      }
      let json: unknown = undefined;
      const trimmed = stdout.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          json = JSON.parse(trimmed);
        } catch {
          json = undefined;
        }
      }
      log.debug("sentra cli finished", { command: args[0], code, durationMs, timedOut });
      return { code, stdout, stderr, json, timedOut, durationMs };
    } finally {
      release();
    }
  }

  /**
   * Runs a `--json` command and returns the parsed document, mapping CLI failures to an
   * HttpError that carries the core's own error code when it printed one.
   */
  async runJson<T = Record<string, unknown>>(args: string[], options: CliRunOptions = {}): Promise<T> {
    return requireJson<T>(args[0] ?? "sentra", await this.run(args, options));
  }
}

/** The parsed JSON document of a successful `--json` run; timeouts and failures become HttpErrors. */
export function requireJson<T = Record<string, unknown>>(command: string, result: CliResult): T {
  if (result.timedOut) {
    throw new HttpError(504, "core_timeout", `sentra ${command} timed out`);
  }
  if (result.code !== 0 || result.json === undefined) {
    throw cliFailure(command, result);
  }
  return result.json as T;
}

/** Builds an HttpError from a failed CLI invocation without echoing unbounded output. */
export function cliFailure(command: string, result: CliResult): HttpError {
  let coreCode: string | undefined;
  for (const candidate of [result.stdout, result.stderr]) {
    const trimmed = candidate.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      const value = parsed.error ?? parsed.code;
      if (typeof value === "string") {
        coreCode = value;
        break;
      }
    } catch {
      // not JSON
    }
  }
  const stderrLine = result.stderr.trim().split(/\r?\n/).slice(0, 3).join(" ").slice(0, 400);
  const message = coreCode
    ? `sentra ${command} failed: ${coreCode}`
    : `sentra ${command} exited with code ${result.code}${stderrLine ? `: ${stderrLine}` : ""}`;
  return new HttpError(422, "core_command_failed", message, { command, exitCode: result.code, coreError: coreCode ?? null });
}
