import type { Role } from "./config.ts";
import { HttpError } from "./http-error.ts";
import { log } from "./logger.ts";
import type { Permission } from "./permissions.ts";
import { asObject, type JsonObject } from "./validate.ts";

export { HttpError };

export interface Principal {
  role: Role;
  label: string;
  via: "session" | "bearer";
  sessionIdHash?: string;
}

/**
 * - public: no authentication (health, login, static assets)
 * - session: requires an authenticated principal holding `permission`
 * - webhook: authenticated by the handler itself (HMAC / shared token), never by cookies
 */
export type AuthMode = "public" | "session" | "webhook";

export interface RouteContext {
  req: Request;
  url: URL;
  params: Record<string, string>;
  principal: Principal | null;
  ip: string;
  readJson(maxBytes?: number): Promise<JsonObject>;
  readText(maxBytes?: number): Promise<string>;
}

/** Context for session routes, where the dispatcher guarantees an authenticated principal. */
export interface AuthedContext extends RouteContext {
  principal: Principal;
}

export type Handler<C extends RouteContext = RouteContext> = (ctx: C) => Promise<Response> | Response;

export interface RouteOptions {
  auth: AuthMode;
  permission?: Permission;
  /** Overrides the default request body limit for this route. */
  maxBodyBytes?: number;
}

export interface RouteDefinition {
  method: string;
  path: string;
  regex: RegExp;
  keys: string[];
  options: RouteOptions;
  handler: Handler<RouteContext>;
}

export interface RouteMatch {
  route: RouteDefinition;
  params: Record<string, string>;
}

function compilePath(pathPattern: string): { regex: RegExp; keys: string[] } {
  const keys: string[] = [];
  const source = pathPattern
    .split("/")
    .map((segment) => {
      if (segment.startsWith(":")) {
        keys.push(segment.slice(1));
        return "([^/]+)";
      }
      return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");
  return { regex: new RegExp(`^${source}$`), keys };
}

export class Router {
  private readonly routes: RouteDefinition[] = [];

  private add(method: string, path: string, options: RouteOptions, handler: Handler<any>): void {
    if (options.auth === "session" && !options.permission) {
      throw new Error(`Route ${method} ${path} requires an explicit permission`);
    }
    const { regex, keys } = compilePath(path);
    this.routes.push({ method, path, regex, keys, options, handler });
  }

  get(path: string, options: RouteOptions & { auth: "session" }, handler: Handler<AuthedContext>): void;
  get(path: string, options: RouteOptions, handler: Handler<RouteContext>): void;
  get(path: string, options: RouteOptions, handler: Handler<any>): void {
    this.add("GET", path, options, handler);
  }

  post(path: string, options: RouteOptions & { auth: "session" }, handler: Handler<AuthedContext>): void;
  post(path: string, options: RouteOptions, handler: Handler<RouteContext>): void;
  post(path: string, options: RouteOptions, handler: Handler<any>): void {
    this.add("POST", path, options, handler);
  }

  put(path: string, options: RouteOptions & { auth: "session" }, handler: Handler<AuthedContext>): void {
    this.add("PUT", path, options, handler);
  }

  delete(path: string, options: RouteOptions & { auth: "session" }, handler: Handler<AuthedContext>): void {
    this.add("DELETE", path, options, handler);
  }

  /** Returns the matching route, `"method_not_allowed"` when only the method differs, or null. */
  match(method: string, pathname: string): RouteMatch | "method_not_allowed" | null {
    let pathMatched = false;
    for (const route of this.routes) {
      const result = route.regex.exec(pathname);
      if (!result) continue;
      pathMatched = true;
      if (route.method !== method && !(method === "HEAD" && route.method === "GET")) continue;
      const params: Record<string, string> = {};
      route.keys.forEach((key, index) => {
        try {
          params[key] = decodeURIComponent(result[index + 1]);
        } catch {
          throw new HttpError(400, "invalid_request", `Malformed URL parameter '${key}'`);
        }
      });
      return { route, params };
    }
    return pathMatched ? "method_not_allowed" : null;
  }

  list(): readonly RouteDefinition[] {
    return this.routes;
  }
}

export const API_SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cache-Control": "no-store",
};

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

export function errorResponse(error: HttpError): Response {
  const body: { error: { code: string; message: string; details?: unknown } } = {
    error: { code: error.code, message: error.message },
  };
  if (error.details !== undefined) body.error.details = error.details;
  return json(body, error.status);
}

export function withHeaders(response: Response, headers: Record<string, string>): Response {
  for (const [key, value] of Object.entries(headers)) {
    if (!response.headers.has(key)) response.headers.set(key, value);
  }
  return response;
}

/** Reads a request body as text while enforcing a hard byte limit (also for chunked bodies). */
export async function readBodyText(req: Request, maxBytes: number): Promise<string> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isFinite(length) || length < 0) {
      throw new HttpError(400, "invalid_request", "Invalid Content-Length header");
    }
    if (length > maxBytes) {
      throw new HttpError(413, "payload_too_large", `Request body exceeds ${maxBytes} bytes`);
    }
  }
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new HttpError(413, "payload_too_large", `Request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

export async function readBodyJson(req: Request, maxBytes: number): Promise<JsonObject> {
  const contentType = (req.headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new HttpError(415, "unsupported_media_type", "Expected Content-Type: application/json");
  }
  const text = await readBodyText(req, maxBytes);
  if (!text.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json", "Request body is not valid JSON");
  }
  return asObject(parsed);
}

export interface SseChannel {
  send(event: string, data: unknown): void;
  readonly closed: boolean;
}

/**
 * Interval of the SSE comment line (`: keep-alive`) written while a stream is open. Reverse proxies
 * close a response that sends nothing for their read timeout (nginx 60 s by default, Cloudflare
 * 100 s, IIS ARR 120 s); a CodeQL host analysis can be silent for many minutes, and a closed stream
 * cancels the scan.
 */
export const SSE_KEEPALIVE_MS = 15_000;

/**
 * Builds a Server-Sent Events response. `run` receives a channel and an AbortSignal that
 * fires when the client disconnects; the stream closes when `run` settles. A comment line is
 * written every `keepAliveMs` while the stream is open (clients ignore comment lines).
 */
export function sseResponse(
  request: Request,
  run: (channel: SseChannel, signal: AbortSignal) => Promise<void>,
  options: { keepAliveMs?: number } = {},
): Response {
  const encoder = new TextEncoder();
  let closed = false;
  let keepAlive: ReturnType<typeof setInterval> | null = null;
  const stopKeepAlive = () => {
    if (keepAlive) clearInterval(keepAlive);
    keepAlive = null;
  };
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      keepAlive = setInterval(() => {
        if (closed) return stopKeepAlive();
        try {
          controller.enqueue(encoder.encode(": keep-alive\n\n"));
        } catch {
          closed = true;
          stopKeepAlive();
        }
      }, options.keepAliveMs ?? SSE_KEEPALIVE_MS);
      const channel: SseChannel = {
        send(event, data) {
          if (closed) return;
          try {
            controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
          } catch {
            closed = true;
          }
        },
        get closed() {
          return closed;
        },
      };
      try {
        await run(channel, request.signal);
      } catch (error) {
        if (!(error instanceof HttpError)) {
          log.error("stream failed", { error: error instanceof Error ? (error.stack ?? error.message) : String(error) });
        }
        // Same shape as the `error` member of ScanStreamEvent, which the console parser expects.
        const event =
          error instanceof HttpError
            ? { type: "error" as const, status: error.status, code: error.code, message: error.message }
            : { type: "error" as const, status: 500, code: "stream_failed", message: "The stream failed unexpectedly; see the bridge log." };
        channel.send(event.type, event);
      } finally {
        closed = true;
        stopKeepAlive();
        try {
          controller.close();
        } catch {
          // already closed by client disconnect
        }
      }
    },
    cancel() {
      closed = true;
      stopKeepAlive();
    },
  });
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
