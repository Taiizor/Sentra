type Level = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const configuredLevel = (process.env.SENTRA_WEB_LOG_LEVEL ?? "info").toLowerCase() as Level;
const threshold = LEVEL_ORDER[configuredLevel] ?? LEVEL_ORDER.info;

const SECRET_PATTERNS: RegExp[] = [
  /\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g,
  /\b(github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\b(sk-[A-Za-z0-9_-]{16,})\b/g,
  /\b(sk-ant-[A-Za-z0-9_-]{16,})\b/g,
  /\b(AIza[0-9A-Za-z_-]{30,})\b/g,
  /\b(xai-[A-Za-z0-9_-]{16,})\b/g,
  /(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
  /([?&](?:key|token|api_key|apikey)=)[^&\s]+/gi,
];

/** Masks credential-shaped substrings before anything is written to logs. */
export function redact(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (_match, prefix: string) =>
      prefix && (prefix.endsWith(" ") || prefix.endsWith("=")) ? `${prefix}[REDACTED]` : "[REDACTED]",
    );
  }
  return out;
}

function emit(level: Level, message: string, fields?: Record<string, unknown>) {
  if (LEVEL_ORDER[level] < threshold) return;
  const record: Record<string, unknown> = { ts: new Date().toISOString(), level, msg: message };
  if (fields) {
    for (const [key, value] of Object.entries(fields)) {
      record[key] = value instanceof Error ? value.message : value;
    }
  }
  const line = redact(JSON.stringify(record));
  if (level === "error" || level === "warn") {
    console.error(line);
  } else {
    console.log(line);
  }
}

export const log = {
  debug: (message: string, fields?: Record<string, unknown>) => emit("debug", message, fields),
  info: (message: string, fields?: Record<string, unknown>) => emit("info", message, fields),
  warn: (message: string, fields?: Record<string, unknown>) => emit("warn", message, fields),
  error: (message: string, fields?: Record<string, unknown>) => emit("error", message, fields),
};
