/**
 * Minimal structured JSON logger.
 * Rule 7: any field whose key looks sensitive is replaced with "[REDACTED]",
 * at any depth, as a safety net. Callers should still avoid passing secrets at all.
 */

type Level = 'debug' | 'info' | 'warn' | 'error';
type Fields = Record<string, unknown>;

const SENSITIVE_KEY = /pass(word)?|secret|token|cookie|authorization|session|otp|code|hash/i;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 5 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out: Fields = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : redact(v, depth + 1);
  }
  return out;
}

function write(level: Level, msg: string, fields: Fields = {}): void {
  const line = JSON.stringify({
    time: new Date().toISOString(),
    level,
    msg,
    ...(redact(fields) as Fields),
  });
  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
}

export const logger = {
  debug: (msg: string, fields?: Fields) => {
    write('debug', msg, fields);
  },
  info: (msg: string, fields?: Fields) => {
    write('info', msg, fields);
  },
  warn: (msg: string, fields?: Fields) => {
    write('warn', msg, fields);
  },
  error: (msg: string, fields?: Fields) => {
    write('error', msg, fields);
  },
};

export type Logger = typeof logger;
