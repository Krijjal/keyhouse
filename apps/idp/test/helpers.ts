import { createPrismaClient } from '@keyhouse/db';
import { createApp, type AppDeps } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import type { Logger } from '../src/logger.js';
import type { Mailer, MailMessage } from '../src/mail/mailer.js';
import { createRedis } from '../src/redis.js';
import { PwnedCheckUnavailable, type PwnedChecker } from '../src/security/pwned.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set for integration tests (see .env.example)`);
  return value;
}

export interface LogLine {
  level: string;
  msg: string;
  fields?: Record<string, unknown>;
}

/** Logger that records calls instead of printing, so tests stay quiet and can inspect output. */
export function createTestLogger(): Logger & { lines: LogLine[] } {
  const lines: LogLine[] = [];
  const rec = (level: string) => (msg: string, fields?: Record<string, unknown>) => {
    lines.push(fields ? { level, msg, fields } : { level, msg });
  };
  return { lines, debug: rec('debug'), info: rec('info'), warn: rec('warn'), error: rec('error') };
}

/** Mailer that keeps messages in memory. `waitFor` resolves when a message to `to` arrives. */
export function createTestMailer(): Mailer & {
  sent: MailMessage[];
  waitFor(to: string, timeoutMs?: number): Promise<MailMessage>;
} {
  const sent: MailMessage[] = [];
  return {
    sent,
    send(message) {
      sent.push(message);
      return Promise.resolve();
    },
    async waitFor(to, timeoutMs = 2000) {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const found = sent.find((m) => m.to === to);
        if (found) return found;
        await new Promise((r) => setTimeout(r, 10));
      }
      throw new Error(`no email to ${to} within ${timeoutMs}ms`);
    },
  };
}

/** Passwords the fake breach checker reports as breached. No network calls in tests. */
export const BREACHED_PASSWORDS = new Set(['password1234', 'qwertyuiop123']);

export function createFakePwned(mode: 'normal' | 'unavailable' = 'normal'): PwnedChecker {
  return (password) =>
    mode === 'unavailable'
      ? Promise.reject(new PwnedCheckUnavailable('TimeoutError'))
      : Promise.resolve(BREACHED_PASSWORDS.has(password));
}

/** Pulls the token out of a link like https://.../verify-email#token=abc */
export function tokenFromEmail(message: MailMessage): string {
  const match = /#token=([A-Za-z0-9_-]+)/.exec(message.text);
  if (!match?.[1]) throw new Error('no #token= link in email');
  return match[1];
}

export type TestDeps = AppDeps & {
  logger: ReturnType<typeof createTestLogger>;
  mailer: ReturnType<typeof createTestMailer>;
};

/**
 * Builds deps pointed at the TEST database and TEST Redis DB, connected the same way
 * server.ts connects them. Overrides allow fault injection and are used as given.
 */
export async function createTestDeps(overrides: Partial<AppDeps> = {}): Promise<TestDeps> {
  const databaseUrl = required('TEST_DATABASE_URL');
  const redisUrl = required('TEST_REDIS_URL');
  const config = loadConfig({
    ...process.env,
    NODE_ENV: 'test',
    DATABASE_URL: databaseUrl,
    REDIS_URL: redisUrl,
  });
  const prisma = overrides.prisma ?? createPrismaClient(databaseUrl);
  const redis = overrides.redis ?? createRedis(redisUrl);
  if (!overrides.prisma) await prisma.$connect();
  if (!overrides.redis) await redis.connect();
  return {
    config,
    prisma,
    redis,
    logger: createTestLogger(),
    mailer: createTestMailer(),
    pwned: createFakePwned(),
    ...overrides,
  } as TestDeps;
}

export async function closeDeps(deps: AppDeps): Promise<void> {
  await Promise.allSettled([deps.prisma.$disconnect(), deps.redis.quit()]);
}

export { createApp };
