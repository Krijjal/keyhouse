import { createPrismaClient } from '@keyhouse/db';
import { createApp, type AppDeps } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import type { Logger } from '../src/logger.js';
import { createRedis } from '../src/redis.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set for integration tests (see .env.example)`);
  return value;
}

/** Logger that records calls instead of printing, so tests stay quiet and can inspect output. */
export function createTestLogger(): Logger & { lines: { level: string; msg: string }[] } {
  const lines: { level: string; msg: string }[] = [];
  const rec = (level: string) => (msg: string) => {
    lines.push({ level, msg });
  };
  return { lines, debug: rec('debug'), info: rec('info'), warn: rec('warn'), error: rec('error') };
}

/** Builds deps pointed at the TEST database and TEST Redis DB. Overrides allow fault injection. */
export function createTestDeps(overrides: Partial<AppDeps> = {}): AppDeps {
  const databaseUrl = required('TEST_DATABASE_URL');
  const redisUrl = required('TEST_REDIS_URL');
  const config = loadConfig({
    ...process.env,
    NODE_ENV: 'test',
    DATABASE_URL: databaseUrl,
    REDIS_URL: redisUrl,
  });
  return {
    config,
    prisma: createPrismaClient(databaseUrl),
    redis: createRedis(redisUrl),
    logger: createTestLogger(),
    ...overrides,
  };
}

export { createApp };
