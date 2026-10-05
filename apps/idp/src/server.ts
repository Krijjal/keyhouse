import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createPrismaClient } from '@keyhouse/db';
import { createApp } from './app.js';
import { ConfigError, loadConfig } from './config.js';
import { logger } from './logger.js';
import { createRedis } from './redis.js';

// Local development convenience: load the repo-root .env if present.
// Variables already set in the real environment take precedence.
const rootEnv = fileURLToPath(new URL('../../../.env', import.meta.url));
if (process.env.NODE_ENV !== 'production' && existsSync(rootEnv)) process.loadEnvFile(rootEnv);

let config;
try {
  config = loadConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(err.message + '\n');
    process.exit(1);
  }
  throw err;
}

const prisma = createPrismaClient(config.DATABASE_URL);
const redis = createRedis(config.REDIS_URL);
redis.on('error', (err: Error) => {
  logger.warn('redis error', { reason: err.message });
});

// Connect before listening: never accept traffic while a dependency is unreachable.
// Without this, the first requests after a restart would fail rate-limit checks.
try {
  await Promise.all([prisma.$connect(), redis.connect()]);
} catch (err) {
  logger.error('startup failed: dependency unavailable', {
    reason: err instanceof Error ? err.message : 'unknown',
  });
  process.exit(1);
}

const app = createApp({ config, prisma, redis, logger });
const server = app.listen(config.IDP_PORT, () => {
  logger.info('idp listening', { port: config.IDP_PORT, env: config.NODE_ENV });
});

function shutdown(signal: string): void {
  logger.info('shutting down', { signal });
  server.close(() => {
    void Promise.allSettled([prisma.$disconnect(), redis.quit()]).then(() => process.exit(0));
  });
}
process.on('SIGINT', () => {
  shutdown('SIGINT');
});
process.on('SIGTERM', () => {
  shutdown('SIGTERM');
});
