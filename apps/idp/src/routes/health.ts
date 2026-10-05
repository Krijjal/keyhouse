import { Router } from 'express';
import type { PrismaClient } from '@keyhouse/db';
import type { Logger } from '../logger.js';
import type { Redis } from '../redis.js';

const CHECK_TIMEOUT_MS = 1500;

type CheckStatus = 'ok' | 'error';

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`timed out after ${ms}ms`));
    }, ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    clearTimeout(timer);
  });
}

async function check(
  name: string,
  fn: () => Promise<unknown>,
  logger: Logger,
): Promise<CheckStatus> {
  try {
    await withTimeout(fn(), CHECK_TIMEOUT_MS);
    return 'ok';
  } catch (err) {
    // The detailed reason goes to the server log only. The HTTP response never
    // includes driver errors, which can reveal hostnames, usernames or versions.
    logger.warn('health check failed', {
      check: name,
      reason: err instanceof Error ? err.message : 'unknown',
    });
    return 'error';
  }
}

export function healthRouter(deps: { prisma: PrismaClient; redis: Redis; logger: Logger }): Router {
  const router = Router();

  router.get('/health', async (_req, res) => {
    const [postgres, redis] = await Promise.all([
      check('postgres', () => deps.prisma.$queryRaw`SELECT 1`, deps.logger),
      check('redis', () => deps.redis.ping(), deps.logger),
    ]);
    const healthy = postgres === 'ok' && redis === 'ok';

    res
      .status(healthy ? 200 : 503)
      .set('Cache-Control', 'no-store')
      .json({ status: healthy ? 'ok' : 'error', checks: { postgres, redis } });
  });

  return router;
}
