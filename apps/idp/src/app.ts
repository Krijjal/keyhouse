import express, { type ErrorRequestHandler, type Express } from 'express';
import type { PrismaClient } from '@keyhouse/db';
import type { Config } from './config.js';
import type { Logger } from './logger.js';
import type { Redis } from './redis.js';
import { healthRouter } from './routes/health.js';

export interface AppDeps {
  config: Config;
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
}

export function createApp(deps: AppDeps): Express {
  const app = express();

  // Don't advertise the framework to attackers fingerprinting the stack.
  app.disable('x-powered-by');
  // No reverse proxy in front yet. Leaving this off means req.ip is the real socket
  // address; turning it on blindly would let clients spoof X-Forwarded-For and
  // dodge per-IP rate limits.
  app.set('trust proxy', false);

  // Small body limit: auth payloads are tiny, large bodies are only a DoS vector.
  app.use(express.json({ limit: '10kb' }));

  app.use(healthRouter(deps));

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  const errorHandler: ErrorRequestHandler = (err: unknown, _req, res, _next) => {
    // Malformed JSON / oversized body from express.json().
    if (isHttpError(err) && err.status >= 400 && err.status < 500) {
      res.status(err.status).json({ error: 'bad_request' });
      return;
    }
    deps.logger.error('unhandled error', {
      error:
        err instanceof Error
          ? { name: err.name, message: err.message, stack: err.stack }
          : 'unknown',
    });
    // Generic response: no stack traces or internal messages to the client.
    res.status(500).json({ error: 'internal_error' });
  };
  app.use(errorHandler);

  return app;
}

function isHttpError(err: unknown): err is { status: number } {
  return (
    typeof err === 'object' && err !== null && 'status' in err && typeof err.status === 'number'
  );
}
