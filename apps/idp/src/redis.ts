import { Redis } from 'ioredis';

export function createRedis(url: string): Redis {
  return new Redis(url, {
    // Fail fast instead of queueing commands forever while Redis is down.
    // Rate limiting must not silently hang requests.
    connectTimeout: 2000,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    // With no offline queue, commands sent before the connection is ready are rejected.
    // So the caller must `await redis.connect()` before serving traffic (see server.ts).
    lazyConnect: true,
  });
}

export type { Redis };
