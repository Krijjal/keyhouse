import { Redis } from 'ioredis';

export function createRedis(url: string): Redis {
  return new Redis(url, {
    // Fail fast instead of queueing commands forever while Redis is down.
    // Rate limiting must not silently hang requests.
    connectTimeout: 2000,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
  });
}

export type { Redis };
