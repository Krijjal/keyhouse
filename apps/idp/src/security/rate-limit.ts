import type { Redis } from '../redis.js';

/** Every rate-limit key lives under this prefix, so they never collide with other Redis data. */
export const RATE_LIMIT_PREFIX = 'rl:';

export interface WindowState {
  /** How many hits are in the current window (0 if there is no window). */
  count: number;
  /** Milliseconds until the window ends and the count resets (0 if there is no window). */
  retryAfterMs: number;
}

/**
 * ─── YOU IMPLEMENT THIS (learning item c) ───────────────────────────────────
 * Records one hit in a FIXED window and returns the state after the hit.
 *
 * The stored Redis key is RATE_LIMIT_PREFIX + key (e.g. key "login:ip:abc" → "rl:login:ip:abc").
 * Callers pass keys that are already hashed: a raw email never goes into Redis.
 *
 * Must:
 *  - Throw a RangeError if windowMs is not a positive integer (before touching Redis).
 *  - In ONE atomic MULTI transaction (ioredis: redis.multi()...exec()):
 *      1. INCR the key                          → the new count
 *      2. PEXPIRE the key windowMs NX            → set the TTL ONLY if the key has none yet
 *      3. PTTL the key                           → milliseconds left in the window
 *  - Return { count, retryAfterMs } from the INCR and PTTL results.
 *
 * Why atomic: with INCR and PEXPIRE as two separate calls, a crash or dropped connection
 * in between leaves a key with NO expiry. That counter never resets: a permanent lockout.
 *
 * Why NX: without it, every hit pushes the expiry back (a sliding window). An attacker
 * hitting slowly keeps the window open forever, and a real user who keeps retrying
 * never gets let back in. With NX, the window ends windowMs after the FIRST hit.
 *
 * Hints:
 *  - exec() resolves to an array with one [error, result] pair per queued command,
 *    or null if the transaction was aborted. Treat null or any error as a failure: throw.
 *  - The INCR and PTTL results arrive typed as unknown. Check they are numbers before using.
 *  - ioredis spells PEXPIRE with NX as: .pexpire(fullKey, windowMs, 'NX')
 */
export async function increment(redis: Redis, key: string, windowMs: number): Promise<WindowState> {
  if (windowMs <= 0 || !Number.isInteger(windowMs)) {
    throw new RangeError('windowMs must be a positive integer');
  }
  const fullKey = RATE_LIMIT_PREFIX + key;
  const results = await redis
    .multi()
    .incr(fullKey)
    .pexpire(fullKey, windowMs, 'NX')
    .pttl(fullKey)
    .exec();

  if (!results) {
    throw new Error('Transaction aborted');
  }

  const [incrResult, pexpireResult, pttlResult] = results;
  if (incrResult?.[0]) throw incrResult[0];
  const count = incrResult?.[1];
  if (pexpireResult?.[0]) throw pexpireResult[0];
  if (pttlResult?.[0]) throw pttlResult[0];

  const retryAfterMs = pttlResult?.[1];

  if (typeof count !== 'number' || typeof retryAfterMs !== 'number') {
    throw new Error('Unexpected result types from Redis');
  }

  return { count, retryAfterMs };
}

/**
 * ─── YOU IMPLEMENT THIS (learning item c) ───────────────────────────────────
 * Reads the current window WITHOUT recording a hit. Used to reject a blocked login
 * before any password work is done.
 *
 * Must:
 *  - Read the count (GET) and the time left (PTTL) of RATE_LIMIT_PREFIX + key.
 *  - Never create or modify the key.
 *  - If the key doesn't exist (GET returns null, PTTL returns -2), return { count: 0, retryAfterMs: 0 }.
 *  - Otherwise return the count as a number and the PTTL as retryAfterMs.
 *
 * Hint: both reads can go in one redis.multi() so they describe the same moment, but two
 * plain awaits are acceptable here: a read can't leave a key in a broken state.
 */
export async function peek(redis: Redis, key: string): Promise<WindowState> {
  const raw = await redis.get(RATE_LIMIT_PREFIX + key);
  const pttl = await redis.pttl(RATE_LIMIT_PREFIX + key);

  if (raw === null || pttl === -2) {
    return { count: 0, retryAfterMs: 0 };
  }
  const count = parseInt(raw, 10);
  if (isNaN(count)) {
    throw new Error('Unexpected result type from Redis');
  }
  return { count, retryAfterMs: pttl };
}

// ─── Written for you (not a learning item) ──────────────────────────────────

/** Ends a window early (e.g. a successful login resets the email counters). */
export async function resetCounter(redis: Redis, key: string): Promise<void> {
  await redis.del(RATE_LIMIT_PREFIX + key);
}
