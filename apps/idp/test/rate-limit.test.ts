import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createRedis, type Redis } from '../src/redis.js';
import { increment, peek, RATE_LIMIT_PREFIX, resetCounter } from '../src/security/rate-limit.js';

// ─── Learning item c: these fail until you implement increment / peek ───

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let redis: Redis;

beforeAll(async () => {
  const url = process.env.TEST_REDIS_URL;
  if (!url) throw new Error('TEST_REDIS_URL must be set (see .env.example)');
  redis = createRedis(url);
  await redis.connect();
});
afterAll(async () => {
  await redis.quit();
});
beforeEach(async () => {
  await redis.flushdb(); // the TEST Redis database only
});

describe('increment', () => {
  it('starts a window: count 1 and a TTL of about windowMs', async () => {
    const state = await increment(redis, 'k', 60_000);
    expect(state.count).toBe(1);
    expect(state.retryAfterMs).toBeGreaterThan(59_000);
    expect(state.retryAfterMs).toBeLessThanOrEqual(60_000);
  });

  it('counts every hit in the window', async () => {
    await increment(redis, 'k', 60_000);
    await increment(redis, 'k', 60_000);
    const third = await increment(redis, 'k', 60_000);
    expect(third.count).toBe(3);
  });

  it('stores the key under the rl: prefix, with an expiry', async () => {
    await increment(redis, 'login:ip:abc', 60_000);
    expect(await redis.get(`${RATE_LIMIT_PREFIX}login:ip:abc`)).toBe('1');
    expect(await redis.exists('login:ip:abc')).toBe(0);
    // -1 would mean "no expiry": a counter that never resets.
    expect(await redis.pttl(`${RATE_LIMIT_PREFIX}login:ip:abc`)).toBeGreaterThan(0);
  });

  it('keeps separate keys separate', async () => {
    await increment(redis, 'a', 60_000);
    await increment(redis, 'a', 60_000);
    const b = await increment(redis, 'b', 60_000);
    expect(b.count).toBe(1);
  });

  it('does NOT slide: later hits do not push the window back', async () => {
    await increment(redis, 'k', 1_000);
    await sleep(400);
    const later = await increment(redis, 'k', 1_000);
    // A sliding window would be back near 1000 ms here.
    expect(later.retryAfterMs).toBeLessThanOrEqual(650);
  });

  it('resets once the window has passed', async () => {
    await increment(redis, 'k', 200);
    await increment(redis, 'k', 200);
    await sleep(350);
    const fresh = await increment(redis, 'k', 200);
    expect(fresh.count).toBe(1);
  });

  it('is atomic: 50 parallel hits give counts 1..50 with no duplicates', async () => {
    const results = await Promise.all(
      Array.from({ length: 50 }, () => increment(redis, 'k', 60_000)),
    );
    const counts = results.map((r) => r.count).sort((x, y) => x - y);
    expect(counts).toEqual(Array.from({ length: 50 }, (_, i) => i + 1));
    expect(await redis.pttl(`${RATE_LIMIT_PREFIX}k`)).toBeGreaterThan(0);
  });

  it('repairs a key that somehow has no expiry instead of locking out forever', async () => {
    await redis.set(`${RATE_LIMIT_PREFIX}k`, '7'); // no TTL
    const state = await increment(redis, 'k', 60_000);
    expect(state.count).toBe(8);
    expect(state.retryAfterMs).toBeGreaterThan(0);
  });

  it('rejects a window that is not a positive integer, before touching Redis', async () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await expect(increment(redis, 'k', bad)).rejects.toBeInstanceOf(RangeError);
    }
    expect(await redis.exists(`${RATE_LIMIT_PREFIX}k`)).toBe(0);
  });
});

describe('peek', () => {
  it('returns zeros for a key that does not exist, and does not create it', async () => {
    await expect(peek(redis, 'nothing')).resolves.toEqual({ count: 0, retryAfterMs: 0 });
    expect(await redis.exists(`${RATE_LIMIT_PREFIX}nothing`)).toBe(0);
  });

  it('reads the current count and time left without changing them', async () => {
    await increment(redis, 'k', 60_000);
    await increment(redis, 'k', 60_000);

    const first = await peek(redis, 'k');
    const second = await peek(redis, 'k');
    expect(first.count).toBe(2);
    expect(second.count).toBe(2);
    expect(first.retryAfterMs).toBeGreaterThan(59_000);
    expect(first.retryAfterMs).toBeLessThanOrEqual(60_000);
  });
});

describe('resetCounter (written for you)', () => {
  it('ends the window early', async () => {
    await increment(redis, 'k', 60_000);
    await resetCounter(redis, 'k');
    await expect(peek(redis, 'k')).resolves.toEqual({ count: 0, retryAfterMs: 0 });
  });
});
