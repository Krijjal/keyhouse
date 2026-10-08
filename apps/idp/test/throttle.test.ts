import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createRedis, type Redis } from '../src/redis.js';
import { peek, resetCounter } from '../src/security/rate-limit.js';
import {
  allowResetEmail,
  beginLoginAttempt,
  finishLoginAttempt,
  ipBucket,
  LOGIN_PAIR_LOCK_MS,
  loginKeys,
  progressiveDelayMs,
  retryAfterSeconds,
} from '../src/security/throttle.js';

// ─── 1.6 exercises: these fail until you implement throttle.ts ───

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** A stand-in for hashToken(email): tests never need a real address. */
const fakeEmailHash = () => randomBytes(32).toString('hex');
const ipN = (n: number) => `198.51.100.${n}`; // documentation range, never a real host

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

/** One full failed login: begin, and if it was let through, record the failure. */
async function fail(emailHash: string, ip: string) {
  const blocked = await beginLoginAttempt(redis, emailHash, ip);
  if (!blocked) await finishLoginAttempt(redis, emailHash, ip, false);
  return blocked;
}

describe('written for you', () => {
  it('ipBucket groups IPv6 by /64 and unwraps IPv4-mapped addresses', () => {
    expect(ipBucket('203.0.113.9')).toBe('203.0.113.9');
    expect(ipBucket('::ffff:203.0.113.9')).toBe('203.0.113.9');
    expect(ipBucket('2001:db8:aa:bb:1:2:3:4')).toBe('2001:db8:aa:bb::/64');
    expect(ipBucket('2001:db8:aa:bb::99')).toBe('2001:db8:aa:bb::/64');
    expect(ipBucket('2001:DB8::1')).toBe('2001:db8:0:0::/64');
    expect(ipBucket('::1')).toBe('0:0:0:0::/64');
    expect(ipBucket(null)).toBe('unknown');
    expect(ipBucket('not an ip')).toBe('unknown');
  });

  it('retryAfterSeconds rounds up and is never 0', () => {
    expect(retryAfterSeconds(1)).toBe(1);
    expect(retryAfterSeconds(1500)).toBe(2);
    expect(retryAfterSeconds(0)).toBe(1);
    expect(retryAfterSeconds(-1)).toBe(1);
  });
});

describe('exercise 1: progressiveDelayMs', () => {
  it('is free for the first 4 attempts', () => {
    for (const n of [0, 1, 2, 3, 4]) expect(progressiveDelayMs(n)).toBe(0);
  });

  it('starts at 1 s on the 5th attempt and doubles', () => {
    expect(progressiveDelayMs(5)).toBe(1000);
    expect(progressiveDelayMs(6)).toBe(2000);
    expect(progressiveDelayMs(7)).toBe(4000);
    expect(progressiveDelayMs(9)).toBe(16000);
  });

  it('never goes above 30 s', () => {
    expect(progressiveDelayMs(10)).toBe(30000);
    expect(progressiveDelayMs(500)).toBe(30000);
  });
});

describe('exercise 2 + 3: login attempts', () => {
  it('lets a fresh attempt through', async () => {
    await expect(beginLoginAttempt(redis, fakeEmailHash(), ipN(1))).resolves.toBeNull();
  });

  it('per IP: the 31st failure in a window is blocked, across different emails', async () => {
    for (let i = 0; i < 30; i++) expect(await fail(fakeEmailHash(), ipN(1))).toBeNull();

    const blocked = await beginLoginAttempt(redis, fakeEmailHash(), ipN(1));
    expect(blocked?.reason).toBe('ip');
    expect(blocked?.retryAfterMs).toBeGreaterThan(0);

    // Another IP is not affected.
    await expect(beginLoginAttempt(redis, fakeEmailHash(), ipN(2))).resolves.toBeNull();
  });

  it('per IP: IPv6 addresses in the same /64 share one counter', async () => {
    for (let i = 1; i <= 30; i++) await fail(fakeEmailHash(), `2001:db8:1:2::${i.toString(16)}`);
    const blocked = await beginLoginAttempt(redis, fakeEmailHash(), '2001:db8:1:2:ffff::1');
    expect(blocked?.reason).toBe('ip');
  });

  it('per IP: successful logins do not use up the limit', async () => {
    for (let i = 0; i < 40; i++) {
      const h = fakeEmailHash();
      expect(await beginLoginAttempt(redis, h, ipN(1))).toBeNull();
      await finishLoginAttempt(redis, h, ipN(1), true);
    }
  });

  it('per email: 5 free attempts, then a wait of about 1 s, then about 2 s', async () => {
    const h = fakeEmailHash();
    // Different IPs, so only the per-email rule can trigger.
    for (let i = 1; i <= 5; i++) expect(await fail(h, ipN(i))).toBeNull();

    const tooSoon = await beginLoginAttempt(redis, h, ipN(6));
    expect(tooSoon?.reason).toBe('email');
    expect(tooSoon?.retryAfterMs).toBeGreaterThan(0);
    expect(tooSoon?.retryAfterMs).toBeLessThanOrEqual(1000);

    await sleep(1100);
    expect(await fail(h, ipN(7))).toBeNull(); // waited long enough: allowed

    const next = await beginLoginAttempt(redis, h, ipN(8));
    expect(next?.reason).toBe('email');
    expect(next?.retryAfterMs).toBeGreaterThan(1000); // the wait grew
  });

  it('per email: never a hard lock, an attacker on other IPs cannot lock the owner out', async () => {
    const h = fakeEmailHash();
    for (let i = 1; i <= 12; i++) await fail(h, ipN(i));
    // However many failures, the result is a wait (email), never a lock for a fresh IP.
    const k = loginKeys(h, ipN(99));
    await resetCounter(redis, k.emailWait); // pretend the wait has passed
    await expect(beginLoginAttempt(redis, h, ipN(99))).resolves.toBeNull();
  });

  it('per email + IP: 5 failures lock that pair for 15 minutes, even after the wait', async () => {
    const h = fakeEmailHash();
    for (let i = 0; i < 5; i++) expect(await fail(h, ipN(1))).toBeNull();

    const k = loginKeys(h, ipN(1));
    await resetCounter(redis, k.emailWait); // take the per-email wait out of the picture

    const locked = await beginLoginAttempt(redis, h, ipN(1));
    expect(locked?.reason).toBe('pair');
    expect(locked?.retryAfterMs).toBeGreaterThan(LOGIN_PAIR_LOCK_MS - 60_000);

    // The same email from a different IP is not hard-locked.
    await resetCounter(redis, k.emailWait);
    await expect(beginLoginAttempt(redis, h, ipN(2))).resolves.toBeNull();
  });

  it('success resets the email counters', async () => {
    const h = fakeEmailHash();
    for (let i = 0; i < 4; i++) await fail(h, ipN(1));
    expect(await beginLoginAttempt(redis, h, ipN(1))).toBeNull();
    await finishLoginAttempt(redis, h, ipN(1), true);

    const k = loginKeys(h, ipN(1));
    expect((await peek(redis, k.email)).count).toBe(0);
    expect((await peek(redis, k.pair)).count).toBe(0);
    // 4 more failures are free again.
    for (let i = 0; i < 4; i++) expect(await fail(h, ipN(1))).toBeNull();
  });

  it('race: a burst of 20 parallel attempts on one account lets at most 5 through', async () => {
    const h = fakeEmailHash();
    const results = await Promise.all(
      Array.from({ length: 20 }, () => beginLoginAttempt(redis, h, ipN(1))),
    );
    const through = results.filter((r) => r === null).length;
    expect(through).toBeGreaterThan(0);
    expect(through).toBeLessThanOrEqual(5);
  });

  it('never puts anything but hashes and IP buckets into Redis keys', async () => {
    const h = fakeEmailHash();
    await fail(h, ipN(1));
    const keys = await redis.keys('*');
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(key.startsWith('rl:')).toBe(true);
      expect(key).not.toContain('@');
    }
  });
});

describe('exercise 4: allowResetEmail', () => {
  it('allows 3 emails per address per hour, then refuses', async () => {
    const h = fakeEmailHash();
    for (let i = 0; i < 3; i++) expect(await allowResetEmail(redis, h, ipN(i + 1))).toBe(true);
    expect(await allowResetEmail(redis, h, ipN(9))).toBe(false);
  });

  it('allows 20 requests per IP per hour, across different addresses', async () => {
    for (let i = 0; i < 20; i++)
      expect(await allowResetEmail(redis, fakeEmailHash(), ipN(1))).toBe(true);
    expect(await allowResetEmail(redis, fakeEmailHash(), ipN(1))).toBe(false);
    expect(await allowResetEmail(redis, fakeEmailHash(), ipN(2))).toBe(true);
  });
});
