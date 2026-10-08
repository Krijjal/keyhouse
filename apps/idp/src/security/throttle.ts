import { isIPv4, isIPv6 } from 'node:net';
import type { Redis } from '../redis.js';
import { increment, peek, refund, resetCounter, startBlock, tryClaim } from './rate-limit.js';

// The owner's throttling decisions (see CLAUDE.md, "Security decisions").
const MINUTE_MS = 60 * 1000;
export const LOGIN_WINDOW_MS = 15 * MINUTE_MS;
export const LOGIN_IP_MAX_FAILURES = 30;
export const LOGIN_PAIR_MAX_FAILURES = 5;
export const LOGIN_PAIR_LOCK_MS = 15 * MINUTE_MS;
export const LOGIN_EMAIL_FREE_FAILURES = 5;
export const LOGIN_EMAIL_BASE_DELAY_MS = 1000;
export const LOGIN_EMAIL_MAX_DELAY_MS = 30 * 1000;
export const RESET_WINDOW_MS = 60 * MINUTE_MS;
export const RESET_EMAIL_MAX = 3;
export const RESET_IP_MAX = 20;

export interface Throttled {
  /** Only for the audit log. Every reason gets the same response. */
  reason: 'ip' | 'email' | 'pair';
  retryAfterMs: number;
}

// ─── Written for you (not part of the exercise) ─────────────────────────────

/**
 * The address that rate limits are counted against. IPv4 as is. IPv6 is grouped by its
 * /64 prefix: one home or server usually gets a whole /64, so counting single IPv6
 * addresses would let an attacker rotate through billions of them for free.
 */
export function ipBucket(ip: string | null): string {
  if (!ip) return 'unknown';
  const bare = ip.split('%')[0] ?? ''; // drop an IPv6 zone id like "%eth0"
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(bare);
  if (mapped?.[1]) return mapped[1]; // IPv4 written as IPv6 by the socket
  if (isIPv4(bare)) return bare;
  if (!isIPv6(bare)) return 'unknown';

  // Expand "::" so we can take the first four 16-bit groups. An embedded IPv4 tail
  // (a.b.c.d) takes two groups; it sits in the last 32 bits, so it never reaches the /64.
  const [head = '', tail = ''] = bare.split('::');
  const groups = (part: string) =>
    part ? part.split(':').flatMap((g) => (g.includes('.') ? ['0', '0'] : [g])) : [];
  const headGroups = groups(head);
  const tailGroups = bare.includes('::') ? groups(tail) : [];
  const zeros = Array<string>(8 - headGroups.length - tailGroups.length).fill('0');
  const full = bare.includes('::') ? [...headGroups, ...zeros, ...tailGroups] : headGroups;
  return `${full
    .slice(0, 4)
    .map((g) => parseInt(g, 16).toString(16))
    .join(':')}::/64`;
}

/** Retry-After is in whole seconds; never 0, or clients would retry immediately. */
export function retryAfterSeconds(ms: number): number {
  return Math.max(1, Math.ceil(ms / 1000));
}

/**
 * The Redis keys for one login attempt. Callers pass a HASH of the normalized email:
 * the raw address never goes into Redis.
 */
export function loginKeys(emailHash: string, ip: string | null) {
  const bucket = ipBucket(ip);
  return {
    ip: `login:ip:${bucket}`,
    email: `login:email:${emailHash}`,
    emailWait: `login:email-wait:${emailHash}`,
    pair: `login:pair:${emailHash}:${bucket}`,
    pairLock: `login:pair-lock:${emailHash}:${bucket}`,
  };
}

// ─── YOUR EXERCISE (1.6) ────────────────────────────────────────────────────
// Tools you have (rate-limit.ts):
//   increment(redis, key, windowMs) → { count, retryAfterMs }   your code: adds 1, atomic
//   peek(redis, key)                → { count, retryAfterMs }   your code: read only
//   resetCounter(redis, key)        → deletes the key
//   refund(redis, key)              → takes 1 back (never below 0, never creates a key)
//   startBlock(redis, key, ms)      → sets a block that lasts ms (overwrites)
//   tryClaim(redis, key, ms)        → true if it grabbed a free slot for ms, false if taken

/**
 * ─── EXERCISE 1 (warm-up) ───
 * The wait that the Nth attempt on one email imposes on the NEXT attempt.
 *
 * Must return:
 *  - 0 for attempts below LOGIN_EMAIL_FREE_FAILURES (attempts 1-4 are free)
 *  - LOGIN_EMAIL_BASE_DELAY_MS * 2 to the power (attempt - LOGIN_EMAIL_FREE_FAILURES)
 *    for attempt 5 and up: 5 → 1000, 6 → 2000, 7 → 4000 ...
 *  - but never more than LOGIN_EMAIL_MAX_DELAY_MS (30 000)
 *
 * Hints: `2 ** n` is "2 to the power n". Math.min(a, b) returns the smaller one.
 */
export function progressiveDelayMs(attempt: number): number {
  if (attempt < LOGIN_EMAIL_FREE_FAILURES) {
    return 0;
  }
  const delay = LOGIN_EMAIL_BASE_DELAY_MS * 2 ** (attempt - LOGIN_EMAIL_FREE_FAILURES);
  return Math.min(delay, LOGIN_EMAIL_MAX_DELAY_MS);
}

/**
 * ─── EXERCISE 2 (the main one) ───
 * Runs BEFORE any password work. Returns null if the attempt may go ahead, or a
 * Throttled { reason, retryAfterMs } saying why not.
 *
 * Why every counter is incremented HERE and not after a failure: increment is atomic,
 * so in a burst of 100 parallel requests each one gets a different count, and only the
 * allowed number get through. "Check now, count the failure later" lets the whole burst
 * see zero failures and test 100 passwords (the same TOCTOU lesson as your token code).
 *
 * Start with:  const k = loginKeys(emailHash, ip);
 *
 * Then three gates, in this order. Return as soon as one says no.
 *
 *  1. Per IP (password spraying from one source):
 *     increment k.ip with LOGIN_WINDOW_MS.
 *     If its count is ABOVE LOGIN_IP_MAX_FAILURES → return { reason: 'ip', retryAfterMs }.
 *
 *  2. Per email, all IPs (progressive delay, never a hard lock):
 *     increment k.email with LOGIN_WINDOW_MS.
 *     delay = progressiveDelayMs(that count).
 *     If delay > 0, try to claim k.emailWait for `delay` ms with tryClaim.
 *     If the claim FAILS (someone holds the slot) → peek k.emailWait and
 *     return { reason: 'email', retryAfterMs: <the peek's retryAfterMs> }.
 *
 *  3. Per email + IP (hard lock):
 *     peek k.pairLock. If its count > 0 → return { reason: 'pair', retryAfterMs }.
 *     Then increment k.pair with LOGIN_WINDOW_MS.
 *     If its count is ABOVE LOGIN_PAIR_MAX_FAILURES → return { reason: 'pair', retryAfterMs }.
 *
 *  If all three gates pass → return null.
 *
 * Why gate 2 comes before gate 3: a real user clicking "log in" during a 2-second wait
 * must not push themselves into the 15-minute lock.
 */
export async function beginLoginAttempt(
  redis: Redis,
  emailHash: string,
  ip: string | null,
): Promise<Throttled | null> {
  const k = loginKeys(emailHash, ip);

  // 1. Per IP
  const ipState = await increment(redis, k.ip, LOGIN_WINDOW_MS);
  if (ipState.count > LOGIN_IP_MAX_FAILURES) {
    return { reason: 'ip', retryAfterMs: ipState.retryAfterMs };
  }

  // 2. Per email
  const emailState = await increment(redis, k.email, LOGIN_WINDOW_MS);
  const delay = progressiveDelayMs(emailState.count);
  if (delay > 0) {
    const claimed = await tryClaim(redis, k.emailWait, delay);
    if (!claimed) {
      const waitState = await peek(redis, k.emailWait);
      return { reason: 'email', retryAfterMs: waitState.retryAfterMs };
    }
  }

  // 3. Per email + IP
  const pairLockState = await peek(redis, k.pairLock);
  if (pairLockState.count > 0) {
    return { reason: 'pair', retryAfterMs: pairLockState.retryAfterMs };
  }

  const pairState = await increment(redis, k.pair, LOGIN_WINDOW_MS);
  if (pairState.count > LOGIN_PAIR_MAX_FAILURES) {
    return { reason: 'pair', retryAfterMs: pairState.retryAfterMs };
  }

  // All gates passed
  return null;
}

/**
 * ─── EXERCISE 3 ───
 * Runs AFTER the password check, only for attempts beginLoginAttempt let through.
 *
 * Start with:  const k = loginKeys(emailHash, ip);
 *
 *  If passwordCorrect:
 *    - resetCounter on k.email, k.emailWait, k.pair and k.pairLock
 *      ("success resets the email counters")
 *    - refund k.ip (give back this attempt's count: only FAILURES count against an IP)
 *    - then return.
 *
 *  If not:
 *    - peek k.pair. If its count is AT LEAST LOGIN_PAIR_MAX_FAILURES (this was the 5th
 *      failure) → startBlock on k.pairLock for LOGIN_PAIR_LOCK_MS (a full 15 minutes).
 *
 * Hint: the five success calls don't depend on each other. You can await them one by
 * one, or all at once with  await Promise.all([ ..., ... ]).
 */
export async function finishLoginAttempt(
  redis: Redis,
  emailHash: string,
  ip: string | null,
  passwordCorrect: boolean,
): Promise<void> {
  const k = loginKeys(emailHash, ip);
  if (passwordCorrect) {
    await Promise.all([
      resetCounter(redis, k.email),
      resetCounter(redis, k.emailWait),
      resetCounter(redis, k.pair),
      resetCounter(redis, k.pairLock),
      refund(redis, k.ip),
    ]);
  } else {
    const pairState = await peek(redis, k.pair);
    if (pairState.count >= LOGIN_PAIR_MAX_FAILURES) {
      await startBlock(redis, k.pairLock, LOGIN_PAIR_LOCK_MS);
    }
  }
}

/**
 * ─── EXERCISE 4 ───
 * Forgot-password limit: EVERY request counts (not just failures).
 *
 *  - increment `reset:ip:${ipBucket(ip)}` with RESET_WINDOW_MS
 *  - increment `reset:email:${emailHash}` with RESET_WINDOW_MS
 *  - return true only if the IP count is at most RESET_IP_MAX AND the email count is at
 *    most RESET_EMAIL_MAX.
 *
 * The caller answers exactly as usual when this returns false, but sends no email:
 * that stops mail-bombing without revealing that the address was recently targeted.
 */
export async function allowResetEmail(
  redis: Redis,
  emailHash: string,
  ip: string | null,
): Promise<boolean> {
  const [ipState, emailState] = await Promise.all([
    increment(redis, `reset:ip:${ipBucket(ip)}`, RESET_WINDOW_MS),
    increment(redis, `reset:email:${emailHash}`, RESET_WINDOW_MS),
  ]);

  return ipState.count <= RESET_IP_MAX && emailState.count <= RESET_EMAIL_MAX;
}
