import argon2 from 'argon2';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { getDummyHash, hashPassword, verifyPassword } from '../src/security/passwords.js';

const PASSWORD = 'correct horse battery staple';

describe('hashPassword', () => {
  it('produces an argon2id PHC string with the OWASP parameters and a fresh salt', async () => {
    const a = await hashPassword(PASSWORD);
    const b = await hashPassword(PASSWORD);
    expect(a).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
    expect(a).not.toBe(b); // random salt per hash
    expect(a).not.toContain(PASSWORD);
  });
});

// ─── Learning item a: these fail until you implement verifyPassword ───────────
describe('verifyPassword', () => {
  let storedHash: string;

  beforeAll(async () => {
    storedHash = await hashPassword(PASSWORD);
    await getDummyHash(); // warm the cache so timing tests compare like with like
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns true for the right password', async () => {
    await expect(verifyPassword(storedHash, PASSWORD)).resolves.toBe(true);
  });

  it('returns false for a wrong password', async () => {
    await expect(verifyPassword(storedHash, 'wrong horse battery staple')).resolves.toBe(false);
  });

  it('returns false for an unknown user (null hash)', async () => {
    await expect(verifyPassword(null, PASSWORD)).resolves.toBe(false);
  });

  it('still runs argon2 against the dummy hash for an unknown user', async () => {
    const spy = vi.spyOn(argon2, 'verify');
    await verifyPassword(null, PASSWORD);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toBe(await getDummyHash());
  });

  it('takes about as long for an unknown user as for a real one (no timing oracle)', async () => {
    async function median(fn: () => Promise<unknown>): Promise<number> {
      const times: number[] = [];
      for (let i = 0; i < 7; i++) {
        const t = performance.now();
        await fn();
        times.push(performance.now() - t);
      }
      times.sort((x, y) => x - y);
      return times[3] ?? 0;
    }
    const known = await median(() => verifyPassword(storedHash, 'wrong horse battery staple'));
    const unknown = await median(() => verifyPassword(null, 'wrong horse battery staple'));
    // argon2 takes tens of ms; skipping it would take well under 1 ms.
    expect(unknown / known).toBeGreaterThan(0.5);
    expect(unknown / known).toBeLessThan(2);
  });

  it('normalizes Unicode the same way hashPassword does (NFKC)', async () => {
    const composed = 'café au lait 2026'; // "é" as one code point
    const decomposed = 'café au lait 2026'; // "e" + combining accent
    const hash = await hashPassword(composed);
    await expect(verifyPassword(hash, decomposed)).resolves.toBe(true);
  });

  it('returns false instead of throwing for a corrupted stored hash', async () => {
    await expect(verifyPassword('not-a-phc-string', PASSWORD)).resolves.toBe(false);
  });
});
