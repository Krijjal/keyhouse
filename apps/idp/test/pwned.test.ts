import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createPwnedChecker, PwnedCheckUnavailable } from '../src/security/pwned.js';

function sha1(s: string): string {
  return createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();
}

/** A fake fetch that records the URL and answers with the given body/status. */
function fakeFetch(body: string, status = 200) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const impl: typeof fetch = (input, init) => {
    calls.push({
      url: input instanceof Request ? input.url : input.toString(),
      headers: (init?.headers ?? {}) as Record<string, string>,
    });
    return Promise.resolve(new Response(body, { status }));
  };
  return { impl, calls };
}

describe('Pwned Passwords check (k-anonymity)', () => {
  const password = `test-${randomBytes(6).toString('hex')}`;
  const hash = sha1(password);
  const suffix = hash.slice(5);

  it('sends only the 5-char hash prefix, never the password or full hash', async () => {
    const { impl, calls } = fakeFetch('');
    await createPwnedChecker(impl)(password);

    expect(calls).toHaveLength(1);
    const url = calls[0]?.url ?? '';
    expect(url).toBe(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`);
    expect(url).not.toContain(password);
    expect(url).not.toContain(suffix);
    expect(calls[0]?.headers['Add-Padding']).toBe('true');
  });

  it('reports a breached password when its suffix is listed with a count', async () => {
    const { impl } = fakeFetch(`0000000000000000000000000000000000A:3\r\n${suffix}:42\r\n`);
    await expect(createPwnedChecker(impl)(password)).resolves.toBe(true);
  });

  it('ignores padding entries (count 0)', async () => {
    const { impl } = fakeFetch(`${suffix}:0\r\n`);
    await expect(createPwnedChecker(impl)(password)).resolves.toBe(false);
  });

  it('returns false when the suffix is not listed', async () => {
    const { impl } = fakeFetch('0000000000000000000000000000000000A:3\r\n');
    await expect(createPwnedChecker(impl)(password)).resolves.toBe(false);
  });

  it('throws PwnedCheckUnavailable on a non-200 response', async () => {
    const { impl } = fakeFetch('oops', 503);
    await expect(createPwnedChecker(impl)(password)).rejects.toBeInstanceOf(PwnedCheckUnavailable);
  });

  it('throws PwnedCheckUnavailable on network errors and timeouts', async () => {
    const failing = (() =>
      Promise.reject(new DOMException('timed out', 'TimeoutError'))) as typeof fetch;
    await expect(createPwnedChecker(failing)(password)).rejects.toBeInstanceOf(
      PwnedCheckUnavailable,
    );
  });
});
