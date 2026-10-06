import { createHash } from 'node:crypto';

/** Thrown when the breach check cannot give an answer. Registration fails closed on it. */
export class PwnedCheckUnavailable extends Error {
  override name = 'PwnedCheckUnavailable';
}

/** Returns true if the password appears in a known breach. */
export type PwnedChecker = (password: string) => Promise<boolean>;

const RANGE_URL = 'https://api.pwnedpasswords.com/range/';
const TIMEOUT_MS = 2000;

/**
 * Rule 3: Pwned Passwords check using k-anonymity.
 *
 * Only the first 5 hex chars of the password's SHA-1 leave this server. The API
 * returns every breached hash suffix in that bucket (hundreds), and we compare
 * locally, so the service never learns which password, or even which hash, we asked about.
 * "Add-Padding" makes every response a similar size, so a network observer can't
 * guess the bucket from the response length.
 *
 * SHA-1 is used only because that is the API's format. It is not used to store anything.
 */
export function createPwnedChecker(fetchImpl: typeof fetch = fetch): PwnedChecker {
  return async (password) => {
    const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    let body: string;
    try {
      const res = await fetchImpl(RANGE_URL + prefix, {
        headers: { 'Add-Padding': 'true', 'User-Agent': 'KeyHouse-IdP' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) throw new PwnedCheckUnavailable(`status ${res.status}`);
      body = await res.text();
    } catch (err) {
      if (err instanceof PwnedCheckUnavailable) throw err;
      throw new PwnedCheckUnavailable(err instanceof Error ? err.name : 'unknown');
    }

    for (const line of body.split('\n')) {
      const [lineSuffix, count] = line.trim().split(':');
      // Padding entries have a count of 0 and are not real breaches.
      if (lineSuffix === suffix && Number(count) > 0) return true;
    }
    return false;
  };
}
