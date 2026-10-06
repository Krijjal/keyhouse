/* eslint-disable @typescript-eslint/require-await, @typescript-eslint/no-meaningless-void-operator --
   Only needed while verifyPassword is a stub. Delete this comment when you implement it. */
import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';

/** OWASP Password Storage Cheat Sheet minimum for argon2id: 19 MiB, 2 iterations, 1 lane. */
export const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export const PASSWORD_MIN_LENGTH = 12;
/** Upper bound so nobody can make us hash megabytes per request (CPU/memory DoS). */
export const PASSWORD_MAX_LENGTH = 128;

/**
 * Unicode NFKC normalization (NIST SP 800-63B). The same password typed on two keyboards
 * can arrive as different code points (e.g. "é" as one or two characters). Normalizing
 * before hashing AND before verifying makes them match. Both sides must call this.
 */
export function normalizePassword(password: string): string {
  return password.normalize('NFKC');
}

/** Hashes a password with argon2id. The result is a PHC string containing params and salt. */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(normalizePassword(password), ARGON2_OPTIONS);
}

let dummyHash: Promise<string> | undefined;

/**
 * A real argon2id hash of a random password nobody knows, made with the same options as
 * real hashes, so verifying against it costs exactly as much as verifying a real one.
 * Computed once and cached.
 */
export function getDummyHash(): Promise<string> {
  dummyHash ??= argon2.hash(randomBytes(32).toString('base64url'), ARGON2_OPTIONS);
  return dummyHash;
}

/**
 * ─── YOU IMPLEMENT THIS (learning item a) ───────────────────────────────────
 * Checks a login password. `storedHash` is the user's password_hash, or null when no
 * user exists with the submitted email.
 *
 * Must:
 *  - Known user: return the result of argon2.verify(storedHash, normalizePassword(password)).
 *  - Unknown user (storedHash === null): STILL run argon2.verify, against getDummyHash(),
 *    then return false no matter what it says.
 *    The attack this stops: if unknown emails return instantly (~1 ms) while real ones take
 *    the ~50 ms argon2 costs, an attacker can time the login endpoint and learn which
 *    emails have accounts, even though the response body is identical (rule 5).
 *    So no early `if (!storedHash) return false` before doing the argon2 work.
 *  - Normalize the password with normalizePassword(), exactly like hashPassword() does,
 *    or users whose password contains accented characters may be unable to log in.
 *  - Never throw for a wrong password. If argon2.verify throws (e.g. a corrupted hash in
 *    the database), return false. A login must fail closed, not crash with a 500.
 *  - Return a plain boolean. The caller treats `true` as the only success.
 */
export async function verifyPassword(
  storedHash: string | null,
  password: string,
): Promise<boolean> {
  void [storedHash, password]; // delete this line when you implement
  throw new Error('Not implemented: verifyPassword');
}
