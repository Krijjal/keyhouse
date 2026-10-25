import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@keyhouse/db';
import { hashToken } from './tokens.js';

// One-time backup codes for when the phone with the authenticator app is lost.
// A recovery code is effectively a second password that skips MFA, so:
//   - 80 bits of randomness each: far too many to guess, which is why a plain SHA-256 hash
//     (rule 2) is enough here, unlike passwords, which need argon2's deliberate slowness
//   - each works exactly once, and only for the account it was issued to

export const RECOVERY_CODE_COUNT = 10;
/** Lowercase Base32: no 0/1/8/9, so nothing to confuse with o/l/b/g when typing. */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const CODE_CHARS = 16; // 16 × 5 bits = 80 bits
const NORMALIZED = /^[a-z2-7]{16}$/;

// ─── Written for you (not part of the exercise) ─────────────────────────────

/** "k7qm-2fxw-9tpb-hn4r": 16 random characters, in groups of 4 for readability. */
function newCode(): string {
  // 5 random bits per character: take one random byte per character, keep its low 5 bits.
  // 256 is a multiple of 32, so every character is equally likely (no modulo bias).
  const chars = Array.from(randomBytes(CODE_CHARS), (byte) => ALPHABET.charAt(byte & 31));
  return chars.join('').replace(/(.{4})(?=.)/g, '$1-');
}

/**
 * What people type, made comparable: lowercase, spaces and dashes removed.
 * "K7QM 2FXW-9tpb hn4r" → "k7qm2fxw9tpbhn4r". Anything that can't be a code → null.
 */
export function normalizeRecoveryCode(input: string): string | null {
  const clean = input.toLowerCase().replace(/[\s-]/g, '');
  return NORMALIZED.test(clean) ? clean : null;
}

/** The stored form: SHA-256 hex of the normalized code. */
export function hashRecoveryCode(normalized: string): string {
  return hashToken(normalized);
}

/**
 * Creates a fresh set of codes for a user and stores ONLY their hashes. Any older codes
 * that were still usable are revoked in the same transaction, so only the newest set works.
 * Returns the readable codes: show them once, never store or log them.
 */
export async function issueRecoveryCodes(
  db: PrismaClient,
  userId: string,
  now: Date = new Date(),
): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, newCode);
  await db.$transaction([
    db.mfaRecoveryCode.updateMany({
      where: { userId, usedAt: null, revokedAt: null },
      data: { revokedAt: now },
    }),
    db.mfaRecoveryCode.createMany({
      data: codes.map((code) => ({
        userId,
        codeHash: hashRecoveryCode(normalizeRecoveryCode(code) ?? ''),
      })),
    }),
  ]);
  return codes;
}

/** How many usable codes a user has left (for "you have 7 left" in the alert email). */
export async function countRemainingRecoveryCodes(
  db: PrismaClient,
  userId: string,
): Promise<number> {
  return db.mfaRecoveryCode.count({ where: { userId, usedAt: null, revokedAt: null } });
}

// ─── PHASE 2, EXERCISE 2.3 (yours) ──────────────────────────────────────────

/**
 * ─── YOU IMPLEMENT THIS ───
 * Uses up one recovery code for one user. Returns true if the code was valid and is now
 * spent, false for anything else (wrong, already used, revoked, someone else's, garbage).
 *
 * Must:
 *  1. normalized = normalizeRecoveryCode(input). If null → return false, before any DB work.
 *  2. codeHash = hashRecoveryCode(normalized). Look up by HASH only: the typed code never
 *     goes into a query or a log.
 *  3. In ONE conditional write, mark it used only if it is still usable:
 *       db.mfaRecoveryCode.updateMany({
 *         where: { userId, codeHash, usedAt: null, revokedAt: null },
 *         data: { usedAt: now },
 *       })
 *     Why one write: with "find it, check it, then update it", two requests sent at the
 *     same moment would both find it unused, and the code would work twice. Same lesson
 *     as your consumeEmailToken.
 *     Why userId in the WHERE: the code must belong to THIS account. Without it, any
 *     user's leftover code would get an attacker past MFA on any other account.
 *  4. Return true only if exactly one row changed (result.count === 1).
 */
export async function consumeRecoveryCode(
  db: PrismaClient,
  userId: string,
  input: string,
  now: Date = new Date(),
): Promise<boolean> {
  const normalized = normalizeRecoveryCode(input);
  if (!normalized) {
    return false;
  }

  const codeHash = hashRecoveryCode(normalized);

  const result = await db.mfaRecoveryCode.updateMany({
    where: { userId, codeHash, usedAt: null, revokedAt: null },
    data: { usedAt: now },
  });

  return result.count === 1;
}
