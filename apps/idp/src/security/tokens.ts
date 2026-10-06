import type { EmailTokenPurpose, PrismaClient } from '@keyhouse/db';
import { createHash, randomBytes } from 'node:crypto';

/** Raw token size. 32 bytes = 256 bits of entropy: unguessable, so plain SHA-256 is enough. */
export const TOKEN_BYTES = 32;

/** Base64url token format: 43 chars, URL-safe alphabet, no '=' padding. */
export const BASE64URL_TOKEN_REGEX = /^[A-Za-z0-9_-]{43}$/;

export interface GeneratedToken {
  /** Goes to the user (email link, cookie). NEVER stored, NEVER logged. */
  token: string;
  /** Goes to the database. Lowercase hex SHA-256 of `token`, 64 chars. */
  tokenHash: string;
}

/**
 * ─── YOU IMPLEMENT THIS (learning item d) ───────────────────────────────────
 * Hashes a raw token for storage and lookup (rule 2: store hashes, never raw tokens).
 *
 * Must:
 *  - Return the SHA-256 of the token's UTF-8 bytes as lowercase hex (exactly 64 chars).
 *  - Be deterministic: the same token always gives the same hash (that is how lookups work).
 *  - Use node:crypto. No pepper/HMAC/salt is needed here: unlike a password, the input
 *    already has 256 bits of entropy, so nobody can brute-force a hash back to a token.
 *
 * Why this matters: if the database leaks, an attacker gets hashes they cannot turn into
 * working reset links or session cookies.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf-8').digest('hex');
}

/**
 * ─── YOU IMPLEMENT THIS (learning item d) ───────────────────────────────────
 * Creates a new random token and its hash.
 *
 * Must:
 *  - Take TOKEN_BYTES bytes from a CSPRNG (node:crypto randomBytes). Never Math.random:
 *    it is predictable, so an attacker who sees a few outputs can predict the next token.
 *  - Encode them as base64url (URL-safe, no padding) → a 43-character `token`.
 *  - Return `tokenHash = hashToken(token)` (hash the encoded string, not the raw bytes,
 *    so later lookups only need the string the user sends back).
 */
export function generateToken(): GeneratedToken {
  const bytes = randomBytes(TOKEN_BYTES);

  const token = bytes.toString('base64url');

  const tokenHash = hashToken(token);

  return { token, tokenHash };
}

/**
 * ─── YOU IMPLEMENT THIS (learning item d) ───────────────────────────────────
 * Consumes an email token (verification or password reset) exactly once.
 *
 * Returns `{ userId }` if, and only if, ALL of these hold at the moment of consumption:
 *  - a row exists whose token_hash = hashToken(rawToken)
 *  - its purpose matches `purpose` (a verify token must not work as a reset token)
 *  - it is not expired: expires_at > now
 *  - it has not been consumed: consumed_at IS NULL
 * and in that same step it sets consumed_at = now. Otherwise returns null.
 *
 * Must:
 *  - Reject obviously malformed input (not 43 base64url characters) with null
 *    before touching the database.
 *  - Look up by HASH only. The raw token never goes into a query or a log.
 *  - Be ATOMIC. Check-and-mark must be one conditional write, not "read, then update".
 *    The attack: an attacker (or a double-click) sends the same link twice in parallel.
 *    With read-then-update, both requests read "not consumed" before either writes, and
 *    both succeed, so a single-use reset link gets used twice.
 *    Hint: a conditional UPDATE whose WHERE contains every condition above, then check
 *    how many rows it changed (Prisma: updateMany returns { count }).
 *  - Return the same null for unknown, expired, already-used and wrong-purpose tokens.
 *    The caller shows one generic message, so an attacker learns nothing.
 *
 * `now` is a parameter so tests can control time. Default it to new Date().
 */
export async function consumeEmailToken(
  db: PrismaClient,
  rawToken: string,
  purpose: EmailTokenPurpose,
  now: Date = new Date(),
): Promise<{ userId: string } | null> {
  // 1. Guard clause: reject obviously malformed input before touching the DB
  if (!rawToken || typeof rawToken !== 'string' || !BASE64URL_TOKEN_REGEX.test(rawToken)) {
    return null;
  }

  const tokenHash = hashToken(rawToken);

  const updateResult = await db.emailToken.updateMany({
    where: {
      tokenHash,
      purpose,
      expiresAt: { gt: now },
      consumedAt: null,
    },
    data: {
      consumedAt: now,
    },
  });

  // If no rows were updated, either the token doesn't exist, is expired,
  // is wrong purpose, or has already been consumed. Return generic null.
  if (updateResult.count === 0) {
    return null;
  }

  // 4. Retrieve the userId for the newly consumed token
  const tokenRecord = await db.emailToken.findUnique({
    where: { tokenHash },
    select: { userId: true },
  });

  if (!tokenRecord) {
    return null;
  }

  return { userId: tokenRecord.userId };
}

// ─── Written for you (not a learning item) ──────────────────────────────────

/**
 * Issues a new email token for a user and returns the RAW token (to put in the email link).
 * Any older unused token of the same purpose is invalidated first, so only the newest
 * link works: a leaked old reset email becomes useless once a new one is requested.
 */
export async function issueEmailToken(
  db: PrismaClient,
  userId: string,
  purpose: EmailTokenPurpose,
  ttlMs: number,
  now: Date = new Date(),
): Promise<string> {
  const { token, tokenHash } = generateToken();
  await db.$transaction([
    db.emailToken.updateMany({
      where: { userId, purpose, consumedAt: null },
      data: { consumedAt: now },
    }),
    db.emailToken.create({
      data: { userId, purpose, tokenHash, expiresAt: new Date(now.getTime() + ttlMs) },
    }),
  ]);
  return token;
}
