import type { PrismaClient } from '@keyhouse/db';
import type { RequestMeta } from '../http/request-meta.js';
import { BASE64URL_TOKEN_REGEX, generateToken, hashToken } from './tokens.js';

/** Sliding idle timeout: a session unused for this long is dead. */
export const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
/** Absolute lifetime: a session dies this long after creation, however active it is. */
export const SESSION_ABSOLUTE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface CreatedSession {
  /** Goes into the cookie. Never stored, never logged. */
  token: string;
  sessionId: string;
}

export interface ValidSession {
  sessionId: string;
  userId: string;
}

/**
 * ─── LEARNING ITEM b ─────────────────────────────────────────────────────────
 * Creates a new session for a user who just proved their password.
 *
 * Must:
 *  - Get a fresh random token with generateToken() from ./tokens.js (your item d code).
 *    A brand-new token on every login is what "rotate the session on every login" means.
 *  - Insert one row into sessions with:
 *      userId, tokenHash (NEVER the raw token, rule 2), lastSeenAt = now,
 *      absoluteExpiresAt = now + SESSION_ABSOLUTE_TTL_MS, ip and userAgent from `meta`.
 *  - Return { token, sessionId }: the raw token for the cookie, and the new row's id.
 */
export async function createSession(
  db: PrismaClient,
  userId: string,
  meta: RequestMeta,
  now: Date = new Date(),
): Promise<CreatedSession> {
  const { token, tokenHash } = generateToken();
  const session = await db.session.create({
    data: {
      userId,
      tokenHash,
      lastSeenAt: now,
      absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      ip: meta.ip,
      userAgent: meta.userAgent,
    },
  });
  return { token, sessionId: session.id };
}

/**
 * ─── LEARNING ITEM b ─────────────────────────────────────────────────────────
 * Checks the token from a request's cookie. Returns who is logged in, or null.
 *
 * A session is valid only if ALL of these hold right now:
 *  - a row exists with tokenHash = hashToken(rawToken)
 *  - revokedAt is null                          (not logged out / revoked)
 *  - absoluteExpiresAt > now                    (younger than 7 days)
 *  - lastSeenAt > now - SESSION_IDLE_TIMEOUT_MS (used within the last 30 minutes)
 * If valid, it also SLIDES the idle window: lastSeenAt = now.
 *
 * Must:
 *  - Reject malformed tokens (not 43 base64url chars, reuse BASE64URL_TOKEN_REGEX from
 *    ./tokens.js) with null before touching the database.
 *  - Check and slide in ONE conditional write, the same trick as consumeEmailToken:
 *    updateMany with every condition above in `where`, data { lastSeenAt: now }, and
 *    count === 1 means valid. Why: with "read, then update", a logout that lands between
 *    the read and the update would be ignored and the revoked session would keep working.
 *  - Then read the row's id and userId (by tokenHash) and return them.
 *  - Return null for every kind of invalid. The caller answers 401 either way.
 */
export async function validateSession(
  db: PrismaClient,
  rawToken: string,
  now: Date = new Date(),
): Promise<ValidSession | null> {
  if (!BASE64URL_TOKEN_REGEX.test(rawToken)) {
    return null;
  }
  const tokenHash = hashToken(rawToken);
  const idleCutoff = new Date(now.getTime() - SESSION_IDLE_TIMEOUT_MS);

  // Check and slide in one write: only a live session gets its lastSeenAt bumped.
  const updateResult = await db.session.updateMany({
    where: {
      tokenHash,
      revokedAt: null,
      absoluteExpiresAt: { gt: now },
      lastSeenAt: { gt: idleCutoff },
    },
    data: {
      lastSeenAt: now,
    },
  });

  if (updateResult.count !== 1) {
    return null;
  }

  const session = await db.session.findUnique({
    where: { tokenHash },
    select: { id: true, userId: true },
  });
  if (!session) {
    return null;
  }

  return { sessionId: session.id, userId: session.userId };
}

// ─── Written for you (not a learning item) ──────────────────────────────────

/** Revokes one session (logout). Idempotent: revoking twice is harmless. */
export async function revokeSession(
  db: PrismaClient,
  sessionId: string,
  now: Date = new Date(),
): Promise<void> {
  await db.session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data: { revokedAt: now },
  });
}

/** Revokes every session of a user ("sign out everywhere"). Returns how many were live. */
export async function revokeAllSessions(
  db: PrismaClient,
  userId: string,
  now: Date = new Date(),
): Promise<number> {
  const result = await db.session.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: now },
  });
  return result.count;
}

/**
 * Revokes one session, but only if it belongs to `userId`. Ownership is part of the
 * WHERE clause, so another user's session id simply matches nothing (IDOR defense).
 * Returns false for unknown, already revoked and other users' sessions alike.
 */
export async function revokeOwnSession(
  db: PrismaClient,
  userId: string,
  sessionId: string,
  now: Date = new Date(),
): Promise<boolean> {
  const result = await db.session.updateMany({
    where: { id: sessionId, userId, revokedAt: null },
    data: { revokedAt: now },
  });
  return result.count === 1;
}

export interface SessionSummary {
  id: string;
  createdAt: Date;
  lastSeenAt: Date;
  ip: string | null;
  userAgent: string | null;
}

/** The user's live sessions, most recently used first. Never selects the token hash. */
export async function listActiveSessions(
  db: PrismaClient,
  userId: string,
  now: Date = new Date(),
): Promise<SessionSummary[]> {
  return db.session.findMany({
    where: {
      userId,
      revokedAt: null,
      absoluteExpiresAt: { gt: now },
      lastSeenAt: { gt: new Date(now.getTime() - SESSION_IDLE_TIMEOUT_MS) },
    },
    select: { id: true, createdAt: true, lastSeenAt: true, ip: true, userAgent: true },
    orderBy: { lastSeenAt: 'desc' },
  });
}
