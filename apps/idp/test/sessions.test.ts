import type { PrismaClient } from '@keyhouse/db';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createSession,
  revokeSession,
  SESSION_ABSOLUTE_TTL_MS,
  SESSION_IDLE_TIMEOUT_MS,
  validateSession,
} from '../src/security/sessions.js';
import { generateToken, hashToken } from '../src/security/tokens.js';
import { appDb, ownerDb, resetDb, uniqueEmail } from './db.js';

// ─── Learning item b: these fail until you implement createSession / validateSession ───

const META = { ip: '203.0.113.7', userAgent: 'vitest' };
const MINUTE = 60 * 1000;

describe('sessions', () => {
  let db: PrismaClient;
  let userId: string;

  beforeAll(() => {
    db = appDb();
  });
  afterAll(async () => {
    await db.$disconnect();
  });
  beforeEach(async () => {
    await resetDb();
    const user = await db.user.create({
      data: { email: uniqueEmail(), passwordHash: 'not-a-real-hash', emailVerifiedAt: new Date() },
    });
    userId = user.id;
  });

  describe('createSession', () => {
    it('returns a 43-char token and stores only its hash', async () => {
      const { token, sessionId } = await createSession(db, userId, META);
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const row = await db.session.findUniqueOrThrow({ where: { id: sessionId } });
      expect(row.tokenHash).toBe(hashToken(token));
      expect(JSON.stringify(row)).not.toContain(token);
      expect(row.userId).toBe(userId);
      expect(row.ip).toBe(META.ip);
      expect(row.userAgent).toBe(META.userAgent);
      expect(row.revokedAt).toBeNull();
    });

    it('sets a 7-day absolute expiry and lastSeenAt = now', async () => {
      const now = new Date('2026-03-01T12:00:00Z');
      const { sessionId } = await createSession(db, userId, META, now);
      const row = await db.session.findUniqueOrThrow({ where: { id: sessionId } });
      expect(row.lastSeenAt.getTime()).toBe(now.getTime());
      expect(row.absoluteExpiresAt.getTime()).toBe(now.getTime() + SESSION_ABSOLUTE_TTL_MS);
    });

    it('gives every login a new token (rotation)', async () => {
      const a = await createSession(db, userId, META);
      const b = await createSession(db, userId, META);
      expect(a.token).not.toBe(b.token);
      expect(a.sessionId).not.toBe(b.sessionId);
    });
  });

  describe('validateSession', () => {
    it('accepts a fresh session and returns who it belongs to', async () => {
      const { token, sessionId } = await createSession(db, userId, META);
      await expect(validateSession(db, token)).resolves.toEqual({ sessionId, userId });
    });

    it('slides the idle window (updates lastSeenAt)', async () => {
      const start = new Date('2026-03-01T12:00:00Z');
      const { token, sessionId } = await createSession(db, userId, META, start);
      const later = new Date(start.getTime() + 20 * MINUTE);
      await validateSession(db, token, later);
      const row = await db.session.findUniqueOrThrow({ where: { id: sessionId } });
      expect(row.lastSeenAt.getTime()).toBe(later.getTime());
    });

    it('keeps an active session alive past 30 min total, as long as it is used', async () => {
      const start = new Date('2026-03-01T12:00:00Z');
      const { token } = await createSession(db, userId, META, start);
      const t1 = new Date(start.getTime() + 25 * MINUTE);
      const t2 = new Date(start.getTime() + 50 * MINUTE);
      await expect(validateSession(db, token, t1)).resolves.not.toBeNull();
      await expect(validateSession(db, token, t2)).resolves.not.toBeNull();
    });

    it('rejects a session idle for more than 30 minutes', async () => {
      const start = new Date('2026-03-01T12:00:00Z');
      const { token } = await createSession(db, userId, META, start);
      const tooLate = new Date(start.getTime() + SESSION_IDLE_TIMEOUT_MS + 1000);
      await expect(validateSession(db, token, tooLate)).resolves.toBeNull();
    });

    it('rejects a session past its 7-day absolute expiry, even if active', async () => {
      const start = new Date('2026-03-01T12:00:00Z');
      const { token, sessionId } = await createSession(db, userId, META, start);
      const justBefore = new Date(start.getTime() + SESSION_ABSOLUTE_TTL_MS - MINUTE);
      // Pretend it was used a moment ago, so only the absolute limit can stop it.
      await ownerDb().session.update({
        where: { id: sessionId },
        data: { lastSeenAt: justBefore },
      });
      const after = new Date(start.getTime() + SESSION_ABSOLUTE_TTL_MS + 1000);
      await expect(validateSession(db, token, after)).resolves.toBeNull();
    });

    it('rejects a revoked session', async () => {
      const { token, sessionId } = await createSession(db, userId, META);
      await revokeSession(db, sessionId);
      await expect(validateSession(db, token)).resolves.toBeNull();
    });

    it('does not slide a dead session back to life', async () => {
      const start = new Date('2026-03-01T12:00:00Z');
      const { token, sessionId } = await createSession(db, userId, META, start);
      await validateSession(db, token, new Date(start.getTime() + 31 * MINUTE)); // rejected
      const row = await db.session.findUniqueOrThrow({ where: { id: sessionId } });
      expect(row.lastSeenAt.getTime()).toBe(start.getTime());
    });

    it('rejects unknown and malformed tokens', async () => {
      await expect(validateSession(db, generateToken().token)).resolves.toBeNull();
      await expect(validateSession(db, '')).resolves.toBeNull();
      await expect(validateSession(db, 'x'.repeat(5000))).resolves.toBeNull();
    });
  });
});
