import type { PrismaClient } from '@keyhouse/db';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  consumeEmailToken,
  generateToken,
  hashToken,
  issueEmailToken,
} from '../src/security/tokens.js';
import { appDb, resetDb, uniqueEmail } from './db.js';

const HOUR = 60 * 60 * 1000;
const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

describe('hashToken', () => {
  it('returns the lowercase hex SHA-256 of the input (known test vector)', () => {
    // SHA-256("abc") from FIPS 180-2.
    expect(hashToken('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('is deterministic and 64 hex chars', () => {
    const h = hashToken('some-token');
    expect(h).toBe(hashToken('some-token'));
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('generateToken', () => {
  it('returns a 43-char base64url token and its hash', () => {
    const { token, tokenHash } = generateToken();
    expect(token).toMatch(BASE64URL_43);
    expect(tokenHash).toBe(hashToken(token));
  });

  it('never repeats', () => {
    const tokens = new Set(Array.from({ length: 1000 }, () => generateToken().token));
    expect(tokens.size).toBe(1000);
  });
});

describe('consumeEmailToken', () => {
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
      data: { email: uniqueEmail(), passwordHash: 'not-a-real-hash' },
    });
    userId = user.id;
  });

  it('stores only the hash, never the raw token', async () => {
    const token = await issueEmailToken(db, userId, 'VERIFY_EMAIL', HOUR);
    const row = await db.emailToken.findFirstOrThrow({ where: { userId } });
    expect(row.tokenHash).toBe(hashToken(token));
    expect(JSON.stringify(row)).not.toContain(token);
  });

  it('consumes a valid token once and returns the user id', async () => {
    const token = await issueEmailToken(db, userId, 'VERIFY_EMAIL', HOUR);
    await expect(consumeEmailToken(db, token, 'VERIFY_EMAIL')).resolves.toEqual({ userId });
    const row = await db.emailToken.findFirstOrThrow({ where: { userId } });
    expect(row.consumedAt).not.toBeNull();
  });

  it('rejects a second use (single use)', async () => {
    const token = await issueEmailToken(db, userId, 'VERIFY_EMAIL', HOUR);
    await consumeEmailToken(db, token, 'VERIFY_EMAIL');
    await expect(consumeEmailToken(db, token, 'VERIFY_EMAIL')).resolves.toBeNull();
  });

  it('lets exactly one of many concurrent attempts win (no race)', async () => {
    const token = await issueEmailToken(db, userId, 'RESET_PASSWORD', HOUR);
    const results = await Promise.all(
      Array.from({ length: 10 }, () => consumeEmailToken(db, token, 'RESET_PASSWORD')),
    );
    expect(results.filter((r) => r !== null)).toHaveLength(1);
  });

  it('rejects an expired token', async () => {
    const issuedAt = new Date('2026-01-01T00:00:00Z');
    const token = await issueEmailToken(db, userId, 'VERIFY_EMAIL', HOUR, issuedAt);
    const later = new Date(issuedAt.getTime() + HOUR + 1);
    await expect(consumeEmailToken(db, token, 'VERIFY_EMAIL', later)).resolves.toBeNull();
  });

  it('rejects a token used for the wrong purpose', async () => {
    const token = await issueEmailToken(db, userId, 'VERIFY_EMAIL', HOUR);
    await expect(consumeEmailToken(db, token, 'RESET_PASSWORD')).resolves.toBeNull();
    // ...and the failed attempt did not burn it.
    await expect(consumeEmailToken(db, token, 'VERIFY_EMAIL')).resolves.toEqual({ userId });
  });

  it('rejects unknown and malformed tokens', async () => {
    await expect(consumeEmailToken(db, generateToken().token, 'VERIFY_EMAIL')).resolves.toBeNull();
    await expect(consumeEmailToken(db, '', 'VERIFY_EMAIL')).resolves.toBeNull();
    await expect(consumeEmailToken(db, "' OR 1=1 --", 'VERIFY_EMAIL')).resolves.toBeNull();
    await expect(consumeEmailToken(db, 'a'.repeat(5000), 'VERIFY_EMAIL')).resolves.toBeNull();
  });

  it('invalidates older tokens when a new one is issued', async () => {
    const first = await issueEmailToken(db, userId, 'RESET_PASSWORD', HOUR);
    const second = await issueEmailToken(db, userId, 'RESET_PASSWORD', HOUR);
    await expect(consumeEmailToken(db, first, 'RESET_PASSWORD')).resolves.toBeNull();
    await expect(consumeEmailToken(db, second, 'RESET_PASSWORD')).resolves.toEqual({ userId });
  });
});
