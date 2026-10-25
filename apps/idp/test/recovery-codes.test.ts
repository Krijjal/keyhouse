import type { PrismaClient } from '@keyhouse/db';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  consumeRecoveryCode,
  countRemainingRecoveryCodes,
  hashRecoveryCode,
  issueRecoveryCodes,
  normalizeRecoveryCode,
  RECOVERY_CODE_COUNT,
} from '../src/security/recovery-codes.js';
import { appDb, resetDb, uniqueEmail } from './db.js';

let db: PrismaClient;

beforeAll(() => {
  db = appDb();
});
afterAll(async () => {
  await db.$disconnect();
});
beforeEach(async () => {
  await resetDb();
});

async function makeUser(): Promise<string> {
  const user = await db.user.create({
    data: { email: uniqueEmail(), passwordHash: 'not-a-real-hash', emailVerifiedAt: new Date() },
  });
  return user.id;
}

describe('written for you', () => {
  it('issues 10 readable codes and stores only their hashes', async () => {
    const userId = await makeUser();
    const codes = await issueRecoveryCodes(db, userId);

    expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    expect(new Set(codes).size).toBe(RECOVERY_CODE_COUNT);
    for (const code of codes) expect(code).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);

    const rows = await db.mfaRecoveryCode.findMany({ where: { userId } });
    const dump = JSON.stringify(rows);
    for (const code of codes) {
      expect(dump).not.toContain(code);
      expect(dump).not.toContain(normalizeRecoveryCode(code));
    }
    expect(rows.map((r) => r.codeHash).sort()).toEqual(
      codes.map((c) => hashRecoveryCode(normalizeRecoveryCode(c) ?? '')).sort(),
    );
  });

  it('normalizes what people type, and refuses what cannot be a code', () => {
    expect(normalizeRecoveryCode('K7QM 2FXW-9tpb hn4r')).toBeNull(); // 9 is not in the alphabet
    expect(normalizeRecoveryCode('K7QM 2FXW-3tpb hn4r')).toBe('k7qm2fxw3tpbhn4r');
    expect(normalizeRecoveryCode('abcd-efgh')).toBeNull();
    expect(normalizeRecoveryCode('')).toBeNull();
  });

  it('issuing a new set revokes the old one', async () => {
    const userId = await makeUser();
    await issueRecoveryCodes(db, userId);
    await issueRecoveryCodes(db, userId);
    expect(await countRemainingRecoveryCodes(db, userId)).toBe(RECOVERY_CODE_COUNT);
  });
});

describe('exercise 2.3: consumeRecoveryCode', () => {
  it('accepts a valid code once, then never again', async () => {
    const userId = await makeUser();
    const [code = ''] = await issueRecoveryCodes(db, userId);

    await expect(consumeRecoveryCode(db, userId, code)).resolves.toBe(true);
    await expect(consumeRecoveryCode(db, userId, code)).resolves.toBe(false);
    expect(await countRemainingRecoveryCodes(db, userId)).toBe(RECOVERY_CODE_COUNT - 1);
  });

  it('accepts the code however it is typed (caps, spaces, no dashes)', async () => {
    const userId = await makeUser();
    const [code = ''] = await issueRecoveryCodes(db, userId);
    const typed = code.toUpperCase().replaceAll('-', ' ');
    await expect(consumeRecoveryCode(db, userId, typed)).resolves.toBe(true);
  });

  it("refuses another user's code", async () => {
    const alice = await makeUser();
    const bob = await makeUser();
    const [bobsCode = ''] = await issueRecoveryCodes(db, bob);

    await expect(consumeRecoveryCode(db, alice, bobsCode)).resolves.toBe(false);
    // And Bob's code is still usable by Bob.
    await expect(consumeRecoveryCode(db, bob, bobsCode)).resolves.toBe(true);
  });

  it('refuses revoked codes (from an older set)', async () => {
    const userId = await makeUser();
    const [oldCode = ''] = await issueRecoveryCodes(db, userId);
    await issueRecoveryCodes(db, userId);
    await expect(consumeRecoveryCode(db, userId, oldCode)).resolves.toBe(false);
  });

  it('refuses wrong codes and garbage without touching anything', async () => {
    const userId = await makeUser();
    await issueRecoveryCodes(db, userId);
    for (const bad of ['', 'nope', 'aaaa-aaaa-aaaa-aaaa', 'x'.repeat(5000)]) {
      await expect(consumeRecoveryCode(db, userId, bad)).resolves.toBe(false);
    }
    expect(await countRemainingRecoveryCodes(db, userId)).toBe(RECOVERY_CODE_COUNT);
  });

  it('works only once even with 10 attempts at the same moment', async () => {
    const userId = await makeUser();
    const [code = ''] = await issueRecoveryCodes(db, userId);
    const results = await Promise.all(
      Array.from({ length: 10 }, () => consumeRecoveryCode(db, userId, code)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('records when it was used', async () => {
    const userId = await makeUser();
    const [code = ''] = await issueRecoveryCodes(db, userId);
    const when = new Date('2026-10-25T12:00:00Z');
    await consumeRecoveryCode(db, userId, code, when);

    const row = await db.mfaRecoveryCode.findUniqueOrThrow({
      where: { codeHash: hashRecoveryCode(normalizeRecoveryCode(code) ?? '') },
    });
    expect(row.usedAt?.toISOString()).toBe(when.toISOString());
  });
});
