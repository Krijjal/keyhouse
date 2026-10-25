import type { PrismaClient } from '@keyhouse/db';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { recordTotpUse } from '../src/security/totp-use.js';
import { appDb, resetDb, uniqueEmail } from './db.js';

// ─── Phase 2, exercise 2.5: these fail until you implement recordTotpUse ───

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

async function userWithMfa(opts: { enabled?: boolean; lastUsedStep?: number | null } = {}) {
  const user = await db.user.create({
    data: { email: uniqueEmail(), passwordHash: 'not-a-real-hash', emailVerifiedAt: new Date() },
  });
  await db.userMfa.create({
    data: {
      userId: user.id,
      secretSealed: 'v1.placeholder',
      enabledAt: opts.enabled === false ? null : new Date(),
      lastUsedStep: opts.lastUsedStep ?? null,
    },
  });
  return user.id;
}

const storedStep = async (userId: string) =>
  (await db.userMfa.findUniqueOrThrow({ where: { userId } })).lastUsedStep;

describe('exercise 2.5: recordTotpUse', () => {
  it('records the first use of a step', async () => {
    const userId = await userWithMfa();
    await expect(recordTotpUse(db, userId, 1000)).resolves.toBe(true);
    expect(await storedStep(userId)).toBe(1000);
  });

  it('refuses the same step twice', async () => {
    const userId = await userWithMfa({ lastUsedStep: 1000 });
    await expect(recordTotpUse(db, userId, 1000)).resolves.toBe(false);
  });

  it('refuses an older step and leaves the stored one alone', async () => {
    const userId = await userWithMfa({ lastUsedStep: 1000 });
    await expect(recordTotpUse(db, userId, 999)).resolves.toBe(false);
    expect(await storedStep(userId)).toBe(1000);
  });

  it('accepts a newer step', async () => {
    const userId = await userWithMfa({ lastUsedStep: 1000 });
    await expect(recordTotpUse(db, userId, 1001)).resolves.toBe(true);
    expect(await storedStep(userId)).toBe(1001);
  });

  it('RACE: 10 sign-ins with the same code at the same moment, exactly one wins', async () => {
    const userId = await userWithMfa({ lastUsedStep: 1000 });
    const results = await Promise.all(
      Array.from({ length: 10 }, () => recordTotpUse(db, userId, 1001)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('refuses when MFA is not switched on', async () => {
    const userId = await userWithMfa({ enabled: false });
    await expect(recordTotpUse(db, userId, 1000)).resolves.toBe(false);
  });

  it("only touches the right user's row", async () => {
    const alice = await userWithMfa({ lastUsedStep: 1000 });
    const bob = await userWithMfa({ lastUsedStep: 1000 });
    await recordTotpUse(db, alice, 1001);
    expect(await storedStep(bob)).toBe(1000);
  });
});
