import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../src/index.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env.example)`);
  return value;
}

// The app role may read, add and update MFA rows, but never delete them: turning MFA off
// and replacing recovery codes are UPDATEs, so their history can't be erased by the app.
describe('MFA tables: app-role grants', () => {
  let app: PrismaClient;
  let userId: string;
  let codeId: string;

  beforeAll(async () => {
    app = createPrismaClient(required('TEST_DATABASE_URL'));
    const user = await app.user.create({
      data: { email: `mfa-grants-${randomUUID()}@example.test`, passwordHash: 'not-a-real-hash' },
    });
    userId = user.id;
    await app.userMfa.create({ data: { userId, secretSealed: 'v1.test' } });
    const code = await app.mfaRecoveryCode.create({
      data: { userId, codeHash: createHash('sha256').update(randomBytes(16)).digest('hex') },
    });
    codeId = code.id;
  });

  afterAll(async () => {
    await app.$disconnect();
  });

  it('allows SELECT, INSERT and UPDATE on user_mfa', async () => {
    await app.userMfa.update({
      where: { userId },
      data: { enabledAt: new Date(), lastUsedStep: 1 },
    });
    const row = await app.userMfa.findUniqueOrThrow({ where: { userId } });
    expect(row.lastUsedStep).toBe(1);
  });

  it('allows SELECT, INSERT and UPDATE on mfa_recovery_codes', async () => {
    await app.mfaRecoveryCode.update({ where: { id: codeId }, data: { usedAt: new Date() } });
    const row = await app.mfaRecoveryCode.findUniqueOrThrow({ where: { id: codeId } });
    expect(row.usedAt).not.toBeNull();
  });

  it('denies DELETE on user_mfa', async () => {
    await expect(app.userMfa.delete({ where: { userId } })).rejects.toThrow(/permission denied/i);
  });

  it('denies DELETE on mfa_recovery_codes', async () => {
    await expect(app.mfaRecoveryCode.delete({ where: { id: codeId } })).rejects.toThrow(
      /permission denied/i,
    );
  });
});
