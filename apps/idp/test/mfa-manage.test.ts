import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { hashPassword } from '../src/security/passwords.js';
import { issueRecoveryCodes } from '../src/security/recovery-codes.js';
import { sealSecret } from '../src/security/secret-box.js';
import { generateTotpSecret, hotp, stepAt } from '../src/security/totp.js';
import { resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, sessionCookie, type TestDeps } from './helpers.js';

const knownPw = randomBytes(18).toString('base64url'); // generated per run, never a literal
const otherPw = randomBytes(18).toString('base64url');

let deps: TestDeps;
let app: ReturnType<typeof createApp>;
let pwHash: string;
let key: Buffer;

beforeAll(async () => {
  deps = await createTestDeps();
  app = createApp(deps);
  pwHash = await hashPassword(knownPw);
  key = Buffer.from(deps.config.MFA_ENCRYPTION_KEY, 'base64url');
});
afterAll(async () => {
  await closeDeps(deps);
});
beforeEach(async () => {
  await resetDb();
  await deps.redis.flushdb();
  deps.mailer.sent.length = 0;
});

/** A signed-in user with MFA on. Signs in first, then switches MFA on directly in the DB. */
async function signedInWithMfa() {
  const email = uniqueEmail();
  const user = await deps.prisma.user.create({
    data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
  });
  const login = await request(app).post('/auth/login').send({ email, password: knownPw });
  const { bytes, base32 } = generateTotpSecret();
  await deps.prisma.userMfa.create({
    data: {
      userId: user.id,
      secretSealed: sealSecret(base32, user.id, key),
      enabledAt: new Date(),
    },
  });
  const recoveryCodes = await issueRecoveryCodes(deps.prisma, user.id);
  const codeNow = () => hotp(bytes, stepAt(new Date()));
  return { userId: user.id, email, cookie: sessionCookie(login).pair, recoveryCodes, codeNow };
}

const post = (path: string, cookie: string, body: object) =>
  request(app).post(path).set('Cookie', cookie).send(body);

const wrongCode = (right: string) => (right === '000000' ? '111111' : '000000');

describe('turning MFA off', () => {
  it('requires being signed in', async () => {
    const res = await request(app).post('/auth/mfa/disable').send({ password: 'x', code: '1' });
    expect(res.status).toBe(401);
  });

  it('password + current code turns it off, wipes the secret and revokes the codes', async () => {
    const { userId, email, cookie, codeNow } = await signedInWithMfa();

    const res = await post('/auth/mfa/disable', cookie, { password: knownPw, code: codeNow() });
    expect(res.status).toBe(204);

    const row = await deps.prisma.userMfa.findUniqueOrThrow({ where: { userId } });
    expect(row.enabledAt).toBeNull();
    expect(row.secretSealed).toBeNull();
    const usable = await deps.prisma.mfaRecoveryCode.count({
      where: { userId, usedAt: null, revokedAt: null },
    });
    expect(usable).toBe(0);
    // Revoked, not deleted: the rows stay for the record.
    expect(await deps.prisma.mfaRecoveryCode.count({ where: { userId } })).toBe(10);

    const audit = await deps.prisma.auditEvent.findMany({
      where: { userId, type: 'mfa.disabled' },
    });
    expect(audit).toHaveLength(1);
    const mail = await deps.mailer.waitFor(email);
    expect(mail.subject).toMatch(/two-step verification is off/i);

    // Signing in now needs only the password again.
    const login = await request(app).post('/auth/login').send({ email, password: knownPw });
    expect(login.body).toEqual({ status: 'logged_in' });
  });

  it('a recovery code works instead of the app code (lost phone)', async () => {
    const { cookie, recoveryCodes } = await signedInWithMfa();
    const res = await post('/auth/mfa/disable', cookie, {
      password: knownPw,
      recoveryCode: recoveryCodes[0],
    });
    expect(res.status).toBe(204);
  });

  it('a wrong password is refused, and does not use up the code', async () => {
    const { userId, cookie, recoveryCodes } = await signedInWithMfa();
    const [code = ''] = recoveryCodes;

    const res = await post('/auth/mfa/disable', cookie, { password: otherPw, recoveryCode: code });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_password_or_code' });
    const row = await deps.prisma.userMfa.findUniqueOrThrow({ where: { userId } });
    expect(row.enabledAt).not.toBeNull();

    // The recovery code is still unspent.
    const again = await post('/auth/mfa/disable', cookie, {
      password: knownPw,
      recoveryCode: code,
    });
    expect(again.status).toBe(204);
  });

  it('a wrong code gets the same answer as a wrong password, and is audited', async () => {
    const { userId, cookie, codeNow } = await signedInWithMfa();
    const res = await post('/auth/mfa/disable', cookie, {
      password: knownPw,
      code: wrongCode(codeNow()),
    });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_password_or_code' });
    const audit = await deps.prisma.auditEvent.findMany({
      where: { userId, type: 'mfa.reauth_failed' },
    });
    expect(audit[0]?.metadata).toMatchObject({ action: 'disable' });
  });

  it('REPLAY: a code already used cannot be used again', async () => {
    const { userId, cookie, codeNow } = await signedInWithMfa();
    await deps.prisma.userMfa.update({
      where: { userId },
      data: { lastUsedStep: stepAt(new Date()) },
    });
    const res = await post('/auth/mfa/disable', cookie, { password: knownPw, code: codeNow() });
    expect(res.status).toBe(400);
  });

  it('needs both: a password alone or a code alone is a bad request', async () => {
    const { cookie, codeNow } = await signedInWithMfa();
    expect((await post('/auth/mfa/disable', cookie, { password: knownPw })).status).toBe(400);
    expect((await post('/auth/mfa/disable', cookie, { code: codeNow() })).status).toBe(400);
  });

  it('409 when MFA is already off', async () => {
    const { cookie, codeNow } = await signedInWithMfa();
    await post('/auth/mfa/disable', cookie, { password: knownPw, code: codeNow() });
    const again = await post('/auth/mfa/disable', cookie, { password: knownPw, code: codeNow() });
    expect(again.status).toBe(409);
    expect(again.body).toEqual({ error: 'mfa_not_enabled' });
  });

  it('limits attempts: the 11th in 15 minutes gets 429, even with the right answers', async () => {
    const { cookie, codeNow } = await signedInWithMfa();
    for (let i = 0; i < 10; i++) {
      await post('/auth/mfa/disable', cookie, { password: otherPw, code: codeNow() });
    }
    const blocked = await post('/auth/mfa/disable', cookie, { password: knownPw, code: codeNow() });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThanOrEqual(1);
  });
});

describe('replacing recovery codes', () => {
  it('gives 10 new codes, never cached, and the old ones stop working', async () => {
    const { userId, email, cookie, codeNow, recoveryCodes: oldCodes } = await signedInWithMfa();

    const res = await post('/auth/mfa/recovery-codes', cookie, {
      password: knownPw,
      code: codeNow(),
    });
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    const fresh = (res.body as { recoveryCodes: string[] }).recoveryCodes;
    expect(fresh).toHaveLength(10);
    expect(fresh).not.toContain(oldCodes[0]);

    const usable = await deps.prisma.mfaRecoveryCode.count({
      where: { userId, usedAt: null, revokedAt: null },
    });
    expect(usable).toBe(10);

    const audit = await deps.prisma.auditEvent.findMany({
      where: { userId, type: 'mfa.recovery_codes_replaced' },
    });
    expect(audit).toHaveLength(1);
    const mail = await deps.mailer.waitFor(email);
    expect(mail.subject).toMatch(/recovery codes were replaced/i);
    for (const code of fresh) expect(mail.text).not.toContain(code);

    // An old code no longer works, even with the right password.
    const withOld = await post('/auth/mfa/recovery-codes', cookie, {
      password: knownPw,
      recoveryCode: oldCodes[1],
    });
    expect(withOld.status).toBe(400);
  });

  it('a wrong code keeps the old set', async () => {
    const { userId, cookie, codeNow } = await signedInWithMfa();
    const res = await post('/auth/mfa/recovery-codes', cookie, {
      password: knownPw,
      code: wrongCode(codeNow()),
    });
    expect(res.status).toBe(400);
    const usable = await deps.prisma.mfaRecoveryCode.count({
      where: { userId, usedAt: null, revokedAt: null },
    });
    expect(usable).toBe(10);
  });
});
