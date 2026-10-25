import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { hashPassword } from '../src/security/passwords.js';
import { base32Decode, hotp, stepAt } from '../src/security/totp.js';
import { resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, sessionCookie, type TestDeps } from './helpers.js';

const knownPw = randomBytes(18).toString('base64url'); // generated per run, never a literal

let deps: TestDeps;
let app: ReturnType<typeof createApp>;
let pwHash: string;

beforeAll(async () => {
  deps = await createTestDeps();
  app = createApp(deps);
  pwHash = await hashPassword(knownPw);
});
afterAll(async () => {
  await closeDeps(deps);
});
beforeEach(async () => {
  await resetDb();
  await deps.redis.flushdb();
  deps.mailer.sent.length = 0;
});

/** A verified user, signed in. Returns the cookie pair to send back. */
async function signedIn(): Promise<{ userId: string; email: string; cookie: string }> {
  const email = uniqueEmail();
  const user = await deps.prisma.user.create({
    data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
  });
  const res = await request(app).post('/auth/login').send({ email, password: knownPw });
  return { userId: user.id, email, cookie: sessionCookie(res).pair };
}

const currentCode = (secretBase32: string) => hotp(base32Decode(secretBase32), stepAt(new Date()));

async function startSetup(cookie: string) {
  const res = await request(app).post('/auth/mfa/setup').set('Cookie', cookie);
  return { res, secret: (res.body as { secret: string }).secret };
}

describe('MFA status and setup', () => {
  it('requires being signed in', async () => {
    expect((await request(app).get('/auth/mfa')).status).toBe(401);
    expect((await request(app).post('/auth/mfa/setup')).status).toBe(401);
    expect((await request(app).post('/auth/mfa/enable').send({ code: '123456' })).status).toBe(401);
  });

  it('reports MFA off for a new user', async () => {
    const { cookie } = await signedIn();
    const res = await request(app).get('/auth/mfa').set('Cookie', cookie);
    expect(res.body).toEqual({ enabled: false, enabledAt: null, recoveryCodesLeft: 0 });
  });

  it('setup returns the secret, an otpauth link and a QR image, never cached', async () => {
    const { cookie, email } = await signedIn();
    const { res, secret } = await startSetup(cookie);

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    const body = res.body as { otpauthUri: string; qrDataUrl: string };
    expect(body.otpauthUri).toContain(`secret=${secret}`);
    expect(body.otpauthUri).toContain(encodeURIComponent(email));
    expect(body.qrDataUrl.startsWith('data:image/png;base64,')).toBe(true);
  });

  it('stores the secret sealed, never in plain text, and still switched off', async () => {
    const { cookie, userId } = await signedIn();
    const { secret } = await startSetup(cookie);

    const row = await deps.prisma.userMfa.findUniqueOrThrow({ where: { userId } });
    expect(row.secretSealed?.startsWith('v1.')).toBe(true);
    expect(row.secretSealed).not.toContain(secret);
    expect(row.enabledAt).toBeNull();
  });
});

describe('turning MFA on', () => {
  it('a correct code switches it on and returns 10 recovery codes once', async () => {
    const { cookie, userId, email } = await signedIn();
    const { secret } = await startSetup(cookie);

    const res = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: currentCode(secret) });
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect((res.body as { recoveryCodes: string[] }).recoveryCodes).toHaveLength(10);

    const row = await deps.prisma.userMfa.findUniqueOrThrow({ where: { userId } });
    expect(row.enabledAt).not.toBeNull();
    expect(row.lastUsedStep).toBe(stepAt(new Date()));

    const status = await request(app).get('/auth/mfa').set('Cookie', cookie);
    expect(status.body).toMatchObject({ enabled: true, recoveryCodesLeft: 10 });

    const mail = await deps.mailer.waitFor(email);
    expect(mail.subject).toMatch(/two-step verification is on/i);
    expect(mail.text).not.toContain(secret);
  });

  it('accepts the code typed with a space ("123 456")', async () => {
    const { cookie } = await signedIn();
    const { secret } = await startSetup(cookie);
    const code = currentCode(secret);
    const res = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: `${code.slice(0, 3)} ${code.slice(3)}` });
    expect(res.status).toBe(200);
  });

  it('a wrong code keeps it off, and is audited', async () => {
    const { cookie, userId } = await signedIn();
    const { secret } = await startSetup(cookie);
    const wrong = currentCode(secret) === '000000' ? '111111' : '000000';

    const res = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: wrong });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_code' });

    const row = await deps.prisma.userMfa.findUniqueOrThrow({ where: { userId } });
    expect(row.enabledAt).toBeNull();
    const audit = await deps.prisma.auditEvent.findMany({
      where: { userId, type: 'mfa.enable_failed' },
    });
    expect(audit).toHaveLength(1);
  });

  it('needs setup first', async () => {
    const { cookie } = await signedIn();
    const res = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: '123456' });
    expect(res.status).toBe(409);
    expect(res.body).toEqual({ error: 'mfa_setup_not_started' });
  });

  it('cannot be set up or enabled again while it is on', async () => {
    const { cookie } = await signedIn();
    const { secret } = await startSetup(cookie);
    await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: currentCode(secret) });

    expect((await request(app).post('/auth/mfa/setup').set('Cookie', cookie)).status).toBe(409);
    const again = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: currentCode(secret) });
    expect(again.status).toBe(409);
  });

  it('starting setup again replaces the secret: the old one stops working', async () => {
    const { cookie } = await signedIn();
    const { secret: first } = await startSetup(cookie);
    const { secret: second } = await startSetup(cookie);
    expect(second).not.toBe(first);

    const withOld = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: currentCode(first) });
    // Very rarely two secrets share a code by chance; only check when they differ.
    if (currentCode(first) !== currentCode(second)) expect(withOld.status).toBe(400);
  });

  it('limits wrong codes: the 11th attempt in 15 minutes gets 429', async () => {
    const { cookie } = await signedIn();
    const { secret } = await startSetup(cookie);
    const wrong = currentCode(secret) === '000000' ? '111111' : '000000';

    for (let i = 0; i < 10; i++) {
      await request(app).post('/auth/mfa/enable').set('Cookie', cookie).send({ code: wrong });
    }
    const blocked = await request(app)
      .post('/auth/mfa/enable')
      .set('Cookie', cookie)
      .send({ code: currentCode(secret) });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThanOrEqual(1);
  });
});
