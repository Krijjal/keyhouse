import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { REGISTER_ACCEPTED } from '../src/routes/auth.js';
import { hashPassword } from '../src/security/passwords.js';
import { hashToken } from '../src/security/tokens.js';
import { resetDb, uniqueEmail } from './db.js';
import {
  closeDeps,
  createApp,
  createFakePwned,
  createTestDeps,
  tokenFromEmail,
  type TestDeps,
} from './helpers.js';

const GOOD_PASSWORD = 'correct horse battery staple';

let deps: TestDeps;
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  deps = await createTestDeps();
  app = createApp(deps);
});
afterAll(async () => {
  await closeDeps(deps);
});
beforeEach(async () => {
  await resetDb();
  deps.mailer.sent.length = 0;
});

function register(body: unknown) {
  return request(app)
    .post('/auth/register')
    .send(body as object);
}

async function auditTypes(userId: string): Promise<string[]> {
  const rows = await deps.prisma.auditEvent.findMany({ where: { userId }, orderBy: { id: 'asc' } });
  return rows.map((r) => r.type);
}

describe('POST /auth/register', () => {
  it('creates an unverified user with an argon2id hash and emails a verify link', async () => {
    const email = uniqueEmail();
    const res = await register({ email, password: GOOD_PASSWORD });

    expect(res.status).toBe(202);
    expect(res.body).toEqual(REGISTER_ACCEPTED);

    const user = await deps.prisma.user.findUniqueOrThrow({ where: { email } });
    expect(user.passwordHash).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
    expect(user.passwordHash).not.toContain(GOOD_PASSWORD);
    expect(user.emailVerifiedAt).toBeNull();

    const mail = await deps.mailer.waitFor(email);
    expect(mail.text).toContain(`${deps.config.WEB_ORIGIN}/verify-email#token=`);
    // The token is in the fragment, never the query string.
    expect(mail.text).not.toMatch(/\?token=/);

    // Only the hash of the emailed token is stored.
    const token = tokenFromEmail(mail);
    const row = await deps.prisma.emailToken.findFirstOrThrow({ where: { userId: user.id } });
    expect(row.purpose).toBe('VERIFY_EMAIL');
    expect(row.tokenHash).toBe(hashToken(token));
    const ttlHours = (row.expiresAt.getTime() - row.createdAt.getTime()) / 3_600_000;
    expect(ttlHours).toBeCloseTo(24, 1);

    expect(await auditTypes(user.id)).toEqual(['user.registered']);
  });

  it('normalizes email case and whitespace', async () => {
    const email = uniqueEmail();
    await register({ email: `  ${email.toUpperCase()}  `, password: GOOD_PASSWORD });
    await expect(deps.prisma.user.findUnique({ where: { email } })).resolves.not.toBeNull();
  });

  it.each([
    ['short password', { email: 'a@example.test', password: 'short' }, 'password'],
    ['long password', { email: 'a@example.test', password: 'x'.repeat(129) }, 'password'],
    ['bad email', { email: 'not-an-email', password: GOOD_PASSWORD }, 'email'],
    ['missing fields', {}, 'email'],
  ])('rejects %s with 400 and never echoes values', async (_name, body, field) => {
    const res = await register(body);
    expect(res.status).toBe(400);
    const resBody = res.body as { error: string; fields: Record<string, string> };
    expect(resBody.error).toBe('invalid_request');
    expect(resBody.fields).toHaveProperty(field);
    expect(res.text).not.toContain(GOOD_PASSWORD);
    expect(await deps.prisma.user.count()).toBe(0);
  });

  it('rejects a breached password', async () => {
    const res = await register({ email: uniqueEmail(), password: 'password1234' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'password_breached' });
    expect(await deps.prisma.user.count()).toBe(0);
  });

  it('fails closed with 503 when the breach check is unavailable', async () => {
    const down = createApp({ ...deps, pwned: createFakePwned('unavailable') });
    const res = await request(down)
      .post('/auth/register')
      .send({ email: uniqueEmail(), password: GOOD_PASSWORD });
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'password_check_unavailable' });
    expect(res.headers['retry-after']).toBe('30');
    expect(await deps.prisma.user.count()).toBe(0);
  });

  describe('existing email (no enumeration)', () => {
    it('gives the identical response for new and existing emails', async () => {
      const email = uniqueEmail();
      const first = await register({ email, password: GOOD_PASSWORD });
      const second = await register({ email, password: 'another long password 42' });
      expect(second.status).toBe(first.status);
      expect(second.body).toEqual(first.body);
    });

    it('verified account: sends "already registered" and keeps the password', async () => {
      const email = uniqueEmail();
      const original = await hashPassword(GOOD_PASSWORD);
      const user = await deps.prisma.user.create({
        data: { email, passwordHash: original, emailVerifiedAt: new Date() },
      });

      const res = await register({ email, password: 'attacker chosen password' });
      expect(res.status).toBe(202);

      const mail = await deps.mailer.waitFor(email);
      expect(mail.subject).toBe('You already have a KeyHouse account');
      expect(mail.text).not.toContain('#token=');
      const after = await deps.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(after.passwordHash).toBe(original);
      expect(await auditTypes(user.id)).toEqual(['register.duplicate']);
    });

    it('unverified account: sends a choose-password link, never overwrites (pre-hijacking)', async () => {
      const email = uniqueEmail();
      // The attacker registered first, with a password they know.
      await register({ email, password: 'attacker chosen password' });
      const user = await deps.prisma.user.findUniqueOrThrow({ where: { email } });
      const attackerHash = user.passwordHash;
      deps.mailer.sent.length = 0;

      // The real owner registers later.
      await register({ email, password: GOOD_PASSWORD });

      const mail = await deps.mailer.waitFor(email);
      expect(mail.subject).toBe('Finish setting up your KeyHouse account');
      expect(mail.text).toContain(`${deps.config.WEB_ORIGIN}/reset-password#token=`);
      const token = tokenFromEmail(mail);
      const row = await deps.prisma.emailToken.findUniqueOrThrow({
        where: { tokenHash: hashToken(token) },
      });
      expect(row.purpose).toBe('RESET_PASSWORD');
      expect((row.expiresAt.getTime() - row.createdAt.getTime()) / 60_000).toBeCloseTo(30, 1);

      // The registration request itself changed nothing.
      const after = await deps.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(after.passwordHash).toBe(attackerHash);
      expect(after.emailVerifiedAt).toBeNull();
    });

    it('takes a similar time for new and existing emails', async () => {
      const existing = uniqueEmail();
      await register({ email: existing, password: GOOD_PASSWORD });

      async function median(fn: () => Promise<unknown>): Promise<number> {
        const times: number[] = [];
        for (let i = 0; i < 5; i++) {
          const t = performance.now();
          await fn();
          times.push(performance.now() - t);
        }
        times.sort((a, b) => a - b);
        return times[2] ?? 0;
      }
      const tNew = await median(() => register({ email: uniqueEmail(), password: GOOD_PASSWORD }));
      const tExisting = await median(() => register({ email: existing, password: GOOD_PASSWORD }));

      // Both paths are dominated by argon2 (~tens of ms). A missing hash on one path
      // would make it several times faster, so a 2x bound catches it without flaking.
      expect(tExisting / tNew).toBeGreaterThan(0.5);
      expect(tExisting / tNew).toBeLessThan(2);
    });
  });
});

describe('POST /auth/verify-email', () => {
  async function registerAndGetToken(): Promise<{ email: string; token: string }> {
    const email = uniqueEmail();
    await register({ email, password: GOOD_PASSWORD });
    return { email, token: tokenFromEmail(await deps.mailer.waitFor(email)) };
  }

  it('verifies the email with the emailed token, once', async () => {
    const { email, token } = await registerAndGetToken();

    const res = await request(app).post('/auth/verify-email').send({ token });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'verified' });

    const user = await deps.prisma.user.findUniqueOrThrow({ where: { email } });
    expect(user.emailVerifiedAt).not.toBeNull();
    expect(await auditTypes(user.id)).toEqual(['user.registered', 'email.verified']);

    const again = await request(app).post('/auth/verify-email').send({ token });
    expect(again.status).toBe(400);
    expect(again.body).toEqual({ error: 'invalid_or_expired_token' });
  });

  it.each([
    ['garbage', { token: 'not-a-real-token' }],
    ['empty', { token: '' }],
  ])('rejects a %s token with the generic error', async (_name, body) => {
    const res = await request(app).post('/auth/verify-email').send(body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_or_expired_token' });
  });

  it('rejects a body without a token as invalid_request', async () => {
    const res = await request(app).post('/auth/verify-email').send({});
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: 'invalid_request' });
  });

  it('does not accept a choose-password token as a verify token', async () => {
    const email = uniqueEmail();
    await register({ email, password: GOOD_PASSWORD });
    deps.mailer.sent.length = 0;
    await register({ email, password: GOOD_PASSWORD }); // unverified duplicate → reset link
    const resetToken = tokenFromEmail(await deps.mailer.waitFor(email));

    const res = await request(app).post('/auth/verify-email').send({ token: resetToken });
    expect(res.status).toBe(400);
  });

  it('never writes the raw token or password to the audit log', async () => {
    const { email, token } = await registerAndGetToken();
    await request(app).post('/auth/verify-email').send({ token });
    const user = await deps.prisma.user.findUniqueOrThrow({ where: { email } });
    const rows = await deps.prisma.auditEvent.findMany({ where: { userId: user.id } });
    const dump = JSON.stringify(rows, (_k, v: unknown) => (typeof v === 'bigint' ? String(v) : v));
    expect(dump).not.toContain(token);
    expect(dump).not.toContain(GOOD_PASSWORD);
  });
});
