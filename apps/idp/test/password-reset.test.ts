import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RESET_REQUESTED } from '../src/routes/auth.js';
import { SESSION_COOKIE } from '../src/http/cookies.js';
import { hashPassword } from '../src/security/passwords.js';
import { hashToken, issueEmailToken } from '../src/security/tokens.js';
import { ownerDb, resetDb, uniqueEmail } from './db.js';
import {
  BREACHED_PASSWORDS,
  closeDeps,
  createApp,
  createFakePwned,
  createTestDeps,
  sessionCookie,
  tokenFromEmail,
  type TestDeps,
} from './helpers.js';

/** A fresh, long, never-breached value per call. No credential-shaped literals in the repo. */
const freshPw = () => randomBytes(18).toString('base64url');
const breachedPw = (): string => {
  const [first] = BREACHED_PASSWORDS;
  if (!first) throw new Error('BREACHED_PASSWORDS is empty');
  return first;
};

const oldPw = freshPw();

let deps: TestDeps;
let app: ReturnType<typeof createApp>;
let oldHash: string;

beforeAll(async () => {
  deps = await createTestDeps();
  app = createApp(deps);
  oldHash = await hashPassword(oldPw);
});
afterAll(async () => {
  await closeDeps(deps);
});
beforeEach(async () => {
  await resetDb();
  await deps.redis.flushdb(); // rate-limit counters (TEST Redis database only)
  deps.mailer.sent.length = 0;
});

async function makeUser(verified = true): Promise<{ id: string; email: string }> {
  const email = uniqueEmail();
  const user = await deps.prisma.user.create({
    data: { email, passwordHash: oldHash, emailVerifiedAt: verified ? new Date() : null },
  });
  return { id: user.id, email };
}

function forgot(email: string) {
  return request(app).post('/auth/forgot-password').send({ email });
}

function reset(token: string, password: string) {
  return request(app).post('/auth/reset-password').send({ token, password });
}

function login(email: string, password: string) {
  return request(app).post('/auth/login').send({ email, password });
}

/** Requests a reset and returns the token from the emailed link. */
async function resetTokenFor(email: string): Promise<string> {
  expect((await forgot(email)).status).toBe(202);
  const mail = await deps.mailer.waitFor(email);
  deps.mailer.sent.length = 0;
  return tokenFromEmail(mail);
}

describe('POST /auth/forgot-password', () => {
  it('emails a reset link with the token in the URL fragment', async () => {
    const user = await makeUser();
    const res = await forgot(user.email);
    expect(res.status).toBe(202);
    expect(res.body).toEqual(RESET_REQUESTED);

    const mail = await deps.mailer.waitFor(user.email);
    expect(mail.text).toContain(`${deps.config.WEB_ORIGIN}/reset-password#token=`);
    expect(mail.text).not.toContain('?token=');
  });

  it('answers an unknown email exactly the same, and sends nothing', async () => {
    const known = await makeUser();
    const unknownEmail = uniqueEmail();
    const a = await forgot(known.email);
    const b = await forgot(unknownEmail);

    expect(b.status).toBe(a.status);
    expect(b.body).toEqual(a.body);
    await deps.mailer.waitFor(known.email);
    await new Promise((r) => setTimeout(r, 100));
    expect(deps.mailer.sent.some((m) => m.to === unknownEmail)).toBe(false);
  });

  it('stores only the token hash', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    const row = await deps.prisma.emailToken.findUniqueOrThrow({
      where: { tokenHash: hashToken(token) },
    });
    expect(row.purpose).toBe('RESET_PASSWORD');
    expect(JSON.stringify(row)).not.toContain(token);
  });

  it('audits both known and unknown requests by email hash only', async () => {
    const user = await makeUser();
    const unknownEmail = uniqueEmail();
    await forgot(user.email);
    await forgot(unknownEmail);

    // The audit table is append-only, so earlier tests' rows are still there: filter to ours.
    const ours = new Set([hashToken(user.email), hashToken(unknownEmail)]);
    const rows = (
      await deps.prisma.auditEvent.findMany({
        where: { type: 'password_reset.requested' },
        orderBy: { id: 'asc' },
      })
    ).filter((r) => ours.has((r.metadata as { emailHash?: string }).emailHash ?? ''));
    expect(rows).toHaveLength(2);
    expect(rows[0]?.userId).toBe(user.id);
    expect(rows[1]?.userId).toBeNull();
    expect(JSON.stringify(rows, (_k, v: unknown) => (typeof v === 'bigint' ? 0 : v))).not.toContain(
      unknownEmail,
    );
  });

  it('a newer request invalidates the older link', async () => {
    const user = await makeUser();
    const first = await resetTokenFor(user.email);
    const second = await resetTokenFor(user.email);

    expect((await reset(first, freshPw())).status).toBe(400);
    expect((await reset(second, freshPw())).status).toBe(200);
  });
});

describe('POST /auth/reset-password', () => {
  it('sets the new password: old one stops working, new one works', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    const newPw = freshPw();

    const res = await reset(token, newPw);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'password_reset' });

    expect((await login(user.email, oldPw)).status).toBe(401);
    expect((await login(user.email, newPw)).status).toBe(200);
  });

  it('signs out every existing session, does not log in, and clears the cookie', async () => {
    const user = await makeUser();
    const laptop = sessionCookie(await login(user.email, oldPw));
    const phone = sessionCookie(await login(user.email, oldPw));
    const token = await resetTokenFor(user.email);

    const res = await reset(token, freshPw());
    expect(String(res.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);

    for (const s of [laptop, phone]) {
      expect((await request(app).get('/auth/me').set('Cookie', s.pair)).status).toBe(401);
    }
    const live = await deps.prisma.session.count({ where: { userId: user.id, revokedAt: null } });
    expect(live).toBe(0);
  });

  it('emails a "password changed" alert and audits the reset', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    const newPw = freshPw();
    await reset(token, newPw);

    const alert = await deps.mailer.waitFor(user.email);
    expect(alert.subject).toMatch(/password was changed/i);
    expect(alert.text).not.toContain(newPw);

    const types = (
      await deps.prisma.auditEvent.findMany({ where: { userId: user.id }, orderBy: { id: 'asc' } })
    ).map((r) => r.type);
    expect(types).toContain('password_reset.completed');
  });

  it('verifies the email of an unverified account', async () => {
    const user = await makeUser(false);
    const token = await resetTokenFor(user.email);
    const newPw = freshPw();
    await reset(token, newPw);

    const row = await deps.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row.emailVerifiedAt).not.toBeNull();
    expect((await login(user.email, newPw)).status).toBe(200);
  });

  it('works only once', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    expect((await reset(token, freshPw())).status).toBe(200);

    const again = await reset(token, freshPw());
    expect(again.status).toBe(400);
    expect(again.body).toEqual({ error: 'invalid_or_expired_token' });
  });

  it('works only once, even with two requests in parallel', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    const results = await Promise.all([reset(token, freshPw()), reset(token, freshPw())]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
  });

  it('rejects an expired link', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    await ownerDb().emailToken.update({
      where: { tokenHash: hashToken(token) },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await reset(token, freshPw())).status).toBe(400);
  });

  it('rejects an email-verification token used as a reset token', async () => {
    const user = await makeUser(false);
    const verifyToken = await issueEmailToken(deps.prisma, user.id, 'VERIFY_EMAIL', 60_000);
    const res = await reset(verifyToken, freshPw());
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_or_expired_token' });
  });

  it('rejects unknown and malformed tokens with the same answer', async () => {
    const unknown = await reset(randomBytes(32).toString('base64url'), freshPw());
    const garbage = await reset('nope', freshPw());
    expect(unknown.status).toBe(400);
    expect(garbage.body).toEqual(unknown.body);
  });

  it('enforces the password policy', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);
    const res = await reset(token, 'x'.repeat(5));
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: 'invalid_request' });
  });

  it('rejects a breached password WITHOUT burning the link', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);

    const res = await reset(token, breachedPw());
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'password_breached' });

    expect((await reset(token, freshPw())).status).toBe(200);
  });

  it('fails closed when the breach check is down, WITHOUT burning the link', async () => {
    const user = await makeUser();
    const token = await resetTokenFor(user.email);

    const downDeps = await createTestDeps({ pwned: createFakePwned('unavailable') });
    try {
      const res = await request(createApp(downDeps))
        .post('/auth/reset-password')
        .send({ token, password: freshPw() });
      expect(res.status).toBe(503);
      expect(res.headers['retry-after']).toBe('30');
    } finally {
      await closeDeps(downDeps);
    }

    expect((await reset(token, freshPw())).status).toBe(200);
  });
});
