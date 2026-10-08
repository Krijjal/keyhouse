import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RESET_REQUESTED } from '../src/routes/auth.js';
import { hashPassword } from '../src/security/passwords.js';
import { hashToken } from '../src/security/tokens.js';
import { resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, type TestDeps } from './helpers.js';

// ─── 1.6 exercise 5: these fail until throttle.ts is wired into routes/auth.ts ───

// Generated per run: no credential-shaped literals in the repo.
const knownPw = randomBytes(18).toString('base64url');
const wrongPw = () => randomBytes(18).toString('base64url');

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
  await deps.redis.flushdb(); // rate-limit counters (TEST Redis database only)
  deps.mailer.sent.length = 0;
});

async function makeUser(): Promise<string> {
  const email = uniqueEmail();
  await deps.prisma.user.create({
    data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
  });
  return email;
}

function login(email: string, password: string) {
  return request(app).post('/auth/login').send({ email, password });
}

async function auditRows(type: string, email: string) {
  const rows = await deps.prisma.auditEvent.findMany({ where: { type } });
  // The audit table is append-only, so filter to this test's email.
  return rows.filter((r) => (r.metadata as { emailHash?: string }).emailHash === hashToken(email));
}

describe('login throttling (wired into POST /auth/login)', () => {
  it('after 5 wrong passwords, even the right one gets 429 with Retry-After', async () => {
    const email = await makeUser();
    for (let i = 0; i < 5; i++) expect((await login(email, wrongPw())).status).toBe(401);

    const res = await login(email, knownPw);
    expect(res.status).toBe(429);
    expect(res.body).toEqual({ error: 'too_many_attempts' });
    expect(Number(res.headers['retry-after'])).toBeGreaterThanOrEqual(1);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('blocked attempts are rejected BEFORE the password check', async () => {
    const email = await makeUser();
    for (let i = 0; i < 5; i++) await login(email, wrongPw());
    await login(email, wrongPw()); // blocked

    // Only the 5 checked attempts produced a login.failed row; the blocked one did not.
    expect(await auditRows('login.failed', email)).toHaveLength(5);
    const throttled = await auditRows('login.throttled', email);
    expect(throttled).toHaveLength(1);
    expect((throttled[0]?.metadata as { reason?: string }).reason).toBeDefined();
  });

  it('an unknown email is throttled exactly like a real one', async () => {
    const real = await makeUser();
    const unknown = uniqueEmail();
    for (let i = 0; i < 5; i++) {
      await login(real, wrongPw());
      await login(unknown, wrongPw());
    }
    const a = await login(real, wrongPw());
    const b = await login(unknown, wrongPw());
    expect(b.status).toBe(a.status);
    expect(b.body).toEqual(a.body);
    expect(a.status).toBe(429);
  });

  it('a successful login resets the email counters', async () => {
    const email = await makeUser();
    for (let i = 0; i < 4; i++) await login(email, wrongPw());
    expect((await login(email, knownPw)).status).toBe(200);
    for (let i = 0; i < 4; i++) expect((await login(email, wrongPw())).status).toBe(401);
  });

  it('the raw email never reaches Redis', async () => {
    const email = await makeUser();
    await login(email, wrongPw());
    const keys = await deps.redis.keys('*');
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) expect(key).not.toContain(email);
  });
});

describe('forgot-password throttling (wired into POST /auth/forgot-password)', () => {
  it('sends at most 3 emails per address per hour, with the same answer every time', async () => {
    const email = await makeUser();
    const responses = [];
    for (let i = 0; i < 5; i++) {
      responses.push(await request(app).post('/auth/forgot-password').send({ email }));
    }

    for (const res of responses) {
      expect(res.status).toBe(202);
      expect(res.body).toEqual(RESET_REQUESTED);
    }
    await new Promise((r) => setTimeout(r, 100)); // let background sends finish
    expect(deps.mailer.sent.filter((m) => m.to === email)).toHaveLength(3);
    expect(await auditRows('password_reset.throttled', email)).toHaveLength(2);
  });

  it('an unknown email is counted the same way', async () => {
    const unknown = uniqueEmail();
    for (let i = 0; i < 4; i++) {
      await request(app).post('/auth/forgot-password').send({ email: unknown });
    }
    expect(await auditRows('password_reset.throttled', unknown)).toHaveLength(1);
  });
});
