import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SESSION_COOKIE } from '../src/http/cookies.js';
import { hashPassword } from '../src/security/passwords.js';
import { hashToken } from '../src/security/tokens.js';
import { ownerDb, resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, sessionCookie, type TestDeps } from './helpers.js';

// These depend on learning item b (sessions) and pass once it is implemented.

const PASSWORD = 'correct horse battery staple';

let deps: TestDeps;
let app: ReturnType<typeof createApp>;
let passwordHash: string;

beforeAll(async () => {
  deps = await createTestDeps();
  app = createApp(deps);
  passwordHash = await hashPassword(PASSWORD);
});
afterAll(async () => {
  await closeDeps(deps);
});
beforeEach(async () => {
  await resetDb();
  await deps.redis.flushdb(); // rate-limit counters (TEST Redis database only)
});

async function makeUser(verified = true): Promise<{ id: string; email: string }> {
  const email = uniqueEmail();
  const user = await deps.prisma.user.create({
    data: { email, passwordHash, emailVerifiedAt: verified ? new Date() : null },
  });
  return { id: user.id, email };
}

function login(body: object, cookie?: string) {
  const req = request(app).post('/auth/login').send(body);
  return cookie ? req.set('Cookie', cookie) : req;
}

describe('POST /auth/login', () => {
  it('logs in a verified user and sets a hardened session cookie', async () => {
    const user = await makeUser();
    const res = await login({ email: user.email, password: PASSWORD });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'logged_in' });

    const { header, token } = sessionCookie(res);
    expect(header).toMatch(/;\s*HttpOnly/i);
    expect(header).toMatch(/;\s*Secure/i);
    expect(header).toMatch(/;\s*SameSite=Lax/i);
    expect(header).toMatch(/;\s*Path=\//i);
    expect(header).not.toMatch(/;\s*Domain=/i);

    // Only the hash is stored.
    const row = await deps.prisma.session.findUniqueOrThrow({
      where: { tokenHash: hashToken(token) },
    });
    expect(row.userId).toBe(user.id);
  });

  it('gives the same 401 for a wrong password and an unknown email', async () => {
    const user = await makeUser();
    const wrong = await login({ email: user.email, password: 'wrong password entirely' });
    const unknown = await login({ email: uniqueEmail(), password: PASSWORD });

    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual({ error: 'invalid_credentials' });
    expect(unknown.body).toEqual(wrong.body);
    expect(wrong.headers['set-cookie']).toBeUndefined();
  });

  it('refuses an unverified user who knows the password', async () => {
    const user = await makeUser(false);
    const res = await login({ email: user.email, password: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'email_not_verified' });
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('audits success and failure without secrets', async () => {
    const user = await makeUser();
    await login({ email: user.email, password: 'wrong password entirely' });
    await login({ email: user.email, password: PASSWORD });
    const rows = await deps.prisma.auditEvent.findMany({
      where: { userId: user.id },
      orderBy: { id: 'asc' },
    });
    expect(rows.map((r) => r.type)).toEqual(['login.failed', 'login.succeeded']);
    const dump = JSON.stringify(rows, (_k, v: unknown) => (typeof v === 'bigint' ? String(v) : v));
    expect(dump).not.toContain(PASSWORD);
  });

  it('rotates: logging in again revokes the session the browser already had', async () => {
    const user = await makeUser();
    const first = sessionCookie(await login({ email: user.email, password: PASSWORD }));
    const second = sessionCookie(
      await login({ email: user.email, password: PASSWORD }, first.pair),
    );

    expect(second.token).not.toBe(first.token);
    const old = await deps.prisma.session.findUniqueOrThrow({
      where: { tokenHash: hashToken(first.token) },
    });
    expect(old.revokedAt).not.toBeNull();
  });
});

describe('requireAuth (GET /auth/me)', () => {
  async function loggedIn(): Promise<{ email: string; pair: string; token: string }> {
    const user = await makeUser();
    const c = sessionCookie(await login({ email: user.email, password: PASSWORD }));
    return { email: user.email, ...c };
  }

  it('returns the current user with a valid session', async () => {
    const { email, pair } = await loggedIn();
    const res = await request(app).get('/auth/me').set('Cookie', pair);
    expect(res.status).toBe(200);
    expect((res.body as { user: { email: string } }).user.email).toBe(email);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('rejects requests without a cookie', async () => {
    const res = await request(app).get('/auth/me');
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'unauthenticated' });
  });

  it('rejects and clears a garbage cookie', async () => {
    const res = await request(app).get('/auth/me').set('Cookie', `${SESSION_COOKIE}=garbage`);
    expect(res.status).toBe(401);
    expect(String(res.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);
  });

  it('rejects a session idle for over 30 minutes', async () => {
    const { pair, token } = await loggedIn();
    await ownerDb().session.update({
      where: { tokenHash: hashToken(token) },
      data: { lastSeenAt: new Date(Date.now() - 31 * 60 * 1000) },
    });
    const res = await request(app).get('/auth/me').set('Cookie', pair);
    expect(res.status).toBe(401);
  });

  it('rejects a revoked session', async () => {
    const { pair, token } = await loggedIn();
    await ownerDb().session.update({
      where: { tokenHash: hashToken(token) },
      data: { revokedAt: new Date() },
    });
    const res = await request(app).get('/auth/me').set('Cookie', pair);
    expect(res.status).toBe(401);
  });
});
