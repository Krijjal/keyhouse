import { randomBytes, randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SESSION_COOKIE } from '../src/http/cookies.js';
import { hashPassword } from '../src/security/passwords.js';
import { hashToken } from '../src/security/tokens.js';
import { ownerDb, resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, sessionCookie, type TestDeps } from './helpers.js';

// Generated per run: no credential-shaped literal in the repo.
const knownPw = randomBytes(18).toString('base64url');

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
});

async function makeUser(): Promise<{ id: string; email: string }> {
  const email = uniqueEmail();
  const user = await deps.prisma.user.create({
    data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
  });
  return { id: user.id, email };
}

/** Logs in and returns the cookie pair to send back, plus the raw token for DB lookups. */
async function loginAs(
  email: string,
  userAgent = 'vitest',
): Promise<{ pair: string; token: string }> {
  const res = await request(app)
    .post('/auth/login')
    .set('User-Agent', userAgent)
    .send({ email, password: knownPw });
  expect(res.status).toBe(200);
  return sessionCookie(res);
}

function me(pair: string) {
  return request(app).get('/auth/me').set('Cookie', pair);
}

async function sessionRow(token: string) {
  return deps.prisma.session.findUniqueOrThrow({ where: { tokenHash: hashToken(token) } });
}

async function auditTypes(userId: string): Promise<string[]> {
  const rows = await deps.prisma.auditEvent.findMany({ where: { userId }, orderBy: { id: 'asc' } });
  return rows.map((r) => r.type);
}

describe('POST /auth/logout', () => {
  it('revokes the session server-side and clears the cookie', async () => {
    const user = await makeUser();
    const { pair, token } = await loginAs(user.email);

    const res = await request(app).post('/auth/logout').set('Cookie', pair);
    expect(res.status).toBe(204);
    expect(String(res.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);

    // A stolen copy of the cookie is dead too, not just the browser's copy.
    expect((await sessionRow(token)).revokedAt).not.toBeNull();
    expect((await me(pair)).status).toBe(401);
    expect(await auditTypes(user.id)).toContain('logout');
  });

  it('answers 204 and clears the cookie even without a valid session', async () => {
    const none = await request(app).post('/auth/logout');
    expect(none.status).toBe(204);

    const garbage = await request(app).post('/auth/logout').set('Cookie', `${SESSION_COOKIE}=nope`);
    expect(garbage.status).toBe(204);
    expect(String(garbage.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);
  });

  it('only revokes the session it was called with', async () => {
    const user = await makeUser();
    const laptop = await loginAs(user.email);
    const phone = await loginAs(user.email);

    await request(app).post('/auth/logout').set('Cookie', laptop.pair);
    expect((await me(laptop.pair)).status).toBe(401);
    expect((await me(phone.pair)).status).toBe(200);
  });
});

describe('POST /auth/logout-all', () => {
  it('revokes every session of the user, including the current one', async () => {
    const user = await makeUser();
    const a = await loginAs(user.email);
    const b = await loginAs(user.email);
    const c = await loginAs(user.email);

    const res = await request(app).post('/auth/logout-all').set('Cookie', a.pair);
    expect(res.status).toBe(204);
    expect(String(res.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);

    for (const s of [a, b, c]) expect((await me(s.pair)).status).toBe(401);
    expect(await auditTypes(user.id)).toContain('logout.all_sessions');
  });

  it("does not touch other users' sessions", async () => {
    const alice = await makeUser();
    const bob = await makeUser();
    const aliceSession = await loginAs(alice.email);
    const bobSession = await loginAs(bob.email);

    await request(app).post('/auth/logout-all').set('Cookie', aliceSession.pair);
    expect((await me(bobSession.pair)).status).toBe(200);
  });

  it('requires a valid session', async () => {
    const res = await request(app).post('/auth/logout-all');
    expect(res.status).toBe(401);
  });
});

describe('GET /auth/sessions', () => {
  it('lists live sessions, marks the current one, and never exposes token hashes', async () => {
    const user = await makeUser();
    const laptop = await loginAs(user.email, 'laptop-browser');
    const phone = await loginAs(user.email, 'phone-browser');

    const res = await request(app).get('/auth/sessions').set('Cookie', phone.pair);
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');

    const { sessions } = res.body as {
      sessions: { id: string; userAgent: string; current: boolean }[];
    };
    expect(sessions).toHaveLength(2);
    const current = sessions.find((s) => s.current);
    expect(current?.userAgent).toBe('phone-browser');
    expect(sessions.filter((s) => s.current)).toHaveLength(1);

    const body = JSON.stringify(res.body);
    expect(body).not.toContain('tokenHash');
    expect(body).not.toContain(hashToken(laptop.token));
    expect(body).not.toContain(laptop.token);
  });

  it('leaves out revoked and idle-expired sessions', async () => {
    const user = await makeUser();
    const live = await loginAs(user.email);
    const revoked = await loginAs(user.email);
    const idle = await loginAs(user.email);

    await request(app).post('/auth/logout').set('Cookie', revoked.pair);
    await ownerDb().session.update({
      where: { tokenHash: hashToken(idle.token) },
      data: { lastSeenAt: new Date(Date.now() - 31 * 60 * 1000) },
    });

    const res = await request(app).get('/auth/sessions').set('Cookie', live.pair);
    const { sessions } = res.body as { sessions: { id: string }[] };
    expect(sessions.map((s) => s.id)).toEqual([(await sessionRow(live.token)).id]);
  });

  it("never lists another user's sessions", async () => {
    const alice = await makeUser();
    const bob = await makeUser();
    const aliceSession = await loginAs(alice.email);
    await loginAs(bob.email);

    const res = await request(app).get('/auth/sessions').set('Cookie', aliceSession.pair);
    expect((res.body as { sessions: unknown[] }).sessions).toHaveLength(1);
  });

  it('requires a valid session', async () => {
    expect((await request(app).get('/auth/sessions')).status).toBe(401);
  });
});

describe('DELETE /auth/sessions/:id', () => {
  it('revokes one of your other sessions and keeps the current one', async () => {
    const user = await makeUser();
    const laptop = await loginAs(user.email);
    const phone = await loginAs(user.email);
    const laptopId = (await sessionRow(laptop.token)).id;

    const res = await request(app).delete(`/auth/sessions/${laptopId}`).set('Cookie', phone.pair);
    expect(res.status).toBe(204);
    expect(res.headers['set-cookie']).toBeUndefined();

    expect((await me(laptop.pair)).status).toBe(401);
    expect((await me(phone.pair)).status).toBe(200);
    expect(await auditTypes(user.id)).toContain('session.revoked');
  });

  it('clears the cookie when you revoke the session you are using', async () => {
    const user = await makeUser();
    const s = await loginAs(user.email);
    const id = (await sessionRow(s.token)).id;

    const res = await request(app).delete(`/auth/sessions/${id}`).set('Cookie', s.pair);
    expect(res.status).toBe(204);
    expect(String(res.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);
    expect((await me(s.pair)).status).toBe(401);
  });

  it("IDOR: cannot revoke another user's session, and gets the same 404 as a made-up id", async () => {
    const alice = await makeUser();
    const bob = await makeUser();
    const aliceSession = await loginAs(alice.email);
    const bobSession = await loginAs(bob.email);
    const bobId = (await sessionRow(bobSession.token)).id;

    const theirs = await request(app)
      .delete(`/auth/sessions/${bobId}`)
      .set('Cookie', aliceSession.pair);
    const madeUp = await request(app)
      .delete(`/auth/sessions/${randomUUID()}`)
      .set('Cookie', aliceSession.pair);
    const malformed = await request(app)
      .delete('/auth/sessions/not-a-uuid')
      .set('Cookie', aliceSession.pair);

    for (const res of [theirs, madeUp, malformed]) {
      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'session_not_found' });
    }

    // Bob is still logged in, and Alice's probing is on the record.
    expect((await me(bobSession.pair)).status).toBe(200);
    expect((await sessionRow(bobSession.token)).revokedAt).toBeNull();
    expect(await auditTypes(alice.id)).toContain('session.revoke_denied');
  });

  it('requires a valid session', async () => {
    const res = await request(app).delete(`/auth/sessions/${randomUUID()}`);
    expect(res.status).toBe(401);
  });
});
