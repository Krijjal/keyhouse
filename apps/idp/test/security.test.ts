import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, type TestDeps } from './helpers.js';

// ─── 1.7 exercises: these fail until security.ts is written and wired into app.ts ───

const EVIL = 'https://evil.example';

let deps: TestDeps;
let app: ReturnType<typeof createApp>;
let trusted: string;

beforeAll(async () => {
  deps = await createTestDeps();
  app = createApp(deps);
  trusted = new URL(deps.config.WEB_ORIGIN).origin;
});
afterAll(async () => {
  await closeDeps(deps);
});
beforeEach(async () => {
  await resetDb();
  await deps.redis.flushdb();
  deps.mailer.sent.length = 0;
});

describe('exercise 1: security headers', () => {
  it('sends a strict CSP and the other hardening headers', async () => {
    const res = await request(app).get('/health');
    const csp = String(res.headers['content-security-policy']);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).not.toContain('script-src'); // nothing re-allowed: no helmet web-page defaults

    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['cross-origin-resource-policy']).toBe('same-site');
    expect(res.headers['x-frame-options']).toBeDefined();
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('also sends them on 404s and errors', async () => {
    const notFound = await request(app).get('/nope');
    const badBody = await request(app).post('/auth/login').send({});
    for (const res of [notFound, badBody]) {
      expect(String(res.headers['content-security-policy'])).toContain("default-src 'none'");
    }
  });
});

describe('exercise 2: CORS', () => {
  it('lets the web app read responses, with cookies', async () => {
    const res = await request(app).get('/health').set('Origin', trusted);
    expect(res.headers['access-control-allow-origin']).toBe(trusted);
    expect(res.headers['access-control-allow-credentials']).toBe('true');
    expect(String(res.headers.vary)).toMatch(/origin/i);
  });

  it('gives any other site nothing, and never a wildcard', async () => {
    const res = await request(app).get('/health').set('Origin', EVIL);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    expect(String(res.headers.vary)).toMatch(/origin/i);
  });

  it('answers a preflight from the web app', async () => {
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', trusted)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe(trusted);
    expect(String(res.headers['access-control-allow-methods'])).toContain('POST');
    expect(String(res.headers['access-control-allow-methods'])).toContain('DELETE');
    expect(String(res.headers['access-control-allow-headers']).toLowerCase()).toContain(
      'content-type',
    );
    expect(res.headers['access-control-max-age']).toBe('600');
  });

  it('gives a preflight from another site no permission', async () => {
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', EVIL)
      .set('Access-Control-Request-Method', 'POST');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['access-control-allow-methods']).toBeUndefined();
  });
});

describe('exercise 3: Origin check (CSRF)', () => {
  const logout = () => request(app).post('/auth/logout');

  it('allows a POST from the web app', async () => {
    expect((await logout().set('Origin', trusted)).status).toBe(204);
  });

  it('refuses a POST from another site with 403, and audits it', async () => {
    const res = await logout().set('Origin', EVIL);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'forbidden_origin' });

    const rows = await deps.prisma.auditEvent.findMany({
      where: { type: 'request.untrusted_origin' },
      orderBy: { id: 'desc' },
      take: 1,
    });
    expect(rows[0]?.metadata).toMatchObject({ method: 'POST', path: '/auth/logout', origin: EVIL });
  });

  it('refuses the "null" origin (sandboxed frames, local files)', async () => {
    expect((await logout().set('Origin', 'null')).status).toBe(403);
  });

  it('refuses a DELETE from another site before auth even runs', async () => {
    const res = await request(app)
      .delete('/auth/sessions/00000000-0000-7000-8000-000000000000')
      .set('Origin', EVIL);
    expect(res.status).toBe(403); // not 401: the check runs first
  });

  it('a refused request never reaches the route (no reset email is sent)', async () => {
    const email = uniqueEmail();
    const res = await request(app)
      .post('/auth/forgot-password')
      .set('Origin', EVIL)
      .send({ email });
    expect(res.status).toBe(403);
    await new Promise((r) => setTimeout(r, 50));
    expect(deps.mailer.sent).toHaveLength(0);
  });

  it('no Origin: uses Sec-Fetch-Site (cross-site refused, same-site allowed)', async () => {
    expect((await logout().set('Sec-Fetch-Site', 'cross-site')).status).toBe(403);
    expect((await logout().set('Sec-Fetch-Site', 'same-site')).status).toBe(204);
    expect((await logout().set('Sec-Fetch-Site', 'same-origin')).status).toBe(204);
  });

  it('neither header (curl, tests, servers): allowed', async () => {
    expect((await logout()).status).toBe(204);
  });

  it('never blocks safe methods, whatever the origin', async () => {
    const res = await request(app).get('/health').set('Origin', EVIL);
    expect(res.status).not.toBe(403);
  });

  it('caps a huge attacker-controlled Origin before auditing it', async () => {
    const huge = `https://${'a'.repeat(5000)}.example`;
    await logout().set('Origin', huge);
    const [row] = await deps.prisma.auditEvent.findMany({
      where: { type: 'request.untrusted_origin' },
      orderBy: { id: 'desc' },
      take: 1,
    });
    expect(String((row?.metadata as { origin?: string }).origin).length).toBeLessThanOrEqual(200);
  });
});

describe('exercise 4: dev server binding', () => {
  it('listens on this computer only by default', () => {
    const cfg = loadConfig({ ...process.env, IDP_HOST: undefined });
    expect(cfg.IDP_HOST).toBe('127.0.0.1');
  });
});
