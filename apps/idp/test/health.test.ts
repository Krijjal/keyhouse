import request from 'supertest';
import { afterAll, describe, expect, it } from 'vitest';
import type { AppDeps } from '../src/app.js';
import { createRedis } from '../src/redis.js';
import { createApp, createTestDeps } from './helpers.js';

const toClose: AppDeps[] = [];
async function deps(overrides: Partial<AppDeps> = {}): Promise<AppDeps> {
  const d = await createTestDeps(overrides);
  toClose.push(d);
  return d;
}

afterAll(async () => {
  await Promise.allSettled(toClose.flatMap((d) => [d.prisma.$disconnect(), d.redis.quit()]));
});

describe('GET /health', () => {
  it('returns 200 when Postgres and Redis are reachable', async () => {
    const res = await request(createApp(await deps())).get('/health');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok', checks: { postgres: 'ok', redis: 'ok' } });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('returns 503 without leaking error details when Redis is down', async () => {
    // Never connected (nothing listens on port 1): with no offline queue, PING fails at once.
    const brokenRedis = createRedis('redis://:wrong-password-xyz@127.0.0.1:1/0');
    brokenRedis.on('error', () => undefined);
    const res = await request(createApp(await deps({ redis: brokenRedis }))).get('/health');

    expect(res.status).toBe(503);
    // Exact body: only ok/error per dependency, nothing else.
    expect(res.body).toEqual({ status: 'error', checks: { postgres: 'ok', redis: 'error' } });
    expect(res.text).not.toMatch(/ECONNREFUSED|127\.0\.0\.1|wrong-password/);
  });
});

describe('app hardening', () => {
  it('does not send X-Powered-By', async () => {
    const res = await request(createApp(await deps())).get('/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('returns a generic 400 for malformed JSON', async () => {
    const res = await request(createApp(await deps()))
      .post('/anything')
      .set('Content-Type', 'application/json')
      .send('{"broken":');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'bad_request' });
  });

  it('returns JSON 404 for unknown routes', async () => {
    const res = await request(createApp(await deps())).get('/nope');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'not_found' });
  });
});
