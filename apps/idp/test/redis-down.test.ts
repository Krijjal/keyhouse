import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createRedis, type Redis } from '../src/redis.js';
import { hashPassword } from '../src/security/passwords.js';
import { hashToken } from '../src/security/tokens.js';
import { resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, type TestDeps } from './helpers.js';

// ─── Exercise A: these fail until Redis errors fail closed with a fast 503 ───

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const knownPw = randomBytes(18).toString('base64url'); // generated per run, never a literal

let deps: TestDeps; // the normal, healthy Redis
let downDeps: TestDeps; // a Redis that isn't there
let downRedis: Redis;
let pwHash: string;

beforeAll(async () => {
  deps = await createTestDeps();
  // Port 1: nothing listens there. With no offline queue, every command fails at once.
  downRedis = createRedis('redis://127.0.0.1:1');
  downRedis.on('error', () => {}); // expected; keeps the test output quiet
  downDeps = await createTestDeps({ redis: downRedis });
  pwHash = await hashPassword(knownPw);
});
afterAll(async () => {
  downRedis.disconnect();
  await closeDeps(deps);
  await downDeps.prisma.$disconnect();
});
beforeEach(async () => {
  await resetDb();
  await deps.redis.flushdb();
  downDeps.mailer.sent.length = 0;
  downDeps.logger.lines.length = 0;
});

async function makeUser(): Promise<string> {
  const email = uniqueEmail();
  await deps.prisma.user.create({
    data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
  });
  return email;
}

describe('Redis unreachable', () => {
  it('login answers 503 + Retry-After and never checks the password (fails closed)', async () => {
    const email = await makeUser();
    const res = await request(createApp(downDeps))
      .post('/auth/login')
      .send({ email, password: knownPw });

    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'service_unavailable' });
    expect(res.headers['retry-after']).toBe('5');
    expect(res.headers['set-cookie']).toBeUndefined();

    // Not even the correct password gets in, and no login was attempted at all.
    const rows = await deps.prisma.auditEvent.findMany({ where: { type: 'login.failed' } });
    const ours = rows.filter(
      (r) => (r.metadata as { emailHash?: string }).emailHash === hashToken(email),
    );
    expect(ours).toHaveLength(0);
  });

  it('forgot-password answers 503 and sends no email', async () => {
    const email = await makeUser();
    const res = await request(createApp(downDeps)).post('/auth/forgot-password').send({ email });

    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'service_unavailable' });
    await sleep(100);
    expect(downDeps.mailer.sent).toHaveLength(0);
  });

  it('logs the outage without any secrets', async () => {
    const email = await makeUser();
    await request(createApp(downDeps)).post('/auth/login').send({ email, password: knownPw });

    const line = downDeps.logger.lines.find((l) => l.msg === 'rate limiter unavailable');
    expect(line?.level).toBe('error');
    expect(JSON.stringify(downDeps.logger.lines)).not.toContain(knownPw);
  });
});

describe('Redis hanging (connected, but not answering)', () => {
  it('login gives up within about a second instead of waiting forever', async () => {
    const email = await makeUser();
    const app = createApp(deps);

    // CLIENT PAUSE freezes every client's commands for 1.5 s: a stand-in for an
    // overloaded or stuck Redis. A separate connection sends it.
    const admin = createRedis(process.env.TEST_REDIS_URL ?? '');
    await admin.connect();
    await admin.client('PAUSE', 1500);
    admin.disconnect();

    const started = Date.now();
    const res = await request(app).post('/auth/login').send({ email, password: knownPw });
    const took = Date.now() - started;

    expect(res.status).toBe(503);
    expect(took).toBeLessThan(1200); // the 500 ms command timeout kicked in

    await sleep(1500 - took + 200); // let the pause end before the next test
  });
});
