import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { MFA_COOKIE, SESSION_COOKIE } from '../src/http/cookies.js';
import { hashPassword } from '../src/security/passwords.js';
import { issueRecoveryCodes } from '../src/security/recovery-codes.js';
import { sealSecret } from '../src/security/secret-box.js';
import { hashToken } from '../src/security/tokens.js';
import { generateTotpSecret, hotp, stepAt } from '../src/security/totp.js';
import { ownerDb, resetDb, uniqueEmail } from './db.js';
import { closeDeps, createApp, createTestDeps, type TestDeps } from './helpers.js';

// The TOTP-code tests need your recordTotpUse (exercise 2.5); the rest pass without it.

const knownPw = randomBytes(18).toString('base64url'); // generated per run, never a literal

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

/** A verified user with MFA switched on, ready to sign in. */
async function userWithMfa() {
  const email = uniqueEmail();
  const user = await deps.prisma.user.create({
    data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
  });
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
  return { userId: user.id, email, recoveryCodes, codeNow };
}

function cookieFrom(res: request.Response, name: string): string | null {
  const raw = (res.headers['set-cookie'] as unknown as string[] | undefined) ?? [];
  const header = raw.find((c) => c.startsWith(`${name}=`));
  return header ?? null;
}

/** Password step. Returns the ticket cookie pair ("__Host-mfa=...") to send back. */
async function passwordStep(email: string) {
  const res = await request(app).post('/auth/login').send({ email, password: knownPw });
  const header = cookieFrom(res, MFA_COOKIE);
  return { res, header, ticket: header?.split(';')[0] ?? '' };
}

const codeStep = (ticket: string, body: object) =>
  request(app).post('/auth/login/mfa').set('Cookie', ticket).send(body);

const wrongCode = (right: string) => (right === '000000' ? '111111' : '000000');

describe('password step with MFA on', () => {
  it('gives a ticket, not a session', async () => {
    const { email } = await userWithMfa();
    const { res, header } = await passwordStep(email);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'mfa_required' });
    expect(cookieFrom(res, SESSION_COOKIE)).toBeNull();
    expect(header).toMatch(/;\s*HttpOnly/i);
    expect(header).toMatch(/;\s*Secure/i);
    expect(header).toMatch(/;\s*SameSite=Strict/i);
    expect(header).toMatch(/;\s*Path=\//i);
  });

  it('stores only the hash of the ticket', async () => {
    const { email, userId } = await userWithMfa();
    const { ticket } = await passwordStep(email);
    const raw = ticket.slice(MFA_COOKIE.length + 1);
    const row = await deps.prisma.mfaTicket.findUniqueOrThrow({
      where: { tokenHash: hashToken(raw) },
    });
    expect(row.userId).toBe(userId);
    expect(JSON.stringify(row)).not.toContain(raw);
  });

  it('users without MFA still sign in with the password alone', async () => {
    const email = uniqueEmail();
    await deps.prisma.user.create({
      data: { email, passwordHash: pwHash, emailVerifiedAt: new Date() },
    });
    const res = await request(app).post('/auth/login').send({ email, password: knownPw });
    expect(res.body).toEqual({ status: 'logged_in' });
    expect(cookieFrom(res, SESSION_COOKIE)).not.toBeNull();
  });
});

describe('code step: 6-digit code (needs your recordTotpUse)', () => {
  it('a correct code gives a session and clears the ticket', async () => {
    const { email, codeNow } = await userWithMfa();
    const { ticket } = await passwordStep(email);

    const res = await codeStep(ticket, { code: codeNow() });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'logged_in' });
    const session = cookieFrom(res, SESSION_COOKIE);
    expect(session).not.toBeNull();
    expect(String(cookieFrom(res, MFA_COOKIE))).toContain(`${MFA_COOKIE}=;`);

    const me = await request(app)
      .get('/auth/me')
      .set('Cookie', session?.split(';')[0] ?? '');
    expect(me.status).toBe(200);
  });

  it('REPLAY: the same code cannot sign in twice, even with a fresh ticket', async () => {
    const { email, codeNow } = await userWithMfa();
    const code = codeNow();
    const first = await passwordStep(email);
    expect((await codeStep(first.ticket, { code })).status).toBe(200);

    const second = await passwordStep(email);
    const again = await codeStep(second.ticket, { code });
    expect(again.status).toBe(401);
    expect(again.body).toEqual({ error: 'invalid_code' });
  });

  it('RACE: two tickets, the same code, at the same moment: one session', async () => {
    const { email, userId, codeNow } = await userWithMfa();
    // Two tickets for the same user: issue the second directly so the first stays valid.
    const a = await passwordStep(email);
    const { issueMfaTicket } = await import('../src/security/mfa-ticket.js');
    await ownerDb().mfaTicket.updateMany({ where: { userId }, data: { consumedAt: null } });
    const bToken = await issueMfaTicket(deps.prisma, userId);
    await ownerDb().mfaTicket.updateMany({ where: { userId }, data: { consumedAt: null } });

    const code = codeNow();
    const results = await Promise.all([
      codeStep(a.ticket, { code }),
      codeStep(`${MFA_COOKIE}=${bToken}`, { code }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });

  it('accepts the code typed with a space', async () => {
    const { email, codeNow } = await userWithMfa();
    const { ticket } = await passwordStep(email);
    const code = codeNow();
    const res = await codeStep(ticket, { code: `${code.slice(0, 3)} ${code.slice(3)}` });
    expect(res.status).toBe(200);
  });
});

describe('code step: limits and tickets', () => {
  it('a wrong code is refused and audited, and the ticket survives', async () => {
    const { email, userId, codeNow } = await userWithMfa();
    const { ticket } = await passwordStep(email);

    const res = await codeStep(ticket, { code: wrongCode(codeNow()) });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_code' });
    const audit = await deps.prisma.auditEvent.findMany({
      where: { userId, type: 'login.mfa_failed' },
    });
    expect(audit).toHaveLength(1);
  });

  it('after 5 attempts the ticket is dead: the password is needed again', async () => {
    const { email, codeNow } = await userWithMfa();
    const { ticket } = await passwordStep(email);
    for (let i = 0; i < 5; i++) await codeStep(ticket, { code: wrongCode(codeNow()) });

    const sixth = await codeStep(ticket, { code: codeNow() });
    expect(sixth.status).toBe(401);
    expect(sixth.body).toEqual({ error: 'mfa_ticket_invalid' });
  });

  it('per account: at most 10 wrong codes in 15 minutes, even with fresh tickets', async () => {
    const { email, codeNow } = await userWithMfa();
    for (let t = 0; t < 2; t++) {
      const { ticket } = await passwordStep(email);
      for (let i = 0; i < 5; i++) await codeStep(ticket, { code: wrongCode(codeNow()) });
    }
    const { ticket } = await passwordStep(email);
    const res = await codeStep(ticket, { code: codeNow() });
    expect(res.status).toBe(429);
  });

  it('an expired ticket is refused', async () => {
    const { email, userId, codeNow } = await userWithMfa();
    const { ticket } = await passwordStep(email);
    await ownerDb().mfaTicket.updateMany({
      where: { userId },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    const res = await codeStep(ticket, { code: codeNow() });
    expect(res.body).toEqual({ error: 'mfa_ticket_invalid' });
  });

  it('no ticket, or a garbage ticket, is refused', async () => {
    const none = await request(app).post('/auth/login/mfa').send({ code: '123456' });
    expect(none.status).toBe(401);
    const garbage = await codeStep(`${MFA_COOKIE}=garbage`, { code: '123456' });
    expect(garbage.body).toEqual({ error: 'mfa_ticket_invalid' });
  });

  it('a new password step replaces the previous ticket', async () => {
    const { email, codeNow } = await userWithMfa();
    const first = await passwordStep(email);
    await passwordStep(email);
    const res = await codeStep(first.ticket, { code: codeNow() });
    expect(res.body).toEqual({ error: 'mfa_ticket_invalid' });
  });

  it('needs exactly one of code or recoveryCode', async () => {
    const { email, codeNow, recoveryCodes } = await userWithMfa();
    const { ticket } = await passwordStep(email);
    const both = await codeStep(ticket, { code: codeNow(), recoveryCode: recoveryCodes[0] });
    expect(both.status).toBe(400);
    expect((await codeStep(ticket, {})).status).toBe(400);
  });
});

describe('code step: recovery code', () => {
  it('signs in once, audits it and emails how many are left', async () => {
    const { email, userId, recoveryCodes } = await userWithMfa();
    const [code = ''] = recoveryCodes;

    const { ticket } = await passwordStep(email);
    const res = await codeStep(ticket, { recoveryCode: code });
    expect(res.status).toBe(200);
    expect(cookieFrom(res, SESSION_COOKIE)).not.toBeNull();

    const audit = await deps.prisma.auditEvent.findMany({
      where: { userId, type: 'mfa.recovery_code_used' },
    });
    expect(audit[0]?.metadata).toMatchObject({ remaining: 9 });
    const mail = await deps.mailer.waitFor(email);
    expect(mail.subject).toMatch(/recovery code was used/i);
    expect(mail.text).toContain('9 recovery codes left');
    expect(mail.text).not.toContain(code);

    const second = await passwordStep(email);
    const reuse = await codeStep(second.ticket, { recoveryCode: code });
    expect(reuse.status).toBe(401);
  });
});
