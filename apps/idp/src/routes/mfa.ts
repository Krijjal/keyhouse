import { Router, type Request } from 'express';
import QRCode from 'qrcode';
import { z } from 'zod';
import type { AppDeps } from '../app.js';
import { recordAudit } from '../audit.js';
import { getAuth, requireAuth } from '../http/auth-middleware.js';
import { clearMfaCookie, MFA_COOKIE, readCookie } from '../http/cookies.js';
import { HttpError } from '../http/errors.js';
import { requestMeta } from '../http/request-meta.js';
import { completeSignIn } from '../http/sign-in.js';
import { parseBody } from '../http/validate.js';
import type { MailMessage } from '../mail/mailer.js';
import {
  mfaDisabledMessage,
  mfaEnabledMessage,
  recoveryCodesReplacedMessage,
  recoveryCodeUsedMessage,
} from '../mail/templates.js';
import { consumeMfaTicket, reserveMfaAttempt } from '../security/mfa-ticket.js';
import { PASSWORD_MAX_LENGTH, verifyPassword } from '../security/passwords.js';
import { increment, resetCounter } from '../security/rate-limit.js';
import {
  consumeRecoveryCode,
  countRemainingRecoveryCodes,
  issueRecoveryCodes,
} from '../security/recovery-codes.js';
import { openSecret, sealSecret, SecretBoxError } from '../security/secret-box.js';
import { base32Decode, generateTotpSecret, otpauthUri, verifyTotp } from '../security/totp.js';
import { recordTotpUse } from '../security/totp-use.js';
import { retryAfterSeconds } from '../security/throttle.js';

/** Wrong confirmation codes while turning MFA on: per user, per window. */
const ENABLE_MAX_FAILURES = 10;
const ENABLE_WINDOW_MS = 15 * 60 * 1000;
/** Wrong codes at sign-in, per account across tickets (owner's decision). */
const LOGIN_MFA_MAX_FAILURES = 10;
const LOGIN_MFA_WINDOW_MS = 15 * 60 * 1000;
/** Password + code checks before turning MFA off or replacing codes: per user, per window. */
const REAUTH_MAX_ATTEMPTS = 10;
const REAUTH_WINDOW_MS = 15 * 60 * 1000;

const enableBody = z.object({ code: z.string().max(20) });
/** Exactly one of the two: a 6-digit code, or a recovery code. */
const loginMfaBody = z.union([
  z.object({ code: z.string().max(20), recoveryCode: z.undefined().optional() }),
  z.object({ recoveryCode: z.string().max(64), code: z.undefined().optional() }),
]);
/** The password, plus exactly one of a 6-digit code or a recovery code. */
const passwordField = z.string().min(1).max(PASSWORD_MAX_LENGTH);
const reauthBody = z.union([
  z.object({
    password: passwordField,
    code: z.string().max(20),
    recoveryCode: z.undefined().optional(),
  }),
  z.object({
    password: passwordField,
    recoveryCode: z.string().max(64),
    code: z.undefined().optional(),
  }),
]);

export function mfaRouter(deps: AppDeps): Router {
  const { prisma: db, redis, config, logger } = deps;
  const router = Router();
  const key = Buffer.from(config.MFA_ENCRYPTION_KEY, 'base64url');

  /** Counts one attempt with your limiter. Fails closed (503) if Redis can't count. */
  async function countAttempt(limiterKey: string, windowMs: number) {
    try {
      return await increment(redis, limiterKey, windowMs);
    } catch (err) {
      logger.error('rate limiter unavailable', {
        reason: err instanceof Error ? err.message : 'unknown',
      });
      throw new HttpError(503, 'service_unavailable', undefined, { 'Retry-After': '5' });
    }
  }

  function sendInBackground(message: MailMessage): void {
    deps.mailer.send(message).catch((err: unknown) => {
      logger.error('mail send failed', { reason: err instanceof Error ? err.message : 'unknown' });
    });
  }

  /**
   * For changes that weaken or reset MFA: a session alone is not enough. Someone at an
   * unlocked laptop, or holding a stolen session cookie, has neither the password nor the
   * phone. Throws unless BOTH are right; returns the user's email for the alert.
   */
  async function confirmPasswordAndCode(
    req: Request,
    userId: string,
    action: 'disable' | 'replace_recovery_codes',
  ): Promise<string> {
    const meta = requestMeta(req);
    const { password, code, recoveryCode } = parseBody(reauthBody, req);

    const { count, retryAfterMs } = await countAttempt(`mfa:reauth:${userId}`, REAUTH_WINDOW_MS);
    if (count > REAUTH_MAX_ATTEMPTS) {
      await recordAudit(db, 'mfa.reauth_throttled', meta, userId, { action });
      throw new HttpError(429, 'too_many_attempts', undefined, {
        'Retry-After': String(retryAfterSeconds(retryAfterMs)),
      });
    }

    const mfa = await db.userMfa.findUnique({ where: { userId } });
    if (!mfa?.enabledAt || !mfa.secretSealed) throw new HttpError(409, 'mfa_not_enabled');
    const user = await db.user.findUniqueOrThrow({
      where: { id: userId },
      select: { email: true, passwordHash: true },
    });

    // Password first. A wrong password stops here, so it can't use up a code on the way.
    let accepted = await verifyPassword(user.passwordHash, password);
    if (accepted && code !== undefined) {
      const secret = openSecret(mfa.secretSealed, userId, key);
      const step = verifyTotp(
        base32Decode(secret),
        code.replace(/\s/g, ''),
        new Date(),
        mfa.lastUsedStep,
      );
      accepted = step !== null && (await recordTotpUse(db, userId, step));
    } else if (accepted && recoveryCode !== undefined) {
      // Lost phone: a recovery code is the only second factor left, so it counts here too.
      accepted = await consumeRecoveryCode(db, userId, recoveryCode);
    }

    if (!accepted) {
      // One answer for both: a stolen session must not learn whether the password was right.
      await recordAudit(db, 'mfa.reauth_failed', meta, userId, { action });
      throw new HttpError(400, 'invalid_password_or_code');
    }
    await resetCounter(redis, `mfa:reauth:${userId}`).catch(() => undefined);
    return user.email;
  }

  /**
   * Sign-in, step 2: exchange the ticket (cookie) plus a code or a recovery code for a
   * session. Not behind requireAuth: there is no session yet, only the ticket.
   */
  router.post('/auth/login/mfa', async (req, res) => {
    const meta = requestMeta(req);
    const { code, recoveryCode } = parseBody(loginMfaBody, req);
    const ticketToken = readCookie(req, MFA_COOKIE);

    // An attempt is reserved on the ticket before anything is checked (5 per ticket).
    const ticket = ticketToken ? await reserveMfaAttempt(db, ticketToken) : null;
    if (!ticket) {
      clearMfaCookie(res);
      throw new HttpError(401, 'mfa_ticket_invalid');
    }
    const { userId } = ticket;

    // Per account, across tickets: fresh tickets don't buy unlimited guesses.
    const { count, retryAfterMs } = await countAttempt(`mfa:login:${userId}`, LOGIN_MFA_WINDOW_MS);
    if (count > LOGIN_MFA_MAX_FAILURES) {
      await recordAudit(db, 'login.mfa_throttled', meta, userId);
      throw new HttpError(429, 'too_many_attempts', undefined, {
        'Retry-After': String(retryAfterSeconds(retryAfterMs)),
      });
    }

    const mfa = await db.userMfa.findUnique({ where: { userId } });
    if (!mfa?.enabledAt || !mfa.secretSealed) {
      clearMfaCookie(res);
      throw new HttpError(401, 'mfa_ticket_invalid');
    }

    let method: 'totp' | 'recovery_code';
    let accepted: boolean;
    if (code !== undefined) {
      method = 'totp';
      const secret = openSecret(mfa.secretSealed, userId, key);
      const step = verifyTotp(
        base32Decode(secret),
        code.replace(/\s/g, ''),
        new Date(),
        mfa.lastUsedStep,
      );
      // Your recordTotpUse settles races: of two requests with the same code, one wins.
      accepted = step !== null && (await recordTotpUse(db, userId, step));
    } else {
      method = 'recovery_code';
      accepted = await consumeRecoveryCode(db, userId, recoveryCode);
    }

    if (!accepted) {
      await recordAudit(db, 'login.mfa_failed', meta, userId, { method });
      throw new HttpError(401, 'invalid_code');
    }

    // Single use: if a parallel request already exchanged this ticket, this one gets nothing.
    if (!(await consumeMfaTicket(db, ticket.ticketId))) {
      clearMfaCookie(res);
      throw new HttpError(401, 'mfa_ticket_invalid');
    }

    clearMfaCookie(res);
    await completeSignIn(db, req, res, userId, meta, { mfa: method });
    await resetCounter(redis, `mfa:login:${userId}`).catch(() => undefined);

    if (method === 'recovery_code') {
      const remaining = await countRemainingRecoveryCodes(db, userId);
      await recordAudit(db, 'mfa.recovery_code_used', meta, userId, { remaining });
      const user = await db.user.findUniqueOrThrow({
        where: { id: userId },
        select: { email: true },
      });
      sendInBackground(recoveryCodeUsedMessage(user.email, config.WEB_ORIGIN, remaining));
    }

    res.status(200).json({ status: 'logged_in' });
  });

  // Responses that carry the secret or recovery codes must never be cached anywhere.
  router.use('/auth/mfa', requireAuth(db), (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  router.get('/auth/mfa', async (_req, res) => {
    const { userId } = getAuth(res);
    const mfa = await db.userMfa.findUnique({ where: { userId }, select: { enabledAt: true } });
    const enabled = Boolean(mfa?.enabledAt);
    res.json({
      enabled,
      enabledAt: mfa?.enabledAt ?? null,
      recoveryCodesLeft: enabled ? await countRemainingRecoveryCodes(db, userId) : 0,
    });
  });

  /**
   * Step 1: a fresh secret, stored sealed and still switched OFF until a code confirms it.
   * Calling it again while setting up replaces the secret (e.g. the user re-scans).
   */
  router.post('/auth/mfa/setup', async (req, res) => {
    const meta = requestMeta(req);
    const { userId } = getAuth(res);
    const existing = await db.userMfa.findUnique({ where: { userId } });
    if (existing?.enabledAt) throw new HttpError(409, 'mfa_already_enabled');

    const user = await db.user.findUniqueOrThrow({ where: { id: userId } });
    const { base32 } = generateTotpSecret();
    const secretSealed = sealSecret(base32, userId, key);
    await db.userMfa.upsert({
      where: { userId },
      create: { userId, secretSealed },
      update: { secretSealed, enabledAt: null, lastUsedStep: null },
    });
    await recordAudit(db, 'mfa.setup_started', meta, userId);

    const uri = otpauthUri(base32, user.email);
    // A PNG data: URL: the page shows it as an <img>, which the page CSP allows (img-src data:).
    const qrDataUrl = await QRCode.toDataURL(uri, { margin: 1, width: 240 });
    res.json({ secret: base32, otpauthUri: uri, qrDataUrl });
  });

  /** Step 2: prove the app was set up correctly, then switch MFA on. */
  router.post('/auth/mfa/enable', async (req, res) => {
    const meta = requestMeta(req);
    const { userId } = getAuth(res);
    const { code } = parseBody(enableBody, req);

    // Fail closed: if Redis can't count attempts, don't check codes at all.
    const { count: attempts, retryAfterMs } = await countAttempt(
      `mfa:enable:${userId}`,
      ENABLE_WINDOW_MS,
    );
    if (attempts > ENABLE_MAX_FAILURES) {
      await recordAudit(db, 'mfa.enable_throttled', meta, userId);
      throw new HttpError(429, 'too_many_attempts', undefined, {
        'Retry-After': String(retryAfterSeconds(retryAfterMs)),
      });
    }

    const mfa = await db.userMfa.findUnique({ where: { userId } });
    if (mfa?.enabledAt) throw new HttpError(409, 'mfa_already_enabled');
    if (!mfa?.secretSealed) throw new HttpError(409, 'mfa_setup_not_started');

    let secret: string;
    try {
      secret = openSecret(mfa.secretSealed, userId, key);
    } catch (err) {
      // Tampered row or a changed key: never treat it as a valid secret.
      if (err instanceof SecretBoxError) throw new HttpError(409, 'mfa_setup_not_started');
      throw err;
    }

    const now = new Date();
    // People often type "123 456": spaces are fine, everything else must be 6 digits.
    const step = verifyTotp(base32Decode(secret), code.replace(/\s/g, ''), now, null);
    if (step === null) {
      await recordAudit(db, 'mfa.enable_failed', meta, userId);
      throw new HttpError(400, 'invalid_code');
    }

    // Switch on only if still off: two parallel confirmations can't both succeed.
    const switched = await db.userMfa.updateMany({
      where: { userId, enabledAt: null, secretSealed: mfa.secretSealed },
      data: { enabledAt: now, lastUsedStep: step },
    });
    if (switched.count !== 1) throw new HttpError(409, 'mfa_already_enabled');

    const recoveryCodes = await issueRecoveryCodes(db, userId, now);
    await recordAudit(db, 'mfa.enabled', meta, userId);

    const user = await db.user.findUniqueOrThrow({
      where: { id: userId },
      select: { email: true },
    });
    sendInBackground(mfaEnabledMessage(user.email, config.WEB_ORIGIN));

    res.json({ recoveryCodes });
  });

  /** Turn MFA off: wipe the sealed secret and revoke every recovery code (no deletes). */
  router.post('/auth/mfa/disable', async (req, res) => {
    const meta = requestMeta(req);
    const { userId } = getAuth(res);
    const email = await confirmPasswordAndCode(req, userId, 'disable');

    const now = new Date();
    const [switched] = await db.$transaction([
      // Off only if still on: of two parallel requests, one does it and the other gets 409.
      db.userMfa.updateMany({
        where: { userId, enabledAt: { not: null } },
        data: { enabledAt: null, secretSealed: null, lastUsedStep: null },
      }),
      db.mfaRecoveryCode.updateMany({
        where: { userId, usedAt: null, revokedAt: null },
        data: { revokedAt: now },
      }),
    ]);
    if (switched.count !== 1) throw new HttpError(409, 'mfa_not_enabled');

    await recordAudit(db, 'mfa.disabled', meta, userId);
    sendInBackground(mfaDisabledMessage(email, config.WEB_ORIGIN));
    res.status(204).end();
  });

  /** A fresh set of 10 codes. issueRecoveryCodes revokes the old set in the same transaction. */
  router.post('/auth/mfa/recovery-codes', async (req, res) => {
    const meta = requestMeta(req);
    const { userId } = getAuth(res);
    const email = await confirmPasswordAndCode(req, userId, 'replace_recovery_codes');

    const recoveryCodes = await issueRecoveryCodes(db, userId);
    await recordAudit(db, 'mfa.recovery_codes_replaced', meta, userId);
    sendInBackground(recoveryCodesReplacedMessage(email, config.WEB_ORIGIN));
    res.json({ recoveryCodes });
  });

  return router;
}
