import { Router } from 'express';
import QRCode from 'qrcode';
import { z } from 'zod';
import type { AppDeps } from '../app.js';
import { recordAudit } from '../audit.js';
import { getAuth, requireAuth } from '../http/auth-middleware.js';
import { HttpError } from '../http/errors.js';
import { requestMeta } from '../http/request-meta.js';
import { parseBody } from '../http/validate.js';
import { mfaEnabledMessage } from '../mail/templates.js';
import { increment } from '../security/rate-limit.js';
import { countRemainingRecoveryCodes, issueRecoveryCodes } from '../security/recovery-codes.js';
import { openSecret, sealSecret, SecretBoxError } from '../security/secret-box.js';
import { base32Decode, generateTotpSecret, otpauthUri, verifyTotp } from '../security/totp.js';
import { retryAfterSeconds } from '../security/throttle.js';

/** Wrong confirmation codes while turning MFA on: per user, per window. */
const ENABLE_MAX_FAILURES = 10;
const ENABLE_WINDOW_MS = 15 * 60 * 1000;

const enableBody = z.object({ code: z.string().max(20) });

export function mfaRouter(deps: AppDeps): Router {
  const { prisma: db, redis, config, logger } = deps;
  const router = Router();
  const key = Buffer.from(config.MFA_ENCRYPTION_KEY, 'base64url');

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
    let attempts: number;
    let retryAfterMs: number;
    try {
      ({ count: attempts, retryAfterMs } = await increment(
        redis,
        `mfa:enable:${userId}`,
        ENABLE_WINDOW_MS,
      ));
    } catch (err) {
      logger.error('rate limiter unavailable', {
        reason: err instanceof Error ? err.message : 'unknown',
      });
      throw new HttpError(503, 'service_unavailable', undefined, { 'Retry-After': '5' });
    }
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
    deps.mailer.send(mfaEnabledMessage(user.email, config.WEB_ORIGIN)).catch((err: unknown) => {
      logger.error('mail send failed', { reason: err instanceof Error ? err.message : 'unknown' });
    });

    res.json({ recoveryCodes });
  });

  return router;
}
