import { Router } from 'express';
import { Prisma } from '@keyhouse/db';
import { z } from 'zod';
import type { AppDeps } from '../app.js';
import { recordAudit } from '../audit.js';
import { HttpError } from '../http/errors.js';
import { requestMeta } from '../http/request-meta.js';
import { parseBody } from '../http/validate.js';
import type { MailMessage } from '../mail/mailer.js';
import {
  alreadyRegisteredMessage,
  finishSetupMessage,
  verifyEmailMessage,
} from '../mail/templates.js';
import { hashPassword, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../security/passwords.js';
import { PwnedCheckUnavailable } from '../security/pwned.js';
import { consumeEmailToken, issueEmailToken } from '../security/tokens.js';

const HOUR_MS = 60 * 60 * 1000;
export const VERIFY_TOKEN_TTL_MS = 24 * HOUR_MS;
export const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;

/** Trimmed + lowercased before anything else sees it; citext backs this up in the DB. */
export const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(254));

export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `must be at least ${PASSWORD_MIN_LENGTH} characters`)
  .max(PASSWORD_MAX_LENGTH, `must be at most ${PASSWORD_MAX_LENGTH} characters`);

const registerBody = z.object({ email: emailSchema, password: passwordSchema });
const verifyBody = z.object({ token: z.string().max(100) });

/** The one response for every accepted registration, new email or not (rule 5). */
export const REGISTER_ACCEPTED = {
  status: 'accepted',
  message: 'Check your email to continue.',
} as const;

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';
}

export function authRouter(deps: AppDeps): Router {
  const { prisma: db, config, logger } = deps;
  const router = Router();

  /**
   * Sends mail without awaiting it. SMTP latency differs between the "new" and "existing"
   * paths, so awaiting it would leak, through response timing, whether an email is registered.
   */
  function sendInBackground(message: MailMessage): void {
    deps.mailer.send(message).catch((err: unknown) => {
      logger.error('mail send failed', { reason: err instanceof Error ? err.message : 'unknown' });
    });
  }

  router.post('/auth/register', async (req, res) => {
    const meta = requestMeta(req);
    const { email, password } = parseBody(registerBody, req);

    // Rule 3: breached-password check. Fail closed if the service can't answer.
    let breached: boolean;
    try {
      breached = await deps.pwned(password);
    } catch (err) {
      if (!(err instanceof PwnedCheckUnavailable)) throw err;
      await recordAudit(db, 'register.password_check_unavailable', meta, null, {
        reason: err.message,
      });
      throw new HttpError(503, 'password_check_unavailable', undefined, { 'Retry-After': '30' });
    }
    if (breached) {
      await recordAudit(db, 'register.rejected_breached_password', meta);
      throw new HttpError(400, 'password_breached');
    }

    // Hash before knowing whether the email exists, so both paths pay the argon2 cost.
    const passwordHash = await hashPassword(password);

    try {
      // Insert directly and let the UNIQUE constraint decide (no racy "SELECT then INSERT").
      const user = await db.user.create({ data: { email, passwordHash } });
      const token = await issueEmailToken(db, user.id, 'VERIFY_EMAIL', VERIFY_TOKEN_TTL_MS);
      await recordAudit(db, 'user.registered', meta, user.id);
      sendInBackground(verifyEmailMessage(email, config.WEB_ORIGIN, token));
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      const existing = await db.user.findUnique({ where: { email } });
      if (!existing) throw err;

      // Never overwrite the existing password from a registration request (pre-hijacking).
      if (existing.emailVerifiedAt) {
        sendInBackground(alreadyRegisteredMessage(email, config.WEB_ORIGIN));
      } else {
        const token = await issueEmailToken(db, existing.id, 'RESET_PASSWORD', RESET_TOKEN_TTL_MS);
        sendInBackground(finishSetupMessage(email, config.WEB_ORIGIN, token));
      }
      await recordAudit(db, 'register.duplicate', meta, existing.id, {
        verified: existing.emailVerifiedAt !== null,
      });
    }

    res.status(202).json(REGISTER_ACCEPTED);
  });

  router.post('/auth/verify-email', async (req, res) => {
    const meta = requestMeta(req);
    const { token } = parseBody(verifyBody, req);

    const consumed = await consumeEmailToken(db, token, 'VERIFY_EMAIL');
    if (!consumed) {
      await recordAudit(db, 'email.verify_failed', meta);
      // One message for unknown, expired, used and malformed tokens.
      throw new HttpError(400, 'invalid_or_expired_token');
    }

    await db.user.updateMany({
      where: { id: consumed.userId, emailVerifiedAt: null },
      data: { emailVerifiedAt: new Date() },
    });
    await recordAudit(db, 'email.verified', meta, consumed.userId);
    res.status(200).json({ status: 'verified' });
  });

  return router;
}
