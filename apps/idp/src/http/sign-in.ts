import type { PrismaClient } from '@keyhouse/db';
import type { Request, Response } from 'express';
import { recordAudit } from '../audit.js';
import { createSession, revokeSession, validateSession } from '../security/sessions.js';
import { readCookie, SESSION_COOKIE, setSessionCookie } from './cookies.js';
import type { RequestMeta } from './request-meta.js';

/**
 * The last step of every successful sign-in (password only, or password + MFA), so both
 * paths behave identically:
 *  - session fixation defense: whatever session the browser arrived with is revoked, and the
 *    user always gets a brand-new token (rule 4)
 *  - the new session cookie is set and the sign-in is audited
 */
export async function completeSignIn(
  db: PrismaClient,
  req: Request,
  res: Response,
  userId: string,
  meta: RequestMeta,
  auditExtra: Record<string, string> = {},
): Promise<void> {
  const previousToken = readCookie(req, SESSION_COOKIE);
  if (previousToken) {
    const previous = await validateSession(db, previousToken);
    if (previous) {
      await revokeSession(db, previous.sessionId);
      await recordAudit(db, 'session.rotated', meta, previous.userId, {
        revokedSessionId: previous.sessionId,
      });
    }
  }

  const session = await createSession(db, userId, meta);
  setSessionCookie(res, session.token);
  await recordAudit(db, 'login.succeeded', meta, userId, {
    sessionId: session.sessionId,
    ...auditExtra,
  });
}
