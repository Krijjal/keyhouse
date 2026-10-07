import type { PrismaClient } from '@keyhouse/db';
import type { RequestHandler, Response } from 'express';
import { validateSession, type ValidSession } from '../security/sessions.js';
import { clearSessionCookie, readCookie, SESSION_COOKIE } from './cookies.js';
import { HttpError } from './errors.js';

/**
 * Lets the request through only with a valid session cookie, and makes the session
 * available to the route via getAuth(res). Otherwise 401, and the dead cookie is cleared.
 */
export function requireAuth(db: PrismaClient): RequestHandler {
  return async (req, res, next) => {
    const token = readCookie(req, SESSION_COOKIE);
    const session = token ? await validateSession(db, token) : null;
    if (!session) {
      if (token) clearSessionCookie(res);
      throw new HttpError(401, 'unauthenticated');
    }
    res.locals.auth = session;
    next();
  };
}

/** The session attached by requireAuth. Only call this in routes that use requireAuth. */
export function getAuth(res: Response): ValidSession {
  const auth = res.locals.auth as ValidSession | undefined;
  if (!auth) throw new Error('getAuth called on a route without requireAuth');
  return auth;
}
