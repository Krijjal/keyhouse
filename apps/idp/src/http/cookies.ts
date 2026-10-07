import type { Request, Response } from 'express';
import { SESSION_ABSOLUTE_TTL_MS } from '../security/sessions.js';

/**
 * __Host- prefix: the browser only accepts this cookie if it is Secure, has Path=/ and
 * no Domain. A compromised or attacker-controlled subdomain therefore cannot set or
 * overwrite it (cookie tossing / session fixation via subdomains).
 */
export const SESSION_COOKIE = '__Host-session';

/** Rule 4: HttpOnly (no JS access), Secure (HTTPS only), SameSite=Lax (no cross-site POSTs). */
const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
} as const;

export function setSessionCookie(res: Response, token: string): void {
  // The browser drops the cookie at the absolute session lifetime. The server-side
  // checks (idle + absolute) are what actually enforce expiry.
  res.cookie(SESSION_COOKIE, token, { ...SESSION_COOKIE_OPTIONS, maxAge: SESSION_ABSOLUTE_TTL_MS });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, SESSION_COOKIE_OPTIONS);
}

/** Reads one cookie from the Cookie header without a parsing library. */
export function readCookie(req: Request, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}
