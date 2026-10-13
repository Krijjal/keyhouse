import type { PrismaClient } from '@keyhouse/db';
import type { RequestHandler } from 'express';
import helmet from 'helmet';
import { recordAudit } from '../audit.js';
import { HttpError } from './errors.js';
import { requestMeta } from './request-meta.js';

// ─── 1.7: YOUR EXERCISES ────────────────────────────────────────────────────
// `trustedOrigin` is always an exact origin like "http://localhost:3000": scheme + host +
// port, no path, no trailing slash. app.ts computes it once with new URL(WEB_ORIGIN).origin.

/** Methods that only read. Browsers and our routes treat these as side-effect free. */
export const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * ─── EXERCISE 1: security headers ───
 * Returns helmet configured for a JSON-only API.
 *
 * Must return  helmet({ ...options })  with these options:
 *
 *  contentSecurityPolicy: {
 *    useDefaults: false,              ← start from nothing instead of helmet's web-page defaults
 *    directives: {
 *      defaultSrc:     ["'none'"],    ← load NOTHING: no scripts, styles, images, frames
 *      frameAncestors: ["'none'"],    ← no site may frame our responses (clickjacking)
 *      baseUri:        ["'none'"],    ← an injected <base> tag can't redirect relative URLs
 *      formAction:     ["'none'"],    ← an injected <form> can't post anywhere
 *    },
 *  },
 *  crossOriginResourcePolicy: { policy: 'same-site' },   ← only our own site may embed responses
 *  referrerPolicy: { policy: 'no-referrer' },            ← never leak URLs to other sites
 *
 * Notice the quotes: "'none'" is a string that CONTAINS single quotes. CSP needs them.
 * Every other helmet header (nosniff, HSTS, frameguard ...) stays at its safe default.
 */
export function securityHeaders(): RequestHandler {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
      },
    },
    crossOriginResourcePolicy: { policy: 'same-site' },
    referrerPolicy: { policy: 'no-referrer' },
  });
}

/**
 * ─── EXERCISE 2: CORS, by hand ───
 * Lets exactly ONE other origin (the web app) call this API from a browser, with cookies.
 *
 * Returns a middleware  (req, res, next) => { ... }  that:
 *
 *  1. Always sets  Vary: Origin   → res.vary('Origin')
 *     (the answer depends on Origin, so caches must not mix answers between sites)
 *
 *  2. Reads the origin:  const origin = req.get('origin');
 *     If origin === trustedOrigin:
 *        res.set('Access-Control-Allow-Origin', origin)
 *        res.set('Access-Control-Allow-Credentials', 'true')   ← allows the session cookie
 *     Any other origin: set NO Access-Control-* headers. The browser then refuses to give
 *     that site's JavaScript the response.
 *
 *  3. If req.method === 'OPTIONS' (a "preflight": the browser asking permission first):
 *        if the origin was trusted, also set
 *          Access-Control-Allow-Methods: 'GET, POST, DELETE'
 *          Access-Control-Allow-Headers: 'Content-Type'
 *          Access-Control-Max-Age: '600'          ← the browser may cache the answer 10 min
 *        then end it here with  res.status(204).end();  and DON'T call next().
 *     Otherwise call next().
 *
 * NEVER answer with "*", and never copy back whatever Origin was sent: either would let
 * every website read your users' data with their cookies.
 */
export function corsForWebOrigin(trustedOrigin: string): RequestHandler {
  return (req, res, next) => {
    res.vary('Origin');
    const origin = req.get('origin');
    const trusted = origin === trustedOrigin;

    if (trusted) {
      res.set('Access-Control-Allow-Origin', trustedOrigin);
      res.set('Access-Control-Allow-Credentials', 'true');
    }

    if (req.method === 'OPTIONS') {
      if (trusted) {
        res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE');
        res.set('Access-Control-Allow-Headers', 'Content-Type');
        res.set('Access-Control-Max-Age', '600');
      }
      res.status(204).end();
      return;
    }

    next();
  };
}

/**
 * ─── EXERCISE 3: the Origin check (CSRF defense) ───
 * Refuses state-changing requests that a browser sent on behalf of another site.
 * The owner's decision (CLAUDE.md): wrong Origin → refuse; no Origin → use Sec-Fetch-Site;
 * neither header → allow.
 *
 * Returns an ASYNC middleware  async (req, _res, next) => { ... }  that:
 *
 *  1. If SAFE_METHODS has req.method → next() and stop (return).
 *
 *  2. const origin = req.get('origin');            // e.g. "https://evil.example" or undefined
 *     const site = req.get('sec-fetch-site');      // 'same-origin' | 'same-site' | 'cross-site' | 'none' | undefined
 *
 *  3. Decide `allowed`:
 *       origin is not undefined → allowed only if origin === trustedOrigin
 *       else site is not undefined → allowed only if site !== 'cross-site'
 *       else (neither header) → allowed
 *
 *  4. If allowed → next().
 *     If not:
 *       await recordAudit(db, 'request.untrusted_origin', requestMeta(req), null, {
 *         method: req.method,
 *         path: req.path,
 *         origin: origin?.slice(0, 200) ?? null,    ← attacker-controlled: cap its length
 *         secFetchSite: site ?? null,
 *       });
 *       throw new HttpError(403, 'forbidden_origin');
 *
 * Express 5 sends an error thrown inside an async middleware to the error handler.
 */
export function requireTrustedOrigin(db: PrismaClient, trustedOrigin: string): RequestHandler {
  return async (req, _res, next) => {
    if (SAFE_METHODS.has(req.method)) {
      next();
      return;
    }

    const origin = req.get('origin');
    const site = req.get('sec-fetch-site');

    let allowed: boolean;
    if (origin !== undefined) {
      allowed = origin === trustedOrigin;
    } else if (site !== undefined) {
      allowed = site !== 'cross-site';
    } else {
      allowed = true;
    }

    if (allowed) {
      next();
      return;
    }

    await recordAudit(db, 'request.untrusted_origin', requestMeta(req), null, {
      method: req.method,
      path: req.path,
      origin: origin?.slice(0, 200) ?? null,
      secFetchSite: site ?? null,
    });
    throw new HttpError(403, 'forbidden_origin');
  };
}
