// ─── YOUR EXERCISE: the Content Security Policy for the web pages ──────────────
// The API's CSP allows nothing, because it only serves JSON. Pages must run Next.js's own
// scripts, so this policy allows exactly OUR scripts: the ones carrying this request's
// nonce. A script injected by an attacker (XSS) doesn't know the nonce, so it never runs.

/**
 * ─── EXERCISE 1: the nonce ───
 * A fresh, unguessable value for every single page request.
 *
 * Must:
 *  - Take 16 random bytes (128 bits) from the platform's CSPRNG:
 *      const bytes = new Uint8Array(16);
 *      crypto.getRandomValues(bytes);
 *    Never Math.random(): it's predictable, and a predictable nonce is no nonce at all.
 *  - Return them base64-encoded:  btoa(String.fromCharCode(...bytes))
 *    (base64 is what CSP expects inside 'nonce-...')
 */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export interface CspOptions {
  /** This request's nonce, from generateNonce(). */
  nonce: string;
  /** The API's origin, e.g. "http://localhost:4000". The pages fetch from it. */
  idpOrigin: string;
  /** True when running `next dev`. */
  dev: boolean;
}

/**
 * ─── EXERCISE 2: the policy ───
 * Returns ONE line: directives separated by "; ", for example
 *   "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; ..."
 *
 * Must contain these directives, in any order:
 *
 *  default-src 'self'                    ← anything not listed below: our own origin only
 *  script-src 'self' 'nonce-<nonce>' 'strict-dynamic'
 *             + ' 'unsafe-eval'' ONLY when dev is true (React's dev tools need eval;
 *               production never does, and eval is how many XSS payloads run)
 *             NEVER 'unsafe-inline': it would let injected <script> tags run
 *  style-src 'self' 'nonce-<nonce>'      in production
 *  style-src 'self' 'unsafe-inline'      in dev, WITHOUT the nonce (the dev overlay injects
 *             styles, and browsers ignore 'unsafe-inline' whenever a nonce is also present)
 *  connect-src 'self' <idpOrigin>        ← TRAP 1: without this, every fetch to the API is
 *                                          blocked, because default-src 'self' covers fetch too
 *  img-src 'self' data:
 *  font-src 'self'                       ← the font is self-hosted by next/font
 *  object-src 'none'                     ← no Flash/plugins, an old XSS route
 *  base-uri 'none'                       ← an injected <base> can't redirect relative URLs
 *  form-action 'self'                    ← an injected <form> can't post your password elsewhere
 *  frame-ancestors 'none'                ← no site may frame our pages (clickjacking)
 *  upgrade-insecure-requests             ← TRAP 2: ONLY when dev is false. In dev it would
 *                                          turn http://localhost:4000 into https://, and the
 *                                          dev API only speaks http
 *
 * Hint: build an array of strings, one per directive, then  .join('; ').
 * For the conditional parts, a ternary works:  dev ? " 'unsafe-eval'" : ''
 * Notice the quotes again: 'self' and 'none' and 'nonce-...' include single quotes.
 */
export function buildContentSecurityPolicy(options: CspOptions): string {
  const { nonce, idpOrigin, dev } = options;

  const directives: string[] = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    // Browsers ignore 'unsafe-inline' whenever a nonce is present, so dev uses one or the other.
    dev ? `style-src 'self' 'unsafe-inline'` : `style-src 'self' 'nonce-${nonce}'`,
    `connect-src 'self' ${idpOrigin}`,
    `img-src 'self' data:`,
    `font-src 'self'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    // b) inside the array, with a spread of either nothing or one item
    ...(dev ? [] : ['upgrade-insecure-requests']),
  ];

  return directives.join('; ');
}
