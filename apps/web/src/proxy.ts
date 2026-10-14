import { NextResponse, type NextRequest } from 'next/server';
import { IDP_URL } from '@/lib/config';
import { buildContentSecurityPolicy, generateNonce } from '@/lib/csp';

/**
 * ─── EXERCISE 3: the proxy (Next.js 16's name for middleware) ───
 * Runs before every page request. It gives each request its own nonce and CSP.
 *
 * Must:
 *  1. nonce = generateNonce()
 *  2. csp = buildContentSecurityPolicy({
 *       nonce,
 *       idpOrigin: new URL(IDP_URL).origin,          ← exact origin: no path, no slash
 *       dev: process.env.NODE_ENV === 'development',
 *     })
 *  3. Copy the incoming request headers and set the CSP on the COPY:
 *       const requestHeaders = new Headers(request.headers);
 *       requestHeaders.set('Content-Security-Policy', csp);
 *     Next.js reads the nonce from this request header while rendering, and stamps it
 *     onto every <script> it outputs. That's how our scripts get the matching nonce.
 *  4. const response = NextResponse.next({ request: { headers: requestHeaders } });
 *  5. Set the same CSP on the RESPONSE too, so the browser enforces it:
 *       response.headers.set('Content-Security-Policy', csp);
 *  6. return response;
 */
export function proxy(request: NextRequest): NextResponse {
  const nonce = generateNonce();
  const csp = buildContentSecurityPolicy({
    nonce,
    idpOrigin: new URL(IDP_URL).origin,
    dev: process.env.NODE_ENV === 'development',
  });
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('Content-Security-Policy', csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}

// Pages only: static files and link prefetches don't need a nonce.
export const config = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|icon.svg|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
