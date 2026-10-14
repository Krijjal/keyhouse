import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import { IDP_URL } from '../src/lib/config';
import { buildContentSecurityPolicy, generateNonce } from '../src/lib/csp';
import { proxy } from '../src/proxy';

// ─── CSP exercise: these fail until you implement csp.ts and proxy.ts ───

/** "script-src 'self' 'nonce-x'" → ["'self'", "'nonce-x'"] for the named directive. */
function directive(csp: string, name: string): string[] | null {
  for (const part of csp.split(';')) {
    const [key, ...values] = part.trim().split(/\s+/);
    if (key === name) return values;
  }
  return null;
}

const IDP = 'http://localhost:4000';
const policy = (dev: boolean) =>
  buildContentSecurityPolicy({ nonce: 'TESTNONCE', idpOrigin: IDP, dev });

describe('exercise 1: generateNonce', () => {
  it('is 16 random bytes, base64-encoded', () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(atob(nonce)).toHaveLength(16);
  });

  it('is different every time', () => {
    const seen = new Set(Array.from({ length: 1000 }, () => generateNonce()));
    expect(seen.size).toBe(1000);
  });
});

describe('exercise 2: buildContentSecurityPolicy', () => {
  it('is a single line of directives', () => {
    const csp = policy(false);
    expect(csp).not.toMatch(/\n/);
    expect(csp.split(';').length).toBeGreaterThanOrEqual(10);
  });

  it("lets only this request's scripts run", () => {
    const scripts = directive(policy(false), 'script-src');
    expect(scripts).toEqual(
      expect.arrayContaining(["'self'", "'nonce-TESTNONCE'", "'strict-dynamic'"]),
    );
    expect(scripts).not.toContain("'unsafe-inline'");
    expect(scripts).not.toContain("'unsafe-eval'");
  });

  it("allows 'unsafe-eval' only in development", () => {
    expect(directive(policy(true), 'script-src')).toContain("'unsafe-eval'");
    expect(directive(policy(true), 'script-src')).not.toContain("'unsafe-inline'");
  });

  it('allows fetch to our own origin and the API, and nothing else (trap 1)', () => {
    expect(directive(policy(false), 'connect-src')).toEqual(["'self'", IDP]);
  });

  it('upgrades insecure requests only in production (trap 2)', () => {
    expect(directive(policy(false), 'upgrade-insecure-requests')).toEqual([]);
    expect(directive(policy(true), 'upgrade-insecure-requests')).toBeNull();
  });

  it('locks down everything else', () => {
    const csp = policy(false);
    expect(directive(csp, 'default-src')).toEqual(["'self'"]);
    expect(directive(csp, 'style-src')).toEqual(["'self'", "'nonce-TESTNONCE'"]);
    expect(directive(csp, 'img-src')).toEqual(["'self'", 'data:']);
    expect(directive(csp, 'font-src')).toEqual(["'self'"]);
    expect(directive(csp, 'object-src')).toEqual(["'none'"]);
    expect(directive(csp, 'base-uri')).toEqual(["'none'"]);
    expect(directive(csp, 'form-action')).toEqual(["'self'"]);
    expect(directive(csp, 'frame-ancestors')).toEqual(["'none'"]);
  });

  it('allows inline styles only in development (the dev overlay)', () => {
    // A nonce makes browsers ignore 'unsafe-inline', so dev must leave the nonce out.
    expect(directive(policy(true), 'style-src')).toEqual(["'self'", "'unsafe-inline'"]);
    expect(directive(policy(false), 'style-src')).not.toContain("'unsafe-inline'");
  });
});

describe('exercise 3: proxy', () => {
  const run = () => proxy(new NextRequest('http://localhost:3000/login'));

  it('sends the browser a CSP with a fresh nonce', () => {
    const csp = run().headers.get('content-security-policy') ?? '';
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeDefined();
    expect(atob(nonce ?? '')).toHaveLength(16);
    expect(directive(csp, 'connect-src')).toEqual(["'self'", new URL(IDP_URL).origin]);
  });

  it('hands the same CSP to Next.js on the request, so it can stamp the nonce on scripts', () => {
    const res = run();
    // NextResponse.next({ request: { headers } }) passes request headers on this way.
    expect(res.headers.get('x-middleware-request-content-security-policy')).toBe(
      res.headers.get('content-security-policy'),
    );
  });

  it('uses a different nonce for every request', () => {
    const a = run().headers.get('content-security-policy');
    const b = run().headers.get('content-security-policy');
    expect(a).not.toBe(b);
  });
});
