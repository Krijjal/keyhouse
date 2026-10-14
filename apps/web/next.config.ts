import type { NextConfig } from 'next';

// The web app deliberately does NOT load the repo-root .env: it holds database and Redis
// passwords the UI never needs. Its only setting is the public API address
// (NEXT_PUBLIC_IDP_URL, see src/lib/config.ts), which is safe to ship to the browser.

const config: NextConfig = {
  // Don't advertise the framework (the idp does the same with x-powered-by).
  poweredByHeader: false,
  reactStrictMode: true,
  // The dev-only "N" badge sits on top of the page footer.
  devIndicators: false,

  // Baseline hardening for every page. The Content Security Policy is set per request in
  // src/proxy.ts, because it carries a fresh nonce each time.
  headers() {
    return Promise.resolve([
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ]);
  },
};

export default config;
