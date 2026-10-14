/**
 * Where the KeyHouse API lives. NEXT_PUBLIC_ variables are copied into the browser bundle,
 * so this must never hold a secret: it's just an address. Override it in apps/web/.env.local.
 * Use "localhost", not "127.0.0.1": the session cookie belongs to the host name, and the
 * web app runs on localhost too.
 */
export const IDP_URL = process.env.NEXT_PUBLIC_IDP_URL ?? 'http://localhost:4000';
