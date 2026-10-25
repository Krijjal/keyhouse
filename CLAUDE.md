# KeyHouse

A self-built OIDC identity provider, built to learn IAM and full-stack depth.
The owner is learning: explain before building, and leave the security-critical
functions listed below for them to implement.

## Layout

- `apps/idp`: Express 5 + TypeScript API
- `apps/web`: Next.js UI (login, MFA, account, admin)
- `apps/notes`: Next.js client app that signs in only via KeyHouse (Phase 3, not built yet)
- `packages/db`: Prisma 7 schema, migrations and client (Postgres)
- `compose.yaml`: Postgres, Redis, Mailpit for local dev (ports bound to 127.0.0.1)

## Commands

```
pnpm infra:up        # start Postgres, Redis, Mailpit
pnpm db:deploy       # apply migrations (runs as the owner role)
pnpm dev             # run the idp
pnpm test            # all tests (needs infra up)
pnpm typecheck && pnpm lint && pnpm format:check
```

## Hard rules

1. No auth-flow libraries (Auth.js, Clerk, Passport, Supabase Auth, Firebase Auth...).
   Primitives only: argon2, jose, otplib, zod, helmet, qrcode.
2. Never store a raw token, secret or code. Store SHA-256 hashes and compare hashes.
3. Passwords: argon2id, minimum 12 characters, checked against the Pwned Passwords range API.
4. Session cookie: HttpOnly, Secure, SameSite=Lax. Rotate the session token on every login.
5. No account enumeration: identical responses and similar timing whether an email exists or not.
6. Rate limiting is hand-written with Redis counters, not a package.
7. Never log passwords, tokens, cookies or secrets.
8. Every security event goes to the append-only `audit_events` table.
9. TypeScript strict mode. Validate every request body with zod.
10. Secrets come from `.env`. Commit `.env.example` only.

## Learning mode

- Before writing code, explain in a few lines what is being built, why, and the attack it prevents.
- Do NOT write the body of these functions. Write the signature, a comment block saying exactly
  what it must do, and a failing test, then stop for the owner to implement it and review it honestly:
  a. password verification with the dummy hash for unknown users
  b. session creation and validation
  c. the Redis rate limiter
  d. token hashing and single-use consumption
- Everything else (scaffolding, config, UI, routes, schema) can be written fully.

## Workflow

- Small commits with clear messages. Never add a Claude co-author or attribution line.
- Commit as `Krijjal` with the GitHub noreply email (repo-local config, never a personal address); gh account `Krijjal`.
- Stop at the end of each phase. Don't start the next phase until the owner says so.
- Ask when something is ambiguous; never guess on security decisions.

## Security decisions (made by the owner, 2026-10-06)

- Login throttling, all keyed by a hash of the normalized email, identical for unknown emails:
  - per IP across all emails: 30 failures / 15 min → 429 (IPv6 grouped by /64)
  - per email + IP: 5 failures → hard lock 15 min for that pair (correct password still blocked)
  - per email across all IPs: 5 free failures, then minimum wait 1 s doubling to a 30 s cap,
    returned as 429 + Retry-After (never a server-side sleep); no hard lock
  - blocked attempts are rejected before any password check; success resets the email counters
- Forgot-password throttling (decided 2026-10-08): 3 requests per email per hour, 20 per IP
  per hour (IPv6 /64). Over the limit: the same 202 response, but no email is sent (a 429
  would reveal that the address was recently targeted). Prevents mail-bombing a victim.
- CSRF Origin check (decided 2026-10-11), for every POST/PUT/PATCH/DELETE: an Origin header
  other than WEB_ORIGIN → 403. No Origin → use Sec-Fetch-Site: 'cross-site' → 403, otherwise
  allowed. Neither header (curl, tests, server-to-server) → allowed: CSRF needs a victim's
  browser, and modern browsers always send one of the two. Refusals are audited.
- Web app → API (decided 2026-10-13): the browser calls the idp directly (fetch with
  credentials: 'include'), relying on the CORS allowlist and the Origin check. No Next.js
  proxy: it would make every user share one IP at the idp and break per-IP rate limits.
- MFA / TOTP (decided 2026-10-14):
  - Optional per user, turned on from the account page. Turning it off needs the password
    and a current code.
  - The TOTP secret is the one exception to rule 2: it can't be hashed (the server must
    compute codes from it), so it is encrypted at rest with AES-256-GCM, a key from .env
    (MFA_ENCRYPTION_KEY), a random IV per encryption, and the user id as associated data.
  - 10 single-use recovery codes, shown once, stored only as SHA-256 hashes. Using one is
    audited and emails an alert.
  - A correct password with MFA on gives only a short-lived, single-use, hashed "MFA pending"
    ticket, never a session. Code attempts are rate-limited, and a code can't be reused.
  - The ticket (decided 2026-10-25) lives in a `__Host-mfa` cookie (HttpOnly, Secure,
    SameSite=Strict), lasts 5 minutes and allows 5 code attempts; after that the password is
    needed again. Per account, at most 10 wrong codes per 15 minutes across tickets.
  - The owner writes the security core: code verification with replay protection, secret
    encryption/decryption, recovery-code consumption.
- Registration of an existing email: same 202 response. Unverified account → "choose your
  password" link (RESET_PASSWORD purpose); verified account → "you already have an account".
  A registration request never overwrites a password (prevents pre-account hijacking).
- Pwned Passwords API down or slower than 2 s → fail closed (503, "try again shortly").
- Email links carry the token in the URL fragment (`#token=`), never the query string.
- Mail is sent with nodemailer (SMTP transport only).
- Test fixtures never contain credential-shaped literals; generate fake secrets at runtime.

## Database roles

- `keyhouse_owner` owns the schema and runs migrations (`MIGRATION_DATABASE_URL`).
- `keyhouse_app` is what the running idp uses (`DATABASE_URL`). It has only explicit grants.
- Every migration that adds a table must also GRANT the app role exactly what it needs.
  `audit_events` stays INSERT + SELECT only.
