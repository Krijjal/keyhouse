# KeyHouse

KeyHouse is an identity provider (an OpenID Connect provider) built from scratch, as a way
to learn identity and access management (IAM) and full-stack development in depth.

Instead of plugging in Auth0, Clerk or Auth.js, every part of signing in is built by hand:
registration, email verification, password storage, sessions, rate limiting and, later,
MFA and OIDC. Each feature is built together with the attack it exists to stop, and each one
is covered by tests.

> **Status:** learning project, under active development. Not for production use.

## What works today

| Area                   | What it does                                                                                                                                                    | Attack it prevents                                          |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Registration           | Email + password, argon2id hashing (OWASP parameters), Unicode normalization                                                                                    | Password cracking after a database leak                     |
| Breached passwords     | Checks the [Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API with k-anonymity: only 5 characters of a SHA-1 prefix leave the server | Credential stuffing with known-leaked passwords             |
| No account enumeration | Identical responses and similar timing whether or not an email is registered                                                                                    | Attackers learning who has an account                       |
| Email verification     | 32-byte random tokens, stored only as SHA-256 hashes, single use, 24 h expiry; token in the URL fragment                                                        | Token theft from a database leak or server logs; link reuse |
| Pre-account hijacking  | Registering an existing unverified email sends a "choose your password" link instead of trusting the new password                                               | An attacker pre-registering a victim's email                |
| Login                  | Same answer for wrong password and unknown email; a dummy argon2 hash keeps timing equal                                                                        | Timing attacks that reveal registered emails                |
| Sessions               | `__Host-` cookie, HttpOnly, Secure, SameSite=Lax; new token on every login; 30 min idle and 7 day absolute expiry                                               | Cookie theft via XSS, CSRF, session fixation                |
| Race safety            | Single-use tokens and session checks use one conditional database write                                                                                         | Using a one-time link twice with parallel requests          |
| Audit log              | Every security event goes to an append-only table, enforced by a Postgres trigger and table grants                                                              | Attackers or bugs erasing evidence                          |
| Least privilege        | The app's database role can't delete rows, change the audit log, disable triggers or create tables                                                              | Damage from SQL injection or a compromised app              |

## Roadmap

- **Phase 0:** workspace, Docker services, database schema, health check. Done
- **Phase 1:** registration, verification, login and sessions done; logout, session
  management, password reset, hand-written Redis rate limiting, security headers and the web UI
  in progress
- **Phase 2:** MFA (TOTP)
- **Phase 3:** OpenID Connect provider, plus a demo "notes" app that signs in only through KeyHouse

## Ground rules

- No libraries that implement auth flows. Only primitives: `argon2`, `jose`, `otplib`, `zod`, `helmet`, `qrcode`.
- Never store a raw token, secret or code; store SHA-256 hashes.
- Never log passwords, tokens, cookies or secrets.
- Validate every request body with zod; TypeScript strict mode everywhere.
- Rate limiting is written by hand on Redis counters.

## Stack

| Part                     | Technology                                              |
| ------------------------ | ------------------------------------------------------- |
| API (`apps/idp`)         | Express 5, TypeScript                                   |
| Web UI (`apps/web`)      | Next.js (coming in Phase 1)                             |
| Database (`packages/db`) | PostgreSQL 17, Prisma 7                                 |
| Rate limiting            | Redis 7                                                 |
| Local email              | Mailpit                                                 |
| Tests                    | Vitest, Supertest (Playwright planned)                  |
| Tooling                  | pnpm workspaces, ESLint (strict type-checked), Prettier |

## Running it locally

Requirements: Node.js 24+, Docker Desktop, and pnpm (enabled through `corepack`).

```bash
# 1. Install dependencies
pnpm install

# 2. Create your local environment file and replace every "change-me" value
cp .env.example .env
#    Generate strong values with:
#    node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"

# 3. Start Postgres, Redis and Mailpit (bound to 127.0.0.1 only)
pnpm infra:up

# 4. Create the tables (runs as the migration-owner database role)
pnpm db:deploy

# 5. Run the API on http://localhost:4000
pnpm dev
```

Emails sent in development appear in Mailpit at http://localhost:8025.

### Checks

```bash
pnpm test         # all tests (needs step 3)
pnpm typecheck
pnpm lint
pnpm format:check
```

## Project layout

```
apps/idp          Express API: routes, security code, tests
packages/db       Prisma schema, migrations and client
infra/postgres    First-start script that creates the database roles
compose.yaml      Local Postgres, Redis and Mailpit
```

## Security note

This is a learning project. It has not been audited and must not protect real accounts.
Secrets live only in a local `.env` file, which is never committed; `.env.example` holds
placeholders only.
