import { createPrismaClient, type PrismaClient } from '@keyhouse/db';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set for integration tests (see .env.example)`);
  return value;
}

let owner: PrismaClient | undefined;

/** Owner-role client, for test setup/cleanup only. The app under test never gets this. */
export function ownerDb(): PrismaClient {
  owner ??= createPrismaClient(required('TEST_MIGRATION_DATABASE_URL'));
  return owner;
}

/** App-role client, the same privileges the running idp has. */
export function appDb(): PrismaClient {
  return createPrismaClient(required('TEST_DATABASE_URL'));
}

/**
 * Empties the mutable tables. audit_events is append-only (even for the owner),
 * so tests never clean it; they filter audit rows by their own user ids instead.
 */
export async function resetDb(): Promise<void> {
  await ownerDb().$executeRawUnsafe(
    'TRUNCATE "users", "sessions", "email_tokens" RESTART IDENTITY CASCADE',
  );
}

let counter = 0;
/** A unique email per call, so parallel or repeated tests never collide. */
export function uniqueEmail(prefix = 'user'): string {
  counter += 1;
  return `${prefix}-${Date.now()}-${counter}@example.test`;
}
