import { execSync } from 'node:child_process';

/** Brings the test database up to the latest migration before any test runs. */
export default function setup(): void {
  const url = process.env.TEST_MIGRATION_DATABASE_URL;
  if (!url) throw new Error('TEST_MIGRATION_DATABASE_URL must be set (see .env.example)');
  execSync('pnpm exec prisma migrate deploy', {
    stdio: 'inherit',
    env: { ...process.env, MIGRATION_DATABASE_URL: url },
  });
}
