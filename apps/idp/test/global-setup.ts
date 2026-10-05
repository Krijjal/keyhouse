import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** Brings the test database up to the latest migration (as the owner role) before any test runs. */
export default function setup(): void {
  const url = process.env.TEST_MIGRATION_DATABASE_URL;
  if (!url) throw new Error('TEST_MIGRATION_DATABASE_URL must be set (see .env.example)');
  execSync('pnpm exec prisma migrate deploy', {
    cwd: fileURLToPath(new URL('../../../packages/db', import.meta.url)),
    stdio: 'ignore',
    env: { ...process.env, MIGRATION_DATABASE_URL: url },
  });
}
