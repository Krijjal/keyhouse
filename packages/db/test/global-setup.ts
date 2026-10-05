import { execSync } from 'node:child_process';

/** Brings the test database up to the latest migration before any test runs. */
export default function setup(): void {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) throw new Error('TEST_DATABASE_URL must be set (see .env.example)');
  execSync('pnpm exec prisma migrate deploy', {
    stdio: 'inherit',
    env: { ...process.env, DATABASE_URL: url },
  });
}
