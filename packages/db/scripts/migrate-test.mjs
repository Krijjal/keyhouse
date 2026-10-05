// Applies all migrations to the integration-test database (TEST_DATABASE_URL).
import { spawnSync } from 'node:child_process';

const url = process.env.TEST_DATABASE_URL;
if (!url) {
  process.stderr.write('TEST_DATABASE_URL is not set\n');
  process.exit(1);
}

const result = spawnSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env: { ...process.env, DATABASE_URL: url },
});
process.exit(result.status ?? 1);
