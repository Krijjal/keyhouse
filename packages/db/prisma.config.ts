import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, env } from 'prisma/config';

// Load the repo-root .env for local CLI use. In CI/production, real env vars are used instead.
const rootEnv = fileURLToPath(new URL('../../.env', import.meta.url));
if (existsSync(rootEnv)) process.loadEnvFile(rootEnv);

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: env('DATABASE_URL'),
  },
});
