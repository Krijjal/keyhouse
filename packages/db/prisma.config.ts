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
  // The Prisma CLI (migrate, studio) connects as the schema OWNER.
  // The running app uses DATABASE_URL (least-privilege role) via createPrismaClient().
  datasource: {
    url: env('MIGRATION_DATABASE_URL'),
  },
});
