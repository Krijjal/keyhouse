import { z } from 'zod';

const postgresUrl = z
  .url()
  .refine((v) => v.startsWith('postgresql://') || v.startsWith('postgres://'), {
    message: 'must be a postgresql:// URL',
  });

const redisUrl = z.url().refine((v) => v.startsWith('redis://') || v.startsWith('rediss://'), {
  message: 'must be a redis:// or rediss:// URL',
});

const configSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    IDP_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    IDP_PUBLIC_URL: z.url(),
    WEB_ORIGIN: z.url(),
    DATABASE_URL: postgresUrl,
    REDIS_URL: redisUrl,
    SMTP_HOST: z.string().min(1),
    SMTP_PORT: z.coerce.number().int().min(1).max(65535),
    MAIL_FROM: z.string().min(3),
  })
  .superRefine((cfg, ctx) => {
    if (cfg.NODE_ENV !== 'production') return;
    // Placeholder secrets from .env.example must never reach production.
    for (const key of ['DATABASE_URL', 'REDIS_URL'] as const) {
      if (cfg[key].includes('change-me')) {
        ctx.addIssue({ code: 'custom', path: [key], message: 'still contains a placeholder' });
      }
    }
    // Secure cookies and a meaningful CORS origin both require HTTPS in production.
    for (const key of ['WEB_ORIGIN', 'IDP_PUBLIC_URL'] as const) {
      if (!cfg[key].startsWith('https://')) {
        ctx.addIssue({ code: 'custom', path: [key], message: 'must use https in production' });
      }
    }
  });

export type Config = z.infer<typeof configSchema>;

export class ConfigError extends Error {
  override name = 'ConfigError';
}

/**
 * Parses and validates configuration from an env object.
 * On failure, the error lists variable NAMES and problems only, never the values,
 * because the values are secrets (rule 7).
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = configSchema.safeParse(env);
  if (result.success) return result.data;

  const problems = result.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
  throw new ConfigError(`Invalid configuration:\n${problems.join('\n')}`);
}
