import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';

const SECRET = 'S3cr3t-Value-That-Must-Not-Leak';

const validEnv = {
  NODE_ENV: 'development',
  IDP_PORT: '4000',
  IDP_PUBLIC_URL: 'http://localhost:4000',
  WEB_ORIGIN: 'http://localhost:3000',
  DATABASE_URL: `postgresql://keyhouse:${SECRET}@127.0.0.1:5432/keyhouse`,
  REDIS_URL: `redis://:${SECRET}@127.0.0.1:6379/0`,
  SMTP_HOST: '127.0.0.1',
  SMTP_PORT: '1025',
  MAIL_FROM: 'KeyHouse <no-reply@keyhouse.local>',
};

function errorFrom(env: NodeJS.ProcessEnv): ConfigError {
  try {
    loadConfig(env);
  } catch (err) {
    if (err instanceof ConfigError) return err;
    throw err;
  }
  throw new Error('expected loadConfig to throw');
}

describe('loadConfig', () => {
  it('parses a valid environment and coerces numbers', () => {
    const cfg = loadConfig(validEnv);
    expect(cfg.IDP_PORT).toBe(4000);
    expect(cfg.SMTP_PORT).toBe(1025);
  });

  it('names the missing variable', () => {
    const { REDIS_URL: _omit, ...env } = validEnv;
    expect(errorFrom(env).message).toContain('REDIS_URL');
  });

  it('never includes secret values in the error message', () => {
    const err = errorFrom({ ...validEnv, DATABASE_URL: `mysql://u:${SECRET}@h/db` });
    expect(err.message).toContain('DATABASE_URL');
    expect(err.message).not.toContain(SECRET);
  });

  it('rejects placeholder secrets in production', () => {
    const err = errorFrom({
      ...validEnv,
      NODE_ENV: 'production',
      IDP_PUBLIC_URL: 'https://id.example.com',
      WEB_ORIGIN: 'https://app.example.com',
      DATABASE_URL: 'postgresql://keyhouse:change-me@db:5432/keyhouse',
    });
    expect(err.message).toContain('DATABASE_URL');
  });

  it('requires https origins in production', () => {
    const err = errorFrom({ ...validEnv, NODE_ENV: 'production' });
    expect(err.message).toContain('WEB_ORIGIN');
    expect(err.message).toContain('IDP_PUBLIC_URL');
  });
});
