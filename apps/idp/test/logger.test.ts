import { describe, expect, it } from 'vitest';
import { redact } from '../src/logger.js';

describe('redact', () => {
  it('redacts sensitive keys at any depth and keeps the rest', () => {
    const out = redact({
      email: 'a@b.c',
      password: 'hunter2hunter2',
      nested: { sessionToken: 'abc', headers: { Cookie: 'sid=abc', Authorization: 'Bearer x' } },
      list: [{ resetToken: 'xyz', ok: 1 }],
    });

    expect(out).toEqual({
      email: 'a@b.c',
      password: '[REDACTED]',
      nested: {
        sessionToken: '[REDACTED]',
        headers: { Cookie: '[REDACTED]', Authorization: '[REDACTED]' },
      },
      list: [{ resetToken: '[REDACTED]', ok: 1 }],
    });
  });
});
