import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  hotp,
  otpauthUri,
  STEP_SECONDS,
  stepAt,
  verifyTotp,
} from '../src/security/totp.js';

// ─── Phase 2, exercise 2.2: hotp / verifyTotp fail until you implement them ───

// RFC 4226 appendix D: the published test key is the ASCII text "1234567890" twice.
// Built at runtime so no credential-shaped literal sits in the source.
const rfcKey = Buffer.from('1234567890'.repeat(2), 'ascii');
const RFC_CODES = [
  '755224',
  '287082',
  '359152',
  '969429',
  '338314',
  '254676',
  '287922',
  '162583',
  '399871',
  '520489',
];

describe('written for you', () => {
  it('base32 round-trips and matches RFC 4648', () => {
    expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
    expect(base32Decode('mzxw6ytboi').toString()).toBe('foobar');
    const bytes = randomBytes(20);
    expect(base32Decode(base32Encode(bytes)).equals(bytes)).toBe(true);
  });

  it('generates 160-bit secrets', () => {
    const { bytes, base32 } = generateTotpSecret();
    expect(bytes).toHaveLength(20);
    expect(base32).toMatch(/^[A-Z2-7]{32}$/);
  });

  it('builds the otpauth link authenticator apps read', () => {
    const uri = otpauthUri('ABCDEF', 'ada@example.test');
    expect(uri.startsWith('otpauth://totp/KeyHouse%3Aada%40example.test?')).toBe(true);
    expect(uri).toContain('issuer=KeyHouse');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });
});

describe('exercise 2.2 part 1: hotp', () => {
  it('matches every RFC 4226 test vector', () => {
    RFC_CODES.forEach((expected, counter) => {
      expect(hotp(rfcKey, counter)).toBe(expected);
    });
  });

  it('always returns 6 characters, keeping leading zeros', () => {
    for (let counter = 0; counter < 500; counter++) {
      expect(hotp(rfcKey, counter)).toMatch(/^\d{6}$/);
    }
  });
});

describe('exercise 2.2 part 2: verifyTotp', () => {
  const secret = randomBytes(20);
  const now = new Date('2026-10-25T12:00:10Z');
  const step = stepAt(now);
  const codeAt = (s: number) => hotp(secret, s);

  it('accepts the current code and returns its step', () => {
    expect(verifyTotp(secret, codeAt(step), now, null)).toBe(step);
  });

  it('accepts one step of clock drift either way', () => {
    expect(verifyTotp(secret, codeAt(step - 1), now, null)).toBe(step - 1);
    expect(verifyTotp(secret, codeAt(step + 1), now, null)).toBe(step + 1);
  });

  it('refuses codes two or more steps away', () => {
    expect(verifyTotp(secret, codeAt(step - 2), now, null)).toBeNull();
    expect(verifyTotp(secret, codeAt(step + 2), now, null)).toBeNull();
  });

  it('REPLAY: refuses a code that was already used', () => {
    const used = verifyTotp(secret, codeAt(step), now, null);
    expect(used).toBe(step);
    expect(verifyTotp(secret, codeAt(step), now, used)).toBeNull();
  });

  it('REPLAY: refuses an OLDER code once a newer one was used', () => {
    expect(verifyTotp(secret, codeAt(step - 1), now, step)).toBeNull();
  });

  it('still accepts a NEWER code after an older one was used', () => {
    expect(verifyTotp(secret, codeAt(step + 1), now, step - 1)).toBe(step + 1);
  });

  it('refuses wrong codes and anything that is not 6 digits', () => {
    const wrong = codeAt(step) === '000000' ? '111111' : '000000';
    for (const bad of [wrong, '', '12345', '1234567', 'abcdef', ` ${codeAt(step)}`]) {
      expect(verifyTotp(secret, bad, now, null)).toBeNull();
    }
  });

  it("refuses a code made with someone else's secret", () => {
    expect(verifyTotp(secret, hotp(randomBytes(20), step), now, null)).toBeNull();
  });

  it('uses 30-second steps', () => {
    expect(stepAt(new Date(STEP_SECONDS * 1000 * 100))).toBe(100);
  });
});
