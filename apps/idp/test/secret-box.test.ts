import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openSecret, sealSecret, SecretBoxError } from '../src/security/secret-box.js';

// ─── Phase 2, exercise 2.1: these fail until you implement secret-box.ts ───

// Everything generated at runtime: no credential-shaped literals in the repo.
const key = randomBytes(32);
const userId = randomUUID();
const secret = randomBytes(20).toString('hex'); // stands in for a TOTP secret

/** Flips one character of one part of a sealed value. */
function tamper(sealed: string, partIndex: number): string {
  const parts = sealed.split('.');
  const part = parts[partIndex] ?? '';
  const first = part.charAt(0) === 'A' ? 'B' : 'A';
  parts[partIndex] = first + part.slice(1);
  return parts.join('.');
}

describe('sealSecret', () => {
  it('produces v1.<iv>.<ciphertext>.<tag> in base64url', () => {
    const sealed = sealSecret(secret, userId, key);
    const parts = sealed.split('.');
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe('v1');
    for (const p of parts.slice(1)) expect(p).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(parts[1] ?? '', 'base64url')).toHaveLength(12); // IV
    expect(Buffer.from(parts[3] ?? '', 'base64url')).toHaveLength(16); // tag
  });

  it('never contains the plaintext', () => {
    expect(sealSecret(secret, userId, key)).not.toContain(secret);
  });

  it('uses a fresh IV every time: same input, different output', () => {
    const a = sealSecret(secret, userId, key);
    const b = sealSecret(secret, userId, key);
    expect(a).not.toBe(b);
    expect(a.split('.')[1]).not.toBe(b.split('.')[1]);
  });

  it('refuses a key that is not 32 bytes', () => {
    expect(() => sealSecret(secret, userId, randomBytes(16))).toThrow(RangeError);
  });
});

describe('openSecret', () => {
  it('opens what sealSecret sealed', () => {
    expect(openSecret(sealSecret(secret, userId, key), userId, key)).toBe(secret);
  });

  it('refuses a tampered IV, ciphertext or tag', () => {
    const sealed = sealSecret(secret, userId, key);
    for (const part of [1, 2, 3]) {
      expect(() => openSecret(tamper(sealed, part), userId, key)).toThrow(SecretBoxError);
    }
  });

  it('refuses the wrong key', () => {
    const sealed = sealSecret(secret, userId, key);
    expect(() => openSecret(sealed, userId, randomBytes(32))).toThrow(SecretBoxError);
  });

  it("refuses another user's id: a sealed secret can't be moved to another account", () => {
    const sealed = sealSecret(secret, userId, key);
    expect(() => openSecret(sealed, randomUUID(), key)).toThrow(SecretBoxError);
  });

  it('refuses garbage and unknown versions', () => {
    const sealed = sealSecret(secret, userId, key);
    for (const bad of ['', 'nonsense', 'v1.a.b', `v2${sealed.slice(2)}`, `${sealed}.extra`]) {
      expect(() => openSecret(bad, userId, key)).toThrow(SecretBoxError);
    }
  });

  it('never puts the secret in the error message', () => {
    const sealed = sealSecret(secret, userId, key);
    try {
      openSecret(sealed, randomUUID(), key);
    } catch (err) {
      expect(String(err)).not.toContain(secret);
    }
  });

  it('refuses a key that is not 32 bytes', () => {
    const sealed = sealSecret(secret, userId, key);
    expect(() => openSecret(sealed, userId, randomBytes(31))).toThrow(RangeError);
  });
});
