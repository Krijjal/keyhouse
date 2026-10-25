import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// ─── PHASE 2, EXERCISE 2.1 (yours): encrypting TOTP secrets at rest ─────────────
// The one exception to rule 2 (see CLAUDE.md): a TOTP secret can't be hashed, because the
// server must compute codes from it. So it is encrypted with AES-256-GCM instead.
//
// Stored format, one string, four parts separated by dots:
//     v1.<iv>.<ciphertext>.<tag>          (iv, ciphertext and tag are base64url)
// "v1" lets a future version change the scheme without breaking stored values.

export const KEY_BYTES = 32; // AES-256
export const IV_BYTES = 12; // the standard IV size for GCM

/** Thrown for ANY problem opening a sealed value: tampered, wrong key, wrong user, garbage. */
export class SecretBoxError extends Error {
  override name = 'SecretBoxError';
}

/**
 * ─── YOU IMPLEMENT THIS ───
 * Encrypts `plaintext` (e.g. a TOTP secret) for one user.
 *
 * Must:
 *  - Throw a RangeError if key.length !== KEY_BYTES.
 *  - Use a FRESH random IV every call: randomBytes(IV_BYTES).
 *    Why: GCM with the same key and IV twice is catastrophic (it leaks the XOR of the two
 *    plaintexts and lets an attacker forge seals). Never reuse, never derive it from data.
 *  - cipher = createCipheriv('aes-256-gcm', key, iv)
 *  - cipher.setAAD(Buffer.from(userId, 'utf8'))   ← "associated data": not secret, but
 *    sealed in. Decrypting with a different userId fails, so a DB attacker can't copy
 *    their own encrypted secret into someone else's row.
 *  - ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
 *  - tag = cipher.getAuthTag()                       ← the tamper seal (16 bytes)
 *  - Return `v1.${iv}.${ciphertext}.${tag}` with each part .toString('base64url').
 */
export function sealSecret(plaintext: string, userId: string, key: Buffer): string {
  if (key.length !== KEY_BYTES) {
    throw new RangeError(`key must be ${KEY_BYTES} bytes`);
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(userId, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;
}

/**
 * ─── YOU IMPLEMENT THIS ───
 * Reverses sealSecret. Returns the plaintext, or throws SecretBoxError.
 *
 * Must:
 *  - Throw a RangeError if key.length !== KEY_BYTES (a setup bug, not bad data).
 *  - Split `sealed` on '.': exactly 4 parts, the first being 'v1'. Otherwise SecretBoxError.
 *  - Decode iv, ciphertext and tag from base64url. The iv must be IV_BYTES long and the
 *    tag 16 bytes, otherwise SecretBoxError.
 *  - decipher = createDecipheriv('aes-256-gcm', key, iv)
 *    decipher.setAAD(Buffer.from(userId, 'utf8'))
 *    decipher.setAuthTag(tag)
 *    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
 *  - decipher.final() THROWS when the seal doesn't match (tampered data, wrong key, or wrong
 *    userId). Catch that and throw new SecretBoxError('cannot open sealed secret') instead.
 *    Never return partial or unverified plaintext, and never put the secret in the message.
 */
export function openSecret(sealed: string, userId: string, key: Buffer): string {
  if (key.length !== KEY_BYTES) {
    throw new RangeError(`key must be ${KEY_BYTES} bytes`);
  }
  const parts = sealed.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new SecretBoxError('cannot open sealed secret');
  }
  const [, ivBase64 = '', ciphertextBase64 = '', tagBase64 = ''] = parts;
  const iv = Buffer.from(ivBase64, 'base64url');
  const ciphertext = Buffer.from(ciphertextBase64, 'base64url');
  const tag = Buffer.from(tagBase64, 'base64url');
  if (iv.length !== IV_BYTES || tag.length !== 16) {
    throw new SecretBoxError('cannot open sealed secret');
  }
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(userId, 'utf8'));
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
      'utf8',
    );
    return plaintext;
  } catch {
    throw new SecretBoxError('cannot open sealed secret');
  }
}
