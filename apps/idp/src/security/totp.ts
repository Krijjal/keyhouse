import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// TOTP (RFC 6238) = HOTP (RFC 4226) with the counter taken from the clock.
export const STEP_SECONDS = 30;
export const DIGITS = 6;
/** How many steps either side of "now" are accepted, for phone clocks that drift. */
export const DRIFT_STEPS = 1;
/** 20 bytes = 160 bits, the size RFC 4226 recommends for HMAC-SHA1. */
export const SECRET_BYTES = 20;

// ─── Written for you (not part of the exercise) ─────────────────────────────

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Bytes → Base32 (RFC 4648, no padding): the text form authenticator apps expect. */
export function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32.charAt((value << (5 - bits)) & 31);
  return out;
}

/** Base32 → bytes. Accepts lowercase, spaces and padding, as people type them. */
export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index === -1) throw new Error('invalid base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A new TOTP secret from the CSPRNG. Base32 is what the user's app receives. */
export function generateTotpSecret(): { bytes: Buffer; base32: string } {
  const bytes = randomBytes(SECRET_BYTES);
  return { bytes, base32: base32Encode(bytes) };
}

/**
 * The otpauth:// link inside the QR code. The app reads the secret, the issuer and the
 * account label from it. The label is what users see in their app: "KeyHouse (name@x.y)".
 */
export function otpauthUri(secretBase32: string, accountEmail: string, issuer = 'KeyHouse') {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** The 30-second step a moment falls in: whole steps since 1970. */
export function stepAt(now: Date): number {
  return Math.floor(now.getTime() / 1000 / STEP_SECONDS);
}

// ─── PHASE 2, EXERCISE 2.2 (yours) ──────────────────────────────────────────

/**
 * ─── YOU IMPLEMENT THIS (part 1) ───
 * HOTP, RFC 4226 section 5.3: the 6-digit code for one counter value.
 *
 * Must, step by step:
 *  1. Write the counter as 8 bytes, big-endian:
 *       const message = Buffer.alloc(8);
 *       message.writeBigUInt64BE(BigInt(counter));
 *  2. hmac = createHmac('sha1', secret).update(message).digest()       → 20 bytes
 *  3. "Dynamic truncation": the LAST byte's low 4 bits pick where to read from:
 *       const offset = hmac[19] & 0x0f;                                 → 0..15
 *  4. Read 4 bytes from there as one number, dropping the top bit (so it's never negative):
 *       ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16)
 *         | (hmac[offset + 2] << 8) | hmac[offset + 3]
 *  5. Keep the last 6 digits:  number % 1_000_000
 *  6. Return it as text, padded with leading zeros to 6 characters:  String(n).padStart(6, '0')
 *     ("042517", not "42517": a code can start with 0)
 *
 * Note: with noUncheckedIndexedAccess, hmac[i] has type number | undefined. Read each byte
 * with `hmac[i] ?? 0`, or use hmac.readUInt8(i), which always returns a number.
 */
export function hotp(secret: Buffer, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', secret).update(message).digest();
  const offset = hmac.readUInt8(19) & 0x0f;
  const code =
    ((hmac.readUInt8(offset) & 0x7f) << 24) |
    (hmac.readUInt8(offset + 1) << 16) |
    (hmac.readUInt8(offset + 2) << 8) |
    hmac.readUInt8(offset + 3);
  const truncatedCode = code % 1_000_000;
  return String(truncatedCode).padStart(6, '0');
}

/**
 * ─── YOU IMPLEMENT THIS (part 2) ───
 * Checks a code the user typed. Returns the STEP it matched (to be saved as lastUsedStep),
 * or null if it doesn't match or was already used.
 *
 * Must:
 *  1. If `code` isn't exactly 6 digits (/^\d{6}$/), return null before doing any work.
 *  2. current = stepAt(now)
 *  3. Try every step from current - DRIFT_STEPS to current + DRIFT_STEPS (3 steps).
 *     For each one:
 *       - SKIP it if lastUsedStep !== null && step <= lastUsedStep        ← REPLAY PROTECTION:
 *         a code, or any OLDER code, can never be accepted twice.
 *       - Compare hotp(secret, step) with `code` using timingSafeEqual on the two Buffers
 *         (Buffer.from(..., 'utf8')), never ===.
 *         Why: === stops at the first different character, so how long it takes leaks how
 *         many leading digits were right.
 *       - On a match, return that step.
 *  4. No match → return null.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  now: Date,
  lastUsedStep: number | null,
): number | null {
  if (!/^\d{6}$/.test(code)) {
    return null;
  }
  const current = stepAt(now);
  for (let step = current - DRIFT_STEPS; step <= current + DRIFT_STEPS; step++) {
    if (lastUsedStep !== null && step <= lastUsedStep) {
      continue;
    }
    const expectedCode = hotp(secret, step);
    if (timingSafeEqual(Buffer.from(expectedCode, 'utf8'), Buffer.from(code, 'utf8'))) {
      return step;
    }
  }
  return null;
}
