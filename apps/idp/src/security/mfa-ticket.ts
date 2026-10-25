import type { PrismaClient } from '@keyhouse/db';
import { BASE64URL_TOKEN_REGEX, generateToken, hashToken } from './tokens.js';

// The "password was right, now prove the second factor" ticket (owner's decision, CLAUDE.md):
// 5 minutes, 5 code attempts, single use, stored only as a hash.
export const MFA_TICKET_TTL_MS = 5 * 60 * 1000;
export const MFA_TICKET_MAX_ATTEMPTS = 5;

/**
 * Issues a new ticket and returns the raw token for the cookie. Any older unused ticket of
 * the same user is used up first, so only the newest sign-in attempt can be finished.
 */
export async function issueMfaTicket(
  db: PrismaClient,
  userId: string,
  now: Date = new Date(),
): Promise<string> {
  const { token, tokenHash } = generateToken();
  await db.$transaction([
    db.mfaTicket.updateMany({ where: { userId, consumedAt: null }, data: { consumedAt: now } }),
    db.mfaTicket.create({
      data: { userId, tokenHash, expiresAt: new Date(now.getTime() + MFA_TICKET_TTL_MS) },
    }),
  ]);
  return token;
}

/**
 * Reserves one code attempt on a live ticket, atomically: the attempt counter only goes up if
 * the ticket is unused, unexpired and under the limit, all checked in the same write. So five
 * wrong codes sent at the same moment can't sneak a sixth past the limit.
 * Returns the ticket's id and user, or null (unknown, expired, used up, out of attempts).
 */
export async function reserveMfaAttempt(
  db: PrismaClient,
  rawToken: string,
  now: Date = new Date(),
): Promise<{ ticketId: string; userId: string } | null> {
  if (!BASE64URL_TOKEN_REGEX.test(rawToken)) return null;
  const tokenHash = hashToken(rawToken);
  const reserved = await db.mfaTicket.updateMany({
    where: {
      tokenHash,
      consumedAt: null,
      expiresAt: { gt: now },
      attempts: { lt: MFA_TICKET_MAX_ATTEMPTS },
    },
    data: { attempts: { increment: 1 } },
  });
  if (reserved.count !== 1) return null;
  const ticket = await db.mfaTicket.findUnique({
    where: { tokenHash },
    select: { id: true, userId: true },
  });
  return ticket ? { ticketId: ticket.id, userId: ticket.userId } : null;
}

/** Uses the ticket up when it's exchanged for a session. False if something else got there first. */
export async function consumeMfaTicket(
  db: PrismaClient,
  ticketId: string,
  now: Date = new Date(),
): Promise<boolean> {
  const result = await db.mfaTicket.updateMany({
    where: { id: ticketId, consumedAt: null },
    data: { consumedAt: now },
  });
  return result.count === 1;
}
