import type { PrismaClient } from '@keyhouse/db';

// ─── PHASE 2, EXERCISE 2.5 (yours): replay protection that survives a race ──────
//
// Your verifyTotp refuses any step at or before lastUsedStep. But it READS lastUsedStep
// first. Two sign-ins with the same code, arriving at the same moment, both read the old
// value, both pass, and both would get a session: a replayed code gets in.
//
// The fix is the lesson from your email tokens: don't "read, check, then write". Write the
// new step ONLY IF the stored one is still older, in one conditional update, and let the
// number of changed rows decide.

/**
 * ─── YOU IMPLEMENT THIS ───
 * Records that `step` was just used to sign in. Returns true if this caller won the right to
 * use it, false if the step (or a newer one) was already used, or MFA isn't on.
 *
 * Must:
 *  - ONE updateMany on db.userMfa, with data { lastUsedStep: step }, where ALL of these hold:
 *      userId matches
 *      enabledAt is not null              → Prisma:  enabledAt: { not: null }
 *      lastUsedStep is null OR lastUsedStep < step
 *                                         → Prisma:  OR: [{ lastUsedStep: null },
 *                                                         { lastUsedStep: { lt: step } }]
 *  - Return true only if exactly one row changed (result.count === 1).
 *
 * Why it works: the database checks the WHERE and writes in one step, one request at a time
 * for the same row. The first request moves lastUsedStep to `step`; the second then finds
 * "lastUsedStep < step" false, changes nothing, and gets false.
 */
export async function recordTotpUse(
  db: PrismaClient,
  userId: string,
  step: number,
): Promise<boolean> {
  const result = await db.userMfa.updateMany({
    where: {
      userId,
      enabledAt: { not: null },
      OR: [{ lastUsedStep: null }, { lastUsedStep: { lt: step } }],
    },
    data: {
      lastUsedStep: step,
    },
  });

  return result.count === 1;
}
