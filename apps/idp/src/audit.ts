import type { PrismaClient } from '@keyhouse/db';
import type { RequestMeta } from './http/request-meta.js';

/** Every security event type, in one place so they stay consistent and searchable. */
export type AuditEventType =
  | 'user.registered'
  | 'register.duplicate'
  | 'register.rejected_breached_password'
  | 'register.password_check_unavailable'
  | 'email.verified'
  | 'email.verify_failed'
  | 'login.succeeded'
  | 'login.failed'
  | 'login.unverified'
  | 'login.throttled'
  | 'session.rotated'
  | 'logout'
  | 'logout.all_sessions'
  | 'session.revoked'
  | 'session.revoke_denied'
  | 'password_reset.requested'
  | 'password_reset.throttled'
  | 'password_reset.completed'
  | 'password_reset.failed'
  | 'password_reset.rejected_breached_password'
  | 'password_reset.password_check_unavailable';

/**
 * Rule 8: writes one row to the append-only audit_events table.
 * Rule 7: metadata must never contain passwords, tokens, cookies or secrets.
 * It is awaited, so a request whose security event cannot be recorded fails
 * instead of silently going unaudited.
 */
export async function recordAudit(
  db: PrismaClient,
  type: AuditEventType,
  meta: RequestMeta,
  userId: string | null = null,
  metadata: Record<string, string | number | boolean | null> = {},
): Promise<void> {
  await db.auditEvent.create({
    data: { type, userId, ip: meta.ip, userAgent: meta.userAgent, metadata },
  });
}
