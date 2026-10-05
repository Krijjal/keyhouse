import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../src/index.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env.example)`);
  return value;
}

// Two layers protect audit_events:
//   1. Grants: the app role only has INSERT + SELECT and does not own the table.
//   2. Trigger: even the owner role cannot UPDATE / DELETE / TRUNCATE.
describe('audit_events is append-only', () => {
  let app: PrismaClient;
  let owner: PrismaClient;
  let id: bigint;

  beforeAll(async () => {
    app = createPrismaClient(required('TEST_DATABASE_URL'));
    owner = createPrismaClient(required('TEST_MIGRATION_DATABASE_URL'));
    const row = await app.auditEvent.create({
      data: { type: 'test.append_only', metadata: { note: 'trigger test' } },
    });
    id = row.id;
  });

  afterAll(async () => {
    await Promise.all([app.$disconnect(), owner.$disconnect()]);
  });

  describe('as the app role (grants)', () => {
    it('allows INSERT and SELECT', async () => {
      const row = await app.auditEvent.findUnique({ where: { id } });
      expect(row?.type).toBe('test.append_only');
    });

    it('denies UPDATE', async () => {
      await expect(
        app.auditEvent.update({ where: { id }, data: { type: 'tampered' } }),
      ).rejects.toThrow(/permission denied/i);
    });

    it('denies DELETE', async () => {
      await expect(app.auditEvent.delete({ where: { id } })).rejects.toThrow(/permission denied/i);
    });

    it('denies TRUNCATE', async () => {
      await expect(app.$executeRawUnsafe('TRUNCATE "audit_events"')).rejects.toThrow(
        /permission denied/i,
      );
    });

    it('cannot disable the append-only trigger', async () => {
      await expect(
        app.$executeRawUnsafe('ALTER TABLE "audit_events" DISABLE TRIGGER ALL'),
      ).rejects.toThrow(/must be owner/i);
    });

    it('cannot reset the id sequence', async () => {
      await expect(app.$queryRawUnsafe(`SELECT setval('audit_events_id_seq', 1)`)).rejects.toThrow(
        /permission denied/i,
      );
    });

    it('cannot create objects in the schema', async () => {
      await expect(app.$executeRawUnsafe('CREATE TABLE "backdoor" (id int)')).rejects.toThrow(
        /permission denied/i,
      );
    });
  });

  describe('as the owner role (trigger)', () => {
    it('rejects UPDATE', async () => {
      await expect(
        owner.auditEvent.update({ where: { id }, data: { type: 'tampered' } }),
      ).rejects.toThrow(/append-only/);
    });

    it('rejects DELETE', async () => {
      await expect(owner.auditEvent.delete({ where: { id } })).rejects.toThrow(/append-only/);
    });

    it('rejects TRUNCATE', async () => {
      await expect(owner.$executeRawUnsafe('TRUNCATE "audit_events"')).rejects.toThrow(
        /append-only/,
      );
    });
  });
});
