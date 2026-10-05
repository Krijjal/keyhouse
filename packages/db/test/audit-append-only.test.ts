import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../src/index.js';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL must be set (see .env.example)');

describe('audit_events is append-only', () => {
  let prisma: PrismaClient;
  let id: bigint;

  beforeAll(async () => {
    prisma = createPrismaClient(url);
    const row = await prisma.auditEvent.create({
      data: { type: 'test.append_only', metadata: { note: 'trigger test' } },
    });
    id = row.id;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('allows INSERT and SELECT', async () => {
    const row = await prisma.auditEvent.findUnique({ where: { id } });
    expect(row?.type).toBe('test.append_only');
  });

  it('rejects UPDATE', async () => {
    await expect(
      prisma.auditEvent.update({ where: { id }, data: { type: 'tampered' } }),
    ).rejects.toThrow(/append-only/);
  });

  it('rejects DELETE', async () => {
    await expect(prisma.auditEvent.delete({ where: { id } })).rejects.toThrow(/append-only/);
  });

  it('rejects TRUNCATE', async () => {
    await expect(prisma.$executeRawUnsafe('TRUNCATE "audit_events"')).rejects.toThrow(
      /append-only/,
    );
  });
});
