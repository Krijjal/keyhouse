import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { createSmtpMailer } from '../src/mail/mailer.js';
import { uniqueEmail } from './db.js';

const MAILPIT_API = 'http://127.0.0.1:8025/api/v1';

interface MailpitSearch {
  messages: { Subject: string; To: { Address: string }[] }[];
}

describe('SMTP mailer (real Mailpit)', () => {
  it('delivers a message through SMTP', async () => {
    const config = loadConfig({ ...process.env, NODE_ENV: 'test' });
    const mailer = createSmtpMailer({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      from: config.MAIL_FROM,
    });
    const to = uniqueEmail('smtp');
    await mailer.send({ to, subject: 'KeyHouse SMTP test', text: 'hello' });

    const res = await fetch(`${MAILPIT_API}/search?query=${encodeURIComponent(`to:${to}`)}`);
    const body = (await res.json()) as MailpitSearch;
    expect(body.messages).toHaveLength(1);
    expect(body.messages[0]?.Subject).toBe('KeyHouse SMTP test');
  });
});
