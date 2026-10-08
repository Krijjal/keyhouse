import type { MailMessage } from './mailer.js';

// Tokens go in the URL fragment (#token=...). Browsers never send the fragment to any
// server: it stays out of access logs, proxies and Referer headers.

export function verifyEmailMessage(to: string, webOrigin: string, token: string): MailMessage {
  return {
    to,
    subject: 'Verify your KeyHouse email',
    text: [
      'Confirm this email address to finish creating your KeyHouse account:',
      '',
      `${webOrigin}/verify-email#token=${token}`,
      '',
      'The link works once and expires in 24 hours.',
      "If you didn't create an account, you can ignore this email.",
    ].join('\n'),
  };
}

export function finishSetupMessage(to: string, webOrigin: string, token: string): MailMessage {
  return {
    to,
    subject: 'Finish setting up your KeyHouse account',
    text: [
      'Someone tried to register a KeyHouse account with this email, which already has an',
      'account that was never confirmed.',
      '',
      'If it was you, choose your password here. This also confirms your email:',
      '',
      `${webOrigin}/reset-password#token=${token}`,
      '',
      'The link works once and expires in 30 minutes.',
      "If it wasn't you, ignore this email. Nothing changes unless the link is used.",
    ].join('\n'),
  };
}

export function resetPasswordMessage(to: string, webOrigin: string, token: string): MailMessage {
  return {
    to,
    subject: 'Reset your KeyHouse password',
    text: [
      'Someone asked to reset the password of the KeyHouse account for this email.',
      '',
      'If it was you, choose a new password here:',
      '',
      `${webOrigin}/reset-password#token=${token}`,
      '',
      'The link works once and expires in 30 minutes. Using it signs you out everywhere.',
      "If it wasn't you, ignore this email. Your password has not changed.",
    ].join('\n'),
  };
}

export function passwordChangedMessage(to: string, webOrigin: string): MailMessage {
  return {
    to,
    subject: 'Your KeyHouse password was changed',
    text: [
      'The password of your KeyHouse account was just changed, and every device was signed out.',
      '',
      `If it was you, sign in again: ${webOrigin}/login`,
      '',
      "If it wasn't you, reset your password right away:",
      `${webOrigin}/forgot-password`,
    ].join('\n'),
  };
}

export function alreadyRegisteredMessage(to: string, webOrigin: string): MailMessage {
  return {
    to,
    subject: 'You already have a KeyHouse account',
    text: [
      'Someone tried to register a KeyHouse account with this email, but you already have one.',
      '',
      `Sign in: ${webOrigin}/login`,
      `Forgot your password? ${webOrigin}/forgot-password`,
      '',
      "If it wasn't you, you can ignore this email. Your account has not changed.",
    ].join('\n'),
  };
}
