import { ApiError } from './api';

/**
 * One plain sentence for each thing that can go wrong. They say what happened and what to
 * do next, and never whether an email address has an account (rule 5).
 */
export function messageFor(error: unknown): string {
  if (!(error instanceof ApiError)) return 'Something went wrong. Try again.';

  switch (error.code) {
    case 'invalid_credentials':
      return "That email and password don't match. Check both and try again.";
    case 'email_not_verified':
      return 'Confirm your email address first, using the link we sent you.';
    case 'too_many_attempts':
      return error.retryAfterSeconds
        ? `Too many attempts. Try again in ${formatWait(error.retryAfterSeconds)}.`
        : 'Too many attempts. Wait a little, then try again.';
    case 'password_breached':
      return 'This password has appeared in a data breach. Choose a different one.';
    case 'password_check_unavailable':
    case 'service_unavailable':
      return "KeyHouse can't do this right now. Try again in a few seconds.";
    case 'invalid_or_expired_token':
      return 'This link has expired or was already used.';
    case 'unauthenticated':
      return 'Your session has ended. Sign in again.';
    case 'session_not_found':
      return 'That session has already ended.';
    case 'forbidden_origin':
      return 'This request was blocked because it came from another site.';
    case 'invalid_code':
      return "That code didn't work. Check the 6 digits your app shows now and try again.";
    case 'mfa_already_enabled':
      return 'Two-step verification is already on.';
    case 'mfa_setup_not_started':
      return 'Setup expired or was restarted. Start again to get a new QR code.';
    case 'network_error':
      return "Can't reach KeyHouse. Check your connection and try again.";
    case 'invalid_request':
      return 'Check the highlighted fields.';
    default:
      return 'Something went wrong. Try again.';
  }
}

function formatWait(seconds: number): string {
  if (seconds < 60) return seconds === 1 ? '1 second' : `${seconds} seconds`;
  const minutes = Math.ceil(seconds / 60);
  return minutes === 1 ? '1 minute' : `${minutes} minutes`;
}

/** The API's field messages ("must be at least 12 characters") as full sentences. */
export function fieldMessage(error: unknown, field: string): string | null {
  if (!(error instanceof ApiError) || error.code !== 'invalid_request') return null;
  const raw = error.fields[field];
  if (!raw) return null;
  if (field === 'email') return 'Enter an email address like name@example.com.';
  const sentence = raw.charAt(0).toUpperCase() + raw.slice(1);
  return sentence.endsWith('.') ? sentence : `${sentence}.`;
}
