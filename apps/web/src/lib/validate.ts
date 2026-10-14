// Checks done in the browser for fast, friendly feedback. The API checks everything again:
// these are a convenience, never the security boundary.

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export function emailProblem(email: string): string | null {
  if (!email.trim()) return 'Enter your email address.';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return 'Enter an email address like name@example.com.';
  }
  return null;
}

/** For choosing a password (register, reset). Login only checks it isn't empty. */
export function newPasswordProblem(password: string): string | null {
  if (!password) return 'Choose a password.';
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Use at least ${PASSWORD_MIN_LENGTH} characters.`;
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return `Use at most ${PASSWORD_MAX_LENGTH} characters.`;
  }
  return null;
}

/** Text fields from a submitted form, trimmed where it's safe to trim. */
export function formText(form: HTMLFormElement, name: string, trim = true): string {
  const value = new FormData(form).get(name);
  if (typeof value !== 'string') return '';
  return trim ? value.trim() : value;
}
