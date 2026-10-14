'use client';

import Link from 'next/link';
import { useEffect, useRef, useState, type SubmitEvent } from 'react';
import { FormMessage } from '@/components/FormMessage';
import { PasswordField } from '@/components/PasswordField';
import { SubmitButton } from '@/components/SubmitButton';
import { ApiError, auth } from '@/lib/api';
import { takeTokenFromFragment } from '@/lib/fragment';
import { fieldMessage, messageFor } from '@/lib/messages';
import { formText, newPasswordProblem, PASSWORD_MIN_LENGTH } from '@/lib/validate';

type LinkState = 'reading' | 'ok' | 'missing' | 'expired';

export function ResetForm() {
  // The token lives only in memory: it's read from the link once, then erased from the URL.
  const token = useRef<string | null>(null);
  const [link, setLink] = useState<LinkState>('reading');
  const [busy, setBusy] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (token.current) return; // effects run twice in development
    token.current = takeTokenFromFragment();
    setLink(token.current ? 'ok' : 'missing');
  }, []);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !token.current) return;
    const form = event.currentTarget;
    const password = formText(form, 'password', false);

    const problem = newPasswordProblem(password);
    setPasswordError(problem);
    setFormError(null);
    if (problem) {
      form.querySelector<HTMLInputElement>('input[name="password"]')?.focus();
      return;
    }

    setBusy(true);
    try {
      await auth.resetPassword(token.current, password);
      token.current = null;
      setDone(true);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'invalid_or_expired_token') {
        setLink('expired');
      } else if (error instanceof ApiError && error.code === 'password_breached') {
        setPasswordError(messageFor(error));
      } else {
        setPasswordError(fieldMessage(error, 'password'));
        setFormError(messageFor(error));
      }
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="stack">
        <FormMessage tone="success">
          <p>Your password is changed.</p>
          <p>Every device was signed out. We also emailed you a note about the change.</p>
        </FormMessage>
        <Link className="button" href="/login">
          Sign in
        </Link>
      </div>
    );
  }

  if (link === 'reading') return null;

  if (link === 'missing' || link === 'expired') {
    return (
      <div className="stack">
        <FormMessage tone="error">
          {link === 'missing'
            ? 'This link is incomplete. Open it again from the email, or copy the whole link.'
            : 'This link has expired or was already used. Links work once, for 30 minutes.'}
        </FormMessage>
        <Link className="button" href="/forgot-password">
          Get a new link
        </Link>
      </div>
    );
  }

  return (
    <form className="form" noValidate onSubmit={(e) => void onSubmit(e)}>
      {formError ? <FormMessage tone="error">{formError}</FormMessage> : null}
      <PasswordField
        label="New password"
        name="password"
        autoComplete="new-password"
        required
        minLength={PASSWORD_MIN_LENGTH}
        hint={`At least ${PASSWORD_MIN_LENGTH} characters. Use one you don't use anywhere else.`}
        error={passwordError}
      />
      <SubmitButton busy={busy} busyLabel="Saving password">
        Save password
      </SubmitButton>
    </form>
  );
}
