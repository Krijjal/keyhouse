'use client';

import { useState, type SubmitEvent } from 'react';
import { CheckEmail } from '@/components/CheckEmail';
import { Field } from '@/components/Field';
import { FormMessage } from '@/components/FormMessage';
import { SubmitButton } from '@/components/SubmitButton';
import { auth } from '@/lib/api';
import { messageFor } from '@/lib/messages';
import { emailProblem, formText } from '@/lib/validate';

export function ForgotForm() {
  const [busy, setBusy] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const email = formText(form, 'email');

    const problem = emailProblem(email);
    setEmailError(problem);
    setFormError(null);
    if (problem) {
      form.querySelector<HTMLInputElement>('input[name="email"]')?.focus();
      return;
    }

    setBusy(true);
    try {
      await auth.forgotPassword(email);
      setSentTo(email);
    } catch (error) {
      setFormError(messageFor(error));
    } finally {
      setBusy(false);
    }
  }

  if (sentTo) {
    return (
      <CheckEmail
        email={sentTo}
        what="The link in it lets you choose a new password. It works once, for 30 minutes."
        onRestart={() => {
          setSentTo(null);
        }}
        restartLabel="Send to a different email"
      />
    );
  }

  return (
    <form className="form" noValidate onSubmit={(e) => void onSubmit(e)}>
      {formError ? <FormMessage tone="error">{formError}</FormMessage> : null}
      <Field
        label="Email"
        name="email"
        type="email"
        autoComplete="email"
        inputMode="email"
        required
        error={emailError}
      />
      <SubmitButton busy={busy} busyLabel="Sending link">
        Send reset link
      </SubmitButton>
    </form>
  );
}
