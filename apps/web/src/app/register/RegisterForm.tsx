'use client';

import { useState, type SubmitEvent } from 'react';
import { CheckEmail } from '@/components/CheckEmail';
import { Field } from '@/components/Field';
import { FormMessage } from '@/components/FormMessage';
import { PasswordField } from '@/components/PasswordField';
import { SubmitButton } from '@/components/SubmitButton';
import { ApiError, auth } from '@/lib/api';
import { fieldMessage, messageFor } from '@/lib/messages';
import { emailProblem, formText, newPasswordProblem, PASSWORD_MIN_LENGTH } from '@/lib/validate';

interface Errors {
  email?: string | null;
  password?: string | null;
  form?: string | null;
}

export function RegisterForm() {
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Errors>({});
  const [sentTo, setSentTo] = useState<string | null>(null);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const email = formText(form, 'email');
    const password = formText(form, 'password', false);

    const found: Errors = { email: emailProblem(email), password: newPasswordProblem(password) };
    if (found.email || found.password) {
      setErrors(found);
      form.querySelector<HTMLInputElement>('[aria-invalid="true"]')?.focus();
      return;
    }

    setBusy(true);
    setErrors({});
    try {
      await auth.register(email, password);
      // The API answers the same for new and existing emails, and so do we.
      setSentTo(email);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'password_breached') {
        setErrors({ password: messageFor(error) });
      } else {
        setErrors({
          email: fieldMessage(error, 'email'),
          password: fieldMessage(error, 'password'),
          form: messageFor(error),
        });
      }
    } finally {
      setBusy(false);
    }
  }

  if (sentTo) {
    return (
      <CheckEmail
        email={sentTo}
        what="Open the link in it to confirm your address and finish creating your account."
        onRestart={() => {
          setSentTo(null);
        }}
        restartLabel="Use a different email"
      />
    );
  }

  return (
    <form className="form" noValidate onSubmit={(e) => void onSubmit(e)}>
      {errors.form ? <FormMessage tone="error">{errors.form}</FormMessage> : null}
      <Field
        label="Email"
        name="email"
        type="email"
        autoComplete="email"
        inputMode="email"
        required
        error={errors.email}
      />
      <PasswordField
        label="Password"
        name="password"
        autoComplete="new-password"
        required
        minLength={PASSWORD_MIN_LENGTH}
        hint={`At least ${PASSWORD_MIN_LENGTH} characters. A few unrelated words make a strong one.`}
        error={errors.password}
      />
      <SubmitButton busy={busy} busyLabel="Creating account">
        Create account
      </SubmitButton>
    </form>
  );
}
