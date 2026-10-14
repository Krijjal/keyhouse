'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type SubmitEvent } from 'react';
import { Field } from '@/components/Field';
import { FormMessage } from '@/components/FormMessage';
import { PasswordField } from '@/components/PasswordField';
import { SubmitButton } from '@/components/SubmitButton';
import { auth } from '@/lib/api';
import { messageFor } from '@/lib/messages';
import { emailProblem, formText } from '@/lib/validate';

interface Errors {
  email?: string | null;
  password?: string | null;
  form?: string | null;
}

export function LoginForm() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Errors>({});

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const email = formText(form, 'email');
    const password = formText(form, 'password', false);

    const found: Errors = {
      email: emailProblem(email),
      password: password ? null : 'Enter your password.',
    };
    if (found.email || found.password) {
      setErrors(found);
      form.querySelector<HTMLInputElement>('[aria-invalid="true"]')?.focus();
      return;
    }

    setBusy(true);
    setErrors({});
    try {
      await auth.login(email, password);
      router.replace('/account');
    } catch (error) {
      // One message for a wrong password and an unknown email: no account enumeration.
      setErrors({ form: messageFor(error) });
      setBusy(false);
      // Clear the rejected password and put the cursor back, ready to retype it.
      const passwordInput = form.querySelector<HTMLInputElement>('input[name="password"]');
      if (passwordInput) {
        passwordInput.value = '';
        passwordInput.focus();
      }
    }
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
        autoComplete="current-password"
        required
        error={errors.password}
        labelAside={<Link href="/forgot-password">Forgot your password?</Link>}
      />
      <SubmitButton busy={busy} busyLabel="Signing in">
        Sign in
      </SubmitButton>
    </form>
  );
}
