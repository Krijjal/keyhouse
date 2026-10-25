'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState, type SubmitEvent } from 'react';
import { Field } from '@/components/Field';
import { FormMessage } from '@/components/FormMessage';
import { PasswordField } from '@/components/PasswordField';
import { SubmitButton } from '@/components/SubmitButton';
import { ApiError, auth } from '@/lib/api';
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
  /** True after a correct password on an account with two-step verification. */
  const [needsCode, setNeedsCode] = useState(false);
  /** Shown above the password form when the code step sends the user back. */
  const [notice, setNotice] = useState<string | null>(null);

  if (needsCode) {
    return (
      <CodeStep
        onSignedIn={() => {
          router.replace('/account');
        }}
        onStartOver={(message) => {
          setNotice(message);
          setNeedsCode(false);
        }}
      />
    );
  }

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
    setNotice(null);
    try {
      const { status } = await auth.login(email, password);
      if (status === 'mfa_required') {
        setBusy(false);
        setNeedsCode(true);
        return;
      }
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
      {notice ? <FormMessage tone="info">{notice}</FormMessage> : null}
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

/**
 * Step 2 for accounts with two-step verification: a code from the app, or a recovery code.
 * The ticket from step 1 is an HttpOnly cookie: this page never sees or stores it.
 */
function CodeStep({
  onSignedIn,
  onStartOver,
}: {
  onSignedIn: () => void;
  onStartOver: (message: string) => void;
}) {
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Move focus to the new step, so keyboard and screen-reader users land on it.
  useEffect(() => {
    headingRef.current?.focus();
  }, [useRecovery]);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const value = formText(form, 'proof');
    const input = form.querySelector<HTMLInputElement>('input[name="proof"]');

    if (!useRecovery && !/^\d{6}$/.test(value.replace(/\s/g, ''))) {
      setError('Enter the 6-digit code your app shows.');
      input?.focus();
      return;
    }
    if (useRecovery && value.replace(/[\s-]/g, '').length !== 16) {
      setError('Enter one of your recovery codes, like abcd-efgh-ijkl-mnop.');
      input?.focus();
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await auth.loginMfa(useRecovery ? { recoveryCode: value } : { code: value });
      onSignedIn();
    } catch (err) {
      setBusy(false);
      // The ticket expired or ran out of tries: back to the password, with an explanation.
      if (err instanceof ApiError && err.code === 'mfa_ticket_invalid') {
        onStartOver(messageFor(err));
        return;
      }
      setError(
        err instanceof ApiError && err.code === 'invalid_code'
          ? useRecovery
            ? "That recovery code didn't work. Codes work once; try another."
            : messageFor(err)
          : messageFor(err),
      );
      if (input) {
        input.value = '';
        input.focus();
      }
    }
  }

  return (
    <form className="form" noValidate onSubmit={(e) => void onSubmit(e)}>
      <div>
        <h2 className="section-title" ref={headingRef} tabIndex={-1}>
          {useRecovery ? 'Enter a recovery code' : 'Enter the code from your app'}
        </h2>
        <p className="section-lede">
          {useRecovery
            ? 'Use one of the codes you saved when you set up two-step verification. Each works once.'
            : 'Open your authenticator app and type the 6-digit code for KeyHouse.'}
        </p>
      </div>
      <Field
        key={useRecovery ? 'recovery' : 'code'}
        label={useRecovery ? 'Recovery code' : '6-digit code'}
        name="proof"
        inputMode={useRecovery ? 'text' : 'numeric'}
        autoComplete={useRecovery ? 'off' : 'one-time-code'}
        autoCapitalize="none"
        spellCheck={false}
        maxLength={useRecovery ? 24 : 7}
        required
        error={error}
      />
      <SubmitButton busy={busy} busyLabel="Checking">
        Sign in
      </SubmitButton>
      <button
        type="button"
        className="link-button"
        onClick={() => {
          setUseRecovery((v) => !v);
          setError(null);
        }}
      >
        {useRecovery ? 'Use a code from your app instead' : 'Lost your phone? Use a recovery code'}
      </button>
    </form>
  );
}
