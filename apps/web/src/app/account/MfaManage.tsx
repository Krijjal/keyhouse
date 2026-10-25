'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState, type SubmitEvent } from 'react';
import { Field } from '@/components/Field';
import { FormMessage } from '@/components/FormMessage';
import { PasswordField } from '@/components/PasswordField';
import { RecoveryCodes } from '@/components/RecoveryCodes';
import { SubmitButton } from '@/components/SubmitButton';
import { ApiError, mfa } from '@/lib/api';
import { messageFor } from '@/lib/messages';
import { formText } from '@/lib/validate';

type Action = 'disable' | 'replace';

/** The two-step section while it's on: replace the recovery codes, or turn it off. */
export function MfaManage({
  recoveryCodesLeft,
  onChanged,
}: {
  recoveryCodesLeft: number;
  /** Reload the account page, with a success line to show at the top. */
  onChanged: (notice: string) => void;
}) {
  const [action, setAction] = useState<Action | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);

  if (codes) {
    return (
      <RecoveryCodes
        codes={codes}
        notice="New recovery codes are ready. The old ones no longer work."
        onDone={() => {
          setCodes(null);
          onChanged('Your new recovery codes are active.');
        }}
      />
    );
  }

  return (
    <>
      <p className="section-lede">
        On. Signing in needs your password and a code from your authenticator app. You have{' '}
        {recoveryCodesLeft} recovery {recoveryCodesLeft === 1 ? 'code' : 'codes'} left.
      </p>
      {action ? (
        <ConfirmStep
          key={action}
          action={action}
          onCancel={() => {
            setAction(null);
          }}
          onDisabled={() => {
            setAction(null);
            onChanged('Two-step verification is off.');
          }}
          onCodes={(fresh) => {
            setAction(null);
            setCodes(fresh);
          }}
        />
      ) : (
        <div className="account__actions account__actions--spaced">
          <button
            type="button"
            className="button button--quiet button--small"
            onClick={() => {
              setAction('replace');
            }}
          >
            Get new recovery codes
          </button>
          <button
            type="button"
            className="button button--quiet button--small button--danger"
            onClick={() => {
              setAction('disable');
            }}
          >
            Turn off
          </button>
        </div>
      )}
    </>
  );
}

/**
 * "Prove it's you" before the change: the password AND a current code. A signed-in session
 * alone (an unlocked laptop, a stolen cookie) has neither.
 */
function ConfirmStep({
  action,
  onCancel,
  onDisabled,
  onCodes,
}: {
  action: Action;
  onCancel: () => void;
  onDisabled: () => void;
  onCodes: (codes: string[]) => void;
}) {
  const router = useRouter();
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<{
    password?: string | null;
    proof?: string | null;
    form?: string | null;
  }>({});
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const password = formText(form, 'password', false);
    const proof = formText(form, 'proof');

    const found = {
      password: password ? null : 'Enter your password.',
      proof: useRecovery
        ? proof.replace(/[\s-]/g, '').length === 16
          ? null
          : 'Enter one of your recovery codes, like abcd-efgh-ijkl-mnop.'
        : /^\d{6}$/.test(proof.replace(/\s/g, ''))
          ? null
          : 'Enter the 6-digit code your app shows.',
    };
    if (found.password || found.proof) {
      setErrors(found);
      form.querySelector<HTMLInputElement>('[aria-invalid="true"]')?.focus();
      return;
    }

    setBusy(true);
    setErrors({});
    const body = useRecovery ? { password, recoveryCode: proof } : { password, code: proof };
    try {
      if (action === 'disable') {
        await mfa.disable(body);
        onDisabled();
      } else {
        onCodes(await mfa.replaceRecoveryCodes(body));
      }
    } catch (err) {
      setBusy(false);
      if (err instanceof ApiError && err.status === 401) {
        router.replace('/login');
        return;
      }
      // The answer never says which one was wrong, so clear both and start from the top.
      setErrors({ form: messageFor(err) });
      for (const name of ['proof', 'password']) {
        const input = form.querySelector<HTMLInputElement>(`input[name="${name}"]`);
        if (input) input.value = '';
      }
      form.querySelector<HTMLInputElement>('input[name="password"]')?.focus();
    }
  }

  const disabling = action === 'disable';
  return (
    <form className="form mfa-confirm" noValidate onSubmit={(e) => void onSubmit(e)}>
      <div>
        <h3 className="section-title" ref={headingRef} tabIndex={-1}>
          {disabling ? 'Turn off two-step verification' : 'Get new recovery codes'}
        </h3>
        <p className="section-lede">
          {disabling
            ? 'Signing in will need only your password, and your recovery codes will stop working. Confirm it’s you.'
            : 'Your current recovery codes will stop working. Confirm it’s you.'}
        </p>
      </div>
      {errors.form ? <FormMessage tone="error">{errors.form}</FormMessage> : null}
      <PasswordField
        label="Password"
        name="password"
        autoComplete="current-password"
        required
        error={errors.password}
      />
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
        error={errors.proof}
        labelAside={
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setUseRecovery((v) => !v);
              setErrors({});
            }}
          >
            {useRecovery ? 'Use the app instead' : 'Use a recovery code'}
          </button>
        }
      />
      <div className="account__actions">
        <SubmitButton
          busy={busy}
          busyLabel={disabling ? 'Turning off' : 'Creating codes'}
          destructive={disabling}
        >
          {disabling ? 'Turn off two-step verification' : 'Create new codes'}
        </SubmitButton>
        <button type="button" className="button button--quiet" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
