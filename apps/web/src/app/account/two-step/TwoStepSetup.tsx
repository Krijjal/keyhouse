'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState, type SubmitEvent } from 'react';
import { Field } from '@/components/Field';
import { FormMessage } from '@/components/FormMessage';
import { RecoveryCodes } from '@/components/RecoveryCodes';
import { SubmitButton } from '@/components/SubmitButton';
import { ApiError, mfa, type MfaSetup } from '@/lib/api';
import { messageFor } from '@/lib/messages';
import { formText } from '@/lib/validate';

type Stage =
  | { kind: 'loading' }
  | { kind: 'already-on' }
  | { kind: 'failed'; message: string }
  | { kind: 'scan'; setup: MfaSetup }
  | { kind: 'done'; codes: string[] };

/** "ABCD EFGH IJKL ..." is far easier to type into an app than 32 letters in a row. */
const grouped = (secret: string) => secret.replace(/(.{4})(?=.)/g, '$1 ');

export function TwoStepSetup() {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const [codeError, setCodeError] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  // Each setup call makes a NEW secret. React runs effects twice in development, so this
  // guard keeps it to one call: otherwise the QR shown could belong to a replaced secret.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    mfa.setup().then(
      (setup) => {
        setStage({ kind: 'scan', setup });
      },
      (err: unknown) => {
        if (err instanceof ApiError && err.status === 401) router.replace('/login');
        else if (err instanceof ApiError && err.code === 'mfa_already_enabled')
          setStage({ kind: 'already-on' });
        else setStage({ kind: 'failed', message: messageFor(err) });
      },
    );
  }, [router]);

  async function onConfirm(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const code = formText(form, 'code').replace(/\s/g, '');
    if (!/^\d{6}$/.test(code)) {
      setCodeError('Enter the 6-digit code your app shows.');
      form.querySelector<HTMLInputElement>('input[name="code"]')?.focus();
      return;
    }

    setBusy(true);
    setCodeError(null);
    try {
      const codes = await mfa.enable(code);
      setStage({ kind: 'done', codes });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.replace('/login');
        return;
      }
      setCodeError(messageFor(err));
      const input = form.querySelector<HTMLInputElement>('input[name="code"]');
      if (input) {
        input.value = '';
        input.focus();
      }
    } finally {
      setBusy(false);
    }
  }

  if (stage.kind === 'loading') {
    return (
      <p className="working" role="status">
        <span className="spinner" aria-hidden="true" />
        Preparing your QR code
      </p>
    );
  }

  if (stage.kind === 'already-on') {
    return (
      <div className="stack">
        <FormMessage tone="info">Two-step verification is already on for your account.</FormMessage>
        <Link className="button" href="/account">
          Back to your account
        </Link>
      </div>
    );
  }

  if (stage.kind === 'failed') {
    return <FormMessage tone="error">{stage.message}</FormMessage>;
  }

  if (stage.kind === 'done') {
    return (
      <RecoveryCodes
        codes={stage.codes}
        notice="Two-step verification is on."
        onDone={() => {
          router.push('/account');
        }}
      />
    );
  }

  const { setup } = stage;
  return (
    <div className="setup">
      <ol className="setup__steps">
        <li>
          <h2 className="section-title">Scan this with your authenticator app</h2>
          <p className="section-lede">
            Google Authenticator, Microsoft Authenticator, 1Password and similar apps all work.
          </p>
          <img
            className="qr"
            src={setup.qrDataUrl}
            width={200}
            height={200}
            alt="QR code to add KeyHouse to your authenticator app"
          />
          {showSecret ? (
            <p className="secret">
              <span className="secret__label">Setup key</span>
              <code className="secret__value">{grouped(setup.secret)}</code>
            </p>
          ) : (
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setShowSecret(true);
              }}
            >
              Can&apos;t scan? Enter a key instead
            </button>
          )}
        </li>
        <li>
          <h2 className="section-title">Enter the code it shows</h2>
          <form className="form" noValidate onSubmit={(e) => void onConfirm(e)}>
            <Field
              label="6-digit code"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9 ]*"
              maxLength={7}
              required
              error={codeError}
            />
            <SubmitButton busy={busy} busyLabel="Checking code">
              Turn on two-step verification
            </SubmitButton>
          </form>
        </li>
      </ol>
    </div>
  );
}
