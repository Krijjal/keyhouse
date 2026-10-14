'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { FormMessage } from '@/components/FormMessage';
import { ApiError, auth } from '@/lib/api';
import { takeTokenFromFragment } from '@/lib/fragment';
import { messageFor } from '@/lib/messages';

type State =
  { kind: 'working' } | { kind: 'done' } | { kind: 'failed'; message: string; expired: boolean };

export function VerifyEmail() {
  const [state, setState] = useState<State>({ kind: 'working' });
  // The token works once. In development React runs effects twice on purpose; this
  // makes sure we only ever send it once.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const token = takeTokenFromFragment();
    if (!token) {
      setState({
        kind: 'failed',
        message: 'This link is incomplete. Open it again from the email, or copy the whole link.',
        expired: false,
      });
      return;
    }
    auth.verifyEmail(token).then(
      () => {
        setState({ kind: 'done' });
      },
      (error: unknown) => {
        setState({
          kind: 'failed',
          message: messageFor(error),
          expired: error instanceof ApiError && error.code === 'invalid_or_expired_token',
        });
      },
    );
  }, []);

  if (state.kind === 'working') {
    return (
      <p className="working" role="status">
        <span className="spinner" aria-hidden="true" />
        Confirming your email address
      </p>
    );
  }

  if (state.kind === 'done') {
    return (
      <div className="stack">
        <FormMessage tone="success">Your email address is confirmed.</FormMessage>
        <Link className="button" href="/login">
          Sign in
        </Link>
      </div>
    );
  }

  return (
    <div className="stack">
      <FormMessage tone="error">{state.message}</FormMessage>
      {state.expired ? (
        <p>
          If you already confirmed it, you can <Link href="/login">sign in</Link>. Otherwise,{' '}
          <Link href="/register">register again</Link> with the same email to get a new link.
        </p>
      ) : null}
    </div>
  );
}
