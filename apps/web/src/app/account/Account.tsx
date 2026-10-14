'use client';

import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { FormMessage } from '@/components/FormMessage';
import { ApiError, auth, type Me, type SessionInfo } from '@/lib/api';
import { describeDevice, shortDateTime, timeAgo } from '@/lib/describe';
import { messageFor } from '@/lib/messages';

type Loaded = { me: Me; sessions: SessionInfo[] };

export function Account() {
  const router = useRouter();
  const [data, setData] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Which action is running: a session id, "all", or "self". Blocks double clicks. */
  const [pending, setPending] = useState<string | null>(null);

  /** Any 401 means the session is gone (expired, revoked elsewhere): back to sign in. */
  const handle = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        router.replace('/login');
        return;
      }
      setError(messageFor(err));
    },
    [router],
  );

  const load = useCallback(async () => {
    try {
      const [me, sessions] = await Promise.all([auth.me(), auth.sessions()]);
      setData({ me, sessions });
    } catch (err) {
      handle(err);
    }
  }, [handle]);

  useEffect(() => {
    void load();
  }, [load]);

  async function run(
    key: string,
    action: () => Promise<unknown>,
    then: () => Promise<void> | void,
  ) {
    if (pending) return;
    setPending(key);
    setError(null);
    try {
      await action();
      await then();
    } catch (err) {
      handle(err);
    } finally {
      setPending(null);
    }
  }

  const signOut = () =>
    run('self', auth.logout, () => {
      router.replace('/login');
    });

  const signOutEverywhere = () =>
    run('all', auth.logoutAll, () => {
      router.replace('/login');
    });

  const endSession = (id: string) => run(id, () => auth.revokeSession(id), load);

  if (!data) {
    return error ? (
      <FormMessage tone="error">{error}</FormMessage>
    ) : (
      <p className="working" role="status">
        <span className="spinner" aria-hidden="true" />
        Loading your account
      </p>
    );
  }

  const others = data.sessions.filter((s) => !s.current).length;

  return (
    <div className="account">
      {error ? <FormMessage tone="error">{error}</FormMessage> : null}

      <p className="account__who">
        Signed in as <strong>{data.me.email}</strong>
      </p>

      <section aria-labelledby="sessions-title" className="account__section">
        <h2 id="sessions-title" className="section-title">
          Where you&apos;re signed in
        </h2>
        <p className="section-lede">
          Don&apos;t recognise a device? Sign it out, then change your password.
        </p>

        <ul className="sessions">
          {data.sessions.map((s) => (
            <li key={s.id} className="session" data-current={s.current ? '' : undefined}>
              <div className="session__main">
                <p className="session__device">
                  {describeDevice(s.userAgent)}
                  {s.current ? <span className="session__badge">This device</span> : null}
                </p>
                <p className="session__meta">
                  Active {timeAgo(s.lastSeenAt)}
                  {s.ip ? `, from ${s.ip}` : ''}. Signed in {shortDateTime(s.createdAt)}.
                </p>
              </div>
              {s.current ? null : (
                <button
                  type="button"
                  className="button button--quiet button--small"
                  disabled={pending !== null}
                  aria-label={`Sign out ${describeDevice(s.userAgent)}, signed in ${shortDateTime(s.createdAt)}`}
                  onClick={() => void endSession(s.id)}
                >
                  {pending === s.id ? 'Signing out' : 'Sign out'}
                </button>
              )}
            </li>
          ))}
        </ul>
      </section>

      <div className="account__actions">
        <button
          type="button"
          className="button"
          disabled={pending !== null}
          onClick={() => void signOut()}
        >
          {pending === 'self' ? 'Signing out' : 'Sign out'}
        </button>
        <button
          type="button"
          className="button button--quiet button--danger"
          disabled={pending !== null}
          onClick={() => void signOutEverywhere()}
        >
          {pending === 'all'
            ? 'Signing out everywhere'
            : others > 0
              ? `Sign out everywhere (${others + 1} devices)`
              : 'Sign out everywhere'}
        </button>
      </div>
    </div>
  );
}
