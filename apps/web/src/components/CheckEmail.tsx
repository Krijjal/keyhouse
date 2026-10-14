'use client';

import { useEffect, useRef } from 'react';

interface CheckEmailProps {
  email: string;
  /** What the email lets them do, in one sentence. */
  what: string;
  onRestart: () => void;
  restartLabel: string;
}

/**
 * "Check your email", shown after register and forgot-password. It never says whether
 * the address has an account: the API sent the same answer either way.
 * Focus moves here so keyboard and screen-reader users land on the news.
 */
export function CheckEmail({ email, what, onRestart, restartLabel }: CheckEmailProps) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);

  return (
    <div className="check-email" ref={ref} tabIndex={-1} role="status">
      <h2 className="check-email__title">Check your email</h2>
      <p>
        If <strong className="check-email__address">{email}</strong> can receive mail from KeyHouse,
        a message is on its way. {what}
      </p>
      <p className="check-email__small">
        Nothing after a few minutes? Check your spam folder, or try again.
      </p>
      <button type="button" className="button button--quiet" onClick={onRestart}>
        {restartLabel}
      </button>
    </div>
  );
}
