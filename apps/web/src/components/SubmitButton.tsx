import type { ReactNode } from 'react';

interface SubmitButtonProps {
  /** True while the request is running: shows the busy label and blocks double-submits. */
  busy: boolean;
  /** What the button does, e.g. "Sign in". */
  children: ReactNode;
  /** The same action in progress, e.g. "Signing in". */
  busyLabel: string;
}

export function SubmitButton({ busy, children, busyLabel }: SubmitButtonProps) {
  return (
    <button type="submit" className="button" disabled={busy} aria-busy={busy}>
      {busy ? (
        <>
          <span className="spinner" aria-hidden="true" />
          {busyLabel}
        </>
      ) : (
        children
      )}
    </button>
  );
}
