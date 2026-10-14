'use client';

import { useId, type InputHTMLAttributes, type ReactNode } from 'react';

export interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> {
  label: string;
  /** Help shown under the input, e.g. "At least 12 characters". */
  hint?: ReactNode;
  /** Shown in red under the input and announced by screen readers. */
  error?: string | null | undefined;
  /** Something on the label's line, e.g. a "Forgot your password?" link. */
  labelAside?: ReactNode;
}

/**
 * A labelled text input. The label, hint and error are wired to the input with
 * htmlFor / aria-describedby / aria-invalid, so screen readers read them together.
 */
export function Field({ label, hint, error, labelAside, className, ...input }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(' ');

  return (
    <div className="field" data-invalid={error ? '' : undefined}>
      <div className="field__label-row">
        <label htmlFor={id} className="field__label">
          {label}
        </label>
        {labelAside ? <span className="field__aside">{labelAside}</span> : null}
      </div>
      <input
        {...input}
        id={id}
        className={['field__input', className].filter(Boolean).join(' ')}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
      />
      {hint ? (
        <p id={hintId} className="field__hint">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errorId} className="field__error">
          {error}
        </p>
      ) : null}
    </div>
  );
}
