'use client';

import { useId, useState, type KeyboardEvent } from 'react';
import type { FieldProps } from './Field';

/**
 * A password input with a Show/Hide button and a "Caps Lock is on" hint.
 * Pass autoComplete="current-password" on login and "new-password" when choosing one,
 * so password managers fill or generate correctly.
 */
export function PasswordField({ label, hint, error, labelAside, ...input }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const capsId = `${id}-caps`;
  const errorId = `${id}-error`;
  const [visible, setVisible] = useState(false);
  const [capsLock, setCapsLock] = useState(false);

  const checkCaps = (event: KeyboardEvent<HTMLInputElement>) => {
    setCapsLock(event.getModifierState('CapsLock'));
  };
  const describedBy = [hint ? hintId : null, capsId, error ? errorId : null]
    .filter(Boolean)
    .join(' ');

  return (
    <div className="field" data-invalid={error ? '' : undefined}>
      <div className="field__label-row">
        <label htmlFor={id} className="field__label">
          {label}
        </label>
        {labelAside ? <span className="field__aside">{labelAside}</span> : null}
      </div>
      <div className="field__control">
        <input
          {...input}
          id={id}
          type={visible ? 'text' : 'password'}
          className="field__input field__input--with-toggle"
          spellCheck={false}
          autoCapitalize="none"
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          onKeyDown={checkCaps}
          onKeyUp={checkCaps}
          onBlur={() => {
            setCapsLock(false);
          }}
        />
        <button
          type="button"
          className="field__toggle"
          aria-controls={id}
          aria-pressed={visible}
          aria-label={visible ? 'Hide password' : 'Show password'}
          onClick={() => {
            setVisible((v) => !v);
          }}
        >
          {visible ? 'Hide' : 'Show'}
        </button>
      </div>
      {hint ? (
        <p id={hintId} className="field__hint">
          {hint}
        </p>
      ) : null}
      <p id={capsId} className="field__hint" aria-live="polite">
        {capsLock ? 'Caps Lock is on.' : ''}
      </p>
      {error ? (
        <p id={errorId} className="field__error">
          {error}
        </p>
      ) : null}
    </div>
  );
}
