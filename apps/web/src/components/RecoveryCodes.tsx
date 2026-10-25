'use client';

import { useEffect, useRef, useState } from 'react';
import { FormMessage } from './FormMessage';

/**
 * Shows a fresh set of recovery codes, once, with copy and download. The codes live only in
 * this component's props: nothing stores them, so leaving the page makes them unrecoverable.
 */
export function RecoveryCodes({
  codes,
  notice,
  onDone,
}: {
  codes: string[];
  /** The success line above the codes, e.g. "Two-step verification is on." */
  notice: string;
  onDone: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const text = codes.join('\n');

  // Move focus here, so keyboard and screen-reader users land on the new codes.
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
  };

  const download = () => {
    const blob = new Blob([`KeyHouse recovery codes. Each works once.\n\n${text}\n`], {
      type: 'text/plain',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'keyhouse-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="stack">
      <FormMessage tone="success">{notice}</FormMessage>
      <div>
        <h2 className="section-title" ref={headingRef} tabIndex={-1}>
          Save your recovery codes
        </h2>
        <p className="section-lede">
          If you lose your phone, each of these signs you in once instead of a code. This is the
          only time you&apos;ll see them: store them in a password manager or print them.
        </p>
      </div>
      <ul className="codes" aria-label="Recovery codes">
        {codes.map((code) => (
          <li key={code}>
            <code>{code}</code>
          </li>
        ))}
      </ul>
      <div className="account__actions">
        <button type="button" className="button button--quiet" onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy codes'}
        </button>
        <button type="button" className="button button--quiet" onClick={download}>
          Download as text
        </button>
      </div>
      <button type="button" className="button" onClick={onDone}>
        I&apos;ve saved them
      </button>
    </div>
  );
}
