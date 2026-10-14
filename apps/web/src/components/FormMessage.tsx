import type { ReactNode } from 'react';

interface FormMessageProps {
  tone: 'error' | 'success' | 'info';
  children: ReactNode;
}

/**
 * A message above or below a form. Errors use role="alert" so screen readers announce
 * them immediately; success and info use role="status", which waits politely.
 */
export function FormMessage({ tone, children }: FormMessageProps) {
  return (
    <div className={`message message--${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  );
}
