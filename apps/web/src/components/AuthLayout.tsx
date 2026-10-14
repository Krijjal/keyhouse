import Link from 'next/link';
import type { ReactNode } from 'react';
import { Key } from './Key';

interface AuthLayoutProps {
  title: string;
  /** One sentence under the title. Leave it out when the title says enough. */
  lede?: ReactNode;
  /** This page's key: 4-7 depths from 0 to 5. */
  cuts: readonly number[];
  children: ReactNode;
  /** Small print under the form, e.g. "New here? Create an account". */
  footer?: ReactNode;
}

export function AuthLayout({ title, lede, cuts, children, footer }: AuthLayoutProps) {
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header>
        <Link href="/" className="wordmark">
          KeyHouse
        </Link>
      </header>

      <main id="main" className="shell__main">
        <div className="panel">
          {/* Small key above the title on narrow screens ... */}
          <Key cuts={cuts} className="key--inline" />
          <h1 className="panel__title">{title}</h1>
          {lede ? <p className="panel__lede">{lede}</p> : null}
          <div className="panel__body">{children}</div>
          {footer ? <div className="panel__footer">{footer}</div> : null}
        </div>
        {/* ... and a large one beside the form on wide screens. Decorative only. */}
        <div className="shell__art">
          <Key cuts={cuts} className="key--hero" />
        </div>
      </main>

      <footer className="shell__footer">
        <p>KeyHouse is a learning project. Don&apos;t use a password you use anywhere else.</p>
      </footer>
    </div>
  );
}
