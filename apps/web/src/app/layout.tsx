import type { Metadata, Viewport } from 'next';
import { Instrument_Sans } from 'next/font/google';
import type { ReactNode } from 'react';
import './globals.css';
import { connection } from 'next/server';
// Downloaded at build time and served from our own origin: no request to Google at
// runtime, and nothing extra for the Content Security Policy to allow.
const instrument = Instrument_Sans({
  subsets: ['latin'],
  axes: ['wdth'],
  variable: '--font-instrument',
  display: 'swap',
});

export const metadata: Metadata = {
  title: { default: 'KeyHouse', template: '%s | KeyHouse' },
  description: 'Sign in to KeyHouse.',
  // Account pages have no business in search results.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f2f4f3' },
    { media: '(prefers-color-scheme: dark)', color: '#12171c' },
  ],
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  await connection();

  return (
    <html lang="en" className={instrument.variable}>
      <body>{children}</body>
    </html>
  );
}
