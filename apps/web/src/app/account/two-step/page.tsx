import type { Metadata } from 'next';
import Link from 'next/link';
import { AuthLayout } from '@/components/AuthLayout';
import { TwoStepSetup } from './TwoStepSetup';

export const metadata: Metadata = { title: 'Set up two-step verification' };

export default function TwoStepPage() {
  return (
    <AuthLayout
      title="Set up two-step verification"
      lede="After this, signing in needs your password and a code from an app on your phone."
      cuts={[3, 5, 2, 4, 1, 3]}
      footer={
        <p>
          <Link href="/account">Back to your account</Link>
        </p>
      }
    >
      <TwoStepSetup />
    </AuthLayout>
  );
}
