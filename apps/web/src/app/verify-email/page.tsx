import type { Metadata } from 'next';
import { AuthLayout } from '@/components/AuthLayout';
import { VerifyEmail } from './VerifyEmail';

export const metadata: Metadata = { title: 'Confirm your email' };

export default function VerifyEmailPage() {
  return (
    <AuthLayout title="Confirm your email" cuts={[4, 2, 5, 1, 3, 2]}>
      <VerifyEmail />
    </AuthLayout>
  );
}
