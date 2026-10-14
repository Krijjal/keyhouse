import type { Metadata } from 'next';
import { AuthLayout } from '@/components/AuthLayout';
import { Account } from './Account';

export const metadata: Metadata = { title: 'Your account' };

export default function AccountPage() {
  return (
    <AuthLayout title="Your account" cuts={[2, 2, 5, 3, 1, 4]}>
      <Account />
    </AuthLayout>
  );
}
