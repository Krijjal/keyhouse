import type { Metadata } from 'next';
import { AuthLayout } from '@/components/AuthLayout';
import { ResetForm } from './ResetForm';

export const metadata: Metadata = { title: 'Choose a new password' };

export default function ResetPasswordPage() {
  return (
    <AuthLayout
      title="Choose a new password"
      lede="Saving it signs you out on every device, so only you can get back in."
      cuts={[5, 3, 1, 4, 2, 4]}
    >
      <ResetForm />
    </AuthLayout>
  );
}
