import type { Metadata } from 'next';
import Link from 'next/link';
import { AuthLayout } from '@/components/AuthLayout';
import { ForgotForm } from './ForgotForm';

export const metadata: Metadata = { title: 'Reset your password' };

export default function ForgotPasswordPage() {
  return (
    <AuthLayout
      title="Reset your password"
      lede="Enter the email you signed up with. We'll send a link to choose a new password."
      cuts={[1, 5, 2, 4]}
      footer={
        <p>
          Remembered it? <Link href="/login">Sign in</Link>
        </p>
      }
    >
      <ForgotForm />
    </AuthLayout>
  );
}
