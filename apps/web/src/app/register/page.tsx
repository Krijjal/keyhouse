import type { Metadata } from 'next';
import Link from 'next/link';
import { AuthLayout } from '@/components/AuthLayout';
import { RegisterForm } from './RegisterForm';

export const metadata: Metadata = { title: 'Create an account' };

export default function RegisterPage() {
  return (
    <AuthLayout
      title="Create an account"
      cuts={[2, 4, 1, 5, 3]}
      footer={
        <p>
          Already have an account? <Link href="/login">Sign in</Link>
        </p>
      }
    >
      <RegisterForm />
    </AuthLayout>
  );
}
