import type { Metadata } from 'next';
import Link from 'next/link';
import { AuthLayout } from '@/components/AuthLayout';
import { LoginForm } from './LoginForm';

export const metadata: Metadata = { title: 'Sign in' };

export default function LoginPage() {
  return (
    <AuthLayout
      title="Sign in"
      cuts={[3, 1, 4, 1, 5, 2]}
      footer={
        <p>
          New here? <Link href="/register">Create an account</Link>
        </p>
      }
    >
      <LoginForm />
    </AuthLayout>
  );
}
