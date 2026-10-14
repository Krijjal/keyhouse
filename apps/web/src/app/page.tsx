import { redirect } from 'next/navigation';

// The account page checks the session itself and sends signed-out visitors to /login.
export default function Home(): never {
  redirect('/account');
}
