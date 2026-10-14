/**
 * Reads the token from an email link like /verify-email#token=abc, then erases it from
 * the address bar and the history entry. The fragment (#...) is never sent to a server,
 * so it stays out of logs; erasing it also keeps it out of screenshots, shared screens
 * and the back button. Returns null when the link has no token.
 */
export function takeTokenFromFragment(): string | null {
  const token = new URLSearchParams(window.location.hash.slice(1)).get('token');
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }
  return token && token.length <= 100 ? token : null;
}
