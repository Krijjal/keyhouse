import { IDP_URL } from './config';

/**
 * An error answer from the KeyHouse API, or a failure to reach it at all.
 * `code` is the API's error code ("invalid_credentials", "too_many_attempts" ...), or
 * "network_error" when the request never got an answer.
 */
export class ApiError extends Error {
  override name = 'ApiError';

  constructor(
    readonly status: number,
    readonly code: string,
    /** Per-field problems from a 400 invalid_request, e.g. { password: "..." }. */
    readonly fields: Record<string, string> = {},
    /** Seconds from the Retry-After header (429 / 503), if the API sent one. */
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(code);
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'DELETE';
  body?: unknown;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    typeof value === 'object' &&
    value !== null &&
    Object.values(value).every((v) => typeof v === 'string')
  );
}

/**
 * Calls the API. Always sends the session cookie (credentials: 'include'): the API is on
 * another origin (port 4000), and without this the browser would leave the cookie out.
 * Resolves with the JSON body (or undefined for 204), and throws ApiError otherwise.
 */
export async function api<T>(path: string, { method = 'GET', body }: RequestOptions = {}) {
  let res: Response;
  try {
    res = await fetch(`${IDP_URL}${path}`, {
      method,
      credentials: 'include',
      cache: 'no-store',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    // Offline, API not running, or blocked by CORS: the browser doesn't say which.
    throw new ApiError(0, 'network_error');
  }

  if (res.status === 204) return undefined as T;
  const data: unknown = await res.json().catch(() => null);

  if (!res.ok) {
    const obj = (typeof data === 'object' && data !== null ? data : {}) as Record<string, unknown>;
    const code = typeof obj.error === 'string' ? obj.error : 'unknown';
    const fields = isStringRecord(obj.fields) ? obj.fields : {};
    const retryAfter = Number(res.headers.get('retry-after'));
    throw new ApiError(
      res.status,
      code,
      fields,
      Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null,
    );
  }
  return data as T;
}

// ─── The endpoints, typed ─────────────────────────────────────────────────────

export interface Me {
  id: string;
  email: string;
  emailVerifiedAt: string | null;
  createdAt: string;
}

export interface SessionInfo {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  ip: string | null;
  userAgent: string | null;
  current: boolean;
}

export interface MfaStatus {
  enabled: boolean;
  enabledAt: string | null;
  recoveryCodesLeft: number;
}

export interface MfaSetup {
  /** Base32, for typing into the app by hand. Shown once, never stored by the page. */
  secret: string;
  otpauthUri: string;
  /** PNG data: URL of the QR code. */
  qrDataUrl: string;
}

export const mfa = {
  status: () => api<MfaStatus>('/auth/mfa'),
  setup: () => api<MfaSetup>('/auth/mfa/setup', { method: 'POST' }),
  enable: async (code: string) =>
    (await api<{ recoveryCodes: string[] }>('/auth/mfa/enable', { method: 'POST', body: { code } }))
      .recoveryCodes,
  /** Both need the password AND a current code (or a recovery code): a session isn't enough. */
  disable: (proof: MfaProof) =>
    api<undefined>('/auth/mfa/disable', { method: 'POST', body: proof }),
  replaceRecoveryCodes: async (proof: MfaProof) =>
    (
      await api<{ recoveryCodes: string[] }>('/auth/mfa/recovery-codes', {
        method: 'POST',
        body: proof,
      })
    ).recoveryCodes,
};

export type MfaProof = { password: string } & ({ code: string } | { recoveryCode: string });

export const auth = {
  register: (email: string, password: string) =>
    api<unknown>('/auth/register', { method: 'POST', body: { email, password } }),
  verifyEmail: (token: string) =>
    api<unknown>('/auth/verify-email', { method: 'POST', body: { token } }),
  /** "mfa_required": the password was right; finish with loginMfa. */
  login: (email: string, password: string) =>
    api<{ status: 'logged_in' | 'mfa_required' }>('/auth/login', {
      method: 'POST',
      body: { email, password },
    }),
  /** The second step. The ticket travels in an HttpOnly cookie, never through this page. */
  loginMfa: (proof: { code: string } | { recoveryCode: string }) =>
    api<{ status: 'logged_in' }>('/auth/login/mfa', { method: 'POST', body: proof }),
  forgotPassword: (email: string) =>
    api<unknown>('/auth/forgot-password', { method: 'POST', body: { email } }),
  resetPassword: (token: string, password: string) =>
    api<unknown>('/auth/reset-password', { method: 'POST', body: { token, password } }),
  me: async () => (await api<{ user: Me }>('/auth/me')).user,
  sessions: async () => (await api<{ sessions: SessionInfo[] }>('/auth/sessions')).sessions,
  revokeSession: (id: string) =>
    api<undefined>(`/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  logout: () => api<undefined>('/auth/logout', { method: 'POST' }),
  logoutAll: () => api<undefined>('/auth/logout-all', { method: 'POST' }),
};
