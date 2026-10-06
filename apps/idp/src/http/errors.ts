/**
 * An error with a safe, client-facing code. The error handler turns it into
 * `{ error: code, ...details }` with the given status. Never put secrets or
 * internal messages in `code` or `details`.
 */
export class HttpError extends Error {
  override name = 'HttpError';

  constructor(
    readonly status: number,
    readonly code: string,
    readonly details?: Record<string, unknown>,
    readonly headers?: Record<string, string>,
  ) {
    super(code);
  }
}
