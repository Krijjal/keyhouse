import type { Request } from 'express';
import type { z } from 'zod';
import { HttpError } from './errors.js';

/**
 * Rule 9: every request body is validated with zod.
 * On failure, responds 400 with field names and messages only. The submitted
 * values are never echoed back (they may be passwords or tokens).
 */
export function parseBody<S extends z.ZodType>(schema: S, req: Request): z.output<S> {
  const result = schema.safeParse(req.body);
  if (result.success) return result.data;

  const fields: Record<string, string> = {};
  for (const issue of result.error.issues) {
    const key = issue.path.join('.') || '_';
    fields[key] ??= issue.message;
  }
  throw new HttpError(400, 'invalid_request', { fields });
}
