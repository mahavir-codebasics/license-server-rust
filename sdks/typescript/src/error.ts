/** SDK error — maps the server's error envelope to a typed exception. */

/** Broad classification for `switch`-friendly handling. (Const object + type
 *  rather than `enum` so the source stays erasable-syntax-only — runs with
 *  plain Node type stripping, no transpile step.) */
export const LicenseErrorKind = {
  /** Network/transport failure — retrying may help. */
  Transport: "transport",
  /** 401/403 — token missing, invalid, or not permitted. */
  Auth: "auth",
  /** 404 — resource missing OR cross-tenant (the server never leaks which). */
  NotFound: "not_found",
  /** 409 — duplicate or illegal state transition. */
  Conflict: "conflict",
  /** 422 — licensing policy violated (max machines, max uses, …). */
  Policy: "policy",
  /** 429 — rate limited; back off and retry. */
  RateLimited: "rate_limited",
  /** Other 4xx — the request is malformed; do not blind-retry. */
  BadRequest: "bad_request",
  /** 5xx — server-side; retrying later may help. */
  Server: "server",
} as const;

export type LicenseErrorKind = (typeof LicenseErrorKind)[keyof typeof LicenseErrorKind];

export class LicenseError extends Error {
  readonly status: number;
  readonly code: string;
  readonly kind: LicenseErrorKind;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "LicenseError";
    this.status = status;
    this.code = code;
    this.kind = classify(status);
  }
}

function classify(status: number): LicenseErrorKind {
  if (status === 0) return LicenseErrorKind.Transport;
  if (status === 401 || status === 403) return LicenseErrorKind.Auth;
  if (status === 404) return LicenseErrorKind.NotFound;
  if (status === 409) return LicenseErrorKind.Conflict;
  if (status === 422) return LicenseErrorKind.Policy;
  if (status === 429) return LicenseErrorKind.RateLimited;
  if (status >= 400 && status < 500) return LicenseErrorKind.BadRequest;
  return LicenseErrorKind.Server;
}
