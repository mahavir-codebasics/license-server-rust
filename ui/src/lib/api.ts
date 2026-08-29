// API client — thin fetch wrapper over the license-server REST API.
// Token is stored in localStorage (set at login). All tenant-scoped calls
// go to /v1/accounts/{accountId}/...

// Empty base = same-origin relative ("/v1/..."), which works behind the
// reverse proxy that fronts both the UI and the API under one origin.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "";

const TOKEN_KEY = "license-server.token";
const ACCOUNT_KEY = "license-server.account";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(t: string | null) {
  if (typeof window === "undefined") return;
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

export function getAccountId(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCOUNT_KEY);
}

export function setAccountId(id: string | null) {
  if (typeof window === "undefined") return;
  if (id) localStorage.setItem(ACCOUNT_KEY, id);
  else localStorage.removeItem(ACCOUNT_KEY);
}

const USER_KEY = "license-server.user";

export function getUser(): User | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  return raw ? (JSON.parse(raw) as User) : null;
}

export function setUser(u: User | null) {
  if (typeof window === "undefined") return;
  if (u) localStorage.setItem(USER_KEY, JSON.stringify(u));
  else localStorage.removeItem(USER_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Core fetch wrapper. Throws ApiError on non-2xx. */
export async function apiFetch<T>(
  path: string,
  opts: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  if (token) headers["authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;

  if (!res.ok) {
    const detail =
      body?.errors?.[0]?.detail || body?.errors?.[0]?.title || res.statusText;
    throw new ApiError(res.status, detail);
  }
  return body as T;
}

// ── Types ──────────────────────────────────────────────────────────────

export interface Envelope<T> {
  data: T;
  meta?: { cursor?: string | null; has_more?: boolean };
}
export interface EnvelopePage<T> {
  data: T[];
  meta: { cursor: string | null; has_more: boolean };
}

export interface User {
  id: string;
  email: string;
  full_name?: string | null;
  status: string;
  created_at: string;
}

/** Response of /v1/auth/signup and /v1/auth/login. */
export interface AuthSession {
  user: User;
  account: Account;
  token: string; // plaintext personal token, shown once
}

export interface Account {
  id: string;
  slug: string;
  name: string;
  status: string;
  protection_mode: string;
  created_at: string;
}
export interface CreateAccountResponse extends Account {
  admin_token: string;
}

export interface Product {
  id: string;
  account_id: string;
  name: string;
  url?: string | null;
  created_at: string;
}
export interface Policy {
  id: string;
  account_id: string;
  product_id: string;
  name: string;
  scheme: string;
  max_machines?: number | null;
  duration_secs?: number | null;
  protected: boolean;
  renewable: boolean;
  created_at: string;
}
export interface License {
  id: string;
  account_id: string;
  product_id: string;
  policy_id: string;
  state: string;
  license_type: string;
  uses: number;
  max_uses?: number | null;
  expiry?: string | null;
  key?: string; // only on create
  created_at: string;
}
export interface Machine {
  id: string;
  account_id: string;
  license_id: string;
  fingerprint: string;
  name?: string | null;
  platform?: string | null;
  state: string;
  next_heartbeat?: string | null;
  created_at: string;
}
export interface Token {
  id: string;
  account_id: string;
  kind: string;
  name?: string | null;
  expiry?: string | null;
  last_used_at?: string | null;
  created_at: string;
}
export interface CreateTokenResponse extends Token {
  token: string; // plaintext, only on create
}
export interface EventLog {
  id: string;
  event_type: string;
  severity: string;
  resource_type?: string | null;
  resource_id?: string | null;
  created_at: string;
}
export interface WebhookEndpoint {
  id: string;
  url: string;
  status: string;
  created_at: string;
}
export interface CreateWebhookResponse extends WebhookEndpoint {
  secret: string;
}
export interface ValidateResponse {
  valid: boolean;
  state: string;
  detail?: string | null;
}

// ── API methods ────────────────────────────────────────────────────────

export const api = {
  // — Email/password auth (self-service) —
  signup: (email: string, password: string, fullName?: string, orgName?: string) =>
    apiFetch<Envelope<AuthSession>>("/v1/auth/signup", {
      method: "POST",
      body: JSON.stringify({ email, password, full_name: fullName, org_name: orgName }),
    }),
  login: (email: string, password: string) =>
    apiFetch<Envelope<AuthSession>>("/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  // Bootstrap a new org (no auth). Returns the first admin token.
  createAccount: (slug: string, name: string) =>
    apiFetch<Envelope<CreateAccountResponse>>("/v1/accounts", {
      method: "POST",
      body: JSON.stringify({ slug, name }),
    }),

  getAccount: (id: string) =>
    apiFetch<Envelope<Account>>(`/v1/accounts/${id}`),

  listProducts: (aid: string) =>
    apiFetch<EnvelopePage<Product>>(`/v1/accounts/${aid}/products`),
  createProduct: (aid: string, name: string) =>
    apiFetch<Envelope<Product>>(`/v1/accounts/${aid}/products`, {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  listPolicies: (aid: string) =>
    apiFetch<EnvelopePage<Policy>>(`/v1/accounts/${aid}/policies`),
  createPolicy: (aid: string, productId: string, name: string, scheme: string) =>
    apiFetch<Envelope<Policy>>(`/v1/accounts/${aid}/policies`, {
      method: "POST",
      body: JSON.stringify({ product_id: productId, name, scheme }),
    }),

  listLicenses: (aid: string) =>
    apiFetch<EnvelopePage<License>>(`/v1/accounts/${aid}/licenses`),
  createLicense: (aid: string, productId: string, policyId: string) =>
    apiFetch<Envelope<License>>(`/v1/accounts/${aid}/licenses`, {
      method: "POST",
      body: JSON.stringify({ product_id: productId, policy_id: policyId }),
    }),
  validateLicense: (aid: string, id: string) =>
    apiFetch<Envelope<ValidateResponse>>(
      `/v1/accounts/${aid}/licenses/${id}/actions/validate`,
      { method: "POST" },
    ),

  listMachines: (aid: string) =>
    apiFetch<EnvelopePage<Machine>>(`/v1/accounts/${aid}/machines`),

  listTokens: (aid: string) =>
    apiFetch<EnvelopePage<Token>>(`/v1/accounts/${aid}/tokens`),
  createToken: (aid: string, kind: string, name: string) =>
    apiFetch<Envelope<CreateTokenResponse>>(`/v1/accounts/${aid}/tokens`, {
      method: "POST",
      body: JSON.stringify({ kind, name }),
    }),

  listEvents: (aid: string) =>
    apiFetch<EnvelopePage<EventLog>>(`/v1/accounts/${aid}/events`),

  listWebhooks: (aid: string) =>
    apiFetch<EnvelopePage<WebhookEndpoint>>(
      `/v1/accounts/${aid}/webhooks/endpoints`,
    ),
  createWebhook: (aid: string, url: string, eventTypes: string[] = []) =>
    apiFetch<Envelope<CreateWebhookResponse>>(
      `/v1/accounts/${aid}/webhooks/endpoints`,
      {
        method: "POST",
        body: JSON.stringify({ url, event_types: eventTypes }),
      },
    ),
};
