/** Wire types — field names match the server JSON exactly. */

export interface PageMeta {
  cursor?: string | null;
  has_more?: boolean;
}

export interface Envelope<T> {
  data: T;
}

export interface EnvelopePage<T> {
  data: T[];
  meta?: PageMeta;
}

export interface Account {
  id: string;
  slug: string;
  name: string;
  status: string;
  protection_mode: string;
  created_at: string;
}

/** POST /v1/accounts — carries the bootstrap admin token ONCE. */
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
  max_uses?: number | null;
  renewable: boolean;
  protected: boolean;
  created_at: string;
}

export interface License {
  id: string;
  account_id: string;
  product_id: string;
  policy_id: string;
  /** The signed key — present ONLY on the creation response. */
  key?: string;
  state: string;
  license_type: string;
  uses: number;
  max_uses?: number | null;
  expiry?: string | null;
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

/** POST /tokens — carries the plaintext token ONCE. */
export interface CreateTokenResponse extends Token {
  token: string;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  status: string;
  created_at: string;
}

/** POST /webhooks/endpoints — carries the HMAC secret ONCE. */
export interface CreateWebhookResponse extends WebhookEndpoint {
  secret: string;
}

export interface AuditEvent {
  id: string;
  event_type: string;
  severity: string;
  resource_type?: string | null;
  resource_id?: string | null;
  created_at: string;
}

export interface ValidateResponse {
  valid: boolean;
  state: string;
  detail?: string | null;
}

export interface LicenseFile {
  id: string;
  algorithm: string;
}

/** Signing schemes accepted by createPolicy. */
export const SIGNING_SCHEMES = [
  "ED25519_SIGN",
  "ECDSA_P256_SHA256",
  "RSA_2048_PSS_SHA256",
  "RSA_2048_PKCS1V15_SHA256",
  "JWT_RS256",
  "JWT_EDDSA",
] as const;
export type SigningScheme = (typeof SIGNING_SCHEMES)[number];

/** Token kinds accepted by createToken. */
export const TOKEN_KINDS = ["admin", "product", "license", "user", "personal"] as const;
export type TokenKind = (typeof TOKEN_KINDS)[number];
