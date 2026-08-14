/**
 * The HTTP client. Zero runtime dependencies — uses the global `fetch`
 * (Node 18+, Bun, Deno, browsers, edge runtimes).
 */
import type {
  Account,
  AuditEvent,
  CreateAccountResponse,
  CreateTokenResponse,
  CreateWebhookResponse,
  Envelope,
  EnvelopePage,
  License,
  LicenseFile,
  Machine,
  Policy,
  Product,
  Token,
  ValidateResponse,
  WebhookEndpoint,
} from "./types.ts";
import { LicenseError } from "./error.ts";

const API_VERSION = "v1";
const PAGE_SIZE = 100;

export interface ClientOptions {
  /** Request timeout in ms (default 30_000). */
  timeoutMs?: number;
  /** Extra fetch implementation (tests / edge runtimes). */
  fetch?: typeof fetch;
}

export class LicenseClient {
  private base: string;
  private token: string;
  private accountId: string;
  private fetchImpl: typeof fetch;
  private timeoutMs: number;

  private constructor(base: string, token: string, accountId: string, opts: ClientOptions = {}) {
    this.base = base.replace(/\/+$/, "");
    this.token = token;
    this.accountId = accountId;
    this.fetchImpl = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /** Attach to an existing account with an admin/product token. */
  static new(baseUrl: string, token: string, accountId: string, opts?: ClientOptions): LicenseClient {
    return new LicenseClient(baseUrl, token, accountId, opts);
  }

  /**
   * Bootstrap a brand-new organization (the only unauthenticated call).
   * Returns a ready-to-use client holding the new admin token.
   */
  static async bootstrap(
    baseUrl: string,
    slug: string,
    name: string,
    opts?: ClientOptions,
  ): Promise<{ client: LicenseClient; account: CreateAccountResponse }> {
    const http = opts?.fetch ?? fetch;
    const res = await http(`${baseUrl.replace(/\/+$/, "")}/v1/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ slug, name }),
      signal: AbortSignal.timeout(opts?.timeoutMs ?? 30_000),
    });
    const body = (await res.json()) as Envelope<CreateAccountResponse>;
    if (!res.ok) {
      throw new LicenseError(res.status, body?.data?.slug ? "error" : "error", `bootstrap failed (${res.status})`);
    }
    return {
      client: new LicenseClient(baseUrl, body.data.admin_token, body.data.id, opts),
      account: body.data,
    };
  }

  // ── accounts ──────────────────────────────────────────────────────────

  async account(): Promise<Account> {
    const body = await this.request<Envelope<Account>>("GET", `/accounts/${this.accountId}`);
    return body.data;
  }

  // ── products ──────────────────────────────────────────────────────────

  async createProduct(name: string): Promise<Product> {
    const body = await this.post<Envelope<Product>>(`/accounts/${this.accountId}/products`, { name });
    return body.data;
  }

  async products(cursor?: string): Promise<{ items: Product[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<Product>>(`/accounts/${this.accountId}/products`, cursor);
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  // ── policies ──────────────────────────────────────────────────────────

  async createPolicy(productId: string, name: string, scheme: string): Promise<Policy> {
    const body = await this.post<Envelope<Policy>>(`/accounts/${this.accountId}/policies`, {
      product_id: productId,
      name,
      scheme,
    });
    return body.data;
  }

  async policies(cursor?: string): Promise<{ items: Policy[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<Policy>>(`/accounts/${this.accountId}/policies`, cursor);
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  // ── licenses ──────────────────────────────────────────────────────────

  /**
   * Issue a license. The signed key is present **once** on the returned
   * object — persist it. Pass `idempotencyKey` for safe retries on flaky
   * networks (server requires Redis for replay).
   */
  async createLicense(
    productId: string,
    policyId: string,
    idempotencyKey?: string,
  ): Promise<License> {
    const body = await this.post<Envelope<License>>(
      `/accounts/${this.accountId}/licenses`,
      { product_id: productId, policy_id: policyId },
      idempotencyKey ? { "idempotency-key": idempotencyKey } : undefined,
    );
    return body.data;
  }

  async licenses(cursor?: string): Promise<{ items: License[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<License>>(`/accounts/${this.accountId}/licenses`, cursor);
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  /** Validate a license by id. */
  async validateLicense(licenseId: string): Promise<ValidateResponse> {
    const body = await this.post<Envelope<ValidateResponse>>(
      `/accounts/${this.accountId}/licenses/${licenseId}/actions/validate`,
    );
    return body.data;
  }

  /**
   * Validate by the raw signed key — the device-side call. The license id is
   * resolved from the key's SHA-256 hash server-side; a key belonging to
   * another account is rejected as not-found.
   */
  async validateKey(key: string): Promise<ValidateResponse> {
    const body = await this.post<Envelope<ValidateResponse>>(
      `/accounts/${this.accountId}/licenses/actions/validate-key`,
      { key },
    );
    return body.data;
  }

  /** Check out an offline license-file certificate. */
  async checkOut(licenseId: string): Promise<LicenseFile> {
    const body = await this.post<Envelope<LicenseFile>>(
      `/accounts/${this.accountId}/licenses/${licenseId}/actions/check-out`,
    );
    return body.data;
  }

  // ── machines ──────────────────────────────────────────────────────────

  async machines(cursor?: string): Promise<{ items: Machine[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<Machine>>(`/accounts/${this.accountId}/machines`, cursor);
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  // ── tokens ────────────────────────────────────────────────────────────

  /** Mint a token. The plaintext returns ONCE. */
  async createToken(kind: string, name?: string): Promise<CreateTokenResponse> {
    const body = await this.post<Envelope<CreateTokenResponse>>(
      `/accounts/${this.accountId}/tokens`,
      { kind, name },
    );
    return body.data;
  }

  async tokens(cursor?: string): Promise<{ items: Token[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<Token>>(`/accounts/${this.accountId}/tokens`, cursor);
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  // ── webhooks ──────────────────────────────────────────────────────────

  /** Register a webhook endpoint. The HMAC secret returns ONCE. */
  async createWebhook(url: string, eventTypes: string[] = []): Promise<CreateWebhookResponse> {
    const body = await this.post<Envelope<CreateWebhookResponse>>(
      `/accounts/${this.accountId}/webhooks/endpoints`,
      { url, event_types: eventTypes },
    );
    return body.data;
  }

  async webhooks(cursor?: string): Promise<{ items: WebhookEndpoint[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<WebhookEndpoint>>(
      `/accounts/${this.accountId}/webhooks/endpoints`,
      cursor,
    );
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  // ── audit log ─────────────────────────────────────────────────────────

  async events(cursor?: string): Promise<{ items: AuditEvent[]; nextCursor?: string }> {
    const body = await this.get<EnvelopePage<AuditEvent>>(`/accounts/${this.accountId}/events`, cursor);
    return { items: body.data, nextCursor: body.meta?.cursor ?? undefined };
  }

  // ── internals ─────────────────────────────────────────────────────────

  /** Pagination query params — always URL-encoded via URLSearchParams. */
  private pageParams(cursor?: string): URLSearchParams {
    const params = new URLSearchParams();
    params.set("page[limit]", String(PAGE_SIZE));
    if (cursor) params.set("page[after]", cursor);
    return params;
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
    params?: URLSearchParams,
  ): Promise<T> {
    // Build the URL from structured parts only — never by hand-concatenated
    // strings — so every component is correctly encoded.
    const url = new URL(`${this.base}/${API_VERSION}${path}`);
    if (params) url.search = params.toString();

    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers: {
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
          authorization: `Bearer ${this.token}`,
          ...extraHeaders,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new LicenseError(0, "transport", e instanceof Error ? e.message : String(e));
    }

    const text = await res.text();
    if (!res.ok) {
      let code = "error";
      let message = text.slice(0, 300);
      try {
        const parsed = JSON.parse(text);
        const err = parsed?.errors?.[0];
        if (err) {
          code = err.code ?? code;
          message = err.detail ?? err.title ?? message;
        }
      } catch {
        /* non-JSON body — keep the raw text */
      }
      throw new LicenseError(res.status, code, message);
    }
    try {
      return JSON.parse(text) as T;
    } catch (e) {
      throw new LicenseError(0, "decode", `unexpected response body: ${e instanceof Error ? e.message : e}`);
    }
  }

  private get<T>(path: string, cursor?: string): Promise<T> {
    return this.request<T>("GET", path, undefined, undefined, this.pageParams(cursor));
  }

  private post<T>(path: string, body?: unknown, extraHeaders?: Record<string, string>): Promise<T> {
    return this.request<T>("POST", path, body ?? {}, extraHeaders);
  }
}
