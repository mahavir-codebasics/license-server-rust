/**
 * @license-server/sdk — TypeScript client for license-server.
 *
 * Zero runtime dependencies (global fetch + WebCrypto). Node 18+, Bun, Deno,
 * browsers, edge runtimes.
 *
 * ```ts
 * import { LicenseClient } from "@license-server/sdk";
 *
 * // Bootstrap once (unauthenticated) — the admin token returns exactly once.
 * const { client, account } = await LicenseClient.bootstrap(
 *   "http://localhost:8080", "acme", "ACME Inc.",
 * );
 *
 * // Issue a license; the signed key is present only on this response.
 * const product = await client.createProduct("ACME Pro");
 * const policy  = await client.createPolicy(product.id, "monthly", "ED25519_SIGN");
 * const license = await client.createLicense(product.id, policy.id);
 * console.log(license.key); // persist me
 * ```
 */
export { LicenseClient } from "./client.ts";
export type { ClientOptions } from "./client.ts";

export { LicenseError, LicenseErrorKind } from "./error.ts";

export {
  parseSignatureHeader,
  verifyWebhook,
} from "./webhook.ts";
export type { WebhookSignature } from "./webhook.ts";

export type {
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
  PageMeta,
  Policy,
  Product,
  Token,
  ValidateResponse,
  WebhookEndpoint,
} from "./types.ts";

export { SIGNING_SCHEMES, TOKEN_KINDS } from "./types.ts";
export type { SigningScheme, TokenKind } from "./types.ts";
