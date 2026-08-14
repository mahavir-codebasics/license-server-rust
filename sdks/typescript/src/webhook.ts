/**
 * Webhook signature verification (receiver side).
 *
 * The server signs deliveries as `HMAC-SHA256(secret, "<timestamp>.<raw body>")`
 * and sends `X-License-Signature: t=<ts>,v1=<hex>`. Always verify against the
 * RAW request body — re-serialized JSON will not match.
 */

/** Parsed signature header parts. */
export interface WebhookSignature {
  timestamp: number;
  receivedHex: string;
}

/** Parse an `X-License-Signature` header (`t=…,v1=…`). */
export function parseSignatureHeader(header: string): WebhookSignature | null {
  const parts = header.split(",").map((p) => p.trim());
  let timestamp: number | null = null;
  let receivedHex: string | null = null;
  for (const part of parts) {
    if (part.startsWith("t=")) timestamp = Number(part.slice(2));
    else if (part.startsWith("v1=")) receivedHex = part.slice(3);
  }
  if (timestamp === null || !Number.isFinite(timestamp) || !receivedHex) return null;
  return { timestamp, receivedHex };
}

/**
 * Verify a webhook delivery. Uses WebCrypto (available in Node 18+, Bun,
 * Deno, browsers, edge runtimes) and a constant-time comparison.
 *
 * @param rawBody   the raw request body string (never re-serialized JSON)
 * @param header    the `X-License-Signature` header value
 * @param secret    the endpoint's signing secret (from create-webhook, shown once)
 * @param tolerance reject timestamps older than this many seconds (default 300)
 */
export async function verifyWebhook(
  rawBody: string,
  header: string,
  secret: string,
  toleranceSec = 300,
): Promise<boolean> {
  const sig = parseSignatureHeader(header);
  if (!sig) return false;

  // Replay protection.
  const nowSec = Date.now() / 1000;
  if (Math.abs(nowSec - sig.timestamp) > toleranceSec) return false;

  // Recompute HMAC-SHA256("<ts>.<raw body>").
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${sig.timestamp}.${rawBody}`));
  const expected = bufferToHex(mac);

  return timingSafeEqualHex(expected, sig.receivedHex);
}

function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Constant-time comparison of two hex digests (length check first). */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
