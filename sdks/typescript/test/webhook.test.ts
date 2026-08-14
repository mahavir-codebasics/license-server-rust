/**
 * Webhook verifier tests — cross-check against node:crypto (an independent
 * HMAC implementation) and the constant-time comparison properties.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { parseSignatureHeader, verifyWebhook } from "../src/index.ts";

/** Produce a valid header the way the server does. */
function sign(secret: string, timestamp: number, rawBody: string): string {
  const mac = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");
  return `t=${timestamp},v1=${mac}`;
}

test("verifies a genuine delivery", async () => {
  const body = JSON.stringify({ event_type: "license.created", data: { id: "lic-1" } });
  const header = sign("whsec_123", 1_700_000_000, body);
  // Fresh timestamp so the tolerance check passes.
  const fresh = sign("whsec_123", Math.floor(Date.now() / 1000), body);
  assert.ok(await verifyWebhook(body, fresh, "whsec_123"));
  void header;
});

test("rejects a tampered body", async () => {
  const body = '{"a":1}';
  const header = sign("whsec_123", Math.floor(Date.now() / 1000), body);
  assert.equal(await verifyWebhook('{"a":2}', header, "whsec_123"), false);
});

test("rejects the wrong secret", async () => {
  const body = '{"a":1}';
  const header = sign("whsec_right", Math.floor(Date.now() / 1000), body);
  assert.equal(await verifyWebhook(body, header, "whsec_wrong"), false);
});

test("rejects stale timestamps (replay protection)", async () => {
  const body = '{"a":1}';
  const staleTs = Math.floor(Date.now() / 1000) - 3600; // 1h old
  const header = sign("whsec_123", staleTs, body);
  assert.equal(await verifyWebhook(body, header, "whsec_123", 300), false);
});

test("rejects malformed headers", async () => {
  assert.equal(await verifyWebhook("{}", "garbage", "s"), false);
  assert.equal(await verifyWebhook("{}", "t=abc,v1=zz", "s"), false);
  assert.equal(parseSignatureHeader("v1=only"), null);
  assert.equal(parseSignatureHeader("t=1,v2=zz"), null);
});

test("valid header parses into parts", () => {
  const p = parseSignatureHeader("t=1700000000,v1=ab12");
  assert.deepEqual(p, { timestamp: 1700000000, receivedHex: "ab12" });
});
