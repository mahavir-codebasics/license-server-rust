/**
 * Client wire tests: a real in-process HTTP server (node:http) serves the
 * server's documented envelopes; we assert the client sends the right
 * method/path/auth/headers and decodes responses correctly.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { LicenseClient, LicenseError, LicenseErrorKind } from "../src/index.ts";

interface Captured {
  method: string;
  path: string;
  auth?: string;
  body?: unknown;
  idempotencyKey?: string;
}

/** Serve canned routes; record what the client sent. */
function startMock() {
  const captured: Captured[] = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      // Route on the pathname only (ignore pagination query params).
      const pathname = new URL(req.url ?? "/", "http://mock").pathname;
      const cap: Captured = {
        method: req.method ?? "",
        path: req.url ?? "/",
        auth: req.headers.authorization,
        body: raw ? JSON.parse(raw) : undefined,
        idempotencyKey: req.headers["idempotency-key"] as string | undefined,
      };
      captured.push(cap);

      const ok = (data: unknown, meta?: unknown) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(meta ? { data, meta } : { data }));
      };

      if (pathname === "/v1/accounts" && req.method === "POST") {
        ok({ id: "acct-1", slug: "acme", name: "ACME", status: "active", protection_mode: "protected", created_at: "t", admin_token: "adm_secret" });
      } else if (pathname === "/v1/accounts/acct-1") {
        ok({ id: "acct-1", slug: "acme", name: "ACME", status: "active", protection_mode: "protected", created_at: "t" });
      } else if (pathname.endsWith("/products") && req.method === "POST") {
        ok({ id: "prod-1", account_id: "acct-1", name: "P", created_at: "t" });
      } else if (pathname.endsWith("/products") && req.method === "GET") {
        ok([{ id: "prod-1" }], { cursor: "c2", has_more: true });
      } else if (pathname.endsWith("/policies") && req.method === "POST") {
        ok({ id: "pol-1", scheme: "ED25519_SIGN", created_at: "t" });
      } else if (pathname.endsWith("/licenses/actions/validate-key")) {
        ok({ valid: true, state: "active", detail: null });
      } else if (pathname.includes("/licenses/nope/actions/validate")) {
        res.statusCode = 404;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ errors: [{ code: "not_found", title: "Not found", detail: "license not found", status: 404 }] }));
      } else if (pathname.includes("/actions/validate")) {
        ok({ valid: false, state: "expired", detail: "license has expired" });
      } else if (pathname.endsWith("/licenses") && req.method === "POST") {
        ok({ id: "lic-1", key: "SIGNED_KEY", state: "active", created_at: "t" });
      } else if (pathname.endsWith("/licenses") && req.method === "GET") {
        ok([{ id: "lic-1", state: "active", created_at: "t" }]);
      } else if (pathname.endsWith("/tokens") && req.method === "POST") {
        ok({ id: "tok-1", kind: "product", token: "prod_plain", created_at: "t" });
      } else {
        res.statusCode = 404;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ errors: [{ code: "not_found", title: "Not found", detail: "no route matches this request", status: 404 }] }));
      }
    });
  });
  return new Promise<{ url: string; captured: Captured[]; close: () => Promise<void> }>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const url = `http://127.0.0.1:${(addr as { port: number }).port}`;
      resolve({
        url,
        captured,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

test("bootstrap returns a pinned, authed client", async () => {
  const mock = await startMock();
  try {
    const { client, account } = await LicenseClient.bootstrap(mock.url, "acme", "ACME Inc.");
    assert.equal(account.admin_token, "adm_secret");
    assert.equal(account.id, "acct-1");

    const acct = await client.account();
    assert.equal(acct.slug, "acme");

    const last = mock.captured.at(-1)!;
    assert.equal(last.auth, "Bearer adm_secret");
    assert.equal(last.path, "/v1/accounts/acct-1");
  } finally {
    await mock.close();
  }
});

test("createLicense sends id/body and returns the once-only key", async () => {
  const mock = await startMock();
  try {
    const client = LicenseClient.new(mock.url, "adm_x", "acct-1");
    const lic = await client.createLicense("prod-1", "pol-1", "idem-42");
    assert.equal(lic.key, "SIGNED_KEY");
    assert.equal(lic.id, "lic-1");

    const cap = mock.captured.at(-1)!;
    assert.equal(cap.method, "POST");
    assert.equal(cap.path, "/v1/accounts/acct-1/licenses");
    assert.equal(cap.idempotencyKey, "idem-42");
    assert.deepEqual(cap.body, { product_id: "prod-1", policy_id: "pol-1" });
    assert.equal(cap.auth, "Bearer adm_x");
  } finally {
    await mock.close();
  }
});

test("validateKey posts the raw key to validate-key", async () => {
  const mock = await startMock();
  try {
    const client = LicenseClient.new(mock.url, "lic_x", "acct-1");
    const v = await client.validateKey("SIGNED_KEY");
    assert.equal(v.valid, true);
    const cap = mock.captured.at(-1)!;
    assert.equal(cap.path, "/v1/accounts/acct-1/licenses/actions/validate-key");
    assert.deepEqual(cap.body, { key: "SIGNED_KEY" });
  } finally {
    await mock.close();
  }
});

test("lists parse pagination meta and send cursor params", async () => {
  const mock = await startMock();
  try {
    const client = LicenseClient.new(mock.url, "adm_x", "acct-1");
    const page1 = await client.products();
    assert.equal(page1.items.length, 1);
    assert.equal(page1.nextCursor, "c2");

    await client.products("c2");
    const cap = mock.captured.at(-1)!;
    assert.match(cap.path, /page%5Blimit%5D=100/);
    assert.match(cap.path, /page%5Bafter%5D=c2/);
  } finally {
    await mock.close();
  }
});

test("errors are classified from the envelope", async () => {
  const mock = await startMock();
  try {
    const client = LicenseClient.new(mock.url, "adm_x", "acct-1");
    // Unknown license id -> mock serves the 404 envelope.
    await assert.rejects(client.validateLicense("nope"), (e: unknown) => {
      assert.ok(e instanceof LicenseError);
      assert.equal(e.status, 404);
      assert.equal(e.kind, LicenseErrorKind.NotFound);
      assert.equal(e.code, "not_found");
      return true;
    });
  } finally {
    await mock.close();
  }
});

test("transport failures classify as Transport", async () => {
  // Nothing listens on port 1.
  const client = LicenseClient.new("http://127.0.0.1:1", "adm_x", "acct-1", { timeoutMs: 1000 });
  await assert.rejects(client.account(), (e: unknown) => {
    assert.ok(e instanceof LicenseError);
    assert.equal(e.kind, LicenseErrorKind.Transport);
    assert.equal(e.status, 0);
    return true;
  });
});

test("tokens return the once-only plaintext", async () => {
  const mock = await startMock();
  try {
    const client = LicenseClient.new(mock.url, "adm_x", "acct-1");
    const minted = await client.createToken("product", "ci");
    assert.equal(minted.token, "prod_plain");
  } finally {
    await mock.close();
  }
});
