/**
 * End-to-end example: bootstrap an org, model a product/policy, issue a
 * license, then validate it by raw key — the full licensing round trip.
 *
 * Run against a local server:
 *   cargo run -p license-server            # terminal 1
 *   node --experimental-strip-types examples/issue-and-validate.ts  # terminal 2
 */
import { LicenseClient } from "../src/index.ts";

const BASE = process.env.LICENSE_BASE_URL ?? "http://localhost:8080";

async function main() {
  // 1. Bootstrap (skip if you already have an account + admin token).
  const { client, account } = await LicenseClient.bootstrap(BASE, "demo", "Demo Co");
  console.log("org:", account.id);

  // 2. Model the product + policy.
  const product = await client.createProduct("Demo App");
  const policy = await client.createPolicy(product.id, "node-locked", "ED25519_SIGN");
  console.log("policy:", policy.id, `(${policy.scheme})`);

  // 3. Issue a license — the signed key appears exactly once.
  const license = await client.createLicense(product.id, policy.id, crypto.randomUUID());
  const key = license.key;
  if (!key) throw new Error("signed key missing on creation response");
  console.log("license:", license.id);
  console.log("signed key (persist me):", key.slice(0, 32) + "…");

  // 4. Validate by id, and by the raw key (the device-side call).
  console.log("validate by id: ", await client.validateLicense(license.id));
  console.log("validate by key:", await client.validateKey(key));

  // 5. Mint a product token scoped to license issuance (for your backend).
  const machineToken = await client.createToken("product", "demo-backend");
  console.log("product token (persist me):", machineToken.token.slice(0, 16) + "…");

  // 6. Register a webhook for lifecycle events (secret shown once).
  const hook = await client.createWebhook("https://example.com/hooks/license", [
    "license.created",
  ]);
  console.log("webhook secret (persist me):", hook.secret.slice(0, 12) + "…");

  console.log("\nfull round trip OK");
}

main().catch((e) => {
  console.error("failed:", e);
  process.exit(1);
});
