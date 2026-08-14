//! The HTTP client.

use crate::error::LicenseError;
use crate::models::*;
use crate::API_VERSION;
use reqwest::Client;

/// Default page size used by list methods (server clamps to 1–100).
const PAGE_SIZE: u32 = 100;

/// A configured client bound to one server and one bearer token.
///
/// Clone cheaply (`LicenseClient` is internally an `Arc`); use one instance
/// per token, per account scope.
#[derive(Clone)]
pub struct LicenseClient {
    http: Client,
    base: String,
    token: String,
    account_id: String,
}

impl LicenseClient {
    /// Build a client for an existing account + admin/product token.
    /// Pin the account with [`Self::with_account`] before tenant-scoped calls.
    pub fn new(base_url: &str, token: &str) -> Result<Self, LicenseError> {
        Ok(Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            base: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            account_id: String::new(),
        })
    }

    /// Pin the account used by tenant-scoped calls (required after [`Self::new`]).
    pub fn with_account(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = account_id.into();
        self
    }

    /// Bootstrap a brand-new organization. Returns a ready-to-use client
    /// (pinned to the new account, holding the admin token) **and** the
    /// bootstrap response. This is the only unauthenticated call in the SDK.
    pub async fn bootstrap(
        base_url: &str,
        slug: &str,
        name: &str,
    ) -> Result<(Self, CreateAccountResponse), LicenseError> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let resp: Envelope<CreateAccountResponse> = http
            .post(format!("{base_url}/v1/accounts"))
            .json(&CreateAccountBody { slug, name })
            .send()
            .await?
            .json()
            .await
            .map_err(LicenseError::from)?;

        let client = Self {
            http,
            base: base_url.trim_end_matches('/').to_string(),
            token: resp.data.admin_token.clone(),
            account_id: resp.data.account.id.clone(),
        };
        Ok((client, resp.data))
    }

    // ── internals ────────────────────────────────────────────────────────

    fn acct(&self) -> Result<&str, LicenseError> {
        if self.account_id.is_empty() {
            Err(LicenseError::new(
                0,
                "no_account",
                "client not pinned to an account; call .with_account(id)",
            ))
        } else {
            Ok(&self.account_id)
        }
    }

    fn url(&self, path: &str) -> Result<String, LicenseError> {
        Ok(format!(
            "{}/{}/accounts/{}{}",
            self.base,
            API_VERSION,
            self.acct()?,
            path
        ))
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, LicenseError> {
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if !(200..300).contains(&status) {
            // Decode the error envelope if present.
            let (code, message) = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| {
                    let e = &v["errors"][0];
                    let code = e["code"].as_str()?.to_string();
                    let msg = e["detail"]
                        .as_str()
                        .or_else(|| e["title"].as_str())?
                        .to_string();
                    Some((code, msg))
                })
                .unwrap_or_else(|| ("error".to_string(), text.chars().take(300).collect()));
            return Err(LicenseError::new(status, code, message));
        }
        serde_json::from_str(&text)
            .map_err(|e| LicenseError::new(0, "decode", format!("unexpected response body: {e}")))
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.bearer_auth(&self.token)
    }

    // ── Accounts ─────────────────────────────────────────────────────────

    /// Fetch this client's account.
    pub async fn account(&self) -> Result<Account, LicenseError> {
        let url = format!("{}/{}/accounts/{}", self.base, API_VERSION, self.acct()?);
        let resp: Envelope<Account> = self.send(self.http.get(url)).await?;
        Ok(resp.data)
    }

    // ── Products ─────────────────────────────────────────────────────────

    pub async fn create_product(&self, name: &str) -> Result<Product, LicenseError> {
        let resp: Envelope<Product> = self
            .send(
                self.auth(self.http.post(self.url("/products")?))
                    .json(&CreateProductBody { name }),
            )
            .await?;
        Ok(resp.data)
    }

    pub async fn products(&self) -> Result<Vec<Product>, LicenseError> {
        self.products_after(None).await
    }

    /// Next page, seeded by [`EnvelopePage::next_cursor`].
    pub async fn products_after(&self, cursor: Option<&str>) -> Result<Vec<Product>, LicenseError> {
        let mut rb = self
            .auth(self.http.get(self.url("/products")?))
            .query(&[("page[limit]", PAGE_SIZE.to_string())]);
        if let Some(c) = cursor {
            rb = rb.query(&[("page[after]", c.to_string())]);
        }
        let resp: EnvelopePage<Product> = self.send(rb).await?;
        Ok(resp.data)
    }

    // ── Policies ─────────────────────────────────────────────────────────

    pub async fn create_policy(
        &self,
        product_id: &str,
        name: &str,
        scheme: &str,
    ) -> Result<Policy, LicenseError> {
        let resp: Envelope<Policy> = self
            .send(
                self.auth(self.http.post(self.url("/policies")?))
                    .json(&CreatePolicyBody {
                        product_id,
                        name,
                        scheme,
                    }),
            )
            .await?;
        Ok(resp.data)
    }

    pub async fn policies(&self) -> Result<Vec<Policy>, LicenseError> {
        let resp: EnvelopePage<Policy> = self
            .send(
                self.auth(self.http.get(self.url("/policies")?))
                    .query(&[("page[limit]", PAGE_SIZE.to_string())]),
            )
            .await?;
        Ok(resp.data)
    }

    // ── Licenses ─────────────────────────────────────────────────────────

    /// Issue a license. The signed key is present **once** in `License::key`.
    pub async fn create_license(
        &self,
        product_id: &str,
        policy_id: &str,
    ) -> Result<License, LicenseError> {
        self.create_license_idempotent(product_id, policy_id, None)
            .await
    }

    /// [`Self::create_license`] with an `Idempotency-Key` — retries with the
    /// same key replay the original response instead of double-issuing
    /// (server requires Redis for this; without it both calls issue).
    pub async fn create_license_idempotent(
        &self,
        product_id: &str,
        policy_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<License, LicenseError> {
        let mut rb = self
            .auth(self.http.post(self.url("/licenses")?))
            .json(&CreateLicenseBody {
                product_id,
                policy_id,
            });
        if let Some(k) = idempotency_key {
            rb = rb.header("idempotency-key", k);
        }
        let resp: Envelope<License> = self.send(rb).await?;
        Ok(resp.data)
    }

    pub async fn licenses(&self) -> Result<Vec<License>, LicenseError> {
        let resp: EnvelopePage<License> = self
            .send(
                self.auth(self.http.get(self.url("/licenses")?))
                    .query(&[("page[limit]", PAGE_SIZE.to_string())]),
            )
            .await?;
        Ok(resp.data)
    }

    /// Validate a license by id (server-side).
    pub async fn validate_license(
        &self,
        license_id: &str,
    ) -> Result<ValidateResponse, LicenseError> {
        let url = self.url(&format!("/licenses/{license_id}/actions/validate"))?;
        let resp: Envelope<ValidateResponse> = self.send(self.auth(self.http.post(url))).await?;
        Ok(resp.data)
    }

    /// Validate by the raw signed key — the device-side call. The license id
    /// is resolved from the key's SHA-256 hash server-side; a key belonging
    /// to another account is rejected as not-found.
    pub async fn validate_key(&self, key: &str) -> Result<ValidateResponse, LicenseError> {
        let resp: Envelope<ValidateResponse> = self
            .send(
                self.auth(self.http.post(self.url("/licenses/actions/validate-key")?))
                    .json(&serde_json::json!({ "key": key })),
            )
            .await?;
        Ok(resp.data)
    }

    /// Check out an offline license-file certificate for a license.
    pub async fn check_out(&self, license_id: &str) -> Result<LicenseFile, LicenseError> {
        let url = self.url(&format!("/licenses/{license_id}/actions/check-out"))?;
        let resp: Envelope<LicenseFile> = self.send(self.auth(self.http.post(url))).await?;
        Ok(resp.data)
    }

    // ── Machines ─────────────────────────────────────────────────────────

    pub async fn machines(&self) -> Result<Vec<Machine>, LicenseError> {
        let resp: EnvelopePage<Machine> = self
            .send(
                self.auth(self.http.get(self.url("/machines")?))
                    .query(&[("page[limit]", PAGE_SIZE.to_string())]),
            )
            .await?;
        Ok(resp.data)
    }

    // ── Tokens ───────────────────────────────────────────────────────────

    /// Mint a token (`admin` requires an admin token). Plaintext returns once.
    pub async fn create_token(
        &self,
        kind: &str,
        name: Option<&str>,
    ) -> Result<CreateTokenResponse, LicenseError> {
        let resp: Envelope<CreateTokenResponse> = self
            .send(
                self.auth(self.http.post(self.url("/tokens")?))
                    .json(&CreateTokenBody { kind, name }),
            )
            .await?;
        Ok(resp.data)
    }

    pub async fn tokens(&self) -> Result<Vec<Token>, LicenseError> {
        let resp: EnvelopePage<Token> = self
            .send(
                self.auth(self.http.get(self.url("/tokens")?))
                    .query(&[("page[limit]", PAGE_SIZE.to_string())]),
            )
            .await?;
        Ok(resp.data)
    }

    // ── Webhooks ─────────────────────────────────────────────────────────

    /// Register a webhook endpoint. The HMAC signing secret returns ONCE.
    pub async fn create_webhook(
        &self,
        url: &str,
        event_types: &[String],
    ) -> Result<CreateWebhookResponse, LicenseError> {
        let resp: Envelope<CreateWebhookResponse> = self
            .send(
                self.auth(self.http.post(self.url("/webhooks/endpoints")?))
                    .json(&CreateWebhookBody { url, event_types }),
            )
            .await?;
        Ok(resp.data)
    }

    pub async fn webhooks(&self) -> Result<Vec<WebhookEndpoint>, LicenseError> {
        let resp: EnvelopePage<WebhookEndpoint> = self
            .send(
                self.auth(self.http.get(self.url("/webhooks/endpoints")?))
                    .query(&[("page[limit]", PAGE_SIZE.to_string())]),
            )
            .await?;
        Ok(resp.data)
    }

    // ── Events (audit log) ───────────────────────────────────────────────

    pub async fn events(&self) -> Result<Vec<Event>, LicenseError> {
        let resp: EnvelopePage<Event> = self
            .send(
                self.auth(self.http.get(self.url("/events")?))
                    .query(&[("page[limit]", PAGE_SIZE.to_string())]),
            )
            .await?;
        Ok(resp.data)
    }
}
