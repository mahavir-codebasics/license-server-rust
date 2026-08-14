//! `license-sdk` — the official Rust client for [license-server].
//!
//! A thin, fully-typed wrapper over the REST API. Self-contained: the models
//! live here (no dependency on server crates), so the SDK can be published
//! and used from any client — CLIs, CI, device agents, backend services.
//!
//! # Quick start
//!
//! ```no_run
//! use license_sdk::{LicenseClient, LicenseError};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), LicenseError> {
//! // Bootstrap a new org (one-time, unauthenticated)…
//! let base = "http://localhost:8080";
//! let (client, org) = LicenseClient::bootstrap(base, "acme", "ACME Inc.").await?;
//!
//! // …or attach to an existing account with an admin token:
//! // let client = LicenseClient::new(base, "adm_…")?.with_account(org.account.id);
//!
//! // Model the product + policy, then issue a license.
//! let product = client.create_product("ACME Pro").await?;
//! let policy = client.create_policy(&product.id, "monthly", "ED25519_SIGN").await?;
//! let license = client.create_license(&product.id, &policy.id).await?;
//!
//! // The signed key is returned exactly once — persist it.
//! let key = license.key.expect("key present on creation");
//!
//! // Validate by id, or by the raw key (the device-side call).
//! assert!(client.validate_license(&license.id).await?.valid);
//! assert!(client.validate_key(&key).await?.valid);
//! # let _ = org;
//! # Ok(())
//! # }
//! ```
//!
//! [license-server]: https://github.com/your-org/license-server-rust

mod client;
mod error;
mod models;

pub use client::LicenseClient;
pub use error::{LicenseError, LicenseErrorKind};
pub use models::{
    Account, CreateAccountResponse, CreateTokenResponse, CreateWebhookResponse, Envelope,
    EnvelopePage, Event, License, LicenseFile, Machine, Policy, Product, Token, ValidateResponse,
    WebhookEndpoint,
};

/// Current wire version prefix used by the client.
pub const API_VERSION: &str = "v1";
