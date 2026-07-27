//! `license-grpc` — the gRPC hot-path transport.
//!
//! Mirrors the hottest machine-facing REST actions over gRPC for SDKs that
//! validate billions of times. Shares the domain + db + crypto layers with
//! the REST API — gRPC is just a second transport façade.
//!
//! Auth: `Authorization: Bearer <token>` metadata (same tokens as REST).

// tonic::Status is ~96 bytes; mapping DomainError -> Status at every repo call
// site triggers clippy::result_large_err. Allowing crate-wide since the size
// is dictated by tonic, not our design.
#![allow(clippy::result_large_err)]

pub mod service;

pub use service::{proto, LicenseService};
