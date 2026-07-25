//! Value objects — small, immutable, equality-by-content types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Arbitrary user-supplied metadata attached to licenses, machines, etc.
///
/// Stored as JSONB. Filtering semantics are backend-specific (Postgres `@>`,
/// MySQL `JSON_CONTAINS`, SQLite `json_each`) and handled in the `db` crate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata(pub BTreeMap<String, serde_json::Value>);

impl Metadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) {
        self.0.insert(k.into(), v.into());
    }
}

impl From<BTreeMap<String, serde_json::Value>> for Metadata {
    fn from(m: BTreeMap<String, serde_json::Value>) -> Self {
        Self(m)
    }
}

/// A natural key — a short string a client uses to address a resource, e.g.
/// a license key or a machine fingerprint. We keep it as a newtype so it never
/// gets confused with an internal UUID id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NaturalKey(pub String);

impl NaturalKey {
    #[inline]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NaturalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
