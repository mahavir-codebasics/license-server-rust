//! Declares a typed-id newtype wrapping [`uuid::Uuid`].
//!
//! Using newtypes for every entity's primary key means the compiler rejects
//! cross-entity mix-ups (passing a `LicenseId` where a `TokenId` is expected
//! is a hard type error, not a runtime bug).
//!
//! All IDs are UUIDv7 — time-ordered, so B-tree insertions are append-mostly
//! which keeps index fragmentation low at millions of rows.
macro_rules! declare_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name(pub uuid::Uuid);

        impl $name {
            /// Generate a new time-ordered UUIDv7 id.
            #[inline]
            pub fn now() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            /// Sentinel "no id" value. Used only for filters / unsaved rows.
            #[inline]
            pub fn nil() -> Self {
                Self(uuid::Uuid::nil())
            }

            #[inline]
            pub fn as_uuid(&self) -> uuid::Uuid {
                self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.0, f)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl From<uuid::Uuid> for $name {
            #[inline]
            fn from(u: uuid::Uuid) -> Self {
                Self(u)
            }
        }

        impl From<$name> for uuid::Uuid {
            #[inline]
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                uuid::Uuid::parse_str(s).map(Self)
            }
        }
    };
}

#[allow(unused_imports)]
pub(crate) use declare_id;
