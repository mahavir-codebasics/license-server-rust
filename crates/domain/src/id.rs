//! Strongly-typed identifiers.
//!
//! Most entity IDs are declared in their own modules via the `declare_id!`
//! macro. This module holds the few that don't have a natural home elsewhere.

declare_id!(
    SigningKeyId,
    "Identifier of a [`SigningKey`](crate::SigningKey)."
);
declare_id!(TokenId, "Identifier of a [`Token`](crate::Token).");
