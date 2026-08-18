//! Canonical TITH wire formats.

#![forbid(unsafe_code)]

pub mod address;
pub mod bundle;
pub mod integer;
pub mod item;
pub mod tlv;
pub mod types;

pub use address::{Address, AddressError};
pub use bundle::{Bundle, BundleError, Identity, KeyResolver, VerifiedSignedTlv, build_bundle};
pub use integer::{IntegerError, decode_i64, decode_u64, encode_i64, encode_u64};
pub use item::{ItemKind, SignedItemIdentity, ValidatedItem, validate_payload};
pub use tlv::{FramingError, OwnedTlv, TlvHeader, TlvReader, TlvValue};
