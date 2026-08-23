//! Canonical TITH wire formats.

#![forbid(unsafe_code)]

pub mod address;
pub mod bundle;
mod bundle_types;
mod common;
mod error;
pub mod identity;
pub mod integer;
pub mod item;
pub mod item_format;
pub mod item_types;
mod signed_integer;
pub mod tlv;
mod type_code;
pub mod types;

pub use address::{Address, AddressError};
pub use bundle::{Bundle, BundleError, KeyResolver, VerifiedSignedTlv, build_bundle};
pub use identity::Identity;
pub use integer::{IntegerError, decode_i64, decode_u64, encode_i64, encode_u64};
pub use item::{
	ItemAuthentication, ItemKind, ItemProvenance, ItemSigning, ReadFile, ReadFileRequest,
	ReadMessage, Rejection, RejectionReason, SignedItemIdentity, ValidatedItem, ViaData, item_vias,
	read_file_request, read_message, read_standalone_file, set_request_identifier,
	validate_payload,
};
pub use item_format::{
	AreaData, AttachmentData, ItemModel, ItemModelKind, MessageData, SignedItemKind,
	StandaloneFileData, filename_is_portable, replaces_matches,
};
pub use tlv::{FramingError, OwnedTlv, TlvHeader, TlvReader, TlvValue};
