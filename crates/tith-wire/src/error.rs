//! Errors shared by the common TITH wire values and enclosing formats.

use std::fmt;

use tith_crypto::CryptoError;

use crate::address::{Address, AddressError};
use crate::integer::IntegerError;
use crate::tlv::FramingError;

#[derive(Debug)]
pub enum BundleError {
	Framing(FramingError),
	Address(AddressError),
	Integer(IntegerError),
	Crypto(CryptoError),
	InvalidUtf8,
	Duplicate(&'static str),
	Missing(&'static str),
	Unexpected(&'static str),
	WrongLength(&'static str),
	UnknownKey(Address),
	InvalidSignature,
	IncorrectHeaderHash,
}

impl fmt::Display for BundleError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Framing(error) => write!(f, "bundle framing error: {error}"),
			Self::Address(error) => write!(f, "invalid address: {error}"),
			Self::Integer(error) => write!(f, "invalid integer value: {error}"),
			Self::Crypto(error) => write!(f, "cryptographic error: {error}"),
			Self::InvalidUtf8 => f.write_str("value is not valid UTF-8"),
			Self::Duplicate(name) => write!(f, "duplicate {name}"),
			Self::Missing(name) => write!(f, "missing required {name}"),
			Self::Unexpected(name) => write!(f, "unexpected or misplaced {name}"),
			Self::WrongLength(name) => write!(f, "{name} has the wrong length"),
			Self::UnknownKey(address) => write!(f, "no public key for {address}"),
			Self::InvalidSignature => f.write_str("signature verification failed"),
			Self::IncorrectHeaderHash => f.write_str("payload has the wrong Header TLVHash"),
		}
	}
}

impl std::error::Error for BundleError {}

impl From<FramingError> for BundleError {
	fn from(value: FramingError) -> Self {
		Self::Framing(value)
	}
}

impl From<AddressError> for BundleError {
	fn from(value: AddressError) -> Self {
		Self::Address(value)
	}
}

impl From<IntegerError> for BundleError {
	fn from(value: IntegerError) -> Self {
		Self::Integer(value)
	}
}

impl From<CryptoError> for BundleError {
	fn from(value: CryptoError) -> Self {
		Self::Crypto(value)
	}
}

#[cfg(test)]
mod tests {
	use std::io;

	use super::*;

	#[test]
	fn displays_each_wire_error_without_losing_its_category() {
		let address: Address = "fidonet#1/2".parse().unwrap();
		let errors = [
			BundleError::Framing(FramingError::InvalidType),
			BundleError::Address("bad".parse::<Address>().unwrap_err()),
			BundleError::Integer(IntegerError::NonCanonical),
			BundleError::Crypto(CryptoError::Operation),
			BundleError::InvalidUtf8,
			BundleError::Duplicate("Origin"),
			BundleError::Missing("Origin"),
			BundleError::Unexpected("Origin"),
			BundleError::WrongLength("Signature"),
			BundleError::UnknownKey(address),
			BundleError::InvalidSignature,
			BundleError::IncorrectHeaderHash,
		];
		for error in errors {
			assert!(!error.to_string().is_empty());
		}
	}

	#[test]
	fn converts_each_component_error() {
		assert!(matches!(
			BundleError::from(FramingError::Io(io::Error::other("read"))),
			BundleError::Framing(_)
		));
		assert!(matches!(
			BundleError::from("bad".parse::<Address>().unwrap_err()),
			BundleError::Address(_)
		));
		assert!(matches!(
			BundleError::from(IntegerError::Overflow),
			BundleError::Integer(_)
		));
		assert!(matches!(
			BundleError::from(CryptoError::Operation),
			BundleError::Crypto(_)
		));
	}
}
