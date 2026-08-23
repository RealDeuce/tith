//! Errors produced by a TTS-0006 exchange.

use std::fmt;
use std::io;

use tith_wire::bundle::BundleError;
use tith_wire::item::PayloadError;

#[derive(Debug)]
pub enum ExchangeError {
	Crypto(tith_crypto::CryptoError),
	Payload(PayloadError),
	Bundle(BundleError),
	WrongDestination,
	WrongReplyOrigin,
	WrongReplyDestination,
	UnexpectedResponse,
	UnexpectedRequest,
	DuplicateResponse,
	DuplicateRequestIdentifier,
	InvalidRequestIdentifier,
	InvalidResponse,
	UnauthenticatedResponse,
	UnexpectedPayloadValue,
	IncompleteResponse { expected: usize, received: usize },
	Io(io::Error),
}

impl fmt::Display for ExchangeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Crypto(error) => write!(f, "cryptographic error: {error}"),
			Self::Payload(error) => write!(f, "invalid payload: {error}"),
			Self::Bundle(error) => write!(f, "invalid bundle: {error}"),
			Self::WrongDestination => f.write_str("Bundle has the wrong Destination"),
			Self::WrongReplyOrigin => f.write_str("Reply Bundle has the wrong Origin"),
			Self::WrongReplyDestination => f.write_str("Reply Bundle has the wrong Destination"),
			Self::UnexpectedResponse => {
				f.write_str("response does not identify an outstanding request")
			}
			Self::UnexpectedRequest => {
				f.write_str("peer sent a request after the local write side was closed")
			}
			Self::DuplicateResponse => f.write_str("request received more than one response"),
			Self::DuplicateRequestIdentifier => {
				f.write_str("payload contains duplicate RequestIdentifiers")
			}
			Self::InvalidRequestIdentifier => f.write_str("request has no valid RequestIdentifier"),
			Self::InvalidResponse => f.write_str("payload contains an invalid response"),
			Self::UnauthenticatedResponse => {
				f.write_str("unauthenticated SignedData contains a response")
			}
			Self::UnexpectedPayloadValue => {
				f.write_str("payload contains an unexpected defined value")
			}
			Self::IncompleteResponse { expected, received } => {
				write!(f, "response ended after {received} of {expected} requests")
			}
			Self::Io(error) => write!(f, "exchange I/O error: {error}"),
		}
	}
}

impl std::error::Error for ExchangeError {}

impl From<tith_crypto::CryptoError> for ExchangeError {
	fn from(value: tith_crypto::CryptoError) -> Self {
		Self::Crypto(value)
	}
}

impl From<PayloadError> for ExchangeError {
	fn from(value: PayloadError) -> Self {
		Self::Payload(value)
	}
}

impl From<BundleError> for ExchangeError {
	fn from(value: BundleError) -> Self {
		Self::Bundle(value)
	}
}

impl From<io::Error> for ExchangeError {
	fn from(value: io::Error) -> Self {
		Self::Io(value)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn displays_and_converts_every_exchange_error() {
		let errors = [
			ExchangeError::Crypto(tith_crypto::CryptoError::Operation),
			ExchangeError::Payload(PayloadError {
				item_index: 1,
				source: BundleError::InvalidSignature,
			}),
			ExchangeError::Bundle(BundleError::InvalidSignature),
			ExchangeError::WrongDestination,
			ExchangeError::WrongReplyOrigin,
			ExchangeError::WrongReplyDestination,
			ExchangeError::UnexpectedResponse,
			ExchangeError::UnexpectedRequest,
			ExchangeError::DuplicateResponse,
			ExchangeError::DuplicateRequestIdentifier,
			ExchangeError::InvalidRequestIdentifier,
			ExchangeError::InvalidResponse,
			ExchangeError::UnauthenticatedResponse,
			ExchangeError::UnexpectedPayloadValue,
			ExchangeError::IncompleteResponse {
				expected: 2,
				received: 1,
			},
			ExchangeError::Io(io::Error::other("read")),
		];
		for error in errors {
			assert!(!error.to_string().is_empty());
		}

		assert!(matches!(
			ExchangeError::from(tith_crypto::CryptoError::Operation),
			ExchangeError::Crypto(_)
		));
		assert!(matches!(
			ExchangeError::from(PayloadError {
				item_index: 0,
				source: BundleError::InvalidSignature,
			}),
			ExchangeError::Payload(_)
		));
		assert!(matches!(
			ExchangeError::from(BundleError::InvalidSignature),
			ExchangeError::Bundle(_)
		));
		assert!(matches!(
			ExchangeError::from(io::Error::other("read")),
			ExchangeError::Io(_)
		));
	}
}
