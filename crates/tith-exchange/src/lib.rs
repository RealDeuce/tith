//! TTS-0006 exchange state machines.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};

use tith_wire::bundle::{Bundle, BundleError, KeyResolver};
use tith_wire::item::PayloadError;

mod response;
pub use response::*;

pub trait ExchangeIo: Read + Write {
	fn shutdown_write(&mut self) -> io::Result<()>;
}

#[derive(Debug)]
pub enum ExchangeError {
	Crypto(tith_crypto::CryptoError),
	Payload(PayloadError),
	Bundle(BundleError),
	WrongDestination,
	WrongReplyOrigin,
	WrongReplyDestination,
	UnexpectedResponse,
	DuplicateResponse,
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
			Self::DuplicateResponse => f.write_str("request received more than one response"),
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

pub fn send_bundle(
	io: &mut impl ExchangeIo,
	encoded: &[u8],
	keep_write_open: bool,
) -> Result<(), ExchangeError> {
	io.write_all(encoded)?;
	io.flush()?;
	if !keep_write_open {
		io.shutdown_write()?;
	}
	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
	Ready,
	AwaitingResponses,
	MustSendReply,
	Closing,
	Complete,
	Failed,
}

#[derive(Clone, Debug)]
pub struct ClientSession {
	state: SessionState,
	tracker: ResponseTracker,
}

impl ClientSession {
	#[must_use]
	pub fn new(tracker: ResponseTracker) -> Self {
		Self {
			state: SessionState::Ready,
			tracker,
		}
	}

	#[must_use]
	pub const fn state(&self) -> SessionState {
		self.state
	}

	/// Whether this exchange owes the peer a final Reply Bundle.
	///
	/// TTS-0006 section 4 keeps the client's write side open only for a Bundle
	/// which carries a `FileRequest` or a Poll, because only those get values back
	/// which must themselves be responded to.
	#[must_use]
	pub fn requires_return_bundle(&self) -> bool {
		self.tracker.requires_return_bundle()
	}

	/// The responses received so far, in request order.
	#[must_use]
	pub fn responses(&self) -> &[CompletedResponse] {
		self.tracker.completed()
	}

	pub fn initial_sent(&mut self) {
		self.state = SessionState::AwaitingResponses;
	}

	pub fn reply_received(
		&mut self,
		reply: &Bundle,
		resolver: &impl KeyResolver,
	) -> Result<(), ExchangeError> {
		if self.state != SessionState::AwaitingResponses {
			self.state = SessionState::Failed;
			return Err(ExchangeError::UnexpectedResponse);
		}
		if let Err(error) = self.tracker.observe_reply(reply, resolver) {
			self.state = SessionState::Failed;
			return Err(error);
		}
		if self.tracker.is_complete() {
			self.state = if self.tracker.requires_return_bundle() {
				SessionState::MustSendReply
			} else {
				SessionState::Closing
			};
		}
		Ok(())
	}

	pub fn final_reply_sent(&mut self) {
		if self.state == SessionState::MustSendReply {
			self.state = SessionState::Closing;
		}
	}

	pub fn closed(&mut self) -> Result<(), ExchangeError> {
		if self.state == SessionState::Closing && self.tracker.is_complete() {
			self.state = SessionState::Complete;
			Ok(())
		} else {
			self.state = SessionState::Failed;
			self.tracker.require_complete()
		}
	}
}

#[cfg(test)]
mod tests {
	use std::io::Cursor;

	use tith_crypto::SigningKeyPair;
	use tith_wire::address::Address;
	use tith_wire::bundle::{Identity, build_bundle};
	use tith_wire::integer::encode_u64;
	use tith_wire::tlv::OwnedTlv;
	use tith_wire::types;

	use super::*;

	struct MemoryIo {
		cursor: Cursor<Vec<u8>>,
		shutdown: bool,
	}

	impl Read for MemoryIo {
		fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
			self.cursor.read(buffer)
		}
	}

	impl Write for MemoryIo {
		fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
			self.cursor.get_mut().extend_from_slice(buffer);
			Ok(buffer.len())
		}

		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	impl ExchangeIo for MemoryIo {
		fn shutdown_write(&mut self) -> io::Result<()> {
			self.shutdown = true;
			Ok(())
		}
	}

	fn container(type_code: u64, children: &[OwnedTlv]) -> OwnedTlv {
		let mut bytes = Vec::new();
		for child in children {
			child.write_to(&mut bytes).unwrap();
		}
		OwnedTlv::new(type_code, bytes).unwrap()
	}

	#[test]
	fn send_uses_active_close_policy() {
		let mut io = MemoryIo {
			cursor: Cursor::new(Vec::new()),
			shutdown: false,
		};
		send_bundle(&mut io, b"bundle", false).unwrap();
		assert!(io.shutdown);
		assert_eq!(io.cursor.into_inner(), b"bundle");
	}

	#[test]
	fn tracks_unordered_responses_by_signed_tlv_hash_and_identifier() {
		let a_keys = SigningKeyPair::from_seed(&[21; 32]).unwrap();
		let b_keys = SigningKeyPair::from_seed(&[22; 32]).unwrap();
		let a = Identity {
			address: "fidonet#1/21".parse().unwrap(),
			public_key: a_keys.public,
		};
		let b = Identity {
			address: "fidonet#1/22".parse().unwrap(),
			public_key: b_keys.public,
		};
		let poll_messages = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(9)).unwrap()],
		);
		let poll_files = container(
			types::POLL_FILES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(10)).unwrap()],
		);
		let request_bytes = build_bundle(
			&a,
			&a_keys.secret,
			&b,
			1,
			vec![vec![poll_messages, poll_files]],
		)
		.unwrap();
		let resolver = |address: &Address| {
			if address == &a.address {
				Some(a.public_key)
			} else if address == &b.address {
				Some(b.public_key)
			} else {
				None
			}
		};
		let request = Bundle::parse(&request_bytes, &resolver).unwrap();
		let mut tracker = ResponseTracker::for_bundle(&request, &resolver).unwrap();
		assert!(tracker.requires_return_bundle());

		let request_hash = tracker.outstanding[0].signed_tlv_hash;
		let accepted_second = container(
			types::ACCEPTED,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(10)).unwrap(),
				OwnedTlv::new(types::TLV_HASH, request_hash.as_bytes().to_vec()).unwrap(),
			],
		);
		let accepted_first = container(
			types::ACCEPTED,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(9)).unwrap(),
				OwnedTlv::new(types::TLV_HASH, request_hash.as_bytes().to_vec()).unwrap(),
			],
		);
		let reply_bytes = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			2,
			vec![vec![accepted_second, accepted_first]],
		)
		.unwrap();
		let reply = Bundle::parse(&reply_bytes, &resolver).unwrap();
		tracker.observe_reply(&reply, &resolver).unwrap();
		assert!(tracker.is_complete());
		assert_eq!(tracker.completed()[0].request.request_identifier, 9);
		assert_eq!(tracker.completed()[1].request.request_identifier, 10);
		assert_eq!(tracker.completed()[0].response, ResponseKind::Accepted);
	}
}
