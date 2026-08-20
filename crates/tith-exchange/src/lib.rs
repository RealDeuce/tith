//! TTS-0006 exchange state machines.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};

use tith_crypto::{SecretKey, TlvHash, hash_tlv};
use tith_wire::bundle::{
	Bundle, BundleError, Identity, KeyResolver, build_bundle, build_signed_tlv,
};
use tith_wire::item::{ItemKind, PayloadError, Rejection, ValidatedItem, validate_payload};
use tith_wire::tlv::{OwnedTlv, parse_sequence};
use tith_wire::types;

pub trait ExchangeIo: Read + Write {
	fn shutdown_write(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
	Message,
	File,
	FileRequest,
	PollMessages,
	PollFiles,
	PollFileRequests,
	PublicKeyRequest,
}

impl RequestKind {
	#[must_use]
	pub const fn requires_return_bundle(self) -> bool {
		matches!(
			self,
			Self::FileRequest | Self::PollMessages | Self::PollFiles | Self::PollFileRequests
		)
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutstandingRequest {
	pub signed_tlv_hash: TlvHash,
	pub request_identifier: u64,
	pub kind: RequestKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
	Accepted,
	Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedResponse {
	pub request: OutstandingRequest,
	pub response: ResponseKind,
	/// The reason, retry Timestamp, and description of a Rejected response.
	///
	/// TSP-0002 section 6 gives each reason a different outcome, so a caller
	/// applying failure policy needs this rather than the bare `ResponseKind`.
	pub rejection: Option<Rejection>,
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
	ResponseOutOfOrder,
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
			Self::ResponseOutOfOrder => f.write_str("responses are not in request order"),
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

fn request_kind(item: &ValidatedItem) -> Option<RequestKind> {
	match item.kind {
		ItemKind::NetMail | ItemKind::EchoMail => Some(RequestKind::Message),
		ItemKind::File => Some(RequestKind::File),
		ItemKind::FileRequest => Some(RequestKind::FileRequest),
		ItemKind::PollMessages => Some(RequestKind::PollMessages),
		ItemKind::PollFiles => Some(RequestKind::PollFiles),
		ItemKind::PollFileRequests => Some(RequestKind::PollFileRequests),
		ItemKind::PublicKeyRequest => Some(RequestKind::PublicKeyRequest),
		ItemKind::Accepted | ItemKind::Rejected => None,
	}
}

#[derive(Clone, Debug)]
pub struct ResponseTracker {
	origin: Identity,
	destination: Identity,
	outstanding: Vec<OutstandingRequest>,
	completed: Vec<CompletedResponse>,
}

impl ResponseTracker {
	pub fn for_bundle(bundle: &Bundle, resolver: &impl KeyResolver) -> Result<Self, ExchangeError> {
		let mut outstanding = Vec::new();
		for payload in &bundle.payloads {
			let signed_tlv_hash = hash_tlv(&payload.encoded)?;
			for item in validate_payload(payload, resolver)? {
				if let Some(kind) = request_kind(&item) {
					outstanding.push(OutstandingRequest {
						signed_tlv_hash,
						request_identifier: item.request_identifier,
						kind,
					});
				}
			}
		}
		Ok(Self {
			origin: bundle.origin.clone(),
			destination: bundle.destination.clone(),
			outstanding,
			completed: Vec::new(),
		})
	}

	#[must_use]
	pub fn expected(&self) -> usize {
		self.outstanding.len()
	}

	#[must_use]
	pub fn received(&self) -> usize {
		self.completed.len()
	}

	#[must_use]
	pub fn is_complete(&self) -> bool {
		self.received() == self.expected()
	}

	#[must_use]
	pub fn requires_return_bundle(&self) -> bool {
		self.outstanding
			.iter()
			.any(|request| request.kind.requires_return_bundle())
	}

	#[must_use]
	pub fn completed(&self) -> &[CompletedResponse] {
		&self.completed
	}

	pub fn observe_reply(
		&mut self,
		reply: &Bundle,
		resolver: &impl KeyResolver,
	) -> Result<(), ExchangeError> {
		if reply.origin != self.destination {
			return Err(ExchangeError::WrongReplyOrigin);
		}
		if reply.destination != self.origin {
			return Err(ExchangeError::WrongReplyDestination);
		}
		for payload in &reply.payloads {
			let items = validate_payload(payload, resolver)?;
			for item in items {
				let response = match item.kind {
					ItemKind::Accepted => ResponseKind::Accepted,
					ItemKind::Rejected => ResponseKind::Rejected,
					_ => continue,
				};
				let rejection = item.rejection.clone();
				let response_hash = item.response_to.ok_or(ExchangeError::UnexpectedResponse)?;
				let Some(position) = self.outstanding.iter().position(|request| {
					request.signed_tlv_hash == response_hash
						&& request.request_identifier == item.request_identifier
				}) else {
					return Err(ExchangeError::UnexpectedResponse);
				};
				if item.response_public_key.is_some()
					&& self.outstanding[position].kind != RequestKind::PublicKeyRequest
				{
					return Err(ExchangeError::UnexpectedResponse);
				}
				if position < self.completed.len() {
					return Err(ExchangeError::DuplicateResponse);
				}
				if position != self.completed.len() {
					return Err(ExchangeError::ResponseOutOfOrder);
				}
				self.completed.push(CompletedResponse {
					request: self.outstanding[position].clone(),
					response,
					rejection,
				});
			}
		}
		Ok(())
	}

	pub fn require_complete(&self) -> Result<(), ExchangeError> {
		if self.is_complete() {
			Ok(())
		} else {
			Err(ExchangeError::IncompleteResponse {
				expected: self.expected(),
				received: self.received(),
			})
		}
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

#[derive(Clone, Debug)]
pub struct ServerReply {
	prefix: Vec<u8>,
	header_hash: TlvHash,
	pub origin: Identity,
	pub destination: Identity,
}

impl ServerReply {
	pub fn for_request(
		request: &Bundle,
		local: &Identity,
		local_secret: &SecretKey,
		timestamp: u64,
	) -> Result<Self, ExchangeError> {
		if request.destination != *local {
			return Err(ExchangeError::WrongDestination);
		}
		let prefix = build_bundle(local, local_secret, &request.origin, timestamp, Vec::new())?;
		let top = parse_sequence(&prefix).map_err(BundleError::from)?;
		let header = top
			.iter()
			.find(|value| value.type_code == types::SIGNED_TLV)
			.ok_or(BundleError::Missing("Reply Header SignedTLV"))?;
		Ok(Self {
			header_hash: hash_tlv(&header.encode())?,
			prefix,
			origin: local.clone(),
			destination: request.origin.clone(),
		})
	}

	#[must_use]
	pub fn prefix(&self) -> &[u8] {
		&self.prefix
	}

	pub fn payload(
		&self,
		responses: Vec<OwnedTlv>,
		local_secret: &SecretKey,
	) -> Result<Vec<u8>, ExchangeError> {
		let mut data = Vec::with_capacity(responses.len() + 1);
		data.push(
			OwnedTlv::new(types::TLV_HASH, self.header_hash.as_bytes().to_vec())
				.map_err(BundleError::from)?,
		);
		data.extend(responses);
		Ok(build_signed_tlv(&data, None, local_secret)?.encode())
	}
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
	use tith_wire::bundle::build_bundle;
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
	fn tracks_response_by_signed_tlv_hash_and_identifier() {
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
		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(9)).unwrap()],
		);
		let request_bytes = build_bundle(&a, &a_keys.secret, &b, 1, vec![vec![poll]]).unwrap();
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
		let accepted = container(
			types::ACCEPTED,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(9)).unwrap(),
				OwnedTlv::new(types::TLV_HASH, request_hash.as_bytes().to_vec()).unwrap(),
			],
		);
		let reply_bytes = build_bundle(&b, &b_keys.secret, &a, 2, vec![vec![accepted]]).unwrap();
		let reply = Bundle::parse(&reply_bytes, &resolver).unwrap();
		tracker.observe_reply(&reply, &resolver).unwrap();
		assert!(tracker.is_complete());
		assert_eq!(tracker.completed()[0].response, ResponseKind::Accepted);
	}
}
