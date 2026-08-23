//! TTS-0006 Client exchange engine.
//!
//! This module owns the live Client protocol. Delivery selection, retry
//! scheduling, and durable copy outcomes remain TSP-0002 policy in `deliver`.

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

use tith_crypto::{PublicKey, TlvHash};
use tith_exchange::{
	ClientSession, CompletedResponse, ExchangeError, ExchangeIo, OutstandingRequest,
	ReceivedRequest, SessionState, receive_payload, send_bundle,
};
use tith_wire::bundle::{Bundle, BundleError, Identity, KeyResolver, build_bundle};
use tith_wire::item::{RejectionReason, rejected};
use tith_wire::tlv::{OwnedTlv, TlvReader};
use tith_wire::types;

use crate::accept::Acceptance;
use crate::deliver::{LocalIdentity, Outbound};
use crate::framing::read_header;

/// What one completed or partially completed exchange produced.
pub(super) struct Exchange {
	pub(super) requests: Vec<OutstandingRequest>,
	pub(super) responses: Vec<CompletedResponse>,
	/// How many values the peer returned in answer to a Poll or `FileRequest`.
	pub(super) returned: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureAction {
	RecoverContinuity,
	PreserveCompleted,
	Fail,
}

pub(super) fn failure_action(
	has_completed_responses: bool,
	destination_is_anonymous: bool,
	error: &(dyn Error + 'static),
) -> FailureAction {
	if has_completed_responses {
		FailureAction::PreserveCompleted
	} else if !destination_is_anonymous && is_signature_failure(error) {
		FailureAction::RecoverContinuity
	} else {
		FailureAction::Fail
	}
}

fn is_signature_failure(error: &(dyn Error + 'static)) -> bool {
	if matches!(
		error.downcast_ref::<BundleError>(),
		Some(BundleError::InvalidSignature)
	) {
		return true;
	}
	matches!(
		error.downcast_ref::<ExchangeError>(),
		Some(ExchangeError::Bundle(BundleError::InvalidSignature))
	)
}

impl Outbound {
	/// Sends the Bundle and reads responses until the session is satisfied.
	///
	/// A Bundle carrying a Poll or `FileRequest` also gets values back, which are
	/// dispatched as they arrive and answered in the final Reply Bundle this
	/// then sends. TTS-0006 section 4 is why the write side stays open for
	/// exactly those exchanges and is closed immediately for every other.
	pub(super) fn converse(
		&self,
		stream: &mut TcpStream,
		encoded: &[u8],
		session: &mut ClientSession,
		local: &LocalIdentity,
		destination: &Identity,
	) -> Result<Exchange, Box<dyn Error>> {
		let keep_open = session.requires_return_bundle();
		let writer = if keep_open {
			let mut io = StreamIo(stream.try_clone()?);
			let encoded = encoded.to_vec();
			Some(std::thread::spawn(move || {
				send_bundle(&mut io, &encoded, true)
			}))
		} else {
			let mut io = StreamIo(stream.try_clone()?);
			send_bundle(&mut io, encoded, false)?;
			None
		};
		session.initial_sent()?;

		let received = (|| -> Result<(Vec<OwnedTlv>, usize, bool), Box<dyn Error>> {
			let mut reader = TlvReader::new(stream.try_clone()?);
			let reply = read_header(&mut reader, None, self)?
				.ok_or("peer closed before sending a Reply Header")?;
			session.reply_header_received(&reply.bundle)?;
			let mut answers = Vec::new();
			let mut returned = 0;
			let mut close_after_reply = false;
			while session.state() == SessionState::AwaitingResponses {
				let Some(value) = reader.read_next()? else {
					break;
				};
				let value = value.read_owned()?;
				match value.type_code {
					types::SIGNED_TLV => {
						let payload =
							receive_payload(&value, &reply.bundle.origin, reply.header_hash, self)?;
						session.responses_received(&payload.responses)?;
						require_open_for_requests(keep_open, &payload.requests)?;
						if keep_open {
							returned += self.dispatch_returned(
								&payload.requests,
								payload.response_to,
								local,
								&reply.bundle.origin,
								&mut answers,
							)?;
						}
						if payload.close_after_reply {
							close_after_reply = true;
							break;
						}
					}
					type_code if types::is_defined(type_code) => {
						return Err("unexpected defined value in a reply".into());
					}
					_ => {}
				}
			}
			Ok((answers, returned, close_after_reply))
		})();
		join_writer(writer)?;
		let (answers, returned, close_after_reply) = received?;
		if keep_open {
			// TTS-0005 section 6: one Accepted or Rejected for every value the
			// peer returned, in a Reply Bundle of our own.
			let final_reply = build_bundle(
				&local.identity,
				&local.secret,
				destination,
				crate::now(),
				vec![answers],
			)?;
			let mut io = StreamIo(stream.try_clone()?);
			send_bundle(&mut io, &final_reply, false)?;
			session.final_reply_sent()?;
		}
		if close_after_reply {
			return Err(BundleError::IncorrectHeaderHash.into());
		}
		let responses = session.responses().to_vec();
		session.closed()?;
		// The write side was closed when the last Bundle was sent, so closing the
		// read side completes the client's active close. The peer has usually gone
		// by now, which some systems report as ENOTCONN; that is not a failure.
		drop(stream.shutdown(Shutdown::Read));
		Ok(Exchange {
			requests: session.requests().to_vec(),
			responses,
			returned,
		})
	}

	/// Stores every request value a Poll or `FileRequest` reply carried.
	fn dispatch_returned(
		&self,
		requests: &[ReceivedRequest],
		response_to: TlvHash,
		local: &LocalIdentity,
		peer: &Identity,
		answers: &mut Vec<OwnedTlv>,
	) -> Result<usize, Box<dyn Error>> {
		let acceptance = Acceptance {
			store: &self.inbound,
			application: &self.application,
			configuration: &self.configuration,
			nodelist: &self.nodelist,
			local_ref: &local.reference,
			local: &local.identity,
		};
		let mut count = 0;
		for request in requests {
			count += 1;
			answers.push(match request {
				ReceivedRequest::Valid(item) => acceptance.dispatch(item, response_to, peer)?,
				ReceivedRequest::DataError { request_identifier } => {
					data_error_response(*request_identifier, response_to)?
				}
			});
		}
		Ok(count)
	}
}

fn data_error_response(
	request_identifier: u64,
	response_to: TlvHash,
) -> Result<OwnedTlv, BundleError> {
	rejected(
		request_identifier,
		response_to,
		None,
		RejectionReason::Permanent,
		"request has a data error",
	)
}

fn require_open_for_requests(
	keep_open: bool,
	requests: &[ReceivedRequest],
) -> Result<(), tith_exchange::ExchangeError> {
	if !keep_open && !requests.is_empty() {
		Err(tith_exchange::ExchangeError::UnexpectedRequest)
	} else {
		Ok(())
	}
}

fn join_writer(
	writer: Option<std::thread::JoinHandle<Result<(), tith_exchange::ExchangeError>>>,
) -> Result<(), Box<dyn Error>> {
	if let Some(writer) = writer {
		writer.join().map_err(|_| "Bundle writer panicked")??;
	}
	Ok(())
}

/// Reads exactly through the authenticated payload which completes a
/// dedicated `PublicKeyRequest` reply.
///
/// Bundle completion is defined by the expected authenticated response, not
/// by EOF. Unknown top-level extension values may occur around the two
/// `SignedTLV` values, so the framing boundary is the second `SignedTLV`, not a
/// fixed count of top-level values.
pub(super) fn read_public_key_reply<R: Read>(
	reader: &mut TlvReader<R>,
	resolver: &dyn KeyResolver,
	expected: Option<PublicKey>,
) -> Result<Bundle, Box<dyn Error>> {
	let mut encoded = Vec::new();
	let mut signed_tlvs = 0usize;
	while signed_tlvs < 2 {
		let value = reader
			.read_next()?
			.ok_or("peer closed before completing the PublicKeyRequest reply")?
			.read_owned()?;
		if value.type_code == types::SIGNED_TLV {
			signed_tlvs += 1;
		}
		value.write_to(&mut encoded)?;
	}
	Ok(Bundle::parse_public_key_reply(
		&encoded, resolver, expected,
	)?)
}

pub(super) struct StreamIo(pub(super) TcpStream);

impl Read for StreamIo {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.0.read(buffer)
	}
}

impl Write for StreamIo {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		self.0.write(buffer)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl ExchangeIo for StreamIo {
	fn shutdown_write(&mut self) -> io::Result<()> {
		normalize_shutdown(self.0.shutdown(Shutdown::Write))
	}
}

fn normalize_shutdown(result: io::Result<()>) -> io::Result<()> {
	match result {
		// The peer may close immediately after reading the final complete Bundle.
		// That already-completed close is equivalent to our write-side shutdown.
		Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
		result => result,
	}
}

#[cfg(test)]
mod tests {
	use std::net::{TcpListener, TcpStream};

	use tith_wire::item::{ItemKind, validate_item};

	use super::*;

	#[test]
	fn client_binding_helpers_cover_closed_writes_and_writer_failures() {
		assert!(normalize_shutdown(Ok(())).is_ok());
		assert!(normalize_shutdown(Err(io::Error::from(io::ErrorKind::NotConnected))).is_ok());
		assert_eq!(
			normalize_shutdown(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
				.unwrap_err()
				.kind(),
			io::ErrorKind::BrokenPipe
		);

		assert!(join_writer(None).is_ok());
		let success = std::thread::spawn(|| Ok(()));
		assert!(join_writer(Some(success)).is_ok());
		let failure = std::thread::spawn(|| Err(tith_exchange::ExchangeError::UnexpectedResponse));
		assert!(join_writer(Some(failure)).is_err());
		let panic = std::thread::spawn(|| -> Result<(), tith_exchange::ExchangeError> {
			panic!("test writer panic")
		});
		assert!(join_writer(Some(panic)).is_err());
	}

	#[test]
	fn a_closed_client_write_side_cannot_accept_returned_requests() {
		let request = ReceivedRequest::DataError {
			request_identifier: 1,
		};
		assert!(require_open_for_requests(false, &[]).is_ok());
		assert!(matches!(
			require_open_for_requests(false, std::slice::from_ref(&request)),
			Err(tith_exchange::ExchangeError::UnexpectedRequest)
		));
		assert!(require_open_for_requests(true, &[request]).is_ok());
	}

	#[test]
	fn malformed_returned_data_gets_a_permanent_rejection() {
		let response_to = TlvHash::from_bytes([4; 32]);
		let encoded = data_error_response(7, response_to).unwrap();
		let item = validate_item(&encoded, &|_: &tith_wire::address::Address| None)
			.unwrap()
			.unwrap();
		assert_eq!(item.kind, ItemKind::Rejected);
		assert_eq!(item.request_identifier, 7);
		assert_eq!(item.response_to, Some(response_to));
		assert_eq!(item.rejection.unwrap().reason, RejectionReason::Permanent);
	}

	#[test]
	fn stream_binding_reads_and_writes_tcp_bytes() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = std::thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut input = [0; 4];
			stream.read_exact(&mut input).unwrap();
			assert_eq!(&input, b"ping");
			stream.write_all(b"pong").unwrap();
		});
		let mut io = StreamIo(TcpStream::connect(address).unwrap());
		io.write_all(b"ping").unwrap();
		io.flush().unwrap();
		let mut output = [0; 4];
		io.read_exact(&mut output).unwrap();
		assert_eq!(&output, b"pong");
		server.join().unwrap();
	}

	#[test]
	fn continuity_recovery_is_bounded_to_an_uncompleted_non_anonymous_failure() {
		let direct = BundleError::InvalidSignature;
		let wrapped = ExchangeError::Bundle(BundleError::InvalidSignature);
		let unrelated = ExchangeError::UnexpectedResponse;
		assert_eq!(
			failure_action(false, false, &direct),
			FailureAction::RecoverContinuity
		);
		assert_eq!(
			failure_action(false, false, &wrapped),
			FailureAction::RecoverContinuity
		);
		assert_eq!(failure_action(false, true, &direct), FailureAction::Fail);
		assert_eq!(
			failure_action(false, false, &unrelated),
			FailureAction::Fail
		);
		assert_eq!(
			failure_action(true, false, &direct),
			FailureAction::PreserveCompleted
		);
	}
}
