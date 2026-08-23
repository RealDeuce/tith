//! TTS-0006 exchange state machines.

#![forbid(unsafe_code)]

mod error;
mod receive;
mod response;
mod session;
pub use error::*;
pub use receive::*;
pub use response::*;
pub use session::*;

#[cfg(test)]
mod tests {
	use std::io::{self, Cursor, Read, Write};

	use tith_crypto::SigningKeyPair;
	use tith_wire::address::Address;
	use tith_wire::bundle::{
		Bundle, Identity, build_bundle, build_public_key_probe, build_public_key_reply,
		build_public_key_unavailable_reply, build_signed_tlv,
	};
	use tith_wire::integer::encode_u64;
	use tith_wire::item::{
		RejectionReason, accepted, accepted_public_key, public_key_request, rejected,
		validate_payload,
	};
	use tith_wire::tlv::{OwnedTlv, parse_sequence};
	use tith_wire::types;

	use super::*;

	struct MemoryIo {
		cursor: Cursor<Vec<u8>>,
		shutdown: bool,
	}

	#[derive(Clone, Copy)]
	enum IoFault {
		Write,
		Flush,
		Shutdown,
	}

	struct FaultIo(IoFault);

	impl Read for FaultIo {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			Ok(0)
		}
	}

	impl Write for FaultIo {
		fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
			if matches!(self.0, IoFault::Write) {
				Err(io::Error::other("write failed"))
			} else {
				Ok(buffer.len())
			}
		}

		fn flush(&mut self) -> io::Result<()> {
			if matches!(self.0, IoFault::Flush) {
				Err(io::Error::other("flush failed"))
			} else {
				Ok(())
			}
		}
	}

	impl ExchangeIo for FaultIo {
		fn shutdown_write(&mut self) -> io::Result<()> {
			if matches!(self.0, IoFault::Shutdown) {
				Err(io::Error::other("shutdown failed"))
			} else {
				Ok(())
			}
		}
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

	fn concatenate(values: &[OwnedTlv]) -> Vec<u8> {
		let mut bytes = Vec::new();
		for value in values {
			value.write_to(&mut bytes).unwrap();
		}
		bytes
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

		let mut open = MemoryIo {
			cursor: Cursor::new(Vec::new()),
			shutdown: false,
		};
		send_bundle(&mut open, b"bundle", true).unwrap();
		assert!(!open.shutdown);

		for fault in [IoFault::Write, IoFault::Flush, IoFault::Shutdown] {
			assert!(matches!(
				send_bundle(&mut FaultIo(fault), b"bundle", false),
				Err(ExchangeError::Io(_))
			));
		}
	}

	#[test]
	fn client_session_enforces_header_response_reply_and_close_order() {
		let a_keys = SigningKeyPair::from_seed(&[18; 32]).unwrap();
		let b_keys = SigningKeyPair::from_seed(&[19; 32]).unwrap();
		let a = Identity {
			address: "fidonet#1/18".parse().unwrap(),
			public_key: a_keys.public,
		};
		let b = Identity {
			address: "fidonet#1/19".parse().unwrap(),
			public_key: b_keys.public,
		};
		let resolver = |address: &Address| {
			(address == &a.address)
				.then_some(a.public_key)
				.or_else(|| (address == &b.address).then_some(b.public_key))
		};
		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(7)).unwrap()],
		);
		let request = Bundle::parse(
			&build_bundle(&a, &a_keys.secret, &b, 1, vec![vec![poll]]).unwrap(),
			&resolver,
		)
		.unwrap();
		let tracker = ResponseTracker::for_bundle(&request, &resolver).unwrap();
		let outstanding = tracker.outstanding()[0].clone();
		let reply = Bundle::parse(
			&build_bundle(
				&b,
				&b_keys.secret,
				&a,
				2,
				vec![vec![
					accepted(outstanding.request_identifier, outstanding.signed_tlv_hash).unwrap(),
				]],
			)
			.unwrap(),
			&resolver,
		)
		.unwrap();
		let responses = validate_payload(&reply.payloads[0], &resolver).unwrap();

		let mut before_send = ClientSession::new(tracker.clone());
		assert!(matches!(
			before_send.reply_header_received(&reply),
			Err(ExchangeError::UnexpectedResponse)
		));
		assert_eq!(before_send.state(), SessionState::Failed);
		assert!(before_send.initial_sent().is_err());

		let mut before_header = ClientSession::new(tracker.clone());
		before_header.initial_sent().unwrap();
		assert_eq!(before_header.state(), SessionState::AwaitingReplyHeader);
		assert!(matches!(
			before_header.responses_received(&responses),
			Err(ExchangeError::UnexpectedResponse)
		));

		let mut wrong_identity = ClientSession::new(tracker.clone());
		wrong_identity.initial_sent().unwrap();
		let mut wrong_reply = reply.clone();
		wrong_reply.origin = a.clone();
		assert!(matches!(
			wrong_identity.reply_header_received(&wrong_reply),
			Err(ExchangeError::WrongReplyOrigin)
		));
		assert_eq!(wrong_identity.state(), SessionState::Failed);

		let mut incomplete = ClientSession::new(tracker.clone());
		incomplete.initial_sent().unwrap();
		incomplete.reply_header_received(&reply).unwrap();
		assert_eq!(incomplete.state(), SessionState::AwaitingResponses);
		assert!(matches!(
			incomplete.closed(),
			Err(ExchangeError::IncompleteResponse {
				expected: 1,
				received: 0
			})
		));

		let mut invalid_response = ClientSession::new(tracker.clone());
		invalid_response.initial_sent().unwrap();
		invalid_response.reply_header_received(&reply).unwrap();
		let request_items = validate_payload(&request.payloads[0], &resolver).unwrap();
		assert!(matches!(
			invalid_response.responses_received(&request_items),
			Err(ExchangeError::InvalidResponse)
		));
		assert_eq!(invalid_response.state(), SessionState::Failed);

		let mut session = ClientSession::new(tracker);
		assert!(session.requires_return_bundle());
		assert_eq!(session.requests().len(), 1);
		assert!(session.responses().is_empty());
		session.initial_sent().unwrap();
		session.reply_header_received(&reply).unwrap();
		session.responses_received(&responses).unwrap();
		assert_eq!(session.state(), SessionState::MustSendReply);
		session.final_reply_sent().unwrap();
		assert_eq!(session.state(), SessionState::Closing);
		session.closed().unwrap();
		assert_eq!(session.state(), SessionState::Complete);
		assert!(matches!(
			session.closed(),
			Err(ExchangeError::UnexpectedResponse)
		));
		assert_eq!(session.state(), SessionState::Failed);

		let empty_request = Bundle::parse(
			&build_bundle(&a, &a_keys.secret, &b, 3, vec![Vec::new()]).unwrap(),
			&resolver,
		)
		.unwrap();
		let empty_reply = Bundle::parse(
			&build_bundle(&b, &b_keys.secret, &a, 4, Vec::new()).unwrap(),
			&resolver,
		)
		.unwrap();
		let mut empty =
			ClientSession::new(ResponseTracker::for_bundle(&empty_request, &resolver).unwrap());
		assert!(!empty.requires_return_bundle());
		empty.initial_sent().unwrap();
		empty.reply_header_received(&empty_reply).unwrap();
		assert_eq!(empty.state(), SessionState::Closing);
		assert!(empty.final_reply_sent().is_err());
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
		assert_eq!(request.public_key_request().unwrap(), None);
		let request_item = validate_payload(&request.payloads[0], &resolver).unwrap();
		let mut invalid_response_tracker =
			ResponseTracker::for_bundle(&request, &resolver).unwrap();
		assert!(matches!(
			invalid_response_tracker.observe_responses(&request_item[..1]),
			Err(ExchangeError::InvalidResponse)
		));
		let mut tracker = ResponseTracker::for_bundle(&request, &resolver).unwrap();
		assert!(tracker.requires_return_bundle());
		assert!(matches!(
			tracker.require_complete(),
			Err(ExchangeError::IncompleteResponse {
				expected: 2,
				received: 0
			})
		));

		let request_hash = tracker.outstanding[0].signed_tlv_hash;
		let non_response_bytes = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			2,
			vec![vec![container(
				types::POLL_MESSAGES,
				&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(99)).unwrap()],
			)]],
		)
		.unwrap();
		let non_response = Bundle::parse(&non_response_bytes, &resolver).unwrap();
		tracker.observe_reply(&non_response, &resolver).unwrap();
		assert_eq!(tracker.received(), 0);

		let unexpected_bytes = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			2,
			vec![vec![
				accepted(9, tith_crypto::hash_tlv(b"other").unwrap()).unwrap(),
			]],
		)
		.unwrap();
		let unexpected = Bundle::parse(&unexpected_bytes, &resolver).unwrap();
		assert!(matches!(
			tracker.observe_reply(&unexpected, &resolver),
			Err(ExchangeError::UnexpectedResponse)
		));
		let wrong_identifier_bytes = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			2,
			vec![vec![accepted(99, request_hash).unwrap()]],
		)
		.unwrap();
		let wrong_identifier = Bundle::parse(&wrong_identifier_bytes, &resolver).unwrap();
		assert!(matches!(
			tracker.observe_reply(&wrong_identifier, &resolver),
			Err(ExchangeError::UnexpectedResponse)
		));
		let wrong_key_bytes = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			2,
			vec![vec![
				accepted_public_key(9, request_hash, b.public_key).unwrap(),
			]],
		)
		.unwrap();
		let wrong_key = Bundle::parse(&wrong_key_bytes, &resolver).unwrap();
		assert!(matches!(
			tracker.observe_reply(&wrong_key, &resolver),
			Err(ExchangeError::UnexpectedResponse)
		));
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
		let mut wrong_origin = reply.clone();
		wrong_origin.origin = a.clone();
		assert!(matches!(
			tracker.observe_reply(&wrong_origin, &resolver),
			Err(ExchangeError::WrongReplyOrigin)
		));
		let mut wrong_destination = reply.clone();
		wrong_destination.destination = b.clone();
		assert!(matches!(
			tracker.observe_reply(&wrong_destination, &resolver),
			Err(ExchangeError::WrongReplyDestination)
		));
		tracker.observe_reply(&reply, &resolver).unwrap();
		assert!(tracker.is_complete());
		tracker.require_complete().unwrap();
		assert_eq!(tracker.completed()[0].request.request_identifier, 9);
		assert_eq!(tracker.completed()[1].request.request_identifier, 10);
		assert_eq!(tracker.completed()[0].response, ResponseKind::Accepted);
		assert!(matches!(
			tracker.observe_reply(&reply, &resolver),
			Err(ExchangeError::DuplicateResponse)
		));

		let one_request_bytes = build_bundle(
			&a,
			&a_keys.secret,
			&b,
			3,
			vec![vec![container(
				types::POLL_FILE_REQUESTS,
				&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(12)).unwrap()],
			)]],
		)
		.unwrap();
		let one_request = Bundle::parse(&one_request_bytes, &resolver).unwrap();
		let mut rejected_tracker = ResponseTracker::for_bundle(&one_request, &resolver).unwrap();
		let rejected_hash = rejected_tracker.outstanding[0].signed_tlv_hash;
		let rejected_bytes = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			4,
			vec![vec![
				rejected(12, rejected_hash, None, RejectionReason::Permanent, "no").unwrap(),
			]],
		)
		.unwrap();
		let rejected_reply = Bundle::parse(&rejected_bytes, &resolver).unwrap();
		rejected_tracker
			.observe_reply(&rejected_reply, &resolver)
			.unwrap();
		assert_eq!(
			rejected_tracker.completed()[0].response,
			ResponseKind::Rejected
		);
		assert!(rejected_tracker.completed()[0].rejection.is_some());

		assert!(matches!(
			ServerReply::for_request(&request, &a, &a_keys.secret, 5),
			Err(ExchangeError::WrongDestination)
		));
		let server_reply = ServerReply::for_request(&request, &b, &b_keys.secret, 5).unwrap();
		assert_eq!(server_reply.origin, b);
		assert_eq!(server_reply.destination, a);
		assert!(!server_reply.prefix().is_empty());
		assert!(
			!server_reply
				.payload(vec![accepted(9, request_hash).unwrap()], &b_keys.secret)
				.unwrap()
				.is_empty()
		);
	}

	#[test]
	fn response_accounting_covers_non_requests_public_keys_and_distinct_payloads() {
		let a_keys = SigningKeyPair::from_seed(&[23; 32]).unwrap();
		let b_keys = SigningKeyPair::from_seed(&[24; 32]).unwrap();
		let a = Identity {
			address: "fidonet#1/23".parse().unwrap(),
			public_key: a_keys.public,
		};
		let b = Identity {
			address: "fidonet#1/24".parse().unwrap(),
			public_key: b_keys.public,
		};
		let resolver = |address: &Address| {
			(address == &a.address)
				.then_some(a.public_key)
				.or_else(|| (address == &b.address).then_some(b.public_key))
		};

		let response_only_bytes = build_bundle(
			&a,
			&a_keys.secret,
			&b,
			1,
			vec![vec![
				accepted(1, tith_crypto::hash_tlv(b"response").unwrap()).unwrap(),
			]],
		)
		.unwrap();
		let response_only = Bundle::parse(&response_only_bytes, &resolver).unwrap();
		assert_eq!(response_only.public_key_request().unwrap(), None);
		let response_only_tracker = ResponseTracker::for_bundle(&response_only, &resolver).unwrap();
		assert_eq!(response_only_tracker.expected(), 0);

		let probe_bytes =
			build_public_key_probe(&a, &a_keys.secret, &b.address, Some(b.public_key), 2, 7)
				.unwrap();
		let probe = Bundle::parse(&probe_bytes, &resolver).unwrap();
		let mut probe_tracker = ResponseTracker::for_bundle(&probe, &resolver).unwrap();
		let request = probe_tracker.outstanding[0].clone();
		let mut mixed_probe = parse_sequence(&probe_bytes).unwrap();
		let probe_header_hash = tith_crypto::hash_tlv(&mixed_probe[1].encode()).unwrap();
		let mixed_payload = [
			OwnedTlv::new(types::TLV_HASH, probe_header_hash.as_bytes().to_vec()).unwrap(),
			public_key_request(request.request_identifier).unwrap(),
			container(
				types::POLL_MESSAGES,
				&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(8)).unwrap()],
			),
		];
		mixed_probe[2] = build_signed_tlv(&mixed_payload, None, &a_keys.secret).unwrap();
		assert!(Bundle::parse_header_prefix(&concatenate(&mixed_probe), &resolver).is_err());
		let reply_bytes = build_public_key_reply(
			&b,
			&b_keys.secret,
			&a,
			3,
			request.request_identifier,
			request.signed_tlv_hash,
			b.public_key,
		)
		.unwrap();
		let reply =
			Bundle::parse_public_key_reply(&reply_bytes, &resolver, Some(b.public_key)).unwrap();
		probe_tracker.observe_reply(&reply, &resolver).unwrap();
		assert!(probe_tracker.is_complete());

		let no_advertised_key = build_bundle(
			&b,
			&b_keys.secret,
			&a,
			3,
			vec![vec![
				accepted_public_key(
					request.request_identifier,
					request.signed_tlv_hash,
					b.public_key,
				)
				.unwrap(),
			]],
		)
		.unwrap();
		assert!(
			Bundle::parse_public_key_reply(&no_advertised_key, &resolver, Some(b.public_key))
				.is_err()
		);

		let mut reply_values = parse_sequence(&reply_bytes).unwrap();
		assert!(
			Bundle::parse_public_key_reply(
				&concatenate(&reply_values[..3]),
				&resolver,
				Some(b.public_key)
			)
			.is_err()
		);
		let header_hash = tith_crypto::hash_tlv(&reply_values[2].encode()).unwrap();
		let extended_payload = [
			OwnedTlv::new(types::TLV_HASH, header_hash.as_bytes().to_vec()).unwrap(),
			accepted_public_key(
				request.request_identifier,
				request.signed_tlv_hash,
				b.public_key,
			)
			.unwrap(),
			OwnedTlv::new(200, Vec::new()).unwrap(),
		];
		reply_values[3] = build_signed_tlv(&extended_payload, None, &b_keys.secret).unwrap();
		assert!(
			Bundle::parse_public_key_reply(
				&concatenate(&reply_values),
				&resolver,
				Some(b.public_key)
			)
			.is_err()
		);

		let unavailable = build_public_key_unavailable_reply(
			&b,
			&b_keys.secret,
			&a,
			3,
			request.request_identifier,
			request.signed_tlv_hash,
		)
		.unwrap();
		assert!(
			Bundle::parse_public_key_reply(&unavailable, &resolver, Some(b.public_key)).is_err()
		);

		let other_keys = SigningKeyPair::from_seed(&[25; 32]).unwrap();
		let mismatched = build_public_key_reply(
			&b,
			&b_keys.secret,
			&a,
			3,
			request.request_identifier,
			request.signed_tlv_hash,
			other_keys.public,
		)
		.unwrap();
		assert!(Bundle::parse_public_key_reply(&mismatched, &resolver, None).is_err());

		let request_bytes = build_bundle(
			&a,
			&a_keys.secret,
			&b,
			4,
			vec![
				vec![container(
					types::POLL_MESSAGES,
					&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(8)).unwrap()],
				)],
				vec![container(
					types::POLL_FILES,
					&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(9)).unwrap()],
				)],
			],
		)
		.unwrap();
		let request = Bundle::parse(&request_bytes, &resolver).unwrap();
		assert_eq!(request.public_key_request().unwrap(), None);
		let mut tracker = ResponseTracker::for_bundle(&request, &resolver).unwrap();
		let first = tracker.outstanding[0].clone();
		let second = tracker.outstanding[1].clone();
		for response in [
			accepted(second.request_identifier, second.signed_tlv_hash).unwrap(),
			accepted(first.request_identifier, first.signed_tlv_hash).unwrap(),
		] {
			let bytes = build_bundle(&b, &b_keys.secret, &a, 5, vec![vec![response]]).unwrap();
			let response = Bundle::parse(&bytes, &resolver).unwrap();
			tracker.observe_reply(&response, &resolver).unwrap();
		}
		assert!(tracker.is_complete());
	}
}
