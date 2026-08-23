//! TTS-0006 payload receive policy shared by Client and Server roles.

use std::collections::HashSet;

use tith_crypto::{TlvHash, hash_tlv};
use tith_wire::bundle::{
	BundleError, Identity, KeyResolver, unauthenticated_signed_data, verify_signed_tlv,
};
use tith_wire::item::{ValidatedItem, request_identifier, validate_item};
use tith_wire::tlv::OwnedTlv;
use tith_wire::types;

use crate::ExchangeError;

/// One request whose enclosing payload has been authenticated and correlated.
#[derive(Clone, Debug)]
pub enum ReceivedRequest {
	Valid(Box<ValidatedItem>),
	/// A request which is safe to identify but must receive permanent reason 1.
	DataError {
		request_identifier: u64,
	},
}

/// The actionable result of completely receiving one payload `SignedTLV`.
#[derive(Clone, Debug)]
pub struct ReceivedPayload {
	pub response_to: TlvHash,
	pub requests: Vec<ReceivedRequest>,
	pub responses: Vec<ValidatedItem>,
	/// Responses for identified requests must be sent before closing.
	pub close_after_reply: bool,
}

/// Applies TTS-0006 section 5 before either role acts on payload contents.
pub fn receive_payload(
	value: &OwnedTlv,
	origin: &Identity,
	header_hash: TlvHash,
	resolver: &dyn KeyResolver,
) -> Result<ReceivedPayload, ExchangeError> {
	let response_to = hash_tlv(&value.encode())?;
	let (data, authenticated) = match verify_signed_tlv(value, Some(origin), resolver) {
		Ok(payload) => (payload.data, true),
		Err(BundleError::InvalidSignature) => (
			unauthenticated_signed_data(value).map_err(ExchangeError::from)?,
			false,
		),
		Err(error) => return Err(error.into()),
	};

	let request_values = if data
		.first()
		.is_some_and(|first| first.type_code == types::TLV_HASH)
	{
		&data[1..]
	} else {
		data.as_slice()
	};
	let mut identifiers = HashSet::new();
	for request in request_values
		.iter()
		.filter(|item| types::is_request(item.type_code))
	{
		let identifier =
			request_identifier(request).ok_or(ExchangeError::InvalidRequestIdentifier)?;
		if !identifiers.insert(identifier) {
			return Err(ExchangeError::DuplicateRequestIdentifier);
		}
	}

	let contains_response = request_values
		.iter()
		.any(|item| matches!(item.type_code, types::ACCEPTED | types::REJECTED));
	if !authenticated {
		if contains_response {
			return Err(ExchangeError::UnauthenticatedResponse);
		}
		return Ok(ReceivedPayload {
			response_to,
			requests: request_values
				.iter()
				.filter(|item| types::is_request(item.type_code))
				.map(|item| ReceivedRequest::DataError {
					request_identifier: request_identifier(item)
						.expect("request identifiers were preflighted"),
				})
				.collect(),
			responses: Vec::new(),
			close_after_reply: false,
		});
	}

	let correct_header = data.first().is_some_and(|first| {
		first.type_code == types::TLV_HASH && first.value.as_slice() == header_hash.as_bytes()
	});
	if !correct_header {
		return Ok(ReceivedPayload {
			response_to,
			requests: request_values
				.iter()
				.filter(|item| types::is_request(item.type_code))
				.map(|item| ReceivedRequest::DataError {
					request_identifier: request_identifier(item)
						.expect("request identifiers were preflighted"),
				})
				.collect(),
			responses: Vec::new(),
			close_after_reply: true,
		});
	}

	let mut requests = Vec::new();
	let mut responses = Vec::new();
	for item in request_values {
		if types::is_request(item.type_code) {
			requests.push(match validate_item(item, resolver) {
				Ok(Some(item)) => ReceivedRequest::Valid(Box::new(item)),
				Ok(None) => unreachable!("request types always validate as items"),
				Err(_) => ReceivedRequest::DataError {
					request_identifier: request_identifier(item)
						.expect("request identifiers were preflighted"),
				},
			});
		} else if matches!(item.type_code, types::ACCEPTED | types::REJECTED) {
			responses.push(
				validate_item(item, resolver)?.expect("response types always validate as items"),
			);
		} else if types::is_defined(item.type_code) {
			return Err(ExchangeError::UnexpectedPayloadValue);
		}
	}
	Ok(ReceivedPayload {
		response_to,
		requests,
		responses,
		close_after_reply: false,
	})
}

#[cfg(test)]
mod tests {
	use tith_crypto::SigningKeyPair;
	use tith_wire::address::Address;
	use tith_wire::bundle::{Bundle, build_bundle, build_signed_tlv};
	use tith_wire::integer::encode_u64;
	use tith_wire::item::accepted;
	use tith_wire::tlv::parse_sequence;

	use super::*;

	fn container(type_code: u64, children: &[OwnedTlv]) -> OwnedTlv {
		let mut value = Vec::new();
		for child in children {
			child.write_to(&mut value).unwrap();
		}
		OwnedTlv::new(type_code, value).unwrap()
	}

	fn request(type_code: u64, identifier: u64) -> OwnedTlv {
		container(
			type_code,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(identifier)).unwrap()],
		)
	}

	fn fixture(
		values: Vec<OwnedTlv>,
	) -> (
		SigningKeyPair,
		Identity,
		Identity,
		TlvHash,
		OwnedTlv,
		impl Fn(&Address) -> Option<tith_crypto::PublicKey>,
	) {
		let origin_keys = SigningKeyPair::from_seed(&[81; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[82; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/81".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/82".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let resolver_origin = origin.clone();
		let resolver_destination = destination.clone();
		let resolver = move |address: &Address| {
			(address == &resolver_origin.address)
				.then_some(resolver_origin.public_key)
				.or_else(|| {
					(address == &resolver_destination.address)
						.then_some(resolver_destination.public_key)
				})
		};
		let encoded =
			build_bundle(&origin, &origin_keys.secret, &destination, 1, vec![values]).unwrap();
		let parsed = Bundle::parse(&encoded, &resolver).unwrap();
		let header_hash = hash_tlv(&parsed.header.encoded).unwrap();
		let payload = parse_sequence(&encoded).unwrap().pop().unwrap();
		(
			origin_keys,
			origin,
			destination,
			header_hash,
			payload,
			resolver,
		)
	}

	#[test]
	fn classifies_authenticated_requests_responses_and_extensions() {
		let response_hash = TlvHash::from_bytes([83; 32]);
		let (_, origin, _, header_hash, payload, resolver) = fixture(vec![
			request(types::POLL_MESSAGES, 1),
			accepted(2, response_hash).unwrap(),
			OwnedTlv::new(200, Vec::new()).unwrap(),
		]);
		let received = receive_payload(&payload, &origin, header_hash, &resolver).unwrap();
		assert_eq!(received.requests.len(), 1);
		assert_eq!(received.responses.len(), 1);
		assert!(!received.close_after_reply);
		assert!(matches!(received.requests[0], ReceivedRequest::Valid(_)));

		let malformed = container(
			types::POLL_MESSAGES,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(3)).unwrap(),
				OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
			],
		);
		let (_, origin, _, header_hash, payload, resolver) = fixture(vec![malformed]);
		let received = receive_payload(&payload, &origin, header_hash, &resolver).unwrap();
		assert!(matches!(
			received.requests[0],
			ReceivedRequest::DataError {
				request_identifier: 3
			}
		));
	}

	#[test]
	fn rejects_ambiguous_or_unusable_request_identifiers_before_action() {
		let (_, origin, _, header_hash, duplicate, resolver) = fixture(vec![
			request(types::POLL_MESSAGES, 4),
			request(types::POLL_FILES, 4),
		]);
		assert!(matches!(
			receive_payload(&duplicate, &origin, header_hash, &resolver),
			Err(ExchangeError::DuplicateRequestIdentifier)
		));

		let (_, origin, _, header_hash, missing, resolver) = fixture(vec![
			OwnedTlv::new(types::POLL_MESSAGES, Vec::new()).unwrap(),
		]);
		assert!(matches!(
			receive_payload(&missing, &origin, header_hash, &resolver),
			Err(ExchangeError::InvalidRequestIdentifier)
		));
	}

	#[test]
	fn unauthenticated_data_gets_only_safe_reason_one_inputs() {
		let (_, origin, _, header_hash, mut payload, resolver) =
			fixture(vec![request(types::POLL_MESSAGES, 5)]);
		*payload.value.last_mut().unwrap() ^= 1;
		let received = receive_payload(&payload, &origin, header_hash, &resolver).unwrap();
		assert!(matches!(
			received.requests[0],
			ReceivedRequest::DataError {
				request_identifier: 5
			}
		));

		let (_, origin, _, header_hash, mut response, resolver) =
			fixture(vec![accepted(6, TlvHash::from_bytes([84; 32])).unwrap()]);
		*response.value.last_mut().unwrap() ^= 1;
		assert!(matches!(
			receive_payload(&response, &origin, header_hash, &resolver),
			Err(ExchangeError::UnauthenticatedResponse)
		));

		let (_, origin, _, header_hash, mut missing, resolver) = fixture(vec![
			OwnedTlv::new(types::POLL_MESSAGES, Vec::new()).unwrap(),
		]);
		*missing.value.last_mut().unwrap() ^= 1;
		assert!(matches!(
			receive_payload(&missing, &origin, header_hash, &resolver),
			Err(ExchangeError::InvalidRequestIdentifier)
		));

		let (_, origin, _, header_hash, payload, resolver) =
			fixture(vec![request(types::POLL_MESSAGES, 6)]);
		let mut children = parse_sequence(&payload.value).unwrap();
		children
			.iter_mut()
			.find(|child| child.type_code == types::SIGNED_DATA)
			.unwrap()
			.value = vec![0x80];
		let malformed = container(types::SIGNED_TLV, &children);
		assert!(matches!(
			receive_payload(&malformed, &origin, header_hash, &resolver),
			Err(ExchangeError::Bundle(_))
		));
	}

	#[test]
	fn wrong_header_hash_rejects_requests_then_requires_close() {
		let (origin_keys, origin, _, header_hash, _, resolver) =
			fixture(vec![request(types::POLL_MESSAGES, 7)]);
		let wrong_hash = OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap();
		let payload = build_signed_tlv(
			&[wrong_hash, request(types::POLL_MESSAGES, 7)],
			None,
			&origin_keys.secret,
		)
		.unwrap();
		let received = receive_payload(&payload, &origin, header_hash, &resolver).unwrap();
		assert!(received.close_after_reply);
		assert!(received.responses.is_empty());
		assert!(matches!(
			received.requests[0],
			ReceivedRequest::DataError {
				request_identifier: 7
			}
		));

		let missing_hash =
			build_signed_tlv(&[request(types::POLL_FILES, 8)], None, &origin_keys.secret).unwrap();
		let received = receive_payload(&missing_hash, &origin, header_hash, &resolver).unwrap();
		assert!(received.close_after_reply);
		assert!(matches!(
			received.requests[0],
			ReceivedRequest::DataError {
				request_identifier: 8
			}
		));
	}

	#[test]
	fn malformed_responses_and_unexpected_defined_values_fail() {
		let bad_response = container(
			types::ACCEPTED,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(8)).unwrap()],
		);
		let (_, origin, _, header_hash, payload, resolver) = fixture(vec![bad_response]);
		assert!(matches!(
			receive_payload(&payload, &origin, header_hash, &resolver),
			Err(ExchangeError::Bundle(_))
		));

		let (_, origin, _, header_hash, payload, resolver) = fixture(vec![
			OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
		]);
		assert!(matches!(
			receive_payload(&payload, &origin, header_hash, &resolver),
			Err(ExchangeError::UnexpectedPayloadValue)
		));

		let broken = OwnedTlv::new(types::SIGNED_TLV, Vec::new()).unwrap();
		assert!(matches!(
			receive_payload(&broken, &origin, header_hash, &resolver),
			Err(ExchangeError::Bundle(_))
		));
	}
}
