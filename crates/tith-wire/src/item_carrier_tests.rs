#[cfg(test)]
mod carrier_tests {
	use std::error::Error as _;

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
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(identifier))
				.unwrap()],
		)
	}

	#[test]
	fn carrier_helpers_cover_every_request_and_response_shape() {
		let hash = TlvHash::from_bytes([7; 32]);
		for (type_code, kind) in [
			(types::POLL_MESSAGES, ItemKind::PollMessages),
			(types::POLL_FILES, ItemKind::PollFiles),
			(types::POLL_FILE_REQUESTS, ItemKind::PollFileRequests),
			(types::PUBLIC_KEY_REQUEST, ItemKind::PublicKeyRequest),
		] {
			let value = request(type_code, 9);
			let parsed = validate_item(&value, &|_: &Address| None).unwrap().unwrap();
			assert_eq!(parsed.kind, kind);
			assert_eq!(parsed.request_identifier, 9);
		}
		assert!(simple_request(&request(types::POLL_MESSAGES, 1), ItemKind::PollMessages).is_ok());
		assert!(simple_request(
			&OwnedTlv::new(types::POLL_MESSAGES, Vec::new()).unwrap(),
			ItemKind::PollMessages
		)
		.is_err());
		let extra = container(
			types::POLL_MESSAGES,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
				OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
			],
		);
		assert!(simple_request(&extra, ItemKind::PollMessages).is_err());

		let accepted_value = accepted(3, hash).unwrap();
		let accepted_item = validate_response(&accepted_value, true).unwrap();
		assert_eq!(accepted_item.kind, ItemKind::Accepted);
		assert_eq!(accepted_item.response_public_key, None);
		let key = PublicKey::from_bytes([8; 32]);
		let accepted_key = accepted_public_key(4, hash, key).unwrap();
		assert_eq!(
			validate_response(&accepted_key, true)
				.unwrap()
				.response_public_key,
			Some(key)
		);
		for malformed in [
			container(
				types::ACCEPTED,
				&[OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap()],
			),
			container(
				types::ACCEPTED,
				&[
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
					OwnedTlv::new(types::TLV_HASH, vec![0; 31]).unwrap(),
				],
			),
			container(
				types::ACCEPTED,
				&[
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
					OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap(),
					OwnedTlv::new(types::PUBLIC_KEY, vec![0; 31]).unwrap(),
				],
			),
			container(
				types::ACCEPTED,
				&[
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
					OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap(),
					OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
				],
			),
		] {
			assert!(validate_response(&malformed, true).is_err());
		}
	}

	#[test]
	fn rejected_response_parser_covers_every_reason_boundary() {
		let hash = TlvHash::from_bytes([9; 32]);
		for (reason, timestamp) in [
			(RejectionReason::Permanent, None),
			(RejectionReason::ConditionUnmet, None),
			(RejectionReason::Temporary, None),
			(RejectionReason::Temporary, Some(123)),
		] {
			let value = rejected(1, hash, timestamp, reason, "detail").unwrap();
			let parsed = validate_response(&value, false).unwrap();
			assert_eq!(parsed.rejection.unwrap().reason, reason);
		}
		assert!(rejected(1, hash, Some(1), RejectionReason::Permanent, "").is_err());

		let raw_rejected = |request_type: u64, hash_type: u64, hash_value: Vec<u8>, tail: Vec<u8>| {
			let mut bytes = Vec::new();
			OwnedTlv::new(request_type, vec![1])
				.unwrap()
				.write_to(&mut bytes)
				.unwrap();
			OwnedTlv::new(hash_type, hash_value)
				.unwrap()
				.write_to(&mut bytes)
				.unwrap();
			bytes.extend(tail);
			OwnedTlv::new(types::REJECTED, bytes).unwrap()
		};
		assert!(validate_response(
			&raw_rejected(types::TIMESTAMP, types::TLV_HASH, vec![0; 32], vec![1]),
			false
		)
		.is_err());
		for (hash_type, hash_value) in [(types::ADDRESS, vec![0; 32]), (types::TLV_HASH, vec![0; 31])] {
			assert!(validate_response(
				&raw_rejected(types::REQUEST_IDENTIFIER, hash_type, hash_value, vec![1]),
				false
			)
			.is_err());
		}
		assert!(validate_response(
			&raw_rejected(types::REQUEST_IDENTIFIER, types::TLV_HASH, vec![0; 32], vec![4]),
			false
		)
		.is_err());
		let mut timestamp_and_permanent = OwnedTlv::new(types::TIMESTAMP, vec![1])
			.unwrap()
			.encode();
		timestamp_and_permanent.push(1);
		assert!(validate_response(
			&raw_rejected(
				types::REQUEST_IDENTIFIER,
				types::TLV_HASH,
				vec![0; 32],
				timestamp_and_permanent
			),
			false
		)
		.is_err());
		assert!(validate_response(
			&raw_rejected(
				types::REQUEST_IDENTIFIER,
				types::TLV_HASH,
				vec![0; 32],
				vec![1, 0xff]
			),
			false
		)
		.is_err());
	}

	#[test]
	fn identifier_and_payload_helpers_cover_all_results() {
		let value = request(types::POLL_MESSAGES, 1);
		assert_eq!(request_identifier(&value), Some(1));
		assert_eq!(request_identifier(&OwnedTlv::new(200, vec![0x80]).unwrap()), None);
		assert_eq!(
			request_identifier(&container(
				types::POLL_MESSAGES,
				&[
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![2]).unwrap(),
				]
			)),
			None
		);
		let changed = set_request_identifier(&value, 7).unwrap();
		assert_eq!(request_identifier(&changed), Some(7));
		assert!(set_request_identifier(&OwnedTlv::new(200, Vec::new()).unwrap(), 1).is_err());
		assert!(set_request_identifier(
			&container(
				types::POLL_MESSAGES,
				&[
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![2]).unwrap(),
				]
			),
			1
		)
		.is_err());
		assert!(validate_item(&OwnedTlv::new(200, Vec::new()).unwrap(), &|_: &Address| None)
			.unwrap()
			.is_none());

		let payload_error = PayloadError {
			item_index: 2,
			source: BundleError::Missing("request"),
		};
		assert!(payload_error.to_string().contains("payload item 2"));
		assert!(payload_error.source().is_some());

		let payload = VerifiedSignedTlv {
			encoded: Vec::new(),
			identity: Identity {
				address: "fidonet#1".parse().unwrap(),
				public_key: PublicKey::from_bytes([1; 32]),
			},
			data: vec![
				OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap(),
				OwnedTlv::new(200, Vec::new()).unwrap(),
				OwnedTlv::new(types::POLL_MESSAGES, Vec::new()).unwrap(),
			],
		};
		let error = validate_payload(&payload, &|_: &Address| None).unwrap_err();
		assert_eq!(error.item_index, 2);
	}
}
