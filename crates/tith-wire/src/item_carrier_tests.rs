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
		assert!(simple_request(
			&request(types::POLL_MESSAGES, 128),
			ItemKind::PollMessages
		)
		.is_ok());
		let invalid_identifier = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![0x80]).unwrap()],
		);
		assert!(simple_request(&invalid_identifier, ItemKind::PollMessages).is_err());
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
				&[
					OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![0x80]).unwrap(),
					OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap(),
				],
			),
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
			(RejectionReason::Temporary, Some(0)),
			(RejectionReason::Temporary, Some(u64::MAX)),
		] {
			for description in ["", "réessayez plus tard", "\u{5}\u{1}\u{3}I\0J"] {
				let value = rejected(u64::MAX, hash, timestamp, reason, description).unwrap();
				let parsed = validate_response(&value, false).unwrap();
				assert_eq!(parsed.request_identifier, u64::MAX);
				assert_eq!(parsed.response_to, Some(hash));
				assert_eq!(parsed.rejection, Some(Rejection {
					reason,
					retry_after: timestamp,
					description: description.to_owned(),
				}));
				let children = parse_sequence(&value.value).unwrap();
				assert_eq!(children.len(), 3 + usize::from(timestamp.is_some())
					+ usize::from(!description.is_empty()));
			}
		}
		for reason in [RejectionReason::Permanent, RejectionReason::ConditionUnmet] {
			assert!(rejected(1, hash, Some(1), reason, "").is_err());
			let mut children = parse_sequence(
				&rejected(1, hash, Some(1), RejectionReason::Temporary, "").unwrap().value
			).unwrap();
			children.last_mut().unwrap().value = vec![reason as u8];
			assert!(validate_response(&container(types::REJECTED, &children), false).is_err());
		}

		let base = parse_sequence(
			&rejected(1, hash, None, RejectionReason::Permanent, "").unwrap().value
		).unwrap();
		for missing in 0..base.len() {
			let mut children = base.clone();
			children.remove(missing);
			assert!(validate_response(&container(types::REJECTED, &children), false).is_err());
		}
		for (index, type_code, bytes) in [
			(0, types::TIMESTAMP, vec![1]),
			(0, types::REQUEST_IDENTIFIER, vec![0x80]),
			(1, types::ADDRESS, vec![0; 32]),
			(1, types::TLV_HASH, vec![0; 31]),
			(2, types::ADDRESS, vec![1]),
			(2, types::REJECTION_REASON, vec![]),
			(2, types::REJECTION_REASON, vec![0x80, 1]),
			(2, types::REJECTION_REASON, vec![0x81]),
			(2, types::REJECTION_REASON, vec![1, 0]),
		] {
			let mut children = base.clone();
			children[index] = OwnedTlv::new(type_code, bytes).unwrap();
			assert!(validate_response(&container(types::REJECTED, &children), false).is_err());
		}
		for code in [0, 4, 5, 73, 74, u64::MAX] {
			let mut children = base.clone();
			children[2].value = crate::integer::encode_u64(code);
			assert!(matches!(
				validate_response(&container(types::REJECTED, &children), false),
				Err(BundleError::Unexpected("Rejected reason"))
			), "unassigned reason {code} must not be parsed as a Timestamp");
		}
		for bytes in [vec![], vec![0x80], vec![1, 0]] {
			let mut children = base.clone();
			children[2].value = vec![3];
			children.insert(2, OwnedTlv::new(types::TIMESTAMP, bytes).unwrap());
			assert!(validate_response(&container(types::REJECTED, &children), false).is_err());
		}
		for bytes in [vec![], vec![0xff]] {
			let mut children = base.clone();
			children.push(OwnedTlv::new(types::REJECTION_DESCRIPTION, bytes).unwrap());
			assert!(validate_response(&container(types::REJECTED, &children), false).is_err());
		}
		let prefix = container(types::REJECTED, &base[..2]).value;
		for tail in [
			vec![1], vec![1, 0], vec![1, 0xff], b"\x01request has a data error".to_vec(),
			vec![5, 1, 0, 3], vec![0x49], vec![0x49, 1],
			vec![0x49, 2, 1], vec![0x49, 1, 1, 0x4a],
			vec![0x49, 1, 1, 0x4a, 2, b'x'],
		] {
			let mut bytes = prefix.clone();
			bytes.extend(tail);
			assert!(validate_response(&OwnedTlv::new(types::REJECTED, bytes).unwrap(), false).is_err());
		}
	}

	#[test]
	fn rejected_has_an_exact_tlv_wire_representation() {
		// Independent byte expectation for the response reported in issue #145.
		let hash_bytes = [
			0xb7, 0x30, 0xc3, 0xee, 0x2f, 0xaf, 0xd0, 0xa1,
			0x69, 0x84, 0xaa, 0x5a, 0xc7, 0x17, 0xd7, 0xca,
			0xe5, 0xcd, 0x08, 0x62, 0xa3, 0xe5, 0x3a, 0xea,
			0x02, 0x51, 0x35, 0x14, 0xa3, 0xc5, 0xcb, 0x85,
		];
		let mut expected = vec![0x43, 0x42, 0x62, 0x01, 0x00, 0x63, 0x20];
		expected.extend(hash_bytes);
		expected.extend([0x49, 0x01, 0x01, 0x4a, 0x18]);
		expected.extend_from_slice(b"request has a data error");
		let value = rejected(0, TlvHash::from_bytes(hash_bytes), None,
			RejectionReason::Permanent, "request has a data error").unwrap();
		assert_eq!(value.encode(), expected);
		let decoded = parse_sequence(&expected).unwrap();
		assert_eq!(decoded.len(), 1);
		let children = parse_sequence(&decoded[0].value).unwrap();
		assert_eq!(children.iter().map(|value| value.type_code).collect::<Vec<_>>(),
			[98, 99, 73, 74]);
		assert_eq!(validate_response(&decoded[0], false).unwrap().rejection.unwrap().reason,
			RejectionReason::Permanent);
	}

	#[test]
	fn rejected_children_have_exact_order_cardinality_and_extension_positions() {
		let value = rejected(7, TlvHash::from_bytes([9; 32]), Some(123),
			RejectionReason::Temporary, "detail").unwrap();
		let children = parse_sequence(&value.value).unwrap();
		for index in 0..children.len() {
			let mut duplicate = children.clone();
			duplicate.insert(index, children[index].clone());
			assert!(validate_response(&container(types::REJECTED, &duplicate), false).is_err());
		}
		for index in 0..children.len() - 1 {
			let mut reordered = children.clone();
			reordered.swap(index, index + 1);
			assert!(validate_response(&container(types::REJECTED, &reordered), false).is_err());
		}
		for index in 0..=children.len() {
			let mut extended = children.clone();
			extended.insert(index, OwnedTlv::new(200, vec![0, 5, 73, 74, 0xff]).unwrap());
			let extended = container(types::REJECTED, &extended);
			let parsed = validate_response(&extended, false).unwrap();
			assert_eq!(parsed.raw.encode(), extended.encode());
			assert_eq!(parsed.rejection, validate_response(&value, false).unwrap().rejection);
		}
		for type_code in [types::ORIGIN, types::REJECTION_REASON, types::REJECTION_DESCRIPTION] {
			let mut unexpected = children.clone();
			unexpected.push(OwnedTlv::new(type_code, vec![1]).unwrap());
			assert!(validate_response(&container(types::REJECTED, &unexpected), false).is_err());
		}
		for type_code in [types::REJECTION_REASON, types::REJECTION_DESCRIPTION] {
			let child = OwnedTlv::new(type_code, vec![1]).unwrap();
			let mut accepted_children = parse_sequence(
				&accepted(7, TlvHash::from_bytes([9; 32])).unwrap().value).unwrap();
			accepted_children.push(child.clone());
			assert!(validate_response(&container(types::ACCEPTED, &accepted_children), true).is_err());
			assert!(validate_item(&child, &|_: &Address| None).is_err());
		}
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

		let non_requests = VerifiedSignedTlv {
			data: vec![
				OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap(),
				accepted(1, TlvHash::from_bytes([1; 32])).unwrap(),
				accepted(1, TlvHash::from_bytes([2; 32])).unwrap(),
			],
			..payload.clone()
		};
		assert_eq!(
			validate_payload(&non_requests, &|_: &Address| None)
				.unwrap()
				.len(),
			2
		);

		let distinct_requests = VerifiedSignedTlv {
			data: vec![
				OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap(),
				request(types::POLL_MESSAGES, 1),
				request(types::POLL_FILES, 2),
			],
			..payload
		};
		assert_eq!(
			validate_payload(&distinct_requests, &|_: &Address| None)
				.unwrap()
				.len(),
			2
		);
	}
}
