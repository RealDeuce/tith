#[cfg(test)]
mod tests {
	use tith_crypto::SigningKeyPair;

	use super::*;
	use crate::bundle::{Bundle, build_bundle};

	fn container(type_code: u64, children: &[OwnedTlv]) -> OwnedTlv {
		let mut bytes = Vec::new();
		for child in children {
			child.write_to(&mut bytes).unwrap();
		}
		OwnedTlv::new(type_code, bytes).unwrap()
	}

	fn area(name: &str) -> AreaData {
		AreaData {
			name: name.to_owned(),
			description: None,
		}
	}

	fn verification_error(
		_: &[u8],
		_: &Signature,
		_: &PublicKey,
	) -> Result<bool, CryptoError> {
		Err(CryptoError::Operation)
	}

	#[test]
	fn validates_poll_request() {
		let origin_keys = SigningKeyPair::from_seed(&[10; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[11; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/10".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/11".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![7]).unwrap()],
		);
		let bundle = build_bundle(
			&origin,
			&origin_keys.secret,
			&destination,
			1,
			vec![vec![poll]],
		)
		.unwrap();
		let resolver = |address: &Address| {
			[address == &origin.address, address == &destination.address]
				.iter()
				.position(|matched| *matched)
				.map(|index| [origin.public_key, destination.public_key][index])
		};
		let parsed = Bundle::parse(&bundle, &resolver).unwrap();
		let items = validate_payload(&parsed.payloads[0], &resolver).unwrap();
		assert_eq!(items[0].kind, ItemKind::PollMessages);
		assert_eq!(items[0].request_identifier, 7);
	}

	#[test]
	fn request_identifiers_are_unique_within_one_directional_payload() {
		let origin_keys = SigningKeyPair::from_seed(&[20; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[21; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/20".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/21".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let identifier = OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![7]).unwrap();
		let polls = vec![
			container(types::POLL_MESSAGES, std::slice::from_ref(&identifier)),
			container(types::POLL_FILES, &[identifier]),
		];
		let bundle =
			build_bundle(&origin, &origin_keys.secret, &destination, 1, vec![polls]).unwrap();
		let resolver = |address: &Address| {
			(address == &origin.address)
				.then_some(origin.public_key)
				.or_else(|| (address == &destination.address).then_some(destination.public_key))
		};
		let parsed = Bundle::parse(&bundle, &resolver).unwrap();
		let error = validate_payload(&parsed.payloads[0], &resolver).unwrap_err();
		assert!(matches!(
			error.source,
			BundleError::Duplicate("request identifier")
		));
	}

	#[test]
	fn accepts_unsigned_message_and_standalone_file() {
		let destination_keys = SigningKeyPair::from_seed(&[12; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/12".parse().unwrap(),
			public_key: SigningKeyPair::from_seed(&[13; 32]).unwrap().public,
		};
		let destination = Identity {
			address: "fidonet#1/13".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let message = container(
			types::MESSAGE,
			&[
				OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap(),
				OwnedTlv::new(
					types::DESTINATION,
					destination.address.to_string().into_bytes(),
				)
				.unwrap(),
				OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(1)).unwrap(),
				OwnedTlv::new(types::TO_USER_NAME, b"You".to_vec()).unwrap(),
				OwnedTlv::new(types::FROM_USER_NAME, b"Me".to_vec()).unwrap(),
				OwnedTlv::new(types::SUBJECT, Vec::new()).unwrap(),
				OwnedTlv::new(types::MESSAGE_TEXT, b"Legacy\n".to_vec()).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(10)).unwrap(),
				via_value(&origin, 1, "test"),
			],
		);
		let validated = validate_item(&message, &|address: &Address| {
			(address == &destination.address).then_some(destination.public_key)
		})
		.unwrap()
		.unwrap();
		assert_eq!(validated.authentication, Some(ItemAuthentication::Unsigned));
		assert!(validated.duplicate_identity.is_none());
		assert_eq!(validated.provenance.unwrap().signer, None);

		let file = container(
			types::FILE,
			&[
				OwnedTlv::new(types::FILENAME, b"legacy.zip".to_vec()).unwrap(),
				OwnedTlv::new(types::CONTENTS, b"legacy".to_vec()).unwrap(),
				OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(11)).unwrap(),
			],
		);
		let validated = validate_item(&file, &|_: &Address| None).unwrap().unwrap();
		assert_eq!(validated.authentication, Some(ItemAuthentication::Unsigned));
		assert!(validated.duplicate_identity.is_none());
	}

	#[test]
	fn message_origin_is_the_literal_first_child() {
		let message = container(
			types::MESSAGE,
			&[
				OwnedTlv::new(200, Vec::new()).unwrap(),
				OwnedTlv::new(types::ORIGIN, b"fidonet#1/10".to_vec()).unwrap(),
			],
		);
		assert!(matches!(
			validate_message(&message, &|_: &Address| None),
			Err(BundleError::Missing("initial Message Origin"))
		));
	}

	#[test]
	fn unknown_value_cannot_separate_message_origin_and_key() {
		let origin = Address::anonymous("p2p".into()).unwrap();
		let message = container(
			types::MESSAGE,
			&[
				OwnedTlv::new(types::ORIGIN, origin.to_string().into_bytes()).unwrap(),
				OwnedTlv::new(200, Vec::new()).unwrap(),
				OwnedTlv::new(types::PUBLIC_KEY, vec![0; 32]).unwrap(),
			],
		);
		assert!(matches!(
			validate_message(&message, &|_: &Address| None),
			Err(BundleError::Missing("PublicKey after anonymous address"))
		));
	}

	#[test]
	fn via_and_reply_to_use_raw_utf8_suffixes() {
		let mut via_value = Vec::new();
		OwnedTlv::new(types::ADDRESS, b"fidonet#1/2".to_vec())
			.unwrap()
			.write_to(&mut via_value)
			.unwrap();
		OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(123))
			.unwrap()
			.write_to(&mut via_value)
			.unwrap();
		via_value.extend_from_slice("tith тест 1.0".as_bytes());
		let via = OwnedTlv::new(types::VIA, via_value).unwrap();
		read_via(&via).unwrap();

		let mut reply_value = Vec::new();
		OwnedTlv::new(types::ADDRESS, b"fidonet#1/3".to_vec())
			.unwrap()
			.write_to(&mut reply_value)
			.unwrap();
		reply_value.extend_from_slice(b"message-id@example");
		let reply = OwnedTlv::new(types::REPLY_TO, reply_value).unwrap();
		read_reply_to(&reply).unwrap();

		let mut invalid = via;
		invalid.value.push(0xff);
		assert!(matches!(read_via(&invalid), Err(BundleError::InvalidUtf8)));
	}

	#[test]
	fn anonymous_via_requires_its_public_key_before_the_raw_suffix() {
		let address = Address::anonymous("p2p".to_owned()).unwrap();
		let mut value = Vec::new();
		for child in [
			OwnedTlv::new(types::ADDRESS, address.to_string().into_bytes()).unwrap(),
			OwnedTlv::new(types::PUBLIC_KEY, vec![7; 32]).unwrap(),
			OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(456)).unwrap(),
		] {
			child.write_to(&mut value).unwrap();
		}
		value.extend_from_slice(b"tith 1.0");
		read_via(&OwnedTlv::new(types::VIA, value).unwrap()).unwrap();
	}

	#[test]
	fn signed_origin_authenticates_when_origin_has_no_key() {
		let signer_keys = SigningKeyPair::from_seed(&[20; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[21; 32]).unwrap();
		let provenance = ItemProvenance {
			origin: "fidonet#1/100".parse().unwrap(),
			signer: Some(Identity {
				address: Address::anonymous("p2p".to_owned()).unwrap(),
				public_key: signer_keys.public,
			}),
		};
		let destination = Identity {
			address: "fidonet#1/200".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let message = build_originated_message(
			&MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Legacy\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&provenance,
			&signer_keys.secret,
			7,
			1,
			"test",
			&[],
		)
		.unwrap();
		let validated = validate_item(&message, &|address: &Address| {
			(address == &destination.address).then_some(destination.public_key)
		})
		.unwrap()
		.unwrap();
		assert_eq!(
			validated.authentication,
			Some(ItemAuthentication::SignedOriginValid)
		);
		assert_eq!(validated.provenance, Some(provenance.clone()));
		assert_eq!(
			validated.duplicate_identity.unwrap().signer,
			provenance.signer.unwrap()
		);
	}

	#[test]
	fn origin_key_prevents_signed_origin_fallback() {
		let signer_keys = SigningKeyPair::from_seed(&[22; 32]).unwrap();
		let origin_keys = SigningKeyPair::from_seed(&[23; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[24; 32]).unwrap();
		let origin: Address = "fidonet#1/100".parse().unwrap();
		let destination = Identity {
			address: "fidonet#1/200".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let message = build_originated_message(
			&MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Legacy\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: Address::anonymous("p2p".to_owned()).unwrap(),
					public_key: signer_keys.public,
				}),
			},
			&signer_keys.secret,
			8,
			1,
			"test",
			&[],
		)
		.unwrap();
		let validated = validate_item(&message, &|address: &Address| {
			if address == &origin {
				Some(origin_keys.public)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		})
		.unwrap()
		.unwrap();
		assert_eq!(
			validated.authentication,
			Some(ItemAuthentication::OriginInvalid)
		);
		assert!(validated.duplicate_identity.is_none());
		assert_eq!(
			validated.provenance.unwrap().signer.unwrap().address,
			origin
		);
	}

	#[test]
	fn a_message_carries_every_seen_by_address_in_one_trimmed_value() {
		// Message SeenBy is an optional singleton holding a Trimmed Collection.
		// Emitting one value per address produced a Message which this crate's
		// own validator rejected, so any EchoMail forwarded to more than one
		// link failed to build.
		let signer_keys = SigningKeyPair::from_seed(&[70; 32]).unwrap();
		let origin: Address = "fidonet#1/100".parse().unwrap();
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(Identity {
				address: origin.clone(),
				public_key: signer_keys.public,
			}),
		};
		let message = build_originated_message(
			&MessageData {
				destination: None,
				timestamp: 1,
				to_user: "All".to_owned(),
				from_user: "Me".to_owned(),
				subject: "Hello".to_owned(),
				text: "Body\n".to_owned(),
				area: Some(area("SYNCHRONET")),
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&provenance,
			&signer_keys.secret,
			7,
			1,
			"test",
			&[
				"fidonet#1/400".parse().unwrap(),
				"fidonet#1/300".parse().unwrap(),
				"fidonet#1/300".parse().unwrap(),
			],
		)
		.unwrap();
		let resolver = |address: &Address| (address == &origin).then_some(signer_keys.public);
		validate_item(&message, &resolver).unwrap().unwrap();

		let children = parse_sequence(&message.value).unwrap();
		let values: Vec<_> = children
			.iter()
			.filter(|child| child.type_code == types::SEEN_BY)
			.collect();
		assert_eq!(values.len(), 1, "Message SeenBy is a singleton");
		assert_eq!(values[0].value, b"fidonet#1/300,/400");
		assert_eq!(
			seen_by_addresses(values[0]).unwrap(),
			["fidonet#1/300", "fidonet#1/400"].map(|text| text.parse::<Address>().unwrap())
		);
	}

	#[test]
	fn standalone_file_uses_signed_origin_fallback() {
		let signer_keys = SigningKeyPair::from_seed(&[25; 32]).unwrap();
		let provenance = ItemProvenance {
			origin: "fidonet#1/300".parse().unwrap(),
			signer: Some(Identity {
				address: Address::anonymous("p2p".to_owned()).unwrap(),
				public_key: signer_keys.public,
			}),
		};
		let file = build_originated_file(
			StandaloneFileData {
				filename: Some("test.zip".to_owned()),
				timestamp: None,
				contents: b"file".to_vec(),
				area: Some(area("FILES")),
				short_description: None,
				long_description_lines: Vec::new(),
				tear_line: None,
				magic_word: None,
				replaces: None,
			},
			&provenance,
			&signer_keys.secret,
			9,
			1,
			"test",
			&["fidonet#1/300".parse().unwrap()],
		)
		.unwrap();
		let validated = validate_item(&file, &|_: &Address| None).unwrap().unwrap();
		assert_eq!(
			validated.authentication,
			Some(ItemAuthentication::SignedOriginValid)
		);
		assert_eq!(validated.provenance, Some(provenance));
		assert!(validated.duplicate_identity.is_some());
	}

	#[test]
	fn reading_a_message_inverts_building_one() {
		let signer_keys = SigningKeyPair::from_seed(&[80; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[81; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let destination = Identity {
			address: "fidonet#1:104/1".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(Identity {
				address: origin.clone(),
				public_key: signer_keys.public,
			}),
		};
		let data = MessageData {
			destination: Some(destination.clone()),
			timestamp: 1_755_500_000,
			to_user: "Recipient".to_owned(),
			from_user: "Sender".to_owned(),
			subject: "work.zip".to_owned(),
			text: "Body text\n".to_owned(),
			area: None,
			attachments: vec![
				AttachmentData {
					filename: Some("work.zip".to_owned()),
					timestamp: Some(1_755_400_000),
					contents: b"payload".to_vec(),
					short_description: Some("First attachment".to_owned()),
					long_description_lines: vec!["Long description".to_owned()],
					tear_line: Some("Created by test".to_owned()),
					magic_word: Some("WORK".to_owned()),
					replaces: Some("old*.zip".to_owned()),
				},
				AttachmentData {
					filename: None,
					timestamp: None,
					contents: b"second".to_vec(),
					short_description: None,
					long_description_lines: Vec::new(),
					tear_line: None,
					magic_word: None,
					replaces: None,
				},
			],
			// Bit 4 is not representable here and TearLine and OriginLine are
			// EchoMail's, so this covers the rest and the EchoMail case below
			// covers those two.
			legacy_attributes: Some(1 << 12),
			timestamp_offset: Some(-25200),
			tear_line: None,
			origin_line: None,
			message_id: Some("1:104/36 1a2b3c4d".to_owned()),
			reply_to: Some(("fidonet#1:104/1".parse().unwrap(), "deadbeef".to_owned())),
			original_character_set: Some("CP437 2".to_owned()),
			additional_kludge_lines: vec!["FLAGS KFS".to_owned()],
		};
		let message = build_originated_message(
			&data,
			&provenance,
			&signer_keys.secret,
			42,
			1_755_500_001,
			"tith 0.1",
			&[],
		)
		.unwrap();

		let resolver = |address: &Address| {
			if address == &origin {
				Some(signer_keys.public)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let read = read_message(&message, &resolver).unwrap();
		assert_eq!(read.data, data);
		assert_eq!(read.request_identifier, 42);
		assert_eq!(read.signing.origin, origin);
		assert!(read.signing.signed_origin.is_none());
		assert_eq!(read.vias.len(), 1);
		assert_eq!(read.vias[0].address, origin);
		assert_eq!(read.vias[0].timestamp, 1_755_500_001);
		assert_eq!(read.vias[0].software, "tith 0.1");
		assert!(read.seen_by.is_empty());

		// The signed region must be the exact bytes the Signature covers, which
		// is what TSP-0003 section 3.1 compares a reconstruction against.
		let signature = read.signing.signature.expect("signed");
		assert!(
			verify_tlv(&read.signing.signed_region, &signature, &signer_keys.public).unwrap(),
			"the reported signed region does not verify"
		);

		// The two EchoMail-only values invert the same way.
		let echo = MessageData {
			destination: None,
			area: Some(AreaData {
				name: "SYNCHRONET".to_owned(),
				description: Some("A discussion area".to_owned()),
			}),
			reply_to: None,
			original_character_set: None,
			tear_line: Some("TITH 0.1".to_owned()),
			origin_line: Some("A board (1:104/36)".to_owned()),
			..data
		};
		let message = build_originated_message(
			&echo,
			&provenance,
			&signer_keys.secret,
			43,
			1_755_500_001,
			"tith 0.1",
			&[],
		)
		.unwrap();
		assert_eq!(read_message(&message, &resolver).unwrap().data, echo);
	}

	#[test]
	fn message_model_reencodes_unknown_children_byte_for_byte() {
		let keys = SigningKeyPair::from_seed(&[83; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[84; 32]).unwrap();
		let destination = Identity {
			address: "fidonet#1:104/1".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(Identity {
				address: origin.clone(),
				public_key: keys.public,
			}),
		};
		let mut message = build_originated_message(
			&MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "To".to_owned(),
				from_user: "From".to_owned(),
				subject: String::new(),
				text: "Body\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&provenance,
			&keys.secret,
			7,
			2,
			"test",
			&[],
		)
		.unwrap();
		let mut children = parse_sequence(&message.value).unwrap();
		let signature_index = children
			.iter()
			.position(|child| child.type_code == types::SIGNATURE)
			.unwrap();
		children.insert(
			signature_index,
			OwnedTlv::new(200, b"signed unknown".to_vec()).unwrap(),
		);
		children.insert(
			signature_index,
			OwnedTlv::new(types::ORIGINAL_CHARACTER_SET, b"CP437 2".to_vec()).unwrap(),
		);
		let signature_index = signature_index + 2;
		let signature =
			sign_tlv(&encoded_prefix(&children, signature_index), &keys.secret).unwrap();
		children[signature_index].value = signature.as_bytes().to_vec();
		children.insert(
			signature_index + 2,
			OwnedTlv::new(201, b"unsigned unknown".to_vec()).unwrap(),
		);
		message.value = encoded_prefix(&children, children.len());

		let resolver = |address: &Address| {
			if address == &origin {
				Some(keys.public)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let model = MessageModel::parse(&message, &resolver).unwrap();
		assert_eq!(model.to_tlv().encode(), message.encode());
		assert_eq!(model.children()[signature_index - 1].type_code, 200);
		assert_eq!(model.children()[signature_index + 2].type_code, 201);
	}

	#[test]
	fn reading_carries_the_signed_origin_encoding_a_tithsign_control_needs() {
		let signer_keys = SigningKeyPair::from_seed(&[82; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[83; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let signer = Identity {
			address: Address::anonymous("p2p".to_owned()).unwrap(),
			public_key: signer_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1:104/1".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let message = build_originated_message(
			&MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Text\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(signer.clone()),
			},
			&signer_keys.secret,
			1,
			1,
			"tith 0.1",
			&[],
		)
		.unwrap();
		let read = read_message(&message, &|address: &Address| {
			(address == &destination.address).then_some(destination.public_key)
		})
		.unwrap();
		assert_eq!(read.signing.origin, origin);
		assert_eq!(read.signing.signed_origin, Some(signer.address.clone()));
		assert_eq!(read.signing.signed_origin_key, Some(signer_keys.public));

		// TITHSIGN carries exactly one SignedOrigin TLV followed by one
		// PublicKey TLV, because SignedOrigin here is the anonymous address.
		let mut expected = OwnedTlv::new(
			types::SIGNED_ORIGIN,
			signer.address.to_string().into_bytes(),
		)
		.unwrap()
		.encode();
		OwnedTlv::new(types::PUBLIC_KEY, signer_keys.public.as_bytes().to_vec())
			.unwrap()
			.write_to(&mut expected)
			.unwrap();
		assert_eq!(read.signing.signed_origin_encoding, expected);
	}

	#[test]
	fn reading_a_standalone_file_inverts_building_one() {
		let signer_keys = SigningKeyPair::from_seed(&[84; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let data = StandaloneFileData {
			filename: Some("goodies.zip".to_owned()),
			timestamp: Some(1_755_400_000),
			contents: b"payload".to_vec(),
			area: Some(area("SYNCDATA")),
			short_description: Some("A file".to_owned()),
			long_description_lines: vec!["First".to_owned(), "Second".to_owned()],
			tear_line: Some("TITH 0.1".to_owned()),
			magic_word: Some("GOODIES".to_owned()),
			replaces: Some("goodies.*".to_owned()),
		};
		let file = build_originated_file(
			data.clone(),
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: signer_keys.public,
				}),
			},
			&signer_keys.secret,
			9,
			1_755_500_001,
			"tith 0.1",
			&["fidonet#1:104/36".parse().unwrap()],
		)
		.unwrap();
		let read = read_standalone_file(&file).unwrap();
		assert_eq!(read.data, data);
		assert_eq!(read.request_identifier, 9);
		assert_eq!(read.seen_by, std::slice::from_ref(&origin));
		assert_eq!(read.vias.len(), 1);
		let signature = read.signing.signature.expect("signed");
		assert!(verify_tlv(&read.signing.signed_region, &signature, &signer_keys.public).unwrap());
	}

	#[test]
	fn a_peer_addressed_file_carries_no_area_via_or_seen_by() {
		// TSP-0016 section 3.2 marks all three "F", for a file that is part
		// of a distribution network. A File which is not one carries none of them,
		// and the Bundle Destination addresses it instead.
		let signer_keys = SigningKeyPair::from_seed(&[86; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let data = StandaloneFileData {
			filename: None,
			timestamp: Some(1_755_400_000),
			contents: b"arcmail".to_vec(),
			area: None,
			short_description: None,
			long_description_lines: Vec::new(),
			tear_line: None,
			magic_word: None,
			replaces: None,
		};
		let file = build_originated_file(
			data.clone(),
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: signer_keys.public,
				}),
			},
			&signer_keys.secret,
			4,
			1_755_500_001,
			"tith 0.1",
			// Offered and ignored: a File with no Area has nowhere to put them.
			std::slice::from_ref(&origin),
		)
		.unwrap();

		let children = parse_sequence(&file.value).unwrap();
		for absent in [types::AREA, types::VIA, types::SEEN_BY] {
			assert!(
				!children.iter().any(|child| child.type_code == absent),
				"type {absent} must not occur in a peer-addressed File"
			);
		}
		let resolver = |address: &Address| (address == &origin).then_some(signer_keys.public);
		let validated = validate_item(&file, &resolver).unwrap().expect("an item");
		assert_eq!(validated.kind, ItemKind::File);
		assert_eq!(validated.area, None);
		assert_eq!(validated.request_identifier, 4);
		assert_eq!(
			validated.authentication,
			Some(ItemAuthentication::OriginValid)
		);
		let read = read_standalone_file(&file).unwrap();
		assert_eq!(read.data, data);
		assert!(read.vias.is_empty());
		assert!(read.seen_by.is_empty());
		let model = ItemModel::parse(&file, &resolver).unwrap();
		assert_eq!(model.kind(), ItemModelKind::StandaloneFile);
		assert_eq!(model.to_tlv().encode(), file.encode());
		let mut extended_children = parse_sequence(&file.value).unwrap();
		let signature = extended_children
			.iter()
			.position(|child| child.type_code == types::SIGNATURE)
			.unwrap();
		extended_children.insert(
			signature,
			OwnedTlv::new(200, b"signed extension".to_vec()).unwrap(),
		);
		extended_children.push(OwnedTlv::new(201, b"suffix extension".to_vec()).unwrap());
		let extended = OwnedTlv::new(types::FILE, concatenate(&extended_children)).unwrap();
		assert_eq!(
			ItemModel::parse(&extended, &resolver)
				.unwrap()
				.to_tlv()
				.encode(),
			extended.encode()
		);
		for invalid in [
			StandaloneFileData {
				short_description: Some("two\nlines".to_owned()),
				..data.clone()
			},
			StandaloneFileData {
				long_description_lines: vec!["two\rlines".to_owned()],
				..data.clone()
			},
		] {
			assert!(
				build_originated_file(
					invalid,
					&ItemProvenance {
						origin: origin.clone(),
						signer: Some(Identity {
							address: origin.clone(),
							public_key: signer_keys.public,
						}),
					},
					&signer_keys.secret,
					5,
					1_755_500_001,
					"tith 0.1",
					&[],
				)
				.is_err()
			);
		}
	}

	#[test]
	fn building_a_file_request_inverts_reading_one() {
		for newer_than in [None, Some(1_755_400_000)] {
			let request = build_file_request("nodediff.zip", newer_than, 7).unwrap();
			assert_eq!(request.type_code, types::FILE_REQUEST);
			let validated = validate_item(&request, &|_: &Address| None)
				.unwrap()
				.expect("an item");
			assert_eq!(validated.kind, ItemKind::FileRequest);
			assert_eq!(validated.request_identifier, 7);
			// A FileRequest has no end-to-end signature by design, so its state is
			// Transport rather than a reduced authentication.
			assert_eq!(
				validated.authentication,
				Some(ItemAuthentication::Transport)
			);
			assert!(validated.duplicate_identity.is_none());
			let read = read_file_request(&request).unwrap();
			assert_eq!(read.filename, "nodediff.zip");
			assert_eq!(read.timestamp, newer_than);
			assert_eq!(read.request_identifier, 7);
			let model = ItemModel::parse(&request, &|_: &Address| None).unwrap();
			assert_eq!(model.kind(), ItemModelKind::FileRequest);
			assert_eq!(model.to_tlv().encode(), request.encode());
		}
		// Renumbering for a new exchange works the same way it does for an item.
		let renumbered =
			set_request_identifier(&build_file_request("a.zip", None, 1).unwrap(), 3).unwrap();
		assert_eq!(
			read_file_request(&renumbered).unwrap().request_identifier,
			3
		);
		let mut children = parse_sequence(&renumbered.value).unwrap();
		children.insert(
			0,
			OwnedTlv::new(200, b"leading extension".to_vec()).unwrap(),
		);
		children.push(OwnedTlv::new(201, b"trailing extension".to_vec()).unwrap());
		let extended = OwnedTlv::new(types::FILE_REQUEST, concatenate(&children)).unwrap();
		assert_eq!(
			ItemModel::parse(&extended, &|_: &Address| None)
				.unwrap()
				.to_tlv()
				.encode(),
			extended.encode()
		);
	}

	#[test]
	fn filename_production_avoids_the_exact_list_but_consumption_accepts_it() {
		assert!(matches!(
			build_file_request("bad:name", None, 1),
			Err(BundleError::Unexpected(
				"Filename code point discouraged for production"
			))
		));

		let discouraged = container(
			types::FILE_REQUEST,
			&[
				OwnedTlv::new(types::FILENAME, b"bad:name".to_vec()).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(1)).unwrap(),
			],
		);
		assert!(validate_file_request(&discouraged).is_ok());

		let path = container(
			types::FILE_REQUEST,
			&[
				OwnedTlv::new(types::FILENAME, b"dir/file".to_vec()).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(1)).unwrap(),
			],
		);
		assert!(matches!(
			validate_file_request(&path),
			Err(BundleError::Unexpected("Filename path component"))
		));
	}

	#[test]
	fn reading_preserves_original_character_set_and_refuses_other_item_kinds() {
		// OriginalCharacterSet is an optional signed field and the semantic view
		// must retain it rather than silently lose it.
		let signer_keys = SigningKeyPair::from_seed(&[85; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let message = build_originated_message(
			&MessageData {
				destination: None,
				timestamp: 1,
				to_user: "All".to_owned(),
				from_user: "Me".to_owned(),
				subject: "Hi".to_owned(),
				text: "Text\n".to_owned(),
				area: Some(area("SYNCHRONET")),
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: signer_keys.public,
				}),
			},
			&signer_keys.secret,
			1,
			1,
			"tith 0.1",
			&[],
		)
		.unwrap();
		let mut children = parse_sequence(&message.value).unwrap();
		let signature = children
			.iter()
			.position(|child| child.type_code == types::SIGNATURE)
			.unwrap();
		children.insert(
			signature,
			OwnedTlv::new(types::ORIGINAL_CHARACTER_SET, b"CP437 2".to_vec()).unwrap(),
		);
		let altered = OwnedTlv::new(types::MESSAGE, concatenate(&children)).unwrap();
		assert_eq!(
			read_message(&altered, &|_: &Address| None)
				.unwrap()
				.data
				.original_character_set
				.as_deref(),
			Some("CP437 2")
		);

		// The File and FileRequest semantic readers reject a Message.
		assert!(read_standalone_file(&altered).is_err());
		assert!(read_standalone_file(&message).is_err());
		assert!(read_file_request(&message).is_err());
	}

	#[test]
	fn an_anonymous_identity_is_omitted_from_seen_by() {
		// TSP-0002 section 7: "Anonymous identities are not representable in
		// SeenBy and are omitted." The resulting item still contains exactly one
		// SeenBy, whose collection may be empty.
		let signer_keys = SigningKeyPair::from_seed(&[71; 32]).unwrap();
		let origin: Address = "fidonet#1/100".parse().unwrap();
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(Identity {
				address: origin.clone(),
				public_key: signer_keys.public,
			}),
		};
		let message = build_originated_message(
			&MessageData {
				destination: None,
				timestamp: 1,
				to_user: "All".to_owned(),
				from_user: "Me".to_owned(),
				subject: "Hi".to_owned(),
				text: "Body\n".to_owned(),
				area: Some(area("SYNCHRONET")),
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&provenance,
			&signer_keys.secret,
			7,
			1,
			"test",
			&[],
		)
		.unwrap();
		let resolver = |address: &Address| (address == &origin).then_some(signer_keys.public);
		validate_item(&message, &resolver).unwrap().unwrap();
		let children = parse_sequence(&message.value).unwrap();
		assert_eq!(
			children
				.iter()
				.filter(|child| child.type_code == types::SEEN_BY)
				.count(),
			0,
			"an empty collection emits no SeenBy at all"
		);
	}

	#[test]
	fn every_rejection_reason_and_its_retry_timestamp_survive_parsing() {
		// TSP-0002 section 6 gives each reason a different meaning, and reason 3
		// carries the instant before which the item must not be retried, so
		// neither may be discarded by the parser.
		let hash = TlvHash::from_bytes([3; 32]);
		for (code, expected) in [
			(1, RejectionReason::Permanent),
			(2, RejectionReason::ConditionUnmet),
			(3, RejectionReason::Temporary),
		] {
			let value = rejected(7, hash, None, expected, "because").unwrap();
			let parsed = validate_item(&value, &|_: &Address| None).unwrap().unwrap();
			assert_eq!(parsed.kind, ItemKind::Rejected);
			let rejection = parsed.rejection.expect("a Rejected carries its detail");
			assert_eq!(rejection.reason, expected, "code {code}");
			assert_eq!(rejection.retry_after, None);
			assert_eq!(rejection.description, "because");
		}

		let value = rejected(
			9,
			hash,
			Some(1_755_600_000),
			RejectionReason::Temporary,
			"try later",
		)
		.unwrap();
		let parsed = validate_item(&value, &|_: &Address| None).unwrap().unwrap();
		let rejection = parsed.rejection.unwrap();
		assert_eq!(rejection.reason, RejectionReason::Temporary);
		assert_eq!(rejection.retry_after, Some(1_755_600_000));

		assert!(rejected(10, hash, Some(1), RejectionReason::Permanent, "no").is_err());
		assert!(rejected(10, hash, Some(1), RejectionReason::ConditionUnmet, "no",).is_err());

		let mut obsolete = rejected(11, hash, None, RejectionReason::Temporary, "").unwrap();
		*obsolete.value.last_mut().expect("reason byte") = 4;
		assert!(validate_item(&obsolete, &|_: &Address| None).is_err());

		let mut invalid_timestamp =
			rejected(12, hash, Some(1), RejectionReason::Temporary, "").unwrap();
		*invalid_timestamp.value.last_mut().expect("reason byte") = 1;
		assert!(validate_item(&invalid_timestamp, &|_: &Address| None).is_err());

		// An Accepted has no rejection detail at all.
		let value = accepted(7, hash).unwrap();
		let parsed = validate_item(&value, &|_: &Address| None).unwrap().unwrap();
		assert_eq!(parsed.kind, ItemKind::Accepted);
		assert!(parsed.rejection.is_none());
	}

	#[test]
	fn an_attached_file_cannot_carry_independent_provenance() {
		let base = [
			OwnedTlv::new(types::FILENAME, b"attached.bin".to_vec()).unwrap(),
			OwnedTlv::new(types::CONTENTS, b"contents".to_vec()).unwrap(),
		];
		let valid = OwnedTlv::new(types::FILE, concatenate(&base)).unwrap();
		assert!(validate_file(&valid, false, &|_: &Address| None).is_ok());

		for forbidden in [
			OwnedTlv::new(types::ORIGIN, b"fidonet#1:2/3".to_vec()).unwrap(),
			OwnedTlv::new(types::PUBLIC_KEY, vec![1; 32]).unwrap(),
			OwnedTlv::new(types::SIGNED_ORIGIN, b"fidonet#1:2/3".to_vec()).unwrap(),
			OwnedTlv::new(types::SIGNATURE, vec![2; 64]).unwrap(),
		] {
			let mut children = base.to_vec();
			children.push(forbidden);
			let file = OwnedTlv::new(types::FILE, concatenate(&children)).unwrap();
			assert!(matches!(
				validate_file(&file, false, &|_: &Address| None),
				Err(BundleError::Unexpected("attached File provenance"))
			));
		}
		let mut children = base.to_vec();
		children.push(area_value(&area("FILES")));
		let file = OwnedTlv::new(types::FILE, concatenate(&children)).unwrap();
		assert!(matches!(
			validate_file(&file, false, &|_: &Address| None),
			Err(BundleError::Unexpected("attached File Area"))
		));
	}

	#[test]
	fn a_reason_outside_the_defined_range_is_refused() {
		let mut value = Vec::new();
		OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(1))
			.unwrap()
			.write_to(&mut value)
			.unwrap();
		OwnedTlv::new(types::TLV_HASH, vec![0; 32])
			.unwrap()
			.write_to(&mut value)
			.unwrap();
		value.extend_from_slice(&crate::integer::encode_u64(5));
		let item = OwnedTlv::new(types::REJECTED, value).unwrap();
		assert!(matches!(
			validate_item(&item, &|_: &Address| None),
			Err(BundleError::Unexpected("Rejected reason"))
		));
	}

	/// TSP-0016 sections 3.1 and 4 types 101 and 102 leave exactly one
	/// representation of each of these facts, and this is where a Message is
	/// minted, so this is where a second one is refused.
	#[test]
	fn refuses_a_second_representation_of_a_legacy_fact() {
		let keys = SigningKeyPair::from_seed(&[40; 32]).unwrap();
		let origin: Address = "fidonet#1/100".parse().unwrap();
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(Identity {
				address: origin,
				public_key: keys.public,
			}),
		};
		let netmail = || MessageData {
			destination: Some(Identity {
				address: "fidonet#1/200".parse().unwrap(),
				public_key: keys.public,
			}),
			timestamp: 1,
			to_user: "You".to_owned(),
			from_user: "Me".to_owned(),
			subject: String::new(),
			text: "Body\n".to_owned(),
			area: None,
			attachments: Vec::new(),
			legacy_attributes: None,
			timestamp_offset: None,
			tear_line: None,
			origin_line: None,
			message_id: None,
			reply_to: None,
			original_character_set: None,
			additional_kludge_lines: Vec::new(),
		};
		let build = |data: MessageData| {
			build_originated_message(&data, &provenance, &keys.secret, 7, 1, "test", &[])
		};

		// A Message carrying none of them is what native origination produces.
		assert!(build(netmail()).is_ok());

		// An empty MessageText has no paragraph to terminate.
		assert!(
			build(MessageData {
				text: String::new(),
				..netmail()
			})
			.is_ok()
		);

		let cases: [(MessageData, &str); 8] = [
			(
				MessageData {
					legacy_attributes: Some(0),
					..netmail()
				},
				"zero LegacyAttributes",
			),
			(
				MessageData {
					text: "Body\r\nmore\r\n".to_owned(),
					..netmail()
				},
				"U+000D in MessageText",
			),
			(
				MessageData {
					text: "Body".to_owned(),
					..netmail()
				},
				"a MessageText whose final paragraph is unterminated",
			),
			(
				MessageData {
					timestamp_offset: Some(0),
					..netmail()
				},
				"zero TimestampOffset",
			),
			(
				MessageData {
					legacy_attributes: Some(LEGACY_ATTRIBUTE_FILE_ATTACHED),
					..netmail()
				},
				"LegacyAttributes bit 4, which the File children carry",
			),
			(
				MessageData {
					legacy_attributes: Some(1 << 9),
					..netmail()
				},
				"non-persistent LegacyAttributes bits",
			),
			(
				MessageData {
					tear_line: Some("tosser".to_owned()),
					..netmail()
				},
				"a NetMail TearLine or OriginLine",
			),
			(
				MessageData {
					additional_kludge_lines: vec!["BAD\u{0001}VALUE".to_owned()],
					..netmail()
				},
				"Control-A in AdditionalKludgeLine",
			),
		];
		for (data, expected) in cases {
			match build(data) {
				Err(BundleError::Unexpected(what)) => assert_eq!(what, expected),
				other => panic!("{expected} was accepted: {other:?}"),
			}
		}
		assert!(matches!(
			build(MessageData {
				origin_line: Some("A board (1:1/100)".to_owned()),
				..netmail()
			}),
			Err(BundleError::Unexpected("a NetMail TearLine or OriginLine"))
		));

		let valid = build(netmail()).unwrap();
		let mut children = parse_sequence(&valid.value).unwrap();
		let signature = children
			.iter()
			.position(|child| child.type_code == types::SIGNATURE)
			.unwrap();
		children.insert(
			signature,
			OwnedTlv::new(types::TEAR_LINE, b"legacy display".to_vec()).unwrap(),
		);
		let invalid = OwnedTlv::new(types::MESSAGE, concatenate(&children)).unwrap();
		assert!(matches!(
			validate_message(&invalid, &|_: &Address| Some(keys.public)),
			Err(BundleError::Unexpected("a NetMail TearLine or OriginLine"))
		));

		let mut children = parse_sequence(&valid.value).unwrap();
		children
			.push(OwnedTlv::new(types::ADDITIONAL_KLUDGE_LINE, b"BAD\x01VALUE".to_vec()).unwrap());
		let invalid = OwnedTlv::new(types::MESSAGE, concatenate(&children)).unwrap();
		assert!(matches!(
			validate_message(&invalid, &|_: &Address| Some(keys.public)),
			Err(BundleError::Unexpected("Control-A in AdditionalKludgeLine"))
		));

		// EchoMail keeps both: they are its own control information.
		assert!(
			build(MessageData {
				destination: None,
				area: Some(area("SYNCHRONET")),
				tear_line: Some("tosser".to_owned()),
				origin_line: Some("A board (1:1/100)".to_owned()),
				..netmail()
			})
			.is_ok()
		);
	}

	#[test]
	fn received_messages_enforce_the_canonical_data_rules() {
		let keys = SigningKeyPair::from_seed(&[101; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[102; 32]).unwrap();
		let origin: Address = "fidonet#1/101".parse().unwrap();
		let destination = Identity {
			address: "fidonet#1/102".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let valid = build_originated_message(
			&MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Body\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: keys.public,
				}),
			},
			&keys.secret,
			1,
			1,
			"test",
			&[],
		)
		.unwrap();
		let resolver = |address: &Address| {
			if address == &origin {
				Some(keys.public)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let base = parse_sequence(&valid.value).unwrap();
		let signature = base
			.iter()
			.position(|value| value.type_code == types::SIGNATURE)
			.unwrap();

		for (type_code, bytes, expected) in [
			(types::LEGACY_ATTRIBUTES, crate::integer::encode_u64(0), "zero LegacyAttributes"),
			(
				types::LEGACY_ATTRIBUTES,
				crate::integer::encode_u64(LEGACY_ATTRIBUTE_FILE_ATTACHED),
				"LegacyAttributes bit 4, which the File children carry",
			),
			(
				types::LEGACY_ATTRIBUTES,
				crate::integer::encode_u64(1 << 9),
				"non-persistent LegacyAttributes bits",
			),
			(types::TIMESTAMP_OFFSET, crate::integer::encode_i64(0), "zero TimestampOffset"),
		] {
			let mut children = base.clone();
			children.insert(signature, OwnedTlv::new(type_code, bytes).unwrap());
			let item = container(types::MESSAGE, &children);
			assert!(matches!(
				validate_message(&item, &resolver),
				Err(BundleError::Unexpected(value)) if value == expected
			));
		}

		for (bytes, expected) in [
			(b"Body\r\n".to_vec(), "U+000D in MessageText"),
			(
				b"unterminated".to_vec(),
				"a MessageText whose final paragraph is unterminated",
			),
		] {
			let mut children = base.clone();
			children
				.iter_mut()
				.find(|value| value.type_code == types::MESSAGE_TEXT)
				.unwrap()
				.value = bytes;
			let item = container(types::MESSAGE, &children);
			assert!(matches!(
				validate_message(&item, &resolver),
				Err(BundleError::Unexpected(value)) if value == expected
			));
		}

		let mut children = base;
		children.push(OwnedTlv::new(types::SEEN_BY, b"not an address".to_vec()).unwrap());
		assert!(validate_message(&container(types::MESSAGE, &children), &resolver).is_err());
	}

	#[test]
	fn item_helpers_reject_every_malformed_boundary() {
		let keys = SigningKeyPair::from_seed(&[103; 32]).unwrap();
		let non_anonymous: Address = "fidonet#1/103".parse().unwrap();
		let anonymous = Address::anonymous("p2p".to_owned()).unwrap();
		let key = OwnedTlv::new(types::PUBLIC_KEY, keys.public.as_bytes().to_vec()).unwrap();
		let non_anonymous_value =
			OwnedTlv::new(types::ORIGIN, non_anonymous.to_string().into_bytes()).unwrap();
		let anonymous_value =
			OwnedTlv::new(types::ORIGIN, anonymous.to_string().into_bytes()).unwrap();

		assert!(matches!(
			parse_identity(&anonymous_value, None, &|_: &Address| None),
			Err(BundleError::Missing("anonymous PublicKey"))
		));
		assert!(parse_identity(&anonymous_value, Some(&key), &|_: &Address| None).is_ok());
		assert!(matches!(
			parse_identity(&non_anonymous_value, Some(&key), &|_: &Address| None),
			Err(BundleError::Unexpected("non-anonymous PublicKey"))
		));
		assert!(matches!(
			parse_identity(&non_anonymous_value, None, &|_: &Address| None),
			Err(BundleError::UnknownKey(_))
		));
		assert!(
			parse_identity(&non_anonymous_value, None, &|_: &Address| Some(keys.public)).is_ok()
		);

		assert!(matches!(
			parse_provenance(&anonymous_value, None, None, &|_: &Address| None),
			Err(BundleError::Missing("anonymous Origin PublicKey"))
		));
		assert!(matches!(
			parse_provenance(
				&non_anonymous_value,
				Some(&key),
				None,
				&|_: &Address| None
			),
			Err(BundleError::Unexpected("non-anonymous Origin PublicKey"))
		));
		assert!(matches!(
			parse_provenance(&non_anonymous_value, None, None, &|_: &Address| None),
			Err(BundleError::UnknownKey(_))
		));

		let values = vec![OwnedTlv::new(200, Vec::new()).unwrap(), key.clone()];
		let mut cursor = Cursor::new(&values);
		assert!(conditional_public_key(&mut cursor, &anonymous).is_err());
		let values = vec![key.clone()];
		let mut cursor = Cursor::new(&values);
		assert!(conditional_public_key(&mut cursor, &anonymous).is_ok());
		let mut cursor = Cursor::new(&values);
		assert!(conditional_public_key(&mut cursor, &non_anonymous).is_err());
		let mut cursor = Cursor::new(&[]);
		assert_eq!(conditional_public_key(&mut cursor, &non_anonymous).unwrap(), None);

		let values = vec![
			OwnedTlv::new(200, Vec::new()).unwrap(),
			OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
			OwnedTlv::new(201, Vec::new()).unwrap(),
		];
		let mut cursor = Cursor::new(&values);
		assert_eq!(cursor.next_defined().unwrap().1.type_code, types::TIMESTAMP);
		assert!(cursor.next_defined().is_none());
		let mut cursor = Cursor::new(&values);
		assert!(cursor.take(types::CONTENTS, "Contents").is_err());
		let mut cursor = Cursor::new(&[]);
		assert!(cursor.take(types::CONTENTS, "Contents").is_err());
		let cursor = Cursor::new(&values);
		assert!(cursor.finish().is_err());
		let unknown = vec![OwnedTlv::new(200, Vec::new()).unwrap()];
		assert!(Cursor::new(&unknown).finish().is_ok());

		let mut output = Vec::new();
		assert!(push_file_metadata(&mut output, Some("bad\n"), &[], None, None, None).is_err());
		assert!(
			push_file_metadata(
				&mut output,
				None,
				&["bad\r".to_owned()],
				None,
				None,
				None
			)
			.is_err()
		);
		assert!(validate_produced_filename("dir/file").is_err());
		assert!(validate_produced_filename("bad:name").is_err());
		assert!(validate_produced_filename("good.name").is_ok());
		assert!(push_filename(&mut output, None).is_ok());

		let anonymous_signer = Identity {
			address: anonymous.clone(),
			public_key: keys.public,
		};
		assert!(matches!(
			push_provenance(
				&mut output,
				&ItemProvenance {
					origin: anonymous.clone(),
					signer: None,
				}
			),
			Err(BundleError::Missing("item signing identity"))
		));
		assert!(matches!(
			push_provenance(
				&mut output,
				&ItemProvenance {
					origin: anonymous,
					signer: Some(Identity {
						address: non_anonymous.clone(),
						public_key: keys.public,
					}),
				}
			),
			Err(BundleError::Unexpected(
				"anonymous Origin without its own PublicKey"
			))
		));
		assert!(push_provenance(
			&mut output,
			&ItemProvenance {
				origin: anonymous_signer.address.clone(),
				signer: Some(anonymous_signer),
			}
		)
		.is_ok());

		let malformed_vias = [
			container(
				types::VIA,
				&[OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap()],
			),
			container(
				types::VIA,
				&[
					OwnedTlv::new(types::ADDRESS, b"p2p#-1".to_vec()).unwrap(),
					OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
				],
			),
			container(
				types::VIA,
				&[
					OwnedTlv::new(types::ADDRESS, b"fidonet#1/1".to_vec()).unwrap(),
					key.clone(),
				],
			),
			container(
				types::VIA,
				&[
					OwnedTlv::new(types::ADDRESS, b"fidonet#1/1".to_vec()).unwrap(),
					OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap(),
				],
			),
		];
		for value in malformed_vias {
			assert!(read_via(&value).is_err());
		}
		let reply = container(
			types::REPLY_TO,
			&[OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap()],
		);
		assert!(matches!(
			read_reply_to(&reply),
			Err(BundleError::Missing("ReplyTo Address"))
		));

		assert_eq!(
			validate_area(&area_value(&AreaData {
				name: "ANY UTF-8 😀".to_owned(),
				description: Some("description".to_owned()),
			}))
			.unwrap()
			.description
			.as_deref(),
			Some("description")
		);
	}

	#[test]
	fn retained_and_forwarded_items_cover_every_suffix_path() {
		let keys = SigningKeyPair::from_seed(&[104; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[105; 32]).unwrap();
		let origin: Address = "fidonet#1/104".parse().unwrap();
		let local = Identity {
			address: origin.clone(),
			public_key: keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/105".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let data = MessageData {
			destination: Some(destination.clone()),
			timestamp: 1,
			to_user: "You".to_owned(),
			from_user: "Me".to_owned(),
			subject: String::new(),
			text: "Body\n".to_owned(),
			area: None,
			attachments: Vec::new(),
			legacy_attributes: None,
			timestamp_offset: None,
			tear_line: None,
			origin_line: None,
			message_id: None,
			reply_to: None,
			original_character_set: None,
			additional_kludge_lines: vec!["FLAGS KFS".to_owned()],
		};
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(local.clone()),
		};
		let message = build_originated_message(
			&data,
			&provenance,
			&keys.secret,
			1,
			1,
			"test",
			&[],
		)
		.unwrap();
		let resolver = |address: &Address| {
			if address == &origin {
				Some(keys.public)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let signature = read_message(&message, &resolver)
			.unwrap()
			.signing
			.signature
			.unwrap();
		let suffix = |existing_vias| MessageSuffix {
			existing_vias,
			local_via: &local,
			request_identifier: 2,
			via_timestamp: 2,
			software: "test 2",
			seen_by: &[],
		};
		assert!(build_retained_message(
			&data,
			&provenance,
			Signature::from_bytes([0; SIGNATURE_BYTES]),
			&suffix(&[])
		)
		.is_err());

		let missing_key = [ViaData {
			address: Address::anonymous("p2p".to_owned()).unwrap(),
			public_key: None,
			timestamp: 1,
			software: "old".to_owned(),
		}];
		assert!(build_retained_message(
			&data,
			&provenance,
			signature,
			&suffix(&missing_key)
		)
		.is_err());
		let extra_key = [ViaData {
			address: origin.clone(),
			public_key: Some(keys.public),
			timestamp: 1,
			software: "old".to_owned(),
		}];
		assert!(build_retained_message(
			&data,
			&provenance,
			signature,
			&suffix(&extra_key)
		)
		.is_err());
		let valid_vias = [
			ViaData {
				address: origin.clone(),
				public_key: None,
				timestamp: 1,
				software: "old".to_owned(),
			},
			ViaData {
				address: Address::anonymous("p2p".to_owned()).unwrap(),
				public_key: Some(keys.public),
				timestamp: 1,
				software: "anonymous".to_owned(),
			},
		];
		assert!(build_retained_message(
			&data,
			&provenance,
			signature,
			&suffix(&valid_vias)
		)
		.is_ok());

		let request = build_file_request("file.zip", None, 1).unwrap();
		assert!(forward_item(&request, &local, 2, 2, "test", &[]).is_err());
		let mut unsigned_children = parse_sequence(&message.value).unwrap();
		unsigned_children.retain(|value| value.type_code != types::SIGNATURE);
		let unsigned = container(types::MESSAGE, &unsigned_children);
		assert!(forward_item(&unsigned, &local, 2, 2, "test", &[]).is_err());

		let mut children = parse_sequence(&message.value).unwrap();
		let signature_index = children
			.iter()
			.position(|value| value.type_code == types::SIGNATURE)
			.unwrap();
		children.insert(signature_index + 1, OwnedTlv::new(200, b"extension".to_vec()).unwrap());
		let extended = container(types::MESSAGE, &children);
		let forwarded = forward_item(
			&extended,
			&local,
			3,
			3,
			"test 3",
			&["fidonet#1/200".parse().unwrap()],
		)
		.unwrap();
		assert!(parse_sequence(&forwarded.value)
			.unwrap()
			.iter()
			.any(|value| value.type_code == 200));
		forward_item(&extended, &local, 4, 4, "test 4", &[]).unwrap();

		let file = build_originated_file(
			StandaloneFileData {
				filename: Some("file.zip".to_owned()),
				timestamp: None,
				contents: b"file".to_vec(),
				area: Some(area("FILES")),
				short_description: None,
				long_description_lines: Vec::new(),
				tear_line: None,
				magic_word: None,
				replaces: None,
			},
			&provenance,
			&keys.secret,
			1,
			1,
			"test",
			std::slice::from_ref(&origin),
		)
		.unwrap();
		forward_item(&file, &local, 2, 2, "test 2", &[origin]).unwrap();
		assert!(item_vias(&OwnedTlv::new(types::MESSAGE, vec![1]).unwrap()).is_err());
	}

	#[test]
	fn message_and_file_grammars_reject_each_prohibited_shape() {
		let keys = SigningKeyPair::from_seed(&[106; 32]).unwrap();
		let origin: Address = "fidonet#1/106".parse().unwrap();
		let origin_value = OwnedTlv::new(types::ORIGIN, origin.to_string().into_bytes()).unwrap();
		let request = OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap();
		let via = via_value(
			&Identity {
				address: origin.clone(),
				public_key: keys.public,
			},
			1,
			"test",
		);
		let area = area_value(&area("AREA"));

		let base_message = [
			origin_value.clone(),
			OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
			OwnedTlv::new(types::TO_USER_NAME, Vec::new()).unwrap(),
			OwnedTlv::new(types::FROM_USER_NAME, Vec::new()).unwrap(),
			OwnedTlv::new(types::SUBJECT, Vec::new()).unwrap(),
			OwnedTlv::new(types::MESSAGE_TEXT, Vec::new()).unwrap(),
		];
		let mut neither = base_message.to_vec();
		neither.extend([request.clone(), via.clone()]);
		let mut both = vec![
			origin_value.clone(),
			OwnedTlv::new(types::DESTINATION, b"fidonet#1/107".to_vec()).unwrap(),
		];
		both.extend_from_slice(&base_message[1..]);
		both.extend([area.clone(), request.clone(), via.clone()]);
		for children in [neither, both] {
			assert!(matches!(
				validate_message(&container(types::MESSAGE, &children), &|_: &Address| {
					Some(keys.public)
				}),
				Err(BundleError::Unexpected("Message Destination/Area combination"))
			));
		}
		let mut no_via = base_message.to_vec();
		no_via.extend([area.clone(), request.clone()]);
		assert!(matches!(
			validate_message(&container(types::MESSAGE, &no_via), &|_: &Address| {
				Some(keys.public)
			}),
			Err(BundleError::Missing("Message Via"))
		));
		let mut signed_without_signature = base_message.to_vec();
		signed_without_signature.insert(
			1,
			OwnedTlv::new(types::SIGNED_ORIGIN, origin.to_string().into_bytes()).unwrap(),
		);
		signed_without_signature.extend([area.clone(), request.clone(), via.clone()]);
		assert!(matches!(
			validate_message(
				&container(types::MESSAGE, &signed_without_signature),
				&|_: &Address| Some(keys.public)
			),
			Err(BundleError::Unexpected("SignedOrigin without Signature"))
		));

		let contents = OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap();
		let validate_standalone = |children: &[OwnedTlv]| {
			validate_file(
				&container(types::FILE, children),
				true,
				&|_: &Address| Some(keys.public),
			)
		};
		assert!(matches!(
			validate_standalone(&[contents.clone(), request.clone()]),
			Err(BundleError::Missing("standalone File Origin"))
		));
		assert!(matches!(
			validate_file(
				&container(types::FILE, &[contents.clone(), area.clone()]),
				false,
				&|_: &Address| None
			),
			Err(BundleError::Unexpected("attached File Area"))
		));
		assert!(matches!(
			validate_standalone(&[
				contents.clone(),
				origin_value.clone(),
				OwnedTlv::new(types::SIGNED_ORIGIN, origin.to_string().into_bytes()).unwrap(),
				request.clone(),
			]),
			Err(BundleError::Unexpected("SignedOrigin without Signature"))
		));

		for description in [
			OwnedTlv::new(types::SHORT_DESCRIPTION, b"bad\n".to_vec()).unwrap(),
			OwnedTlv::new(types::LONG_DESCRIPTION_LINE, b"bad\r".to_vec()).unwrap(),
		] {
			assert!(validate_standalone(&[
				contents.clone(),
				origin_value.clone(),
				description,
				request.clone(),
			])
			.is_err());
		}
		assert!(validate_standalone(&[
			OwnedTlv::new(types::FILENAME, b"dir/file".to_vec()).unwrap(),
			contents.clone(),
			origin_value.clone(),
			request.clone(),
		])
		.is_err());

		let seen = OwnedTlv::new(types::SEEN_BY, origin.to_string().into_bytes()).unwrap();
		for suffix in [
			vec![area.clone(), origin_value.clone(), request.clone()],
			vec![area.clone(), origin_value.clone(), request.clone(), via.clone()],
			vec![area, origin_value.clone(), request.clone(), seen.clone()],
		] {
			let mut children = vec![contents.clone()];
			children.extend(suffix);
			assert!(matches!(
				validate_standalone(&children),
				Err(BundleError::Missing("distribution File Via/SeenBy"))
			));
		}
		for suffix in [vec![via], vec![seen]] {
			let mut children = vec![contents.clone(), origin_value.clone(), request.clone()];
			children.extend(suffix);
			assert!(matches!(
				validate_standalone(&children),
				Err(BundleError::Unexpected("non-distribution File Via/SeenBy"))
			));
		}
	}

	#[test]
	fn item_consumers_cover_each_remaining_negative_boundary() {
		let keys = SigningKeyPair::from_seed(&[108; 32]).unwrap();
		let origin: Address = "fidonet#1/108".parse().unwrap();
		let signed_origin: Address = "fidonet#1/109".parse().unwrap();
		let destination = Identity {
			address: "fidonet#1/110".parse().unwrap(),
			public_key: keys.public,
		};
		let provenance = ItemProvenance {
			origin: origin.clone(),
			signer: Some(Identity {
				address: origin.clone(),
				public_key: keys.public,
			}),
		};
		let data = || MessageData {
			destination: Some(destination.clone()),
			timestamp: 1,
			to_user: "You".to_owned(),
			from_user: "Me".to_owned(),
			subject: String::new(),
			text: "Body\n".to_owned(),
			area: None,
			attachments: Vec::new(),
			legacy_attributes: None,
			timestamp_offset: None,
			tear_line: None,
			origin_line: None,
			message_id: None,
			reply_to: None,
			original_character_set: None,
			additional_kludge_lines: Vec::new(),
		};
		let suffix = MessageSuffix {
			existing_vias: &[],
			local_via: provenance.signer.as_ref().unwrap(),
			request_identifier: 1,
			via_timestamp: 1,
			software: "test",
			seen_by: &[],
		};
		for invalid in [
			MessageData {
				destination: None,
				..data()
			},
			MessageData {
				area: Some(area("AREA")),
				..data()
			},
		] {
			assert!(matches!(
				build_retained_message(
					&invalid,
					&provenance,
					Signature::from_bytes([0; SIGNATURE_BYTES]),
					&suffix,
				),
				Err(BundleError::Unexpected("Message Destination/Area combination"))
			));
		}
		let mut bad_attachment = data();
		bad_attachment.attachments.push(AttachmentData {
			filename: Some("file.txt".to_owned()),
			timestamp: None,
			contents: Vec::new(),
			short_description: Some("bad\n".to_owned()),
			long_description_lines: Vec::new(),
			tear_line: None,
			magic_word: None,
			replaces: None,
		});
		assert!(build_originated_message(
			&bad_attachment,
			&provenance,
			&keys.secret,
			1,
			1,
			"test",
			&[],
		)
		.is_err());

		let origin_value = OwnedTlv::new(types::ORIGIN, origin.to_string().into_bytes()).unwrap();
		let via = via_value(provenance.signer.as_ref().unwrap(), 1, "test");
		let message_prefix = || {
			vec![
				origin_value.clone(),
				OwnedTlv::new(
					types::DESTINATION,
					destination.address.to_string().into_bytes(),
				)
				.unwrap(),
				OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
				OwnedTlv::new(types::TO_USER_NAME, Vec::new()).unwrap(),
				OwnedTlv::new(types::FROM_USER_NAME, Vec::new()).unwrap(),
				OwnedTlv::new(types::SUBJECT, Vec::new()).unwrap(),
				OwnedTlv::new(types::MESSAGE_TEXT, Vec::new()).unwrap(),
			]
		};
		let resolver = |address: &Address| (address != &origin).then_some(keys.public);
		let full_resolver = |_: &Address| Some(keys.public);
		let signed_message = build_originated_message(
			&data(),
			&provenance,
			&keys.secret,
			1,
			1,
			"test",
			&[],
		)
		.unwrap();
		let signature = read_message(&signed_message, &resolver)
			.unwrap()
			.signing
			.signature
			.unwrap();
		assert!(build_retained_message_with(
			&data(),
			&provenance,
			signature,
			&suffix,
			verification_error,
		)
		.is_err());
		assert!(validate_message_with(&signed_message, &full_resolver, verification_error).is_err());
		let signed_file = build_originated_file(
			StandaloneFileData {
				filename: Some("file.txt".to_owned()),
				timestamp: None,
				contents: Vec::new(),
				area: None,
				short_description: None,
				long_description_lines: Vec::new(),
				tear_line: None,
				magic_word: None,
				replaces: None,
			},
			&provenance,
			&keys.secret,
			1,
			1,
			"test",
			&[],
		)
		.unwrap();
		assert!(validate_file_with(&signed_file, true, &full_resolver, verification_error).is_err());

		let mut invalid_signed_origin = vec![
			origin_value.clone(),
			OwnedTlv::new(types::SIGNED_ORIGIN, signed_origin.to_string().into_bytes()).unwrap(),
		];
		invalid_signed_origin.extend(message_prefix().into_iter().skip(1));
		invalid_signed_origin.extend([
			OwnedTlv::new(types::SIGNATURE, vec![0; SIGNATURE_BYTES]).unwrap(),
			OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
			via.clone(),
		]);
		let validated = validate_message(
			&container(types::MESSAGE, &invalid_signed_origin),
			&resolver,
		)
		.unwrap();
		assert_eq!(
			validated.authentication,
			Some(ItemAuthentication::SignedOriginInvalid)
		);

		let malformed_attachment = container(
			types::FILE,
			&[
				OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap(),
				OwnedTlv::new(types::SHORT_DESCRIPTION, b"bad\n".to_vec()).unwrap(),
			],
		);
		let malformed_reply = container(
			types::REPLY_TO,
			&[OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap()],
		);
		for extra in [malformed_attachment, malformed_reply] {
			let mut children = message_prefix();
			children.push(extra);
			children.extend([
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
				via.clone(),
			]);
			assert!(validate_message(&container(types::MESSAGE, &children), &resolver).is_err());
		}

		let mut malformed_message_id = message_prefix();
		malformed_message_id.extend([
			OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![0x80]).unwrap(),
			via.clone(),
		]);
		let malformed_message = container(types::MESSAGE, &malformed_message_id);
		assert!(validate_message(&malformed_message, &resolver).is_err());
		assert!(read_message(&malformed_message, &resolver).is_err());

		let mut no_via = message_prefix();
		no_via.push(OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap());
		let no_via = container(types::MESSAGE, &no_via);
		assert!(read_message(&no_via, &resolver).is_err());

		let mut unsigned = message_prefix();
		unsigned.extend([
			OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
			via,
		]);
		assert!(read_message(&container(types::MESSAGE, &unsigned), &resolver)
			.unwrap()
			.signing
			.signature
			.is_none());
		let mut invalid_kludge = message_prefix();
		invalid_kludge.extend([
			OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
			via_value(provenance.signer.as_ref().unwrap(), 1, "test"),
			OwnedTlv::new(types::ADDITIONAL_KLUDGE_LINE, vec![0xff]).unwrap(),
		]);
		assert!(validate_message(&container(types::MESSAGE, &invalid_kludge), &resolver).is_err());

		let malformed_file = container(
			types::FILE,
			&[
				OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap(),
				origin_value.clone(),
				OwnedTlv::new(types::TEAR_LINE, vec![0xff]).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![0x80]).unwrap(),
			],
		);
		assert!(validate_file(&malformed_file, true, &resolver).is_err());
		assert!(read_standalone_file(&malformed_file).is_err());
		let malformed_file_identifier = container(
			types::FILE,
			&[
				OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap(),
				origin_value.clone(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![0x80]).unwrap(),
			],
		);
		assert!(validate_file(&malformed_file_identifier, true, &resolver).is_err());
		assert!(read_standalone_file(&malformed_file_identifier).is_err());
		let invalid_long_description = container(
			types::FILE,
			&[
				OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap(),
				origin_value.clone(),
				OwnedTlv::new(types::LONG_DESCRIPTION_LINE, vec![0xff]).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
			],
		);
		assert!(validate_file(&invalid_long_description, true, &resolver).is_err());

		let malformed_request = container(
			types::FILE_REQUEST,
			&[
				OwnedTlv::new(types::FILENAME, b"file.txt".to_vec()).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![0x80]).unwrap(),
			],
		);
		assert!(validate_file_request(&malformed_request).is_err());
		assert!(read_file_request(&malformed_request).is_err());

		let valid_file = container(
			types::FILE,
			&[
				OwnedTlv::new(types::CONTENTS, Vec::new()).unwrap(),
				origin_value,
				OwnedTlv::new(types::REQUEST_IDENTIFIER, vec![1]).unwrap(),
			],
		);
		assert!(MessageModel::parse(&valid_file, &resolver).is_err());
		assert!(read_message(&valid_file, &resolver).is_err());
		assert!(ItemModel::parse(
			&OwnedTlv::new(types::POLL_MESSAGES, Vec::new()).unwrap(),
			&resolver,
		)
		.is_err());
	}
}
