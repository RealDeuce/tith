// TTS-0005 request, response, and payload-carrier operations.

#[derive(Debug)]
pub struct PayloadError {
	pub item_index: usize,
	pub source: BundleError,
}

impl fmt::Display for PayloadError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "payload item {}: {}", self.item_index, self.source)
	}
}

impl std::error::Error for PayloadError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(&self.source)
	}
}

fn simple_request(value: &OwnedTlv, kind: ItemKind) -> Result<ValidatedItem, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let request_identifier = decode_u64(
		&cursor
			.take(types::REQUEST_IDENTIFIER, "RequestIdentifier")?
			.1
			.value,
	)?;
	cursor.finish()?;
	Ok(ValidatedItem {
		kind,
		request_identifier,
		duplicate_identity: None,
		authentication: None,
		response_to: None,
		response_public_key: None,
		rejection: None,
		provenance: None,
		destination: None,
		area: None,
		raw: value.clone(),
	})
}

fn validate_response(value: &OwnedTlv, accepted: bool) -> Result<ValidatedItem, BundleError> {
	let bytes = &value.value;
	let children = parse_sequence(bytes);
	if accepted {
		let children = children?;
		let mut cursor = Cursor::new(&children);
		let request_identifier = decode_u64(
			&cursor
				.take(types::REQUEST_IDENTIFIER, "Accepted RequestIdentifier")?
				.1
				.value,
		)?;
		let (_, hash) = cursor.take(types::TLV_HASH, "Accepted TLVHash")?;
		if hash.value.len() != 32 {
			return Err(BundleError::WrongLength("TLVHash"));
		}
		let response_to = TlvHash::from_bytes(
			hash.value
				.as_slice()
				.try_into()
				.expect("length checked above"),
		);
		let response_public_key = cursor
			.optional(types::PUBLIC_KEY)
			.map(|(_, value)| parse_public_key(value))
			.transpose()?;
		cursor.finish()?;
		return Ok(ValidatedItem {
			kind: ItemKind::Accepted,
			request_identifier,
			duplicate_identity: None,
			authentication: None,
			response_to: Some(response_to),
			response_public_key,
			rejection: None,
			provenance: None,
			destination: None,
			area: None,
			raw: value.clone(),
		});
	}

	// Rejected ends with a raw canonical reason number and an optional UTF-8
	// description, so parse its leading TLVs without treating the tail as TLV.
	let (request, used_request) = take_encoded_tlv(bytes)?;
	if request.type_code != types::REQUEST_IDENTIFIER {
		return Err(BundleError::Missing("Rejected RequestIdentifier"));
	}
	let request_identifier = decode_u64(&request.value)?;
	let (hash, used_hash) = take_encoded_tlv(&bytes[used_request..])?;
	if hash.type_code != types::TLV_HASH || hash.value.len() != 32 {
		return Err(BundleError::WrongLength("Rejected TLVHash"));
	}
	let response_to = TlvHash::from_bytes(
		hash.value
			.as_slice()
			.try_into()
			.expect("length checked above"),
	);
	let mut offset = used_request + used_hash;
	let mut retry_after = None;
	if let Ok((timestamp, used_timestamp)) = take_encoded_tlv(&bytes[offset..])
		&& timestamp.type_code == types::TIMESTAMP
	{
		retry_after = Some(decode_u64(&timestamp.value)?);
		offset += used_timestamp;
	}
	let (reason, used_reason) = decode_u64_prefix(&bytes[offset..])?;
	let reason =
		RejectionReason::from_code(reason).ok_or(BundleError::Unexpected("Rejected reason"))?;
	if retry_after.is_some() && reason != RejectionReason::Temporary {
		return Err(BundleError::Unexpected(
			"Rejected Timestamp for non-temporary reason",
		));
	}
	offset += used_reason;
	let description = std::str::from_utf8(&bytes[offset..])
		.map_err(|_| BundleError::InvalidUtf8)?
		.to_owned();
	Ok(ValidatedItem {
		kind: ItemKind::Rejected,
		request_identifier,
		duplicate_identity: None,
		authentication: None,
		response_to: Some(response_to),
		response_public_key: None,
		rejection: Some(Rejection {
			reason,
			retry_after,
			description,
		}),
		provenance: None,
		destination: None,
		area: None,
		raw: value.clone(),
	})
}

pub fn accepted(request_identifier: u64, response_to: TlvHash) -> Result<OwnedTlv, BundleError> {
	let children = [
		OwnedTlv::new(
			types::REQUEST_IDENTIFIER,
			crate::integer::encode_u64(request_identifier),
		)?,
		OwnedTlv::new(types::TLV_HASH, response_to.as_bytes().to_vec())?,
	];
	OwnedTlv::new(types::ACCEPTED, encoded_prefix(&children, children.len())).map_err(Into::into)
}

/// Builds an Accepted response which certifies the server's current key for a
/// `PublicKeyRequest`. The enclosing payload `SignedTLV` authenticates the key.
pub fn accepted_public_key(
	request_identifier: u64,
	response_to: TlvHash,
	public_key: PublicKey,
) -> Result<OwnedTlv, BundleError> {
	let children = [
		OwnedTlv::new(
			types::REQUEST_IDENTIFIER,
			crate::integer::encode_u64(request_identifier),
		)?,
		OwnedTlv::new(types::TLV_HASH, response_to.as_bytes().to_vec())?,
		OwnedTlv::new(types::PUBLIC_KEY, public_key.as_bytes().to_vec())?,
	];
	OwnedTlv::new(types::ACCEPTED, encoded_prefix(&children, children.len())).map_err(Into::into)
}

/// Builds the sole request in a native public-key discovery probe.
pub fn public_key_request(request_identifier: u64) -> Result<OwnedTlv, BundleError> {
	let child = OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	)?;
	OwnedTlv::new(types::PUBLIC_KEY_REQUEST, child.encode()).map_err(Into::into)
}

pub fn rejected(
	request_identifier: u64,
	response_to: TlvHash,
	timestamp: Option<u64>,
	reason: RejectionReason,
	description: &str,
) -> Result<OwnedTlv, BundleError> {
	if timestamp.is_some() && reason != RejectionReason::Temporary {
		return Err(BundleError::Unexpected(
			"Rejected Timestamp for non-temporary reason",
		));
	}
	let mut value = Vec::new();
	OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	)?
	.write_to(&mut value)?;
	OwnedTlv::new(types::TLV_HASH, response_to.as_bytes().to_vec())?.write_to(&mut value)?;
	if let Some(timestamp) = timestamp {
		OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(timestamp))?
			.write_to(&mut value)?;
	}
	value.extend_from_slice(&crate::integer::encode_u64(reason as u64));
	value.extend_from_slice(description.as_bytes());
	OwnedTlv::new(types::REJECTED, value).map_err(Into::into)
}

#[must_use]
pub fn request_identifier(value: &OwnedTlv) -> Option<u64> {
	let children = parse_sequence(&value.value).ok()?;
	let mut identifiers = children
		.iter()
		.filter(|child| child.type_code == types::REQUEST_IDENTIFIER)
		.map(|child| decode_u64(&child.value));
	let identifier = identifiers.next()?.ok()?;
	identifiers.next().is_none().then_some(identifier)
}

/// Replaces a stored request's `RequestIdentifier` in place.
///
/// A `RequestIdentifier` identifies a request within one exchange, so a sender
/// which spools an item and later combines several spooled items into one
/// Bundle must renumber them. It sits outside every signed region — the
/// signature covers the children which precede it — so rewriting it does not
/// disturb end-to-end authentication.
///
/// # Errors
///
/// Returns [`BundleError`] when `value` is not a sequence of TLV values or does
/// not carry exactly one `RequestIdentifier`.
pub fn set_request_identifier(value: &OwnedTlv, identifier: u64) -> Result<OwnedTlv, BundleError> {
	let mut children = parse_sequence(&value.value)?;
	let mut found = 0usize;
	for child in &mut children {
		if child.type_code == types::REQUEST_IDENTIFIER {
			child.value = crate::integer::encode_u64(identifier);
			found += 1;
		}
	}
	if found != 1 {
		return Err(BundleError::Missing("exactly one RequestIdentifier"));
	}
	OwnedTlv::new(value.type_code, encoded_prefix(&children, children.len())).map_err(Into::into)
}

pub fn validate_item(
	value: &OwnedTlv,
	resolver: &impl KeyResolver,
) -> Result<Option<ValidatedItem>, BundleError> {
	match value.type_code {
		types::MESSAGE => validate_message(value, resolver).map(Some),
		types::FILE => validate_file(value, true, resolver),
		types::FILE_REQUEST => validate_file_request(value).map(Some),
		types::ACCEPTED => validate_response(value, true).map(Some),
		types::REJECTED => validate_response(value, false).map(Some),
		types::POLL_MESSAGES => simple_request(value, ItemKind::PollMessages).map(Some),
		types::POLL_FILES => simple_request(value, ItemKind::PollFiles).map(Some),
		types::POLL_FILE_REQUESTS => simple_request(value, ItemKind::PollFileRequests).map(Some),
		types::PUBLIC_KEY_REQUEST => simple_request(value, ItemKind::PublicKeyRequest).map(Some),
		_ => Ok(None),
	}
}

pub fn validate_payload(
	payload: &VerifiedSignedTlv,
	resolver: &impl KeyResolver,
) -> Result<Vec<ValidatedItem>, PayloadError> {
	let mut validated = Vec::new();
	let mut request_identifiers = HashSet::new();
	for (index, item) in payload.data.iter().enumerate().skip(1) {
		let result = validate_item(item, resolver);
		match result {
			Ok(Some(validated_item)) => {
				if types::is_request(item.type_code)
					&& !request_identifiers.insert(validated_item.request_identifier)
				{
					return Err(PayloadError {
						item_index: index,
						source: BundleError::Duplicate("request identifier"),
					});
				}
				validated.push(validated_item);
			}
			Ok(None) => {}
			Err(source) => {
				return Err(PayloadError {
					item_index: index,
					source,
				});
			}
		}
	}
	Ok(validated)
}
