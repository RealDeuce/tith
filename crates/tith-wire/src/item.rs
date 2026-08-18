//! Structural and end-to-end validation of TTS-0005 payload values.

use std::fmt;

use tith_crypto::{PublicKey, SIGNATURE_BYTES, Signature, TlvHash, verify_tlv};

use crate::address::Address;
use crate::bundle::{BundleError, Identity, KeyResolver, VerifiedSignedTlv};
use crate::integer::{decode_i64, decode_u64, decode_u64_prefix};
use crate::tlv::{OwnedTlv, parse_sequence};
use crate::types;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
	NetMail,
	EchoMail,
	File,
	FileRequest,
	Accepted,
	Rejected,
	PollMessages,
	PollFiles,
	PollFileRequests,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedItemIdentity {
	pub type_code: u64,
	pub origin: Identity,
	pub signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedItem {
	pub kind: ItemKind,
	pub request_identifier: u64,
	pub duplicate_identity: Option<SignedItemIdentity>,
	pub response_to: Option<TlvHash>,
	pub raw: OwnedTlv,
}

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

struct Cursor<'a> {
	values: &'a [OwnedTlv],
	index: usize,
}

impl<'a> Cursor<'a> {
	fn new(values: &'a [OwnedTlv]) -> Self {
		Self { values, index: 0 }
	}

	fn next_defined(&mut self) -> Option<(usize, &'a OwnedTlv)> {
		while let Some(value) = self.values.get(self.index) {
			let index = self.index;
			self.index += 1;
			if types::is_defined(value.type_code) {
				return Some((index, value));
			}
		}
		None
	}

	fn peek_type(&mut self) -> Option<u64> {
		let saved = self.index;
		let result = self.next_defined().map(|(_, value)| value.type_code);
		self.index = saved;
		result
	}

	fn take(
		&mut self,
		expected: u64,
		name: &'static str,
	) -> Result<(usize, &'a OwnedTlv), BundleError> {
		match self.next_defined() {
			Some((index, value)) if value.type_code == expected => Ok((index, value)),
			Some(_) | None => Err(BundleError::Missing(name)),
		}
	}

	fn optional(&mut self, expected: u64) -> Option<(usize, &'a OwnedTlv)> {
		if self.peek_type() == Some(expected) {
			self.next_defined()
		} else {
			None
		}
	}

	fn repeated(&mut self, expected: u64) -> Vec<(usize, &'a OwnedTlv)> {
		let mut values = Vec::new();
		while self.peek_type() == Some(expected) {
			values.push(self.next_defined().expect("peek found a value"));
		}
		values
	}

	fn finish(mut self) -> Result<(), BundleError> {
		if self.next_defined().is_some() {
			Err(BundleError::Unexpected("defined child value"))
		} else {
			Ok(())
		}
	}
}

fn text(value: &OwnedTlv) -> Result<&str, BundleError> {
	std::str::from_utf8(&value.value).map_err(|_| BundleError::InvalidUtf8)
}

fn parse_address(value: &OwnedTlv) -> Result<Address, BundleError> {
	Ok(text(value)?.parse()?)
}

fn parse_public_key(value: &OwnedTlv) -> Result<PublicKey, BundleError> {
	let bytes = value
		.value
		.as_slice()
		.try_into()
		.map_err(|_| BundleError::WrongLength("PublicKey"))?;
	Ok(PublicKey::from_bytes(bytes))
}

fn parse_signature(value: &OwnedTlv) -> Result<Signature, BundleError> {
	let bytes: [u8; SIGNATURE_BYTES] = value
		.value
		.as_slice()
		.try_into()
		.map_err(|_| BundleError::WrongLength("Signature"))?;
	Ok(Signature::from_bytes(bytes))
}

fn parse_identity(
	origin: &OwnedTlv,
	public_key: Option<&OwnedTlv>,
	resolver: &impl KeyResolver,
) -> Result<Identity, BundleError> {
	let address = parse_address(origin)?;
	let public_key = if address.is_unlisted() {
		parse_public_key(public_key.ok_or(BundleError::Missing("unlisted PublicKey"))?)?
	} else {
		if public_key.is_some() {
			return Err(BundleError::Unexpected("listed PublicKey"));
		}
		resolver
			.public_key(&address)
			.ok_or_else(|| BundleError::UnknownKey(address.clone()))?
	};
	Ok(Identity {
		address,
		public_key,
	})
}

fn conditional_public_key<'a>(
	cursor: &mut Cursor<'a>,
	address: &Address,
) -> Result<Option<&'a OwnedTlv>, BundleError> {
	let value = cursor
		.values
		.get(cursor.index)
		.filter(|value| value.type_code == types::PUBLIC_KEY);
	if value.is_some() {
		cursor.index += 1;
	}
	if address.is_unlisted() && value.is_none() {
		Err(BundleError::Missing("PublicKey after unlisted address"))
	} else if !address.is_unlisted() && value.is_some() {
		Err(BundleError::Unexpected("PublicKey after listed address"))
	} else {
		Ok(value)
	}
}

fn encoded_prefix(values: &[OwnedTlv], end: usize) -> Vec<u8> {
	let mut encoded = Vec::new();
	for value in &values[..end] {
		value
			.write_to(&mut encoded)
			.expect("Vec writes cannot fail");
	}
	encoded
}

fn validate_area(value: &OwnedTlv) -> Result<(), BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	text(cursor.take(types::AREA_NAME, "AreaName")?.1)?;
	if let Some((_, description)) = cursor.optional(types::AREA_DESCRIPTION) {
		text(description)?;
	}
	cursor.finish()
}

fn validate_via(value: &OwnedTlv) -> Result<(), BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let (_, address_value) = cursor.take(types::ADDRESS, "Via Address")?;
	let address = parse_address(address_value)?;
	conditional_public_key(&mut cursor, &address)?;
	decode_u64(&cursor.take(types::TIMESTAMP, "Via Timestamp")?.1.value)?;
	let (_, software) = cursor
		.next_defined()
		.ok_or(BundleError::Missing("Via software string"))?;
	text(software)?;
	cursor.finish()
}

fn validate_message(
	value: &OwnedTlv,
	resolver: &impl KeyResolver,
) -> Result<ValidatedItem, BundleError> {
	let children = parse_sequence(&value.value)?;
	if children.first().map(|value| value.type_code) != Some(types::ORIGIN) {
		return Err(BundleError::Missing("initial Message Origin"));
	}
	let mut cursor = Cursor::new(&children);
	let (_, origin_value) = cursor.take(types::ORIGIN, "Message Origin")?;
	let origin_address = parse_address(origin_value)?;
	let origin_key = conditional_public_key(&mut cursor, &origin_address)?;
	let origin = parse_identity(origin_value, origin_key, resolver)?;

	let destination = if cursor.peek_type() == Some(types::DESTINATION) {
		let (_, destination) = cursor.take(types::DESTINATION, "Destination")?;
		let address = parse_address(destination)?;
		conditional_public_key(&mut cursor, &address)?;
		Some(address)
	} else {
		None
	};
	decode_u64(&cursor.take(types::TIMESTAMP, "Message Timestamp")?.1.value)?;
	for (type_code, name) in [
		(types::TO_USER_NAME, "ToUserName"),
		(types::FROM_USER_NAME, "FromUserName"),
		(types::SUBJECT, "Subject"),
		(types::MESSAGE_TEXT, "MessageText"),
	] {
		text(cursor.take(type_code, name)?.1)?;
	}
	let area = cursor.optional(types::AREA).map(|(_, value)| value);
	match (&destination, area) {
		(Some(_), None) => {}
		(None, Some(area)) => validate_area(area)?,
		_ => {
			return Err(BundleError::Unexpected(
				"Message Destination/Area combination",
			));
		}
	}
	for (_, file) in cursor.repeated(types::FILE) {
		validate_file(file, false, resolver)?;
	}
	if let Some((_, value)) = cursor.optional(types::LEGACY_ATTRIBUTES) {
		decode_u64(&value.value)?;
	}
	if let Some((_, value)) = cursor.optional(types::TIMESTAMP_OFFSET) {
		decode_i64(&value.value)?;
	}
	for type_code in [types::TEAR_LINE, types::ORIGIN_LINE, types::MESSAGE_ID] {
		if let Some((_, value)) = cursor.optional(type_code) {
			text(value)?;
		}
	}
	if let Some((_, reply)) = cursor.optional(types::REPLY_TO) {
		let reply_children = parse_sequence(&reply.value)?;
		let mut reply_cursor = Cursor::new(&reply_children);
		parse_address(reply_cursor.take(types::ADDRESS, "ReplyTo Address")?.1)?;
		let (_, message_id) = reply_cursor
			.next_defined()
			.ok_or(BundleError::Missing("ReplyTo MessageID"))?;
		text(message_id)?;
		reply_cursor.finish()?;
	}
	if let Some((_, value)) = cursor.optional(types::ORIGINAL_CHARACTER_SET) {
		text(value)?;
	}
	let (signature_index, signature_value) = cursor.take(types::SIGNATURE, "Message Signature")?;
	let signature = parse_signature(signature_value)?;
	if !verify_tlv(
		&encoded_prefix(&children, signature_index),
		&signature,
		&origin.public_key,
	)? {
		return Err(BundleError::InvalidSignature);
	}
	let request_identifier = decode_u64(
		&cursor
			.take(types::REQUEST_IDENTIFIER, "Message RequestIdentifier")?
			.1
			.value,
	)?;
	let vias = cursor.repeated(types::VIA);
	if vias.is_empty() {
		return Err(BundleError::Missing("Message Via"));
	}
	for (_, via) in vias {
		validate_via(via)?;
	}
	if let Some((_, seen_by)) = cursor.optional(types::SEEN_BY) {
		text(seen_by)?;
	}
	for (_, line) in cursor.repeated(types::ADDITIONAL_KLUDGE_LINE) {
		text(line)?;
	}
	cursor.finish()?;
	Ok(ValidatedItem {
		kind: if destination.is_some() {
			ItemKind::NetMail
		} else {
			ItemKind::EchoMail
		},
		request_identifier,
		duplicate_identity: Some(SignedItemIdentity {
			type_code: types::MESSAGE,
			origin,
			signature,
		}),
		response_to: None,
		raw: value.clone(),
	})
}

fn validate_file(
	value: &OwnedTlv,
	standalone: bool,
	resolver: &impl KeyResolver,
) -> Result<Option<ValidatedItem>, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	if let Some((_, filename)) = cursor.optional(types::FILENAME) {
		let filename = text(filename)?;
		if filename.contains(['/', '\\']) {
			return Err(BundleError::Unexpected("Filename path component"));
		}
	}
	if let Some((_, timestamp)) = cursor.optional(types::TIMESTAMP) {
		decode_u64(&timestamp.value)?;
	}
	cursor.take(types::CONTENTS, "File Contents")?;
	let area = cursor.optional(types::AREA).map(|(_, value)| value);
	if let Some(area) = area {
		validate_area(area)?;
	}
	let origin_value = cursor.optional(types::ORIGIN).map(|(_, value)| value);
	if standalone && origin_value.is_none() {
		return Err(BundleError::Missing("standalone File Origin"));
	}
	let origin = if let Some(origin_value) = origin_value {
		let address = parse_address(origin_value)?;
		let key = conditional_public_key(&mut cursor, &address)?;
		Some(parse_identity(origin_value, key, resolver)?)
	} else {
		None
	};
	if let Some((_, description)) = cursor.optional(types::SHORT_DESCRIPTION)
		&& text(description)?.contains(['\r', '\n'])
	{
		return Err(BundleError::Unexpected("newline in ShortDescription"));
	}
	for (_, description) in cursor.repeated(types::LONG_DESCRIPTION_LINE) {
		if text(description)?.contains(['\r', '\n']) {
			return Err(BundleError::Unexpected("newline in LongDescriptionLine"));
		}
	}
	for type_code in [types::TEAR_LINE, types::MAGIC_WORD, types::REPLACES] {
		if let Some((_, value)) = cursor.optional(type_code) {
			text(value)?;
		}
	}
	let signature_entry = cursor.optional(types::SIGNATURE);
	if standalone && signature_entry.is_none() {
		return Err(BundleError::Missing("standalone File Signature"));
	}
	if signature_entry.is_some() != origin.is_some() {
		return Err(BundleError::Unexpected("File Origin/Signature combination"));
	}
	let signature = if let Some((signature_index, signature_value)) = signature_entry {
		let signature = parse_signature(signature_value)?;
		let origin = origin.as_ref().expect("combination checked above");
		if !verify_tlv(
			&encoded_prefix(&children, signature_index),
			&signature,
			&origin.public_key,
		)? {
			return Err(BundleError::InvalidSignature);
		}
		Some(signature)
	} else {
		None
	};
	let request_identifier = if standalone {
		Some(decode_u64(
			&cursor
				.take(types::REQUEST_IDENTIFIER, "File RequestIdentifier")?
				.1
				.value,
		)?)
	} else {
		None
	};
	let vias = cursor.repeated(types::VIA);
	let seen_by = cursor.repeated(types::SEEN_BY);
	if area.is_some() && (vias.is_empty() || seen_by.is_empty()) {
		return Err(BundleError::Missing("distribution File Via/SeenBy"));
	}
	if area.is_none() && (!vias.is_empty() || !seen_by.is_empty()) {
		return Err(BundleError::Unexpected("non-distribution File Via/SeenBy"));
	}
	for (_, via) in vias {
		validate_via(via)?;
	}
	for (_, seen_by) in seen_by {
		text(seen_by)?;
	}
	cursor.finish()?;
	Ok(request_identifier.map(|request_identifier| ValidatedItem {
		kind: ItemKind::File,
		request_identifier,
		duplicate_identity: Some(SignedItemIdentity {
			type_code: types::FILE,
			origin: origin.expect("standalone file has Origin"),
			signature: signature.expect("standalone file has Signature"),
		}),
		response_to: None,
		raw: value.clone(),
	}))
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
		response_to: None,
		raw: value.clone(),
	})
}

fn validate_file_request(value: &OwnedTlv) -> Result<ValidatedItem, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let filename = text(cursor.take(types::FILENAME, "Filename")?.1)?;
	if filename.contains(['/', '\\']) {
		return Err(BundleError::Unexpected("Filename path component"));
	}
	if let Some((_, timestamp)) = cursor.optional(types::TIMESTAMP) {
		decode_u64(&timestamp.value)?;
	}
	let request_identifier = decode_u64(
		&cursor
			.take(types::REQUEST_IDENTIFIER, "RequestIdentifier")?
			.1
			.value,
	)?;
	cursor.finish()?;
	Ok(ValidatedItem {
		kind: ItemKind::FileRequest,
		request_identifier,
		duplicate_identity: None,
		response_to: None,
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
		cursor.finish()?;
		return Ok(ValidatedItem {
			kind: ItemKind::Accepted,
			request_identifier,
			duplicate_identity: None,
			response_to: Some(response_to),
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
	if let Ok((timestamp, used_timestamp)) = take_encoded_tlv(&bytes[offset..])
		&& timestamp.type_code == types::TIMESTAMP
	{
		decode_u64(&timestamp.value)?;
		offset += used_timestamp;
	}
	let (reason, used_reason) = decode_u64_prefix(&bytes[offset..])?;
	if !(1..=4).contains(&reason) {
		return Err(BundleError::Unexpected("Rejected reason"));
	}
	offset += used_reason;
	std::str::from_utf8(&bytes[offset..]).map_err(|_| BundleError::InvalidUtf8)?;
	Ok(ValidatedItem {
		kind: ItemKind::Rejected,
		request_identifier,
		duplicate_identity: None,
		response_to: Some(response_to),
		raw: value.clone(),
	})
}

fn take_encoded_tlv(bytes: &[u8]) -> Result<(OwnedTlv, usize), BundleError> {
	let (type_code, type_bytes) = decode_u64_prefix(bytes)?;
	let (length, length_bytes) = decode_u64_prefix(&bytes[type_bytes..])?;
	let length = usize::try_from(length).map_err(|_| crate::tlv::FramingError::LengthOverflow)?;
	let header = type_bytes + length_bytes;
	let end = header
		.checked_add(length)
		.ok_or(crate::tlv::FramingError::LengthOverflow)?;
	let value = bytes
		.get(header..end)
		.ok_or(crate::tlv::FramingError::TruncatedValue {
			expected: length as u64,
			received: bytes.len().saturating_sub(header) as u64,
		})?;
	Ok((OwnedTlv::new(type_code, value.to_vec())?, end))
}

pub fn validate_payload(
	payload: &VerifiedSignedTlv,
	resolver: &impl KeyResolver,
) -> Result<Vec<ValidatedItem>, PayloadError> {
	let mut validated = Vec::new();
	for (index, item) in payload.data.iter().enumerate().skip(1) {
		let result = match item.type_code {
			types::MESSAGE => validate_message(item, resolver).map(Some),
			types::FILE => validate_file(item, true, resolver),
			types::FILE_REQUEST => validate_file_request(item).map(Some),
			types::ACCEPTED => validate_response(item, true).map(Some),
			types::REJECTED => validate_response(item, false).map(Some),
			types::POLL_MESSAGES => simple_request(item, ItemKind::PollMessages).map(Some),
			types::POLL_FILES => simple_request(item, ItemKind::PollFiles).map(Some),
			types::POLL_FILE_REQUESTS => simple_request(item, ItemKind::PollFileRequests).map(Some),
			_ => Ok(None),
		};
		match result {
			Ok(Some(item)) => validated.push(item),
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
		let origin = Address::unlisted("p2p".into()).unwrap();
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
			Err(BundleError::Missing("PublicKey after unlisted address"))
		));
	}
}
