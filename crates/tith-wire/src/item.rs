//! Structural and end-to-end validation of TTS-0005 payload values.

use std::fmt;

use tith_crypto::{
	PublicKey, SIGNATURE_BYTES, SecretKey, Signature, TlvHash, sign_tlv, verify_tlv,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemAuthentication {
	Unsigned,
	SignedOriginInvalid,
	SignedOriginValid,
	OriginInvalid,
	OriginValid,
	Transport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedItemIdentity {
	pub type_code: u64,
	pub signer: Identity,
	pub signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemProvenance {
	pub origin: Address,
	pub signer: Option<Identity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedItem {
	pub kind: ItemKind,
	pub request_identifier: u64,
	pub duplicate_identity: Option<SignedItemIdentity>,
	pub authentication: Option<ItemAuthentication>,
	pub response_to: Option<TlvHash>,
	pub provenance: Option<ItemProvenance>,
	pub destination: Option<Identity>,
	pub area: Option<String>,
	pub raw: OwnedTlv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RejectionReason {
	Permanent = 1,
	Authentication = 2,
	Condition = 3,
	Temporary = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentData {
	pub filename: String,
	pub timestamp: Option<u64>,
	pub contents: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageData {
	pub destination: Option<Identity>,
	pub timestamp: u64,
	pub to_user: String,
	pub from_user: String,
	pub subject: String,
	pub text: String,
	pub area: Option<String>,
	pub attachments: Vec<AttachmentData>,
	pub legacy_attributes: Option<u64>,
	pub timestamp_offset: Option<i64>,
	pub tear_line: Option<String>,
	pub origin_line: Option<String>,
	pub message_id: Option<String>,
	pub reply_to: Option<(Address, String)>,
	pub additional_kludge_lines: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandaloneFileData {
	pub filename: String,
	pub timestamp: Option<u64>,
	pub contents: Vec<u8>,
	pub area: String,
	pub short_description: Option<String>,
	pub long_description_lines: Vec<String>,
	pub tear_line: Option<String>,
	pub magic_word: Option<String>,
	pub replaces: Option<String>,
}

pub fn build_originated_message(
	data: MessageData,
	provenance: &ItemProvenance,
	secret: &SecretKey,
	request_identifier: u64,
	via_timestamp: u64,
	software: &str,
	seen_by: &[String],
) -> Result<OwnedTlv, BundleError> {
	let effective_signer = provenance
		.signer
		.as_ref()
		.ok_or(BundleError::Missing("Message signing identity"))?;
	if data.destination.is_some() == data.area.is_some() {
		return Err(BundleError::Unexpected(
			"Message Destination/Area combination",
		));
	}
	let mut signed = Vec::new();
	push_provenance(&mut signed, provenance)?;
	if let Some(destination) = &data.destination {
		push_identity(&mut signed, types::DESTINATION, destination)?;
	}
	signed.extend([
		OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(data.timestamp))?,
		OwnedTlv::new(types::TO_USER_NAME, data.to_user.into_bytes())?,
		OwnedTlv::new(types::FROM_USER_NAME, data.from_user.into_bytes())?,
		OwnedTlv::new(types::SUBJECT, data.subject.into_bytes())?,
		OwnedTlv::new(types::MESSAGE_TEXT, data.text.into_bytes())?,
	]);
	if let Some(area) = data.area {
		signed.push(area_value(&area)?);
	}
	for attachment in data.attachments {
		let mut children = vec![OwnedTlv::new(
			types::FILENAME,
			attachment.filename.into_bytes(),
		)?];
		if let Some(timestamp) = attachment.timestamp {
			children.push(OwnedTlv::new(
				types::TIMESTAMP,
				crate::integer::encode_u64(timestamp),
			)?);
		}
		children.push(OwnedTlv::new(types::CONTENTS, attachment.contents)?);
		signed.push(OwnedTlv::new(types::FILE, concatenate(&children))?);
	}
	if let Some(value) = data.legacy_attributes {
		signed.push(OwnedTlv::new(
			types::LEGACY_ATTRIBUTES,
			crate::integer::encode_u64(value),
		)?);
	}
	if let Some(value) = data.timestamp_offset {
		signed.push(OwnedTlv::new(
			types::TIMESTAMP_OFFSET,
			crate::integer::encode_i64(value),
		)?);
	}
	for (type_code, value) in [
		(types::TEAR_LINE, data.tear_line),
		(types::ORIGIN_LINE, data.origin_line),
		(types::MESSAGE_ID, data.message_id),
	] {
		if let Some(value) = value {
			signed.push(OwnedTlv::new(type_code, value.into_bytes())?);
		}
	}
	if let Some((address, identifier)) = data.reply_to {
		let mut value = OwnedTlv::new(types::ADDRESS, address.to_string().into_bytes())?.encode();
		value.extend_from_slice(identifier.as_bytes());
		signed.push(OwnedTlv::new(types::REPLY_TO, value)?);
	}
	let signature = sign_tlv(&concatenate(&signed), secret)?;
	signed.push(OwnedTlv::new(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	)?);
	signed.push(OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	)?);
	signed.push(via_value(effective_signer, via_timestamp, software)?);
	for value in seen_by {
		signed.push(OwnedTlv::new(types::SEEN_BY, value.as_bytes().to_vec())?);
	}
	for value in data.additional_kludge_lines {
		signed.push(OwnedTlv::new(
			types::ADDITIONAL_KLUDGE_LINE,
			value.into_bytes(),
		)?);
	}
	OwnedTlv::new(types::MESSAGE, concatenate(&signed)).map_err(Into::into)
}

pub fn build_originated_file(
	data: StandaloneFileData,
	provenance: &ItemProvenance,
	secret: &SecretKey,
	request_identifier: u64,
	via_timestamp: u64,
	software: &str,
	seen_by: &[String],
) -> Result<OwnedTlv, BundleError> {
	let effective_signer = provenance
		.signer
		.as_ref()
		.ok_or(BundleError::Missing("File signing identity"))?;
	let mut signed = vec![OwnedTlv::new(types::FILENAME, data.filename.into_bytes())?];
	if let Some(timestamp) = data.timestamp {
		signed.push(OwnedTlv::new(
			types::TIMESTAMP,
			crate::integer::encode_u64(timestamp),
		)?);
	}
	signed.push(OwnedTlv::new(types::CONTENTS, data.contents)?);
	signed.push(area_value(&data.area)?);
	push_provenance(&mut signed, provenance)?;
	if let Some(value) = data.short_description {
		signed.push(OwnedTlv::new(types::SHORT_DESCRIPTION, value.into_bytes())?);
	}
	for value in data.long_description_lines {
		signed.push(OwnedTlv::new(
			types::LONG_DESCRIPTION_LINE,
			value.into_bytes(),
		)?);
	}
	for (type_code, value) in [
		(types::TEAR_LINE, data.tear_line),
		(types::MAGIC_WORD, data.magic_word),
		(types::REPLACES, data.replaces),
	] {
		if let Some(value) = value {
			signed.push(OwnedTlv::new(type_code, value.into_bytes())?);
		}
	}
	let signature = sign_tlv(&concatenate(&signed), secret)?;
	signed.push(OwnedTlv::new(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	)?);
	signed.push(OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	)?);
	signed.push(via_value(effective_signer, via_timestamp, software)?);
	for value in seen_by {
		signed.push(OwnedTlv::new(types::SEEN_BY, value.as_bytes().to_vec())?);
	}
	OwnedTlv::new(types::FILE, concatenate(&signed)).map_err(Into::into)
}

/// Rebuilds the unsigned routing suffix of an authenticated distribution item.
pub fn forward_item(
	item: &OwnedTlv,
	receiving_identity: &Identity,
	request_identifier: u64,
	via_timestamp: u64,
	software: &str,
	seen_by: &[String],
) -> Result<OwnedTlv, BundleError> {
	if !matches!(item.type_code, types::MESSAGE | types::FILE) {
		return Err(BundleError::Unexpected("forward item kind"));
	}
	let children = parse_sequence(&item.value)?;
	let signature = children
		.iter()
		.position(|child| child.type_code == types::SIGNATURE)
		.ok_or(BundleError::Missing("Signature"))?;
	let mut output = children[..=signature].to_vec();
	output.push(OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	)?);
	for child in &children[signature + 1..] {
		if child.type_code == types::VIA || !types::is_defined(child.type_code) {
			output.push(child.clone());
		}
	}
	output.push(via_value(receiving_identity, via_timestamp, software)?);
	for address in seen_by {
		output.push(OwnedTlv::new(types::SEEN_BY, address.as_bytes().to_vec())?);
	}
	for child in &children[signature + 1..] {
		if child.type_code == types::ADDITIONAL_KLUDGE_LINE {
			output.push(child.clone());
		}
	}
	OwnedTlv::new(item.type_code, concatenate(&output)).map_err(Into::into)
}

fn concatenate(values: &[OwnedTlv]) -> Vec<u8> {
	let mut output = Vec::with_capacity(values.iter().map(OwnedTlv::encoded_len).sum());
	for value in values {
		value.write_to(&mut output).expect("Vec writes cannot fail");
	}
	output
}

fn push_identity(
	output: &mut Vec<OwnedTlv>,
	type_code: u64,
	identity: &Identity,
) -> Result<(), BundleError> {
	output.push(OwnedTlv::new(
		type_code,
		identity.address.to_string().into_bytes(),
	)?);
	if identity.address.is_unlisted() {
		output.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			identity.public_key.as_bytes().to_vec(),
		)?);
	}
	Ok(())
}

fn push_provenance(
	output: &mut Vec<OwnedTlv>,
	provenance: &ItemProvenance,
) -> Result<(), BundleError> {
	let signer = provenance
		.signer
		.as_ref()
		.ok_or(BundleError::Missing("item signing identity"))?;
	if provenance.origin == signer.address {
		return push_identity(output, types::ORIGIN, signer);
	}
	if provenance.origin.is_unlisted() {
		return Err(BundleError::Unexpected(
			"unlisted Origin without its own PublicKey",
		));
	}
	output.push(OwnedTlv::new(
		types::ORIGIN,
		provenance.origin.to_string().into_bytes(),
	)?);
	push_identity(output, types::SIGNED_ORIGIN, signer)
}

fn area_value(name: &str) -> Result<OwnedTlv, BundleError> {
	let child = OwnedTlv::new(types::AREA_NAME, name.as_bytes().to_vec())?;
	OwnedTlv::new(types::AREA, child.encode()).map_err(Into::into)
}

fn via_value(identity: &Identity, timestamp: u64, software: &str) -> Result<OwnedTlv, BundleError> {
	let mut children = Vec::new();
	children.push(OwnedTlv::new(
		types::ADDRESS,
		identity.address.to_string().into_bytes(),
	)?);
	if identity.address.is_unlisted() {
		children.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			identity.public_key.as_bytes().to_vec(),
		)?);
	}
	children.push(OwnedTlv::new(
		types::TIMESTAMP,
		crate::integer::encode_u64(timestamp),
	)?);
	let mut value = concatenate(&children);
	value.extend_from_slice(software.as_bytes());
	OwnedTlv::new(types::VIA, value).map_err(Into::into)
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

fn parse_provenance(
	origin: &OwnedTlv,
	origin_key: Option<&OwnedTlv>,
	signed_origin: Option<(&OwnedTlv, Option<&OwnedTlv>)>,
	resolver: &impl KeyResolver,
) -> Result<ItemProvenance, BundleError> {
	let origin_address = parse_address(origin)?;
	let origin_public_key = if origin_address.is_unlisted() {
		Some(parse_public_key(
			origin_key.ok_or(BundleError::Missing("unlisted Origin PublicKey"))?,
		)?)
	} else {
		if origin_key.is_some() {
			return Err(BundleError::Unexpected("listed Origin PublicKey"));
		}
		resolver.public_key(&origin_address)
	};
	let signed_parts = signed_origin
		.map(|(value, key)| {
			let address = parse_address(value)?;
			let inline_key = key.map(parse_public_key).transpose()?;
			Ok::<_, BundleError>((address, inline_key, value, key))
		})
		.transpose()?;
	let signer = if let Some(public_key) = origin_public_key {
		Identity {
			address: origin_address.clone(),
			public_key,
		}
	} else {
		let (_, _, value, key) =
			signed_parts.ok_or_else(|| BundleError::UnknownKey(origin_address.clone()))?;
		parse_identity(value, key, resolver)?
	};
	Ok(ItemProvenance {
		origin: origin_address,
		signer: Some(signer),
	})
}

fn item_authentication(provenance: &ItemProvenance, authenticated: bool) -> ItemAuthentication {
	let signer = provenance
		.signer
		.as_ref()
		.expect("signed provenance has a signer");
	match (signer.address == provenance.origin, authenticated) {
		(true, true) => ItemAuthentication::OriginValid,
		(true, false) => ItemAuthentication::OriginInvalid,
		(false, true) => ItemAuthentication::SignedOriginValid,
		(false, false) => ItemAuthentication::SignedOriginInvalid,
	}
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

fn validate_area(value: &OwnedTlv) -> Result<String, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let name = text(cursor.take(types::AREA_NAME, "AreaName")?.1)?.to_owned();
	if let Some((_, description)) = cursor.optional(types::AREA_DESCRIPTION) {
		text(description)?;
	}
	cursor.finish()?;
	Ok(name)
}

fn validate_via(value: &OwnedTlv) -> Result<(), BundleError> {
	let (address_value, address_bytes) = take_encoded_tlv(&value.value)?;
	if address_value.type_code != types::ADDRESS {
		return Err(BundleError::Missing("Via Address"));
	}
	let address = parse_address(&address_value)?;
	let mut offset = address_bytes;
	let (next, next_bytes) = take_encoded_tlv(&value.value[offset..])?;
	if address.is_unlisted() {
		if next.type_code != types::PUBLIC_KEY {
			return Err(BundleError::Missing("PublicKey after unlisted Via Address"));
		}
		parse_public_key(&next)?;
		offset += next_bytes;
	} else if next.type_code == types::PUBLIC_KEY {
		return Err(BundleError::Unexpected(
			"PublicKey after listed Via Address",
		));
	}
	let (timestamp, timestamp_bytes) = if address.is_unlisted() {
		take_encoded_tlv(&value.value[offset..])?
	} else {
		(next, next_bytes)
	};
	if timestamp.type_code != types::TIMESTAMP {
		return Err(BundleError::Missing("Via Timestamp"));
	}
	decode_u64(&timestamp.value)?;
	offset += timestamp_bytes;
	std::str::from_utf8(&value.value[offset..]).map_err(|_| BundleError::InvalidUtf8)?;
	Ok(())
}

fn validate_reply_to(value: &OwnedTlv) -> Result<(), BundleError> {
	let (address, used) = take_encoded_tlv(&value.value)?;
	if address.type_code != types::ADDRESS {
		return Err(BundleError::Missing("ReplyTo Address"));
	}
	parse_address(&address)?;
	std::str::from_utf8(&value.value[used..]).map_err(|_| BundleError::InvalidUtf8)?;
	Ok(())
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
	let signed_origin = if let Some((_, value)) = cursor.optional(types::SIGNED_ORIGIN) {
		let address = parse_address(value)?;
		let key = conditional_public_key(&mut cursor, &address)?;
		Some((value, key))
	} else {
		None
	};
	let destination = if cursor.peek_type() == Some(types::DESTINATION) {
		let (_, destination) = cursor.take(types::DESTINATION, "Destination")?;
		let address = parse_address(destination)?;
		let key = conditional_public_key(&mut cursor, &address)?;
		Some(parse_identity(destination, key, resolver)?)
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
	let area = cursor
		.optional(types::AREA)
		.map(|(_, value)| validate_area(value))
		.transpose()?;
	match (&destination, &area) {
		(Some(_), None) | (None, Some(_)) => {}
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
		validate_reply_to(reply)?;
	}
	if let Some((_, value)) = cursor.optional(types::ORIGINAL_CHARACTER_SET) {
		text(value)?;
	}
	let signature_entry = cursor.optional(types::SIGNATURE);
	let (provenance, authentication, duplicate_identity) =
		if let Some((signature_index, signature_value)) = signature_entry {
			let provenance = parse_provenance(origin_value, origin_key, signed_origin, resolver)?;
			let signature = parse_signature(signature_value)?;
			let signer = provenance
				.signer
				.as_ref()
				.expect("signed provenance has a signer");
			let authenticated = verify_tlv(
				&encoded_prefix(&children, signature_index),
				&signature,
				&signer.public_key,
			)?;
			let authentication = item_authentication(&provenance, authenticated);
			let duplicate_identity = authenticated.then_some(SignedItemIdentity {
				type_code: types::MESSAGE,
				signer: signer.clone(),
				signature,
			});
			(provenance, authentication, duplicate_identity)
		} else {
			if signed_origin.is_some() {
				return Err(BundleError::Unexpected("SignedOrigin without Signature"));
			}
			(
				ItemProvenance {
					origin: origin_address,
					signer: None,
				},
				ItemAuthentication::Unsigned,
				None,
			)
		};
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
		duplicate_identity,
		authentication: Some(authentication),
		response_to: None,
		provenance: Some(provenance),
		destination,
		area,
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
	let area = cursor
		.optional(types::AREA)
		.map(|(_, value)| validate_area(value))
		.transpose()?;
	let origin_value = cursor.optional(types::ORIGIN).map(|(_, value)| value);
	if standalone && origin_value.is_none() {
		return Err(BundleError::Missing("standalone File Origin"));
	}
	let provenance_parts = if let Some(origin_value) = origin_value {
		let address = parse_address(origin_value)?;
		let key = conditional_public_key(&mut cursor, &address)?;
		let signed_origin = if let Some((_, value)) = cursor.optional(types::SIGNED_ORIGIN) {
			let address = parse_address(value)?;
			let key = conditional_public_key(&mut cursor, &address)?;
			Some((value, key))
		} else {
			None
		};
		Some((origin_value, address, key, signed_origin))
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
	if signature_entry.is_some() && provenance_parts.is_none() {
		return Err(BundleError::Unexpected("File Signature without Origin"));
	}
	let (provenance, authentication, signature) =
		if let Some((signature_index, signature_value)) = signature_entry {
			let signature = parse_signature(signature_value)?;
			let (origin_value, _, key, signed_origin) = provenance_parts
				.as_ref()
				.expect("combination checked above");
			let provenance = parse_provenance(origin_value, *key, *signed_origin, resolver)?;
			let signer = provenance
				.signer
				.as_ref()
				.expect("signed provenance has a signer");
			let authenticated = verify_tlv(
				&encoded_prefix(&children, signature_index),
				&signature,
				&signer.public_key,
			)?;
			let authentication = item_authentication(&provenance, authenticated);
			(
				Some(provenance),
				Some(authentication),
				Some((signature, authenticated)),
			)
		} else {
			let provenance = provenance_parts
				.map(|(_, origin, _, signed_origin)| {
					if signed_origin.is_some() {
						return Err(BundleError::Unexpected("SignedOrigin without Signature"));
					}
					Ok(ItemProvenance {
						origin,
						signer: None,
					})
				})
				.transpose()?;
			let authentication = provenance.as_ref().map(|_| ItemAuthentication::Unsigned);
			(provenance, authentication, None)
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
		duplicate_identity: signature.filter(|(_, authenticated)| *authenticated).map(
			|(signature, _)| SignedItemIdentity {
				type_code: types::FILE,
				signer: provenance
					.as_ref()
					.expect("standalone file has Origin")
					.signer
					.as_ref()
					.expect("valid signature has a signer")
					.clone(),
				signature,
			},
		),
		authentication,
		response_to: None,
		provenance,
		destination: None,
		area,
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
		authentication: None,
		response_to: None,
		provenance: None,
		destination: None,
		area: None,
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
		authentication: Some(ItemAuthentication::Transport),
		response_to: None,
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
		cursor.finish()?;
		return Ok(ValidatedItem {
			kind: ItemKind::Accepted,
			request_identifier,
			duplicate_identity: None,
			authentication: None,
			response_to: Some(response_to),
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
		authentication: None,
		response_to: Some(response_to),
		provenance: None,
		destination: None,
		area: None,
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

pub fn rejected(
	request_identifier: u64,
	response_to: TlvHash,
	timestamp: Option<u64>,
	reason: RejectionReason,
	description: &str,
) -> Result<OwnedTlv, BundleError> {
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
		_ => Ok(None),
	}
}

pub fn validate_payload(
	payload: &VerifiedSignedTlv,
	resolver: &impl KeyResolver,
) -> Result<Vec<ValidatedItem>, PayloadError> {
	let mut validated = Vec::new();
	for (index, item) in payload.data.iter().enumerate().skip(1) {
		let result = validate_item(item, resolver);
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
				OwnedTlv::new(types::MESSAGE_TEXT, b"Legacy".to_vec()).unwrap(),
				OwnedTlv::new(types::REQUEST_IDENTIFIER, crate::integer::encode_u64(10)).unwrap(),
				via_value(&origin, 1, "test").unwrap(),
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
		validate_via(&via).unwrap();

		let mut reply_value = Vec::new();
		OwnedTlv::new(types::ADDRESS, b"fidonet#1/3".to_vec())
			.unwrap()
			.write_to(&mut reply_value)
			.unwrap();
		reply_value.extend_from_slice(b"message-id@example");
		let reply = OwnedTlv::new(types::REPLY_TO, reply_value).unwrap();
		validate_reply_to(&reply).unwrap();

		let mut invalid = via;
		invalid.value.push(0xff);
		assert!(matches!(
			validate_via(&invalid),
			Err(BundleError::InvalidUtf8)
		));
	}

	#[test]
	fn unlisted_via_requires_its_public_key_before_the_raw_suffix() {
		let address = Address::unlisted("p2p".to_owned()).unwrap();
		let mut value = Vec::new();
		for child in [
			OwnedTlv::new(types::ADDRESS, address.to_string().into_bytes()).unwrap(),
			OwnedTlv::new(types::PUBLIC_KEY, vec![7; 32]).unwrap(),
			OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(456)).unwrap(),
		] {
			child.write_to(&mut value).unwrap();
		}
		value.extend_from_slice(b"tith 1.0");
		validate_via(&OwnedTlv::new(types::VIA, value).unwrap()).unwrap();
	}

	#[test]
	fn signed_origin_authenticates_when_origin_has_no_key() {
		let signer_keys = SigningKeyPair::from_seed(&[20; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[21; 32]).unwrap();
		let provenance = ItemProvenance {
			origin: "fidonet#1/100".parse().unwrap(),
			signer: Some(Identity {
				address: Address::unlisted("p2p".to_owned()).unwrap(),
				public_key: signer_keys.public,
			}),
		};
		let destination = Identity {
			address: "fidonet#1/200".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let message = build_originated_message(
			MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Legacy".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
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
			MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Legacy".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: Address::unlisted("p2p".to_owned()).unwrap(),
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
	fn standalone_file_uses_signed_origin_fallback() {
		let signer_keys = SigningKeyPair::from_seed(&[25; 32]).unwrap();
		let provenance = ItemProvenance {
			origin: "fidonet#1/300".parse().unwrap(),
			signer: Some(Identity {
				address: Address::unlisted("p2p".to_owned()).unwrap(),
				public_key: signer_keys.public,
			}),
		};
		let file = build_originated_file(
			StandaloneFileData {
				filename: "test.zip".to_owned(),
				timestamp: None,
				contents: b"file".to_vec(),
				area: "FILES".to_owned(),
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
			&["fidonet#1/300".to_owned()],
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
}
