//! Structural and end-to-end validation of TSP-0016 items and TTS-0005 requests.

use std::collections::HashSet;
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
	PublicKeyRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemAuthentication {
	Unsigned,
	/// The signature did not verify under the effective key selected for
	/// `SignedOrigin`. This result establishes no cause for the failure.
	SignedOriginInvalid,
	SignedOriginValid,
	/// The signature did not verify under the effective key selected for
	/// `Origin`. This result establishes no cause for the failure.
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
	/// The current key certified by an Accepted `PublicKeyRequest`.
	pub response_public_key: Option<PublicKey>,
	/// Present only for a Rejected response.
	pub rejection: Option<Rejection>,
	pub provenance: Option<ItemProvenance>,
	pub destination: Option<Identity>,
	pub area: Option<String>,
	pub raw: OwnedTlv,
}

/// The detail a Rejected response carries beyond the fact of rejection.
///
/// TSP-0002 section 6 treats each reason differently: 1 and 2 fail as
/// permanent rejection, while 3 retains the unchanged item for retry no
/// earlier than `retry_after`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rejection {
	pub reason: RejectionReason,
	/// The Timestamp a reason 3 rejection may carry. Absent means retry at the
	/// next applicable schedule.
	pub retry_after: Option<u64>,
	pub description: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RejectionReason {
	Permanent = 1,
	ConditionUnmet = 2,
	Temporary = 3,
}

impl RejectionReason {
	#[must_use]
	pub const fn from_code(code: u64) -> Option<Self> {
		Some(match code {
			1 => Self::Permanent,
			2 => Self::ConditionUnmet,
			3 => Self::Temporary,
			_ => return None,
		})
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentData {
	pub filename: String,
	pub timestamp: Option<u64>,
	pub contents: Vec<u8>,
}

/// The FTS-0001.016 `AttributeWord` bit which marks attached files.
///
/// TSP-0016 section 4 type 101 keeps this bit out of `LegacyAttributes`, so it
/// is named here rather than imported: the legacy crates own the legacy formats
/// and this crate may not depend on them.
pub const LEGACY_ATTRIBUTE_FILE_ATTACHED: u64 = 1 << 4;

/// The FTS-0001.016 `AttributeWord` bits which survive packet carriage and
/// therefore have a stable signed meaning after legacy normalization.
///
/// `FileAttached` (bit 4) is represented by `File` children. The other bits
/// which FTS-0001 permits software to change before or after packeting are
/// legacy bookkeeping or transport controls rather than Message data.
pub const LEGACY_ATTRIBUTES_SIGNED_MASK: u64 =
	(1 << 0) | (1 << 1) | (1 << 12) | (1 << 13) | (1 << 14);

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
	/// The distribution area, or `None` for a peer-addressed File.
	///
	/// TSP-0016 section 3.2 marks Area, Via, and `SeenBy` `F`, "for a file
	/// that is part of a distribution network". A File which is not one carries
	/// none of the three, and the enclosing Bundle Destination addresses it.
	pub area: Option<String>,
	pub short_description: Option<String>,
	pub long_description_lines: Vec<String>,
	pub tear_line: Option<String>,
	pub magic_word: Option<String>,
	pub replaces: Option<String>,
}

pub fn build_originated_message(
	data: &MessageData,
	provenance: &ItemProvenance,
	secret: &SecretKey,
	request_identifier: u64,
	via_timestamp: u64,
	software: &str,
	seen_by: &[Address],
) -> Result<OwnedTlv, BundleError> {
	let effective_signer = provenance
		.signer
		.as_ref()
		.ok_or(BundleError::Missing("Message signing identity"))?;
	build_originated_message_for_delivery(
		data,
		provenance,
		secret,
		effective_signer,
		request_identifier,
		via_timestamp,
		software,
		seen_by,
	)
}

/// Constructs and signs a new Message while recording a distinct local
/// identity as its first delivery hop.
///
/// `provenance` and `secret` own the end-to-end item signature. `local_via`
/// independently identifies the local routing identity whose delivery state
/// and Bundle signature carry the Message to its next hop.
#[allow(clippy::too_many_arguments)]
pub fn build_originated_message_for_delivery(
	data: &MessageData,
	provenance: &ItemProvenance,
	secret: &SecretKey,
	local_via: &Identity,
	request_identifier: u64,
	via_timestamp: u64,
	software: &str,
	seen_by: &[Address],
) -> Result<OwnedTlv, BundleError> {
	validate_originated_message_data(data)?;
	let mut signed = message_signed_children(data, provenance)?;
	let signature = sign_tlv(&concatenate(&signed), secret)?;
	signed.push(OwnedTlv::new(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	)?);
	finish_message(
		data,
		signed,
		&MessageSuffix {
			existing_vias: &[],
			local_via,
			request_identifier,
			via_timestamp,
			software,
			seen_by,
		},
	)
}

pub struct MessageSuffix<'a> {
	pub existing_vias: &'a [ViaData],
	pub local_via: &'a Identity,
	pub request_identifier: u64,
	pub via_timestamp: u64,
	pub software: &'a str,
	pub seen_by: &'a [Address],
}

/// Reconstructs a Message carrying an already authenticated end-to-end
/// Signature, while replacing only its unsigned delivery suffix.
///
/// The signature is verified before any item is returned. `existing_vias` and
/// `seen_by` are current unsigned legacy state; `local_via` is appended for the
/// adapter which is committing the reconstructed item.
pub fn build_retained_message(
	data: &MessageData,
	provenance: &ItemProvenance,
	signature: Signature,
	suffix: &MessageSuffix<'_>,
) -> Result<OwnedTlv, BundleError> {
	let effective_signer = provenance
		.signer
		.as_ref()
		.ok_or(BundleError::Missing("Message signing identity"))?;
	validate_originated_message_data(data)?;
	let mut signed = message_signed_children(data, provenance)?;
	if !verify_tlv(
		&concatenate(&signed),
		&signature,
		&effective_signer.public_key,
	)? {
		return Err(BundleError::Unexpected(
			"retained Message Signature does not verify",
		));
	}
	signed.push(OwnedTlv::new(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	)?);
	finish_message(data, signed, suffix)
}

fn validate_originated_message_data(data: &MessageData) -> Result<(), BundleError> {
	if data.destination.is_some() == data.area.is_some() {
		return Err(BundleError::Unexpected(
			"Message Destination/Area combination",
		));
	}
	// TSP-0016 section 4 types 101 and 102: a zero conveys nothing that absence
	// does not, so absence is the only representation of it. TSP-0003 section 4
	// depends on that, because every legacy format carries the AttributeWord in a
	// fixed field and canonical export always emits TZUTC, so a zero and an
	// absent value share one legacy encoding and only one can reconstruct.
	if data.legacy_attributes == Some(0) {
		return Err(BundleError::Unexpected("zero LegacyAttributes"));
	}
	if data.timestamp_offset == Some(0) {
		return Err(BundleError::Unexpected("zero TimestampOffset"));
	}
	// Bit 4 is FileAttached, which the File children already carry.
	if data
		.legacy_attributes
		.is_some_and(|value| value & LEGACY_ATTRIBUTE_FILE_ATTACHED != 0)
	{
		return Err(BundleError::Unexpected(
			"LegacyAttributes bit 4, which the File children carry",
		));
	}
	if data
		.legacy_attributes
		.is_some_and(|value| value & !LEGACY_ATTRIBUTES_SIGNED_MASK != 0)
	{
		return Err(BundleError::Unexpected(
			"non-persistent LegacyAttributes bits",
		));
	}
	// TSP-0016 section 3.1: TearLine and OriginLine are EchoMail control
	// information, so NetMail carries neither. A legacy NetMail which does carry
	// such a line carries it as message text.
	if data.area.is_none() && (data.tear_line.is_some() || data.origin_line.is_some()) {
		return Err(BundleError::Unexpected("a NetMail TearLine or OriginLine"));
	}
	// TSP-0016 section 4 type 106: MessageText is paragraphs each terminated by
	// one U+000A, which is the only line break. A caller with text in another
	// shape converts it before submitting; TSP-0006 has the service do that for
	// an Application, because this is where the signed bytes are decided.
	if data.text.contains('\r') {
		return Err(BundleError::Unexpected("U+000D in MessageText"));
	}
	if !data.text.is_empty() && !data.text.ends_with('\n') {
		return Err(BundleError::Unexpected(
			"a MessageText whose final paragraph is unterminated",
		));
	}
	Ok(())
}

fn message_signed_children(
	data: &MessageData,
	provenance: &ItemProvenance,
) -> Result<Vec<OwnedTlv>, BundleError> {
	let mut signed = Vec::new();
	push_provenance(&mut signed, provenance)?;
	if let Some(destination) = &data.destination {
		push_identity(&mut signed, types::DESTINATION, destination)?;
	}
	signed.extend([
		OwnedTlv::new(types::TIMESTAMP, crate::integer::encode_u64(data.timestamp))?,
		OwnedTlv::new(types::TO_USER_NAME, data.to_user.as_bytes().to_vec())?,
		OwnedTlv::new(types::FROM_USER_NAME, data.from_user.as_bytes().to_vec())?,
		OwnedTlv::new(types::SUBJECT, data.subject.as_bytes().to_vec())?,
		OwnedTlv::new(types::MESSAGE_TEXT, data.text.as_bytes().to_vec())?,
	]);
	if let Some(area) = &data.area {
		signed.push(area_value(area)?);
	}
	for attachment in &data.attachments {
		let mut children = vec![OwnedTlv::new(
			types::FILENAME,
			attachment.filename.as_bytes().to_vec(),
		)?];
		if let Some(timestamp) = attachment.timestamp {
			children.push(OwnedTlv::new(
				types::TIMESTAMP,
				crate::integer::encode_u64(timestamp),
			)?);
		}
		children.push(OwnedTlv::new(types::CONTENTS, attachment.contents.clone())?);
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
		(types::TEAR_LINE, data.tear_line.as_ref()),
		(types::ORIGIN_LINE, data.origin_line.as_ref()),
		(types::MESSAGE_ID, data.message_id.as_ref()),
	] {
		if let Some(value) = value {
			signed.push(OwnedTlv::new(type_code, value.as_bytes().to_vec())?);
		}
	}
	if let Some((address, identifier)) = &data.reply_to {
		let mut value = OwnedTlv::new(types::ADDRESS, address.to_string().into_bytes())?.encode();
		value.extend_from_slice(identifier.as_bytes());
		signed.push(OwnedTlv::new(types::REPLY_TO, value)?);
	}
	Ok(signed)
}

fn finish_message(
	data: &MessageData,
	mut signed: Vec<OwnedTlv>,
	suffix: &MessageSuffix<'_>,
) -> Result<OwnedTlv, BundleError> {
	signed.push(OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(suffix.request_identifier),
	)?);
	for via in suffix.existing_vias {
		let public_key = if via.address.is_anonymous() {
			Some(
				via.public_key
					.ok_or(BundleError::Missing("anonymous Via PublicKey"))?,
			)
		} else {
			if via.public_key.is_some() {
				return Err(BundleError::Unexpected("non-anonymous Via PublicKey"));
			}
			None
		};
		let identity = Identity {
			address: via.address.clone(),
			public_key: public_key.unwrap_or(suffix.local_via.public_key),
		};
		signed.push(via_value(&identity, via.timestamp, &via.software)?);
	}
	signed.push(via_value(
		suffix.local_via,
		suffix.via_timestamp,
		suffix.software,
	)?);
	// TSP-0016 section 3.1 makes Message SeenBy an optional singleton,
	// and type 112 makes its value one Trimmed Collection. A File repeats it.
	if let Some(value) = seen_by_value(suffix.seen_by)? {
		signed.push(value);
	}
	for value in &data.additional_kludge_lines {
		signed.push(OwnedTlv::new(
			types::ADDITIONAL_KLUDGE_LINE,
			value.as_bytes().to_vec(),
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
	seen_by: &[Address],
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
	let distribution = data.area.is_some();
	if let Some(area) = &data.area {
		signed.push(area_value(area)?);
	}
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
	// Via and SeenBy are `F` values like Area, so a peer-addressed File carries
	// neither. `validate_standalone_file` rejects one that does.
	if distribution {
		signed.push(via_value(effective_signer, via_timestamp, software)?);
		// TSP-0016 section 3.2 marks File SeenBy "F+", so unlike a Message it
		// repeats. Each value is still its own Trimmed Collection.
		for value in seen_by {
			signed.push(OwnedTlv::new(
				types::SEEN_BY,
				value.to_string().into_bytes(),
			)?);
		}
	}
	OwnedTlv::new(types::FILE, concatenate(&signed)).map_err(Into::into)
}

/// Builds one `FileRequest`.
///
/// TSP-0016 section 3.3: a mandatory Filename, an optional Timestamp
/// making the request conditional on the named file being newer than it, and a
/// mandatory `RequestIdentifier`. There is no Origin, `SignedOrigin`, or Signature;
/// the enclosing payload `SignedTLV` is the whole of its authentication.
///
/// # Errors
///
/// Returns [`BundleError`] when a value cannot be encoded.
pub fn build_file_request(
	filename: &str,
	newer_than: Option<u64>,
	request_identifier: u64,
) -> Result<OwnedTlv, BundleError> {
	let mut children = vec![OwnedTlv::new(
		types::FILENAME,
		filename.as_bytes().to_vec(),
	)?];
	if let Some(timestamp) = newer_than {
		children.push(OwnedTlv::new(
			types::TIMESTAMP,
			crate::integer::encode_u64(timestamp),
		)?);
	}
	children.push(OwnedTlv::new(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	)?);
	OwnedTlv::new(types::FILE_REQUEST, concatenate(&children)).map_err(Into::into)
}

/// Rebuilds the unsigned routing suffix of an authenticated distribution item.
pub fn forward_item(
	item: &OwnedTlv,
	receiving_identity: &Identity,
	request_identifier: u64,
	via_timestamp: u64,
	software: &str,
	seen_by: &[Address],
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
	if item.type_code == types::MESSAGE {
		if let Some(value) = seen_by_value(seen_by)? {
			output.push(value);
		}
	} else {
		for address in seen_by {
			output.push(OwnedTlv::new(
				types::SEEN_BY,
				address.to_string().into_bytes(),
			)?);
		}
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
	if identity.address.is_anonymous() {
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
	if provenance.origin.is_anonymous() {
		return Err(BundleError::Unexpected(
			"anonymous Origin without its own PublicKey",
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

/// One `SeenBy` holding the whole collection, or nothing when it is empty.
fn seen_by_value(addresses: &[Address]) -> Result<Option<OwnedTlv>, BundleError> {
	if addresses.is_empty() {
		return Ok(None);
	}
	let value = crate::address::format_trimmed_collection(addresses);
	Ok(Some(OwnedTlv::new(types::SEEN_BY, value.into_bytes())?))
}

/// The addresses a `SeenBy` value names.
///
/// Every value is a Trimmed Collection per TSP-0016 section 4 type 112, so a
/// caller comparing against one address must expand it rather than treat the
/// whole value as a single address.
pub fn seen_by_addresses(value: &OwnedTlv) -> Result<Vec<Address>, BundleError> {
	crate::address::parse_trimmed_collection(text(value)?)
		.map_err(|_| BundleError::Unexpected("SeenBy is not a Trimmed Collection of addresses"))
}

fn via_value(identity: &Identity, timestamp: u64, software: &str) -> Result<OwnedTlv, BundleError> {
	let mut children = Vec::new();
	children.push(OwnedTlv::new(
		types::ADDRESS,
		identity.address.to_string().into_bytes(),
	)?);
	if identity.address.is_anonymous() {
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
	PublicKey::try_from(value.value.as_slice()).map_err(|_| BundleError::WrongLength("PublicKey"))
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
	let public_key = if address.is_anonymous() {
		parse_public_key(public_key.ok_or(BundleError::Missing("anonymous PublicKey"))?)?
	} else {
		if public_key.is_some() {
			return Err(BundleError::Unexpected("non-anonymous PublicKey"));
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
	let origin_public_key = if origin_address.is_anonymous() {
		Some(parse_public_key(origin_key.ok_or(
			BundleError::Missing("anonymous Origin PublicKey"),
		)?)?)
	} else {
		if origin_key.is_some() {
			return Err(BundleError::Unexpected("non-anonymous Origin PublicKey"));
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
	if address.is_anonymous() && value.is_none() {
		Err(BundleError::Missing("PublicKey after anonymous address"))
	} else if !address.is_anonymous() && value.is_some() {
		Err(BundleError::Unexpected(
			"PublicKey after non-anonymous address",
		))
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

/// One decoded Via, whose parts a legacy converter needs separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViaData {
	pub address: Address,
	pub public_key: Option<PublicKey>,
	pub timestamp: u64,
	pub software: String,
}

/// Decodes a Via, which validation and conversion both need.
fn read_via(value: &OwnedTlv) -> Result<ViaData, BundleError> {
	let (address_value, address_bytes) = take_encoded_tlv(&value.value)?;
	if address_value.type_code != types::ADDRESS {
		return Err(BundleError::Missing("Via Address"));
	}
	let address = parse_address(&address_value)?;
	let mut offset = address_bytes;
	let (next, next_bytes) = take_encoded_tlv(&value.value[offset..])?;
	let mut public_key = None;
	if address.is_anonymous() {
		if next.type_code != types::PUBLIC_KEY {
			return Err(BundleError::Missing(
				"PublicKey after anonymous Via Address",
			));
		}
		public_key = Some(parse_public_key(&next)?);
		offset += next_bytes;
	} else if next.type_code == types::PUBLIC_KEY {
		return Err(BundleError::Unexpected(
			"PublicKey after non-anonymous Via Address",
		));
	}
	let (timestamp, timestamp_bytes) = if address.is_anonymous() {
		take_encoded_tlv(&value.value[offset..])?
	} else {
		(next, next_bytes)
	};
	if timestamp.type_code != types::TIMESTAMP {
		return Err(BundleError::Missing("Via Timestamp"));
	}
	let timestamp = decode_u64(&timestamp.value)?;
	offset += timestamp_bytes;
	let software = std::str::from_utf8(&value.value[offset..])
		.map_err(|_| BundleError::InvalidUtf8)?
		.to_owned();
	Ok(ViaData {
		address,
		public_key,
		timestamp,
		software,
	})
}

/// The Vias an item carries, in the order they were added.
///
/// A relaying node needs these and nothing else from the item: TSP-0002
/// section 5 has it compare the next hop it selects against every Via and fail
/// as Loop on a match, so reading the whole Message would be more work and more
/// ways to fail than the question requires.
///
/// # Errors
///
/// Returns [`BundleError`] when the item is not a sequence of TLV values or a
/// Via does not decode.
pub fn item_vias(item: &OwnedTlv) -> Result<Vec<ViaData>, BundleError> {
	parse_sequence(&item.value)?
		.iter()
		.filter(|child| child.type_code == types::VIA)
		.map(read_via)
		.collect()
}

/// Decodes a `ReplyTo` into the address and complete identifier string.
fn read_reply_to(value: &OwnedTlv) -> Result<(Address, String), BundleError> {
	let (address, used) = take_encoded_tlv(&value.value)?;
	if address.type_code != types::ADDRESS {
		return Err(BundleError::Missing("ReplyTo Address"));
	}
	let address = parse_address(&address)?;
	let identifier = std::str::from_utf8(&value.value[used..])
		.map_err(|_| BundleError::InvalidUtf8)?
		.to_owned();
	Ok((address, identifier))
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
		read_reply_to(reply)?;
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
		read_via(via)?;
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
		response_public_key: None,
		rejection: None,
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
	if !standalone
		&& children.iter().any(|child| {
			matches!(
				child.type_code,
				types::ORIGIN | types::PUBLIC_KEY | types::SIGNED_ORIGIN | types::SIGNATURE
			)
		}) {
		return Err(BundleError::Unexpected("attached File provenance"));
	}
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
		read_via(via)?;
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
		response_public_key: None,
		rejection: None,
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
		response_public_key: None,
		rejection: None,
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

/// The signer-selecting values a legacy converter must carry across.
///
/// `SignedOrigin` and its conditional `PublicKey` have no traditional legacy
/// field, which is the whole reason TSP-0003 section 3.1 defines `TITHSIGN`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemSigning {
	pub origin: Address,
	pub origin_key: Option<PublicKey>,
	pub signed_origin: Option<Address>,
	pub signed_origin_key: Option<PublicKey>,
	pub signature: Option<Signature>,
	/// The exact encoded bytes the Signature covers, empty when unsigned.
	///
	/// TSP-0003 section 3.1 requires an exporter to compare reconstructed
	/// children against these bytes directly, because "semantic equality alone
	/// is insufficient".
	pub signed_region: Vec<u8>,
	/// The encoded `SignedOrigin` child and its conditional `PublicKey`, which
	/// is exactly what a `TITHSIGN` control carries.
	pub signed_origin_encoding: Vec<u8>,
}

/// A Message decomposed into everything a legacy conversion needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadMessage {
	pub data: MessageData,
	pub signing: ItemSigning,
	pub request_identifier: u64,
	pub vias: Vec<ViaData>,
	pub seen_by: Vec<Address>,
}

/// An ordered, lossless native Message representation.
///
/// `ReadMessage` is the convenient semantic view used at the legacy boundary;
/// this model owns every encoded child, including unknown extensions and their
/// position. A well-formed native Message can therefore pass through the data
/// model without changing either its signed or unsigned serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageModel {
	children: Vec<OwnedTlv>,
}

impl MessageModel {
	/// Parses and structurally validates a Message while retaining every child.
	pub fn parse(value: &OwnedTlv, resolver: &impl KeyResolver) -> Result<Self, BundleError> {
		validate_message(value, resolver)?;
		Ok(Self {
			children: parse_sequence(&value.value)?,
		})
	}

	#[must_use]
	pub fn children(&self) -> &[OwnedTlv] {
		&self.children
	}

	/// Re-encodes the exact ordered child model as one Message.
	#[must_use]
	pub fn to_tlv(&self) -> OwnedTlv {
		OwnedTlv::new(
			types::MESSAGE,
			encoded_prefix(&self.children, self.children.len()),
		)
		.expect("already parsed Message children remain representable")
	}
}

/// A standalone File decomposed the same way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadFile {
	pub data: StandaloneFileData,
	pub signing: ItemSigning,
	pub request_identifier: u64,
	pub vias: Vec<ViaData>,
	pub seen_by: Vec<Address>,
}

/// A `FileRequest`, which carries no Origin, Signature, or route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadFileRequest {
	pub filename: String,
	pub timestamp: Option<u64>,
	pub request_identifier: u64,
}

/// Reads a Message into its values.
///
/// This does not authenticate. The caller already has the item's
/// `ItemAuthentication` from the record which delivered it; [`ItemSigning`]
/// carries the exact bytes and Signature needed to check it again, which
/// TSP-0003 section 3.1 requires an exporter to do. The resolver is only for
/// the Destination key, which a non-anonymous address does not carry inline.
pub fn read_message(
	value: &OwnedTlv,
	resolver: &impl KeyResolver,
) -> Result<ReadMessage, BundleError> {
	if value.type_code != types::MESSAGE {
		return Err(BundleError::Unexpected("read_message item kind"));
	}
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let (_, origin_value) = cursor.take(types::ORIGIN, "Message Origin")?;
	let origin = parse_address(origin_value)?;
	let origin_key = conditional_public_key(&mut cursor, &origin)?
		.map(parse_public_key)
		.transpose()?;
	let signed_origin = read_signed_origin(&mut cursor)?;
	let destination = if cursor.peek_type() == Some(types::DESTINATION) {
		let (_, value) = cursor.take(types::DESTINATION, "Destination")?;
		let address = parse_address(value)?;
		let key = conditional_public_key(&mut cursor, &address)?;
		Some(parse_identity(value, key, resolver)?)
	} else {
		None
	};
	let timestamp = decode_u64(&cursor.take(types::TIMESTAMP, "Message Timestamp")?.1.value)?;
	let to_user = text(cursor.take(types::TO_USER_NAME, "ToUserName")?.1)?.to_owned();
	let from_user = text(cursor.take(types::FROM_USER_NAME, "FromUserName")?.1)?.to_owned();
	let subject = text(cursor.take(types::SUBJECT, "Subject")?.1)?.to_owned();
	let message_text = text(cursor.take(types::MESSAGE_TEXT, "MessageText")?.1)?.to_owned();
	let area = cursor
		.optional(types::AREA)
		.map(|(_, value)| validate_area(value))
		.transpose()?;
	let mut attachments = Vec::new();
	for (_, file) in cursor.repeated(types::FILE) {
		attachments.push(read_attachment(file)?);
	}
	let legacy_attributes = cursor
		.optional(types::LEGACY_ATTRIBUTES)
		.map(|(_, value)| decode_u64(&value.value))
		.transpose()?;
	let timestamp_offset = cursor
		.optional(types::TIMESTAMP_OFFSET)
		.map(|(_, value)| decode_i64(&value.value))
		.transpose()?;
	let mut optional = [types::TEAR_LINE, types::ORIGIN_LINE, types::MESSAGE_ID]
		.into_iter()
		.map(|type_code| {
			cursor
				.optional(type_code)
				.map(|(_, value)| text(value).map(str::to_owned))
				.transpose()
		})
		.collect::<Result<Vec<_>, _>>()?
		.into_iter();
	let tear_line = optional.next().expect("three optional values");
	let origin_line = optional.next().expect("three optional values");
	let message_id = optional.next().expect("three optional values");
	let reply_to = cursor
		.optional(types::REPLY_TO)
		.map(|(_, value)| read_reply_to(value))
		.transpose()?;
	// OriginalCharacterSet is a signed child with no MessageData field. A
	// converter which meets one cannot reproduce the signed region, so it is
	// refused here rather than dropped silently.
	if cursor.optional(types::ORIGINAL_CHARACTER_SET).is_some() {
		return Err(BundleError::Unexpected(
			"OriginalCharacterSet has no conversion",
		));
	}
	let (signature, signed_region) = read_signature(&mut cursor, &children)?;
	let request_identifier = decode_u64(
		&cursor
			.take(types::REQUEST_IDENTIFIER, "Message RequestIdentifier")?
			.1
			.value,
	)?;
	let mut vias = Vec::new();
	for (_, via) in cursor.repeated(types::VIA) {
		vias.push(read_via(via)?);
	}
	if vias.is_empty() {
		return Err(BundleError::Missing("Message Via"));
	}
	let seen_by = match cursor.optional(types::SEEN_BY) {
		Some((_, value)) => seen_by_addresses(value)?,
		None => Vec::new(),
	};
	let mut additional_kludge_lines = Vec::new();
	for (_, line) in cursor.repeated(types::ADDITIONAL_KLUDGE_LINE) {
		additional_kludge_lines.push(text(line)?.to_owned());
	}
	cursor.finish()?;
	Ok(ReadMessage {
		data: MessageData {
			destination,
			timestamp,
			to_user,
			from_user,
			subject,
			text: message_text,
			area,
			attachments,
			legacy_attributes,
			timestamp_offset,
			tear_line,
			origin_line,
			message_id,
			reply_to,
			additional_kludge_lines,
		},
		signing: ItemSigning {
			origin,
			origin_key,
			signed_origin: signed_origin.address,
			signed_origin_key: signed_origin.key,
			signature,
			signed_region,
			signed_origin_encoding: signed_origin.encoding,
		},
		request_identifier,
		vias,
		seen_by,
	})
}

/// Reads a standalone distribution File into its values.
pub fn read_standalone_file(value: &OwnedTlv) -> Result<ReadFile, BundleError> {
	if value.type_code != types::FILE {
		return Err(BundleError::Unexpected("read_standalone_file item kind"));
	}
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let filename = text(
		cursor
			.optional(types::FILENAME)
			.ok_or(BundleError::Missing("standalone File Filename"))?
			.1,
	)?
	.to_owned();
	let timestamp = cursor
		.optional(types::TIMESTAMP)
		.map(|(_, value)| decode_u64(&value.value))
		.transpose()?;
	let contents = cursor
		.take(types::CONTENTS, "File Contents")?
		.1
		.value
		.clone();
	// Absent for a peer-addressed File, which carries no Area, Via, or SeenBy.
	let area = cursor
		.optional(types::AREA)
		.map(|(_, value)| validate_area(value))
		.transpose()?;
	let (_, origin_value) = cursor.take(types::ORIGIN, "standalone File Origin")?;
	let origin = parse_address(origin_value)?;
	let origin_key = conditional_public_key(&mut cursor, &origin)?
		.map(parse_public_key)
		.transpose()?;
	let signed_origin = read_signed_origin(&mut cursor)?;
	let short_description = cursor
		.optional(types::SHORT_DESCRIPTION)
		.map(|(_, value)| text(value).map(str::to_owned))
		.transpose()?;
	let mut long_description_lines = Vec::new();
	for (_, line) in cursor.repeated(types::LONG_DESCRIPTION_LINE) {
		long_description_lines.push(text(line)?.to_owned());
	}
	let mut optional = [types::TEAR_LINE, types::MAGIC_WORD, types::REPLACES]
		.into_iter()
		.map(|type_code| {
			cursor
				.optional(type_code)
				.map(|(_, value)| text(value).map(str::to_owned))
				.transpose()
		})
		.collect::<Result<Vec<_>, _>>()?
		.into_iter();
	let tear_line = optional.next().expect("three optional values");
	let magic_word = optional.next().expect("three optional values");
	let replaces = optional.next().expect("three optional values");
	let (signature, signed_region) = read_signature(&mut cursor, &children)?;
	let request_identifier = decode_u64(
		&cursor
			.take(types::REQUEST_IDENTIFIER, "File RequestIdentifier")?
			.1
			.value,
	)?;
	let mut vias = Vec::new();
	for (_, via) in cursor.repeated(types::VIA) {
		vias.push(read_via(via)?);
	}
	// A File repeats SeenBy, so every value contributes to one collection.
	let mut seen_by = Vec::new();
	for (_, value) in cursor.repeated(types::SEEN_BY) {
		seen_by.extend(seen_by_addresses(value)?);
	}
	cursor.finish()?;
	Ok(ReadFile {
		data: StandaloneFileData {
			filename,
			timestamp,
			contents,
			area,
			short_description,
			long_description_lines,
			tear_line,
			magic_word,
			replaces,
		},
		signing: ItemSigning {
			origin,
			origin_key,
			signed_origin: signed_origin.address,
			signed_origin_key: signed_origin.key,
			signature,
			signed_region,
			signed_origin_encoding: signed_origin.encoding,
		},
		request_identifier,
		vias,
		seen_by,
	})
}

/// Reads a `FileRequest` into its values.
pub fn read_file_request(value: &OwnedTlv) -> Result<ReadFileRequest, BundleError> {
	if value.type_code != types::FILE_REQUEST {
		return Err(BundleError::Unexpected("read_file_request item kind"));
	}
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let filename = text(cursor.take(types::FILENAME, "Filename")?.1)?.to_owned();
	let timestamp = cursor
		.optional(types::TIMESTAMP)
		.map(|(_, value)| decode_u64(&value.value))
		.transpose()?;
	let request_identifier = decode_u64(
		&cursor
			.take(types::REQUEST_IDENTIFIER, "RequestIdentifier")?
			.1
			.value,
	)?;
	cursor.finish()?;
	Ok(ReadFileRequest {
		filename,
		timestamp,
		request_identifier,
	})
}

/// The `SignedOrigin` parts of an [`ItemSigning`], read together.
#[derive(Clone, Debug, Default)]
struct SignedOriginParts {
	address: Option<Address>,
	key: Option<PublicKey>,
	encoding: Vec<u8>,
}

fn read_signed_origin(cursor: &mut Cursor<'_>) -> Result<SignedOriginParts, BundleError> {
	let Some((_, value)) = cursor.optional(types::SIGNED_ORIGIN) else {
		return Ok(SignedOriginParts::default());
	};
	let address = parse_address(value)?;
	let mut encoding = value.encode();
	let key = conditional_public_key(cursor, &address)?;
	if let Some(key) = key {
		key.write_to(&mut encoding)?;
	}
	Ok(SignedOriginParts {
		address: Some(address),
		key: key.map(parse_public_key).transpose()?,
		encoding,
	})
}

fn read_signature(
	cursor: &mut Cursor<'_>,
	children: &[OwnedTlv],
) -> Result<(Option<Signature>, Vec<u8>), BundleError> {
	match cursor.optional(types::SIGNATURE) {
		Some((index, value)) => Ok((
			Some(parse_signature(value)?),
			encoded_prefix(children, index),
		)),
		None => Ok((None, Vec::new())),
	}
}

fn read_attachment(value: &OwnedTlv) -> Result<AttachmentData, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let filename = text(cursor.take(types::FILENAME, "attached Filename")?.1)?.to_owned();
	let timestamp = cursor
		.optional(types::TIMESTAMP)
		.map(|(_, value)| decode_u64(&value.value))
		.transpose()?;
	let contents = cursor
		.take(types::CONTENTS, "attached Contents")?
		.1
		.value
		.clone();
	cursor.finish()?;
	Ok(AttachmentData {
		filename,
		timestamp,
		contents,
	})
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
				area: Some("SYNCHRONET".to_owned()),
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
				filename: "test.zip".to_owned(),
				timestamp: None,
				contents: b"file".to_vec(),
				area: Some("FILES".to_owned()),
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
					filename: "work.zip".to_owned(),
					timestamp: Some(1_755_400_000),
					contents: b"payload".to_vec(),
				},
				AttachmentData {
					filename: "other.zip".to_owned(),
					timestamp: None,
					contents: b"second".to_vec(),
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
			area: Some("SYNCHRONET".to_owned()),
			reply_to: None,
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
			filename: "goodies.zip".to_owned(),
			timestamp: Some(1_755_400_000),
			contents: b"payload".to_vec(),
			area: Some("SYNCDATA".to_owned()),
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
			filename: "0068002400.su0".to_owned(),
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
		}
		// Renumbering for a new exchange works the same way it does for an item.
		let renumbered =
			set_request_identifier(&build_file_request("a.zip", None, 1).unwrap(), 3).unwrap();
		assert_eq!(
			read_file_request(&renumbered).unwrap().request_identifier,
			3
		);
	}

	#[test]
	fn reading_refuses_an_item_it_cannot_represent() {
		// OriginalCharacterSet is signed but has no MessageData field, so a
		// converter must refuse rather than drop it and claim a round trip.
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
				area: Some("SYNCHRONET".to_owned()),
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
		assert!(matches!(
			read_message(&altered, &|_: &Address| None),
			Err(BundleError::Unexpected(_))
		));

		// A File is not a Message and vice versa.
		assert!(read_message(&altered.clone(), &|_: &Address| None).is_err());
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
				area: Some("SYNCHRONET".to_owned()),
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

		let cases: [(MessageData, &str); 7] = [
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

		// EchoMail keeps both: they are its own control information.
		assert!(
			build(MessageData {
				destination: None,
				area: Some("SYNCHRONET".to_owned()),
				tear_line: Some("tosser".to_owned()),
				origin_line: Some("A board (1:1/100)".to_owned()),
				..netmail()
			})
			.is_ok()
		);
	}
}
