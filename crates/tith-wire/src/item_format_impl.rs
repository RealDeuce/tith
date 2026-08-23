use std::collections::HashSet;
use std::fmt;

use tith_crypto::{
	PublicKey, SIGNATURE_BYTES, SecretKey, Signature, TlvHash, sign_tlv, verify_tlv,
};

use crate::address::Address;
use crate::bundle::{BundleError, Identity, KeyResolver, VerifiedSignedTlv};
use crate::integer::{decode_i64, decode_u64, decode_u64_prefix};
pub use crate::item_format::{
	AreaData, AttachmentData, ItemModel, ItemModelKind, MessageData, SignedItemKind,
	StandaloneFileData,
};
use crate::item_format::{filename_has_path_component, filename_is_portable};
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
	pub kind: SignedItemKind,
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
	signed.push(assigned_tlv(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	));
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
	let authenticated = verify_tlv(
		&concatenate(&signed),
		&signature,
		&effective_signer.public_key,
	)?;
	if !authenticated {
		return Err(BundleError::Unexpected(
			"retained Message Signature does not verify",
		));
	}
	signed.push(assigned_tlv(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	));
	finish_message(data, signed, suffix)
}

fn validate_originated_message_data(data: &MessageData) -> Result<(), BundleError> {
	if data.destination.is_some() == data.area.is_some() {
		return Err(BundleError::Unexpected("Message Destination/Area combination"));
	}
	// TSP-0016 section 4 types 101 and 102: a zero conveys nothing that absence
	// does not, so absence is the only representation of it. TSP-0003 section 4
	// depends on that, because every legacy format carries the AttributeWord in a
	// fixed field and canonical export always emits TZUTC, so a zero and an
	// absent value share one legacy encoding and only one can reconstruct.
	if let Some(value) = data.legacy_attributes {
		validate_legacy_attributes(value)?;
	}
	if let Some(value) = data.timestamp_offset {
		validate_timestamp_offset(value)?;
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
	validate_message_text(&data.text)
}

fn validate_legacy_attributes(value: u64) -> Result<(), BundleError> {
	if value == 0 {
		return Err(BundleError::Unexpected("zero LegacyAttributes"));
	}
	// Bit 4 is FileAttached, which the File children already carry.
	if value & LEGACY_ATTRIBUTE_FILE_ATTACHED != 0 {
		return Err(BundleError::Unexpected(
			"LegacyAttributes bit 4, which the File children carry",
		));
	}
	if value & !LEGACY_ATTRIBUTES_SIGNED_MASK != 0 {
		return Err(BundleError::Unexpected(
			"non-persistent LegacyAttributes bits",
		));
	}
	Ok(())
}

fn validate_timestamp_offset(value: i64) -> Result<(), BundleError> {
	if value == 0 {
		Err(BundleError::Unexpected("zero TimestampOffset"))
	} else {
		Ok(())
	}
}

fn validate_message_text(value: &str) -> Result<(), BundleError> {
	if value.contains('\r') {
		return Err(BundleError::Unexpected("U+000D in MessageText"));
	}
	if !value.is_empty() && !value.ends_with('\n') {
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
		push_identity(&mut signed, types::DESTINATION, destination);
	}
	signed.extend([
		assigned_tlv(types::TIMESTAMP, crate::integer::encode_u64(data.timestamp)),
		assigned_tlv(types::TO_USER_NAME, data.to_user.as_bytes().to_vec()),
		assigned_tlv(types::FROM_USER_NAME, data.from_user.as_bytes().to_vec()),
		assigned_tlv(types::SUBJECT, data.subject.as_bytes().to_vec()),
		assigned_tlv(types::MESSAGE_TEXT, data.text.as_bytes().to_vec()),
	]);
	if let Some(area) = &data.area {
		signed.push(area_value(area));
	}
	for attachment in &data.attachments {
		let mut children = Vec::new();
		push_filename(&mut children, attachment.filename.as_deref())?;
		if let Some(timestamp) = attachment.timestamp {
			children.push(assigned_tlv(
				types::TIMESTAMP,
				crate::integer::encode_u64(timestamp),
			));
		}
		children.push(assigned_tlv(types::CONTENTS, attachment.contents.clone()));
		push_file_metadata(
			&mut children,
			attachment.short_description.as_deref(),
			&attachment.long_description_lines,
			attachment.tear_line.as_deref(),
			attachment.magic_word.as_deref(),
			attachment.replaces.as_deref(),
		)?;
		signed.push(assigned_tlv(types::FILE, concatenate(&children)));
	}
	if let Some(value) = data.legacy_attributes {
		signed.push(assigned_tlv(
			types::LEGACY_ATTRIBUTES,
			crate::integer::encode_u64(value),
		));
	}
	if let Some(value) = data.timestamp_offset {
		signed.push(assigned_tlv(
			types::TIMESTAMP_OFFSET,
			crate::integer::encode_i64(value),
		));
	}
	for (type_code, value) in [
		(types::TEAR_LINE, data.tear_line.as_ref()),
		(types::ORIGIN_LINE, data.origin_line.as_ref()),
		(types::MESSAGE_ID, data.message_id.as_ref()),
	] {
		if let Some(value) = value {
			signed.push(assigned_tlv(type_code, value.as_bytes().to_vec()));
		}
	}
	if let Some((address, identifier)) = &data.reply_to {
		let mut value = assigned_tlv(types::ADDRESS, address.to_string().into_bytes()).encode();
		value.extend_from_slice(identifier.as_bytes());
		signed.push(assigned_tlv(types::REPLY_TO, value));
	}
	if let Some(value) = &data.original_character_set {
		signed.push(assigned_tlv(
			types::ORIGINAL_CHARACTER_SET,
			value.as_bytes().to_vec(),
		));
	}
	Ok(signed)
}

fn finish_message(
	data: &MessageData,
	mut signed: Vec<OwnedTlv>,
	suffix: &MessageSuffix<'_>,
) -> Result<OwnedTlv, BundleError> {
	signed.push(assigned_tlv(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(suffix.request_identifier),
	));
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
		signed.push(via_value(&identity, via.timestamp, &via.software));
	}
	signed.push(via_value(
		suffix.local_via,
		suffix.via_timestamp,
		suffix.software,
	));
	// TSP-0016 section 3.1 makes Message SeenBy an optional singleton,
	// and type 112 makes its value one Trimmed Collection. A File repeats it.
	if let Some(value) = seen_by_value(suffix.seen_by) {
		signed.push(value);
	}
	for value in &data.additional_kludge_lines {
		if value.contains('\u{0001}') {
			return Err(BundleError::Unexpected("Control-A in AdditionalKludgeLine"));
		}
		signed.push(assigned_tlv(
			types::ADDITIONAL_KLUDGE_LINE,
			value.as_bytes().to_vec(),
		));
	}
	Ok(assigned_tlv(types::MESSAGE, concatenate(&signed)))
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
	let mut signed = Vec::new();
	push_filename(&mut signed, data.filename.as_deref())?;
	if let Some(timestamp) = data.timestamp {
		signed.push(assigned_tlv(
			types::TIMESTAMP,
			crate::integer::encode_u64(timestamp),
		));
	}
	signed.push(assigned_tlv(types::CONTENTS, data.contents));
	let distribution = data.area.is_some();
	if let Some(area) = &data.area {
		signed.push(area_value(area));
	}
	push_provenance(&mut signed, provenance)?;
	push_file_metadata(
		&mut signed,
		data.short_description.as_deref(),
		&data.long_description_lines,
		data.tear_line.as_deref(),
		data.magic_word.as_deref(),
		data.replaces.as_deref(),
	)?;
	let signature = sign_tlv(&concatenate(&signed), secret)?;
	signed.push(assigned_tlv(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	));
	signed.push(assigned_tlv(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	));
	// Via and SeenBy are `F` values like Area, so a peer-addressed File carries
	// neither. `validate_standalone_file` rejects one that does.
	if distribution {
		signed.push(via_value(effective_signer, via_timestamp, software));
		// TSP-0016 section 3.2 marks File SeenBy "F+", so unlike a Message it
		// repeats. Each value is still its own Trimmed Collection.
		for value in seen_by {
			signed.push(assigned_tlv(
				types::SEEN_BY,
				value.to_string().into_bytes(),
			));
		}
	}
	Ok(assigned_tlv(types::FILE, concatenate(&signed)))
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
	validate_produced_filename(filename)?;
	let mut children = vec![assigned_tlv(
		types::FILENAME,
		filename.as_bytes().to_vec(),
	)];
	if let Some(timestamp) = newer_than {
		children.push(assigned_tlv(
			types::TIMESTAMP,
			crate::integer::encode_u64(timestamp),
		));
	}
	children.push(assigned_tlv(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	));
	Ok(assigned_tlv(types::FILE_REQUEST, concatenate(&children)))
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
	output.push(assigned_tlv(
		types::REQUEST_IDENTIFIER,
		crate::integer::encode_u64(request_identifier),
	));
	for child in &children[signature + 1..] {
		if child.type_code == types::VIA || !types::is_defined(child.type_code) {
			output.push(child.clone());
		}
	}
	output.push(via_value(receiving_identity, via_timestamp, software));
	if item.type_code == types::MESSAGE {
		if let Some(value) = seen_by_value(seen_by) {
			output.push(value);
		}
	} else {
		for address in seen_by {
			output.push(assigned_tlv(
				types::SEEN_BY,
				address.to_string().into_bytes(),
			));
		}
	}
	for child in &children[signature + 1..] {
		if child.type_code == types::ADDITIONAL_KLUDGE_LINE {
			output.push(child.clone());
		}
	}
	Ok(assigned_tlv(item.type_code, concatenate(&output)))
}

fn concatenate(values: &[OwnedTlv]) -> Vec<u8> {
	let mut output = Vec::with_capacity(values.iter().map(OwnedTlv::encoded_len).sum());
	for value in values {
		value.write_to(&mut output).expect("Vec writes cannot fail");
	}
	output
}

/// Constructs a TLV whose Type is one of the nonzero assignments selected by
/// the item grammar. The fallible public constructor exists for caller-supplied
/// Types; every call in this module uses a fixed assigned Type or an outer Type
/// already restricted to Message or File.
fn assigned_tlv(type_code: u64, value: Vec<u8>) -> OwnedTlv {
	OwnedTlv { type_code, value }
}

fn push_identity(
	output: &mut Vec<OwnedTlv>,
	type_code: u64,
	identity: &Identity,
) {
	output.push(assigned_tlv(
		type_code,
		identity.address.to_string().into_bytes(),
	));
	if identity.address.is_anonymous() {
		output.push(assigned_tlv(
			types::PUBLIC_KEY,
			identity.public_key.as_bytes().to_vec(),
		));
	}
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
		push_identity(output, types::ORIGIN, signer);
		return Ok(());
	}
	if provenance.origin.is_anonymous() {
		return Err(BundleError::Unexpected(
			"anonymous Origin without its own PublicKey",
		));
	}
	output.push(assigned_tlv(
		types::ORIGIN,
		provenance.origin.to_string().into_bytes(),
	));
	push_identity(output, types::SIGNED_ORIGIN, signer);
	Ok(())
}

fn area_value(area: &AreaData) -> OwnedTlv {
	let mut children = vec![assigned_tlv(
		types::AREA_NAME,
		area.name.as_bytes().to_vec(),
	)];
	if let Some(description) = &area.description {
		children.push(assigned_tlv(
			types::AREA_DESCRIPTION,
			description.as_bytes().to_vec(),
		));
	}
	assigned_tlv(types::AREA, concatenate(&children))
}

fn validate_produced_filename(value: &str) -> Result<(), BundleError> {
	if filename_has_path_component(value) {
		return Err(BundleError::Unexpected("Filename path component"));
	}
	if !filename_is_portable(value) {
		return Err(BundleError::Unexpected(
			"Filename code point discouraged for production",
		));
	}
	Ok(())
}

fn push_filename(output: &mut Vec<OwnedTlv>, value: Option<&str>) -> Result<(), BundleError> {
	if let Some(value) = value {
		validate_produced_filename(value)?;
		output.push(assigned_tlv(types::FILENAME, value.as_bytes().to_vec()));
	}
	Ok(())
}

fn push_file_metadata(
	output: &mut Vec<OwnedTlv>,
	short_description: Option<&str>,
	long_description_lines: &[String],
	tear_line: Option<&str>,
	magic_word: Option<&str>,
	replaces: Option<&str>,
) -> Result<(), BundleError> {
	if let Some(value) = short_description {
		if value.contains(['\r', '\n']) {
			return Err(BundleError::Unexpected("newline in ShortDescription"));
		}
		output.push(assigned_tlv(
			types::SHORT_DESCRIPTION,
			value.as_bytes().to_vec(),
		));
	}
	for value in long_description_lines {
		if value.contains(['\r', '\n']) {
			return Err(BundleError::Unexpected("newline in LongDescriptionLine"));
		}
		output.push(assigned_tlv(
			types::LONG_DESCRIPTION_LINE,
			value.as_bytes().to_vec(),
		));
	}
	for (type_code, value) in [
		(types::TEAR_LINE, tear_line),
		(types::MAGIC_WORD, magic_word),
		(types::REPLACES, replaces),
	] {
		if let Some(value) = value {
			output.push(assigned_tlv(type_code, value.as_bytes().to_vec()));
		}
	}
	Ok(())
}

/// One `SeenBy` holding the whole collection, or nothing when it is empty.
fn seen_by_value(addresses: &[Address]) -> Option<OwnedTlv> {
	if addresses.is_empty() {
		return None;
	}
	let value = crate::address::format_trimmed_collection(addresses);
	Some(assigned_tlv(types::SEEN_BY, value.into_bytes()))
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

fn via_value(identity: &Identity, timestamp: u64, software: &str) -> OwnedTlv {
	let mut children = Vec::new();
	children.push(assigned_tlv(
		types::ADDRESS,
		identity.address.to_string().into_bytes(),
	));
	if identity.address.is_anonymous() {
		children.push(assigned_tlv(
			types::PUBLIC_KEY,
			identity.public_key.as_bytes().to_vec(),
		));
	}
	children.push(assigned_tlv(
		types::TIMESTAMP,
		crate::integer::encode_u64(timestamp),
	));
	let mut value = concatenate(&children);
	value.extend_from_slice(software.as_bytes());
	assigned_tlv(types::VIA, value)
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
	resolver: &dyn KeyResolver,
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
	resolver: &dyn KeyResolver,
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

fn validate_area(value: &OwnedTlv) -> Result<AreaData, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let name = text(cursor.take(types::AREA_NAME, "AreaName")?.1)?.to_owned();
	let description = cursor
		.optional(types::AREA_DESCRIPTION)
		.map(|(_, description)| text(description).map(str::to_owned))
		.transpose()?;
	cursor.finish()?;
	Ok(AreaData { name, description })
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
	resolver: &dyn KeyResolver,
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
	] {
		text(cursor.take(type_code, name)?.1)?;
	}
	let message_text = text(cursor.take(types::MESSAGE_TEXT, "MessageText")?.1)?;
	validate_message_text(message_text)?;
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
		validate_legacy_attributes(decode_u64(&value.value)?)?;
	}
	if let Some((_, value)) = cursor.optional(types::TIMESTAMP_OFFSET) {
		validate_timestamp_offset(decode_i64(&value.value)?)?;
	}
	let mut echo_control = false;
	for type_code in [types::TEAR_LINE, types::ORIGIN_LINE, types::MESSAGE_ID] {
		if let Some((_, value)) = cursor.optional(type_code) {
			text(value)?;
			echo_control |= matches!(type_code, types::TEAR_LINE | types::ORIGIN_LINE);
		}
	}
	if destination.is_some() && echo_control {
		return Err(BundleError::Unexpected("a NetMail TearLine or OriginLine"));
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
				kind: SignedItemKind::Message,
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
		seen_by_addresses(seen_by)?;
	}
	for (_, line) in cursor.repeated(types::ADDITIONAL_KLUDGE_LINE) {
		if text(line)?.contains('\u{0001}') {
			return Err(BundleError::Unexpected("Control-A in AdditionalKludgeLine"));
		}
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
		area: area.map(|value| value.name),
		raw: value.clone(),
	})
}

fn validate_file(
	value: &OwnedTlv,
	standalone: bool,
	resolver: &dyn KeyResolver,
) -> Result<Option<ValidatedItem>, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	if let Some((_, filename)) = cursor.optional(types::FILENAME) {
		let filename = text(filename)?;
		if filename_has_path_component(filename) {
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
	if !standalone && area.is_some() {
		return Err(BundleError::Unexpected("attached File Area"));
	}
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
		seen_by_addresses(seen_by)?;
	}
	cursor.finish()?;
	Ok(request_identifier.map(|request_identifier| ValidatedItem {
		kind: ItemKind::File,
		request_identifier,
		duplicate_identity: signature.filter(|(_, authenticated)| *authenticated).map(
			|(signature, _)| SignedItemIdentity {
				kind: SignedItemKind::File,
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
		area: area.map(|value| value.name),
		raw: value.clone(),
	}))
}

fn validate_file_request(value: &OwnedTlv) -> Result<ValidatedItem, BundleError> {
	let children = parse_sequence(&value.value)?;
	let mut cursor = Cursor::new(&children);
	let filename = text(cursor.take(types::FILENAME, "Filename")?.1)?;
	if filename_has_path_component(filename) {
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
	item: ItemModel,
}

impl ItemModel {
	/// Parses one TTS-0005-carried item while retaining every encoded child.
	pub fn parse(value: &OwnedTlv, resolver: &dyn KeyResolver) -> Result<Self, BundleError> {
		let kind = match value.type_code {
			types::MESSAGE => {
				validate_message(value, resolver)?;
				ItemModelKind::Message
			}
			types::FILE => {
				validate_file(value, true, resolver)?;
				ItemModelKind::StandaloneFile
			}
			types::FILE_REQUEST => {
				validate_file_request(value)?;
				ItemModelKind::FileRequest
			}
			_ => return Err(BundleError::Unexpected("ItemModel item kind")),
		};
		Ok(Self {
			kind,
			children: parse_sequence(&value.value)?,
		})
	}

	/// Re-encodes the exact ordered model with the TTS-0005 outer Type.
	#[must_use]
	pub fn to_tlv(&self) -> OwnedTlv {
		let type_code = match self.kind {
			ItemModelKind::Message => types::MESSAGE,
			ItemModelKind::StandaloneFile => types::FILE,
			ItemModelKind::FileRequest => types::FILE_REQUEST,
		};
		assigned_tlv(type_code, self.encode_value())
	}
}

impl MessageModel {
	/// Parses and structurally validates a Message while retaining every child.
	pub fn parse(value: &OwnedTlv, resolver: &dyn KeyResolver) -> Result<Self, BundleError> {
		let item = ItemModel::parse(value, resolver)?;
		if item.kind() != ItemModelKind::Message {
			return Err(BundleError::Unexpected("MessageModel item kind"));
		}
		Ok(Self { item })
	}

	#[must_use]
	pub fn children(&self) -> &[OwnedTlv] {
		self.item.children()
	}

	/// Re-encodes the exact ordered child model as one Message.
	#[must_use]
	pub fn to_tlv(&self) -> OwnedTlv {
		self.item.to_tlv()
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
	resolver: &dyn KeyResolver,
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
	let original_character_set = cursor
		.optional(types::ORIGINAL_CHARACTER_SET)
		.map(|(_, value)| text(value).map(str::to_owned))
		.transpose()?;
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
			original_character_set,
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
	let filename = cursor
		.optional(types::FILENAME)
		.map(|(_, value)| text(value).map(str::to_owned))
		.transpose()?;
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
	let filename = cursor
		.optional(types::FILENAME)
		.map(|(_, value)| text(value).map(str::to_owned))
		.transpose()?;
	let timestamp = cursor
		.optional(types::TIMESTAMP)
		.map(|(_, value)| decode_u64(&value.value))
		.transpose()?;
	let contents = cursor
		.take(types::CONTENTS, "attached Contents")?
		.1
		.value
		.clone();
	let short_description = cursor
		.optional(types::SHORT_DESCRIPTION)
		.map(|(_, value)| text(value).map(str::to_owned))
		.transpose()?;
	let mut long_description_lines = Vec::new();
	for (_, value) in cursor.repeated(types::LONG_DESCRIPTION_LINE) {
		long_description_lines.push(text(value)?.to_owned());
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
	cursor.finish()?;
	Ok(AttachmentData {
		filename,
		timestamp,
		contents,
		short_description,
		long_description_lines,
		tear_line,
		magic_word,
		replaces,
	})
}
