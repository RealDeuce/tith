//! The TSP-0003 field mapping, in both directions.
//!
//! Export turns a native Message into a legacy packed Message. Reconstruction
//! is its inverse and exists for one reason: TSP-0003 section 3.1 makes a
//! canonical signed-region export available "only when applying the canonical
//! Legacy-to-TITH rules to the generated legacy Message will reproduce
//! byte-for-byte the encoded Message children from Origin through the final
//! child before Signature", and requires the exporter to perform that inverse
//! conversion and verify the original Signature over the result before
//! publishing.
//!
//! When the self-check fails the message is still delivered, as compatibility
//! output without TITHSIG. Section 10 permits that; it is a deliberate
//! presentation loss rather than an error.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::{PUBLIC_KEY_BYTES, PublicKey, SIGNATURE_BYTES, Signature, verify_tlv};
use tith_message_legacy::{
	Control, ExportError, PackedMessage, control, encode_body, format_date_time, parse_date_time,
	tithsig_controls, tithsign_controls,
};
use tith_wire::bundle::KeyResolver;
use tith_wire::item::{ItemAuthentication, LEGACY_ATTRIBUTES_SIGNED_MASK, ReadMessage};
use tith_wire::{Address, OwnedTlv, types};

use crate::address::{self, AddressError};

/// The FTS-0001.016 attribute bit which marks attached files.
const ATTRIBUTE_FILE_ATTACHED: u16 = 1 << 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConvertError {
	Legacy(ExportError),
	Address(AddressError),
	/// A native value has no legacy representation at all.
	Unrepresentable(&'static str),
	/// A required trusted-context value is absent.
	Missing(&'static str),
}

impl std::fmt::Display for ConvertError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Legacy(error) => write!(f, "{error}"),
			Self::Address(error) => write!(f, "{error}"),
			Self::Unrepresentable(what) => write!(f, "{what} has no legacy representation"),
			Self::Missing(what) => write!(f, "the conversion context has no {what}"),
		}
	}
}

impl std::error::Error for ConvertError {}

impl From<ExportError> for ConvertError {
	fn from(value: ExportError) -> Self {
		Self::Legacy(value)
	}
}

impl From<AddressError> for ConvertError {
	fn from(value: AddressError) -> Self {
		Self::Address(value)
	}
}

/// The trusted local facts a conversion needs which the item does not carry.
#[derive(Clone, Debug)]
pub struct Context {
	/// The immediate legacy packet endpoints, from link configuration.
	pub packet_origin: Address,
	pub packet_destination: Address,
	/// The domain a packet's addresses belong to. A packet has no domain field,
	/// so TSP-0003 section 6 requires the context to supply it and to verify
	/// that the selected endpoints belong to it.
	pub domain: String,
	/// Product and version for a Via whose software string cannot supply them.
	pub product: String,
	pub version: String,
	/// The legacy area tag for each native `AreaName`.
	///
	/// TSP-0003 section 7 requires one unique tag per name and forbids
	/// lowercasing a native name or inventing one from an untrusted AREA.
	pub area_tags: BTreeMap<String, String>,
}

impl Context {
	pub(crate) fn area_tag(&self, name: &str) -> Result<&str, ConvertError> {
		self.area_tags
			.get(name)
			.map(String::as_str)
			.ok_or(ConvertError::Missing("legacy tag for this AreaName"))
	}

	fn native_area(&self, tag: &str) -> Option<&str> {
		self.area_tags
			.iter()
			.find(|(_, value)| value.as_str() == tag)
			.map(|(name, _)| name.as_str())
	}
}

/// How much of the signed region survived the conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fidelity {
	/// The inverse conversion reproduced the signed bytes and the original
	/// Signature verified over them, so the message carries TITHSIG.
	Canonical,
	/// A deliberate presentation loss. TSP-0003 section 10: compatibility output
	/// "MUST NOT carry TITHSIG".
	Compatibility,
}

/// The structured authentication carried by canonical TITHSIGN/TITHSIG
/// controls. The signature is deliberately not verified here: the service
/// owns the current key resolver and verifies the reconstructed Message before
/// committing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSigning {
	pub signature: Signature,
	pub signed_origin: Option<Address>,
	pub signed_origin_key: Option<PublicKey>,
}

/// Decodes canonical revision-1 TITHSIGN/TITHSIG controls.
///
/// Absence returns `None`. A malformed or partial group is an error and must
/// not be passed through as an `AdditionalKludgeLine`.
pub fn retained_signing(controls: &[Control]) -> Result<Option<RetainedSigning>, ConvertError> {
	let signing: Vec<(usize, &Control)> = controls
		.iter()
		.enumerate()
		.filter(|(_, control)| matches!(control.name.as_str(), "TITHSIGN" | "TITHSIG"))
		.collect();
	if signing.is_empty() {
		return Ok(None);
	}
	if signing.windows(2).any(|pair| pair[1].0 != pair[0].0 + 1) {
		return Err(ConvertError::Unrepresentable(
			"a nonconsecutive TITHSIGN/TITHSIG group",
		));
	}
	let sig: Vec<_> = signing
		.iter()
		.filter(|(_, control)| control.name == "TITHSIG")
		.collect();
	if sig.len() != 2 || sig[1].0 != sig[0].0 + 1 {
		return Err(ConvertError::Unrepresentable("a malformed TITHSIG group"));
	}
	let mut signature_text = String::new();
	for (_, control) in sig {
		let Some(chunk) = control.value.strip_prefix("1 ") else {
			return Err(ConvertError::Unrepresentable("a TITHSIG revision"));
		};
		if chunk.len() != 43 {
			return Err(ConvertError::Unrepresentable("a TITHSIG chunk"));
		}
		signature_text.push_str(chunk);
	}
	let signature: [u8; SIGNATURE_BYTES] = STANDARD_NO_PAD
		.decode(signature_text)
		.map_err(|_| ConvertError::Unrepresentable("a TITHSIG encoding"))?
		.try_into()
		.map_err(|_| ConvertError::Unrepresentable("a TITHSIG Signature"))?;

	let sign: Vec<_> = signing
		.iter()
		.filter(|(_, control)| control.name == "TITHSIGN")
		.collect();
	let (signed_origin, signed_origin_key) = if sign.is_empty() {
		(None, None)
	} else {
		if sign.last().expect("not empty").0 + 1
			!= signing
				.iter()
				.find(|(_, control)| control.name == "TITHSIG")
				.expect("two TITHSIG controls")
				.0
		{
			return Err(ConvertError::Unrepresentable(
				"a nonconsecutive TITHSIGN group",
			));
		}
		let mut encoded = String::new();
		for (position, (_, control)) in sign.iter().enumerate() {
			let Some(rest) = control.value.strip_prefix("1 ") else {
				return Err(ConvertError::Unrepresentable("a TITHSIGN revision"));
			};
			let (marker, chunk) = rest
				.split_once(' ')
				.ok_or(ConvertError::Unrepresentable("a TITHSIGN chunk"))?;
			let final_chunk = position + 1 == sign.len();
			if (final_chunk && marker != ".")
				|| (!final_chunk && marker != "+")
				|| chunk.is_empty()
				|| chunk.len() > 43
				|| (!final_chunk && chunk.len() != 43)
			{
				return Err(ConvertError::Unrepresentable("a TITHSIGN chunk"));
			}
			encoded.push_str(chunk);
		}
		let bytes = STANDARD_NO_PAD
			.decode(encoded)
			.map_err(|_| ConvertError::Unrepresentable("a TITHSIGN encoding"))?;
		let values = tith_wire::tlv::parse_sequence(&bytes)
			.map_err(|_| ConvertError::Unrepresentable("a TITHSIGN TLV sequence"))?;
		if values.is_empty() || values[0].type_code != types::SIGNED_ORIGIN {
			return Err(ConvertError::Unrepresentable("a TITHSIGN SignedOrigin"));
		}
		let address = std::str::from_utf8(&values[0].value)
			.map_err(|_| ConvertError::Unrepresentable("a TITHSIGN SignedOrigin"))?
			.parse::<Address>()
			.map_err(|_| ConvertError::Unrepresentable("a TITHSIGN SignedOrigin"))?;
		let key = if address.is_anonymous() {
			if values.len() != 2 || values[1].type_code != types::PUBLIC_KEY {
				return Err(ConvertError::Unrepresentable("a TITHSIGN PublicKey"));
			}
			let bytes: [u8; PUBLIC_KEY_BYTES] = values[1]
				.value
				.as_slice()
				.try_into()
				.map_err(|_| ConvertError::Unrepresentable("a TITHSIGN PublicKey"))?;
			Some(PublicKey::from_bytes(bytes))
		} else {
			if values.len() != 1 {
				return Err(ConvertError::Unrepresentable(
					"a non-anonymous TITHSIGN value",
				));
			}
			None
		};
		(Some(address), key)
	};
	Ok(Some(RetainedSigning {
		signature: Signature::from_bytes(signature),
		signed_origin,
		signed_origin_key,
	}))
}

/// One converted message and what its conversion preserved.
#[derive(Clone, Debug)]
pub struct Converted {
	pub message: PackedMessage,
	pub fidelity: Fidelity,
	/// Why a canonical conversion was unavailable, for the ledger.
	pub diagnostic: Option<String>,
}

/// Converts a native Message into a legacy packed Message.
///
/// `warning` is the TSP-0011 section 5.1 diagnostic to place at the start of
/// the local presentation, or none. Supplying one forces compatibility output:
/// TSP-0013 section 4 forbids including the diagnostic in an object used to
/// reconstruct the original item, and a packet record is the only object here.
pub fn to_legacy(
	read: &ReadMessage,
	context: &Context,
	authentication: ItemAuthentication,
	warning: Option<&str>,
	resolver: &impl KeyResolver,
) -> Result<Converted, ConvertError> {
	let mut message = build(read, context, warning, &[])?;

	// TSP-0003 section 10.1: "Invalid or Unsigned input is not eligible for a
	// canonical signed-region export."
	let eligible = matches!(
		authentication,
		ItemAuthentication::OriginValid | ItemAuthentication::SignedOriginValid
	) && warning.is_none()
		&& read.signing.signature.is_some();
	if !eligible {
		return Ok(Converted {
			message,
			fidelity: Fidelity::Compatibility,
			diagnostic: Some(ineligible_reason(authentication, warning, read).to_owned()),
		});
	}

	// Build the controls TITHSIG needs, then check that the result inverts.
	let signature = read.signing.signature.expect("checked above");
	let encoded = STANDARD_NO_PAD.encode(signature.as_bytes());
	let mut signing_controls = Vec::new();
	if !read.signing.signed_origin_encoding.is_empty() {
		signing_controls.extend(tithsign_controls(
			&STANDARD_NO_PAD.encode(&read.signing.signed_origin_encoding),
		)?);
	}
	signing_controls.extend(tithsig_controls(&encoded)?);
	let candidate = build(read, context, None, &signing_controls)?;

	match self_check(&candidate, context, read, resolver) {
		Ok(()) => Ok(Converted {
			message: candidate,
			fidelity: Fidelity::Canonical,
			diagnostic: None,
		}),
		Err(reason) => {
			// Fall back to the message without TITHSIG rather than refusing to
			// deliver: the loss is in presentation, not in the payload the
			// ledger retains.
			message.controls.retain(|value| !is_signing_control(value));
			Ok(Converted {
				message,
				fidelity: Fidelity::Compatibility,
				diagnostic: Some(reason),
			})
		}
	}
}

fn is_signing_control(value: &Control) -> bool {
	value.name.eq_ignore_ascii_case("TITHSIG") || value.name.eq_ignore_ascii_case("TITHSIGN")
}

fn ineligible_reason(
	authentication: ItemAuthentication,
	warning: Option<&str>,
	read: &ReadMessage,
) -> &'static str {
	if warning.is_some() {
		// TSP-0013 section 4: the diagnostic "MUST NOT be included if the object
		// is later used to reconstruct or forward the original native item".
		"a delivery warning is present, so this object cannot also reconstruct the item"
	} else if read.signing.signature.is_none() {
		"the item is Unsigned and has no signed region to reconstruct"
	} else {
		match authentication {
			ItemAuthentication::OriginInvalid | ItemAuthentication::SignedOriginInvalid => {
				"the item signature does not match its bytes"
			}
			_ => "the item has no end-to-end authentication",
		}
	}
}

/// Assembles the legacy message.
fn build(
	read: &ReadMessage,
	context: &Context,
	warning: Option<&str>,
	signing_controls: &[String],
) -> Result<PackedMessage, ConvertError> {
	let data = &read.data;
	let offset = data.timestamp_offset.unwrap_or(0);
	let local = i64::try_from(data.timestamp)
		.map_err(|_| ConvertError::Unrepresentable("Timestamp"))?
		.checked_add(offset)
		.ok_or(ConvertError::Unrepresentable("Timestamp"))?;

	let mut controls = vec![parse_control("CHRS: UTF-8 4")?];
	for value in signing_controls {
		controls.push(parse_control(
			value.trim_start_matches('\u{1}').trim_end_matches('\r'),
		)?);
	}
	if let Some(identifier) = &data.message_id {
		controls.push(parse_control(&format!("MSGID: {identifier}"))?);
	}
	if let Some((_, identifier)) = &data.reply_to {
		controls.push(parse_control(&format!("REPLY: {identifier}"))?);
	}
	// TSP-0003 section 3 gives NetMail the addressing controls; section 7 gives
	// EchoMail SPTH instead, because AREA and the Origin line carry conference
	// semantics rather than a Destination.
	if let Some(destination) = &data.destination {
		// MSGTO carries the canonical TTS-0004 text address, which is the one
		// control able to express the full domain and point.
		controls.push(parse_control(&format!("MSGTO: {}", destination.address))?);
		controls.push(parse_control(&format!(
			"INTL {} {}",
			address::three_dimensional(&destination.address)?,
			address::three_dimensional(&read.signing.origin)?
		))?);
		if destination.address.point() != 0 {
			controls.push(parse_control(&format!(
				"TOPT {}",
				destination.address.point()
			))?);
		}
		if read.signing.origin.point() != 0 {
			controls.push(parse_control(&format!(
				"FMPT {}",
				read.signing.origin.point()
			))?);
		}
	}
	controls.push(parse_control(&format!("TZUTC: {}", timezone(offset)?))?);
	for attachment in &data.attachments {
		validate_file_spec(&attachment.filename)?;
		controls.push(parse_control(&format!("ASSOC: {}", attachment.filename))?);
	}
	if data.area.is_some() {
		controls.push(parse_control(&spth(read, context)?)?);
	}
	for line in &data.additional_kludge_lines {
		controls.push(parse_control(line)?);
	}

	let mut body = String::new();
	if let Some(warning) = warning {
		// TSP-0011 section 5.1: prepended to the local presentation, followed by
		// an empty line before MessageText.
		body.push_str(&encode_body(warning)?);
		body.push('\r');
	}
	body.push_str(&encode_body(&data.text)?);
	if data.area.is_some() {
		body.push_str(&echomail_footer(read, context)?);
	} else {
		// A native Via is emitted after NetMail body text.
		for via in &read.vias {
			body.push_str(&control(&via_line(via, context)?)?);
		}
	}

	let attach = !data.attachments.is_empty();
	// TSP-0003 section 4: LegacyAttributes, or zero when absent, with bit 4
	// cleared and then set exactly when File children are present.
	let attributes =
		u16::try_from(data.legacy_attributes.unwrap_or(0) & LEGACY_ATTRIBUTES_SIGNED_MASK)
			.map_err(|_| ConvertError::Unrepresentable("LegacyAttributes"))?;
	let attributes = if attach {
		attributes | ATTRIBUTE_FILE_ATTACHED
	} else {
		attributes & !ATTRIBUTE_FILE_ATTACHED
	};

	let subject = if attach {
		// The Subject is overloaded as the FTS-0001.016 FileList.
		let list = data
			.attachments
			.iter()
			.map(|attachment| attachment.filename.clone())
			.collect::<Vec<_>>()
			.join(" ");
		if !data.subject.is_empty() {
			return Err(ConvertError::Unrepresentable(
				"a Subject alongside attached files",
			));
		}
		list
	} else {
		data.subject.clone()
	};

	Ok(PackedMessage {
		origin: address::endpoint(&context.packet_origin)?,
		destination: address::endpoint(&context.packet_destination)?,
		attributes,
		date_time: format_date_time(local)?,
		to_user: data.to_user.clone(),
		from_user: data.from_user.clone(),
		subject,
		controls,
		text: body,
		area: data
			.area
			.as_deref()
			.map(|name| context.area_tag(name).map(str::to_owned))
			.transpose()?,
	})
}

/// TSP-0003 section 4: a `FileSpec` may not contain NUL, Space, comma, a path
/// separator, or a traversal component.
fn validate_file_spec(name: &str) -> Result<(), ConvertError> {
	if name.is_empty() || name.contains(['\0', ' ', ',', '/', '\\']) || name == "." || name == ".."
	{
		return Err(ConvertError::Unrepresentable("attached Filename"));
	}
	Ok(())
}

/// TSP-0003 section 3: TZUTC has a leading minus west of UTC and no leading
/// plus east of it, and requires a whole number of minutes in four digits.
fn timezone(offset: i64) -> Result<String, ConvertError> {
	if offset % 60 != 0 {
		return Err(ConvertError::Unrepresentable(
			"a TimestampOffset which is not a whole minute",
		));
	}
	let minutes = offset / 60;
	let sign = if minutes < 0 { "-" } else { "" };
	let absolute = minutes.abs();
	let (hours, remainder) = (absolute / 60, absolute % 60);
	if hours > 99 {
		return Err(ConvertError::Unrepresentable(
			"a TimestampOffset beyond 99 hours",
		));
	}
	Ok(format!("{sign}{hours:02}{remainder:02}"))
}

/// Parses the TSP-0003 `TZUTC`/`TZUTCINFO` offset syntax into seconds east of
/// UTC.
#[must_use]
pub fn parse_timezone(value: &str) -> Option<i64> {
	let (sign, digits) = match value.strip_prefix('-') {
		Some(rest) => (-1, rest),
		None => (1, value),
	};
	if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	let hours: i64 = digits[..2].parse().ok()?;
	let minutes: i64 = digits[2..].parse().ok()?;
	(minutes < 60).then_some(sign * (hours * 3600 + minutes * 60))
}

/// The FTS-4009.001 Via line for one native Via.
fn via_line(via: &tith_wire::ViaData, context: &Context) -> Result<String, ConvertError> {
	let time = tith_message_legacy::civil_from_local(
		i64::try_from(via.timestamp).map_err(|_| ConvertError::Unrepresentable("Via Timestamp"))?,
	)?;
	// TSP-0003 section 3: two or three space separated printable ASCII fields of
	// one through ten bytes each are used as-is; otherwise the configured
	// gateway product and version are used.
	let fields: Vec<&str> = via.software.split(' ').collect();
	let usable = (2..=3).contains(&fields.len())
		&& fields.iter().all(|field| {
			(1..=10).contains(&field.len()) && field.bytes().all(|byte| byte.is_ascii_graphic())
		});
	let software = if usable {
		via.software.clone()
	} else {
		format!("{} {}", context.product, context.version)
	};
	Ok(format!(
		"Via {} @{:04}{:02}{:02}.{:02}{:02}{:02}.UTC {software}",
		address::five_dimensional(&via.address)?,
		time.year,
		time.month,
		time.day,
		time.hour,
		time.minute,
		time.second
	))
}

/// The FSC-0067.001 SPTH control: a Trimmed List in processing order.
///
/// TSP-0003 section 7: imported SPTH addresses first, then addresses recovered
/// from a following 2D PATH, then native Via addresses in their existing order,
/// followed by the immediate packet origin if it is not already last.
fn spth(read: &ReadMessage, context: &Context) -> Result<String, ConvertError> {
	let mut path: Vec<Address> = read.vias.iter().map(|via| via.address.clone()).collect();
	if path.last() != Some(&context.packet_origin) {
		path.push(context.packet_origin.clone());
	}
	let line = format!("SPTH: {}", tith_wire::address::format_trimmed_list(&path));
	// Section 7 bounds SPTH lines at 80 bytes including Control-A and CR.
	if line.len() + 2 > 80 {
		return Err(ConvertError::Unrepresentable(
			"an SPTH line beyond 80 bytes",
		));
	}
	Ok(line)
}

/// The `EchoMail` footer: the tear line, the Origin line, then Tiny SEEN-BY.
fn echomail_footer(read: &ReadMessage, context: &Context) -> Result<String, ConvertError> {
	let mut output = String::new();
	// A tear line is three ASCII hyphens, then one Space and the value when the
	// value is nonempty.
	let tear = match read.data.tear_line.as_deref() {
		Some(value) if !value.is_empty() => format!("--- {value}"),
		_ => "---".to_owned(),
	};
	if tear.contains(['\r', '\n']) {
		return Err(ConvertError::Unrepresentable(
			"a TearLine containing a line break",
		));
	}
	output.push_str(&tear);
	output.push('\r');

	let origin_line = read.data.origin_line.as_deref().unwrap_or("");
	let origin = format!(" * Origin: {origin_line}");
	if origin.len() > 79 {
		return Err(ConvertError::Unrepresentable(
			"an Origin line beyond 79 bytes",
		));
	}
	if origin.contains(['\r', '\n']) {
		return Err(ConvertError::Unrepresentable(
			"an OriginLine containing a line break",
		));
	}
	output.push_str(&origin);
	output.push('\r');

	// Tiny SEEN-BY per FSC-0068.001: only addresses in the packet domain and
	// zone with point zero are representable, sorted, deduplicated, and emitted
	// in trimmed 2D form.
	let mut recipients: Vec<&Address> = read
		.seen_by
		.iter()
		.filter(|address| {
			address.domain() == context.domain
				&& address.zone() == context.packet_origin.zone()
				&& address.point() == 0
		})
		.collect();
	recipients.sort_by_key(|address| (address.net(), address.node()));
	recipients.dedup();
	let mut entries: Vec<String> = Vec::new();
	let mut previous_net = None;
	for address in recipients {
		if previous_net == Some(address.net()) {
			entries.push(address.node().to_string());
		} else {
			entries.push(format!("{}/{}", address.net(), address.node()));
			previous_net = Some(address.net());
		}
	}
	if entries.is_empty() {
		return Err(ConvertError::Unrepresentable(
			"an EchoMail with no representable SEEN-BY address",
		));
	}
	// Each line begins "SEEN-BY: " and is at most 80 bytes.
	let mut line = String::from("SEEN-BY:");
	for entry in entries {
		if line.len() + 1 + entry.len() > 79 {
			output.push_str(&line);
			output.push('\r');
			line = String::from("SEEN-BY:");
		}
		line.push(' ');
		line.push_str(&entry);
	}
	output.push_str(&line);
	output.push('\r');
	Ok(output)
}

/// Splits an `EchoMail` body into its user text and footer.
fn split_footer(body: &str) -> (&str, Vec<&str>) {
	let mut lines: Vec<&str> = body.split('\r').collect();
	// A trailing empty element is the split after the final CR.
	if lines.last() == Some(&"") {
		lines.pop();
	}
	let mut footer_start = lines.len();
	while footer_start > 0 {
		let line = lines[footer_start - 1];
		if line.starts_with("SEEN-BY:")
			|| line.starts_with(" * Origin: ")
			|| line.starts_with("---")
		{
			footer_start -= 1;
			if line.starts_with("---") {
				break;
			}
		} else {
			break;
		}
	}
	let consumed: usize = lines[footer_start..]
		.iter()
		.map(|line| line.len() + 1)
		.sum();
	let text_end = body.len().saturating_sub(consumed);
	(&body[..text_end], lines.split_off(footer_start))
}

fn parse_control(payload: &str) -> Result<Control, ConvertError> {
	// Round-trip through the writer so a payload the legacy form cannot carry is
	// refused here rather than corrupting the object later.
	control(payload)?;
	let (name, value) = match payload.find([' ', ':']) {
		Some(position) => (
			&payload[..position],
			payload[position..]
				.trim_start_matches(':')
				.trim_start_matches(' '),
		),
		None => (payload, ""),
	};
	Ok(Control {
		name: name.to_owned(),
		value: value.to_owned(),
		raw: payload.to_owned(),
	})
}

/// Applies the canonical legacy-to-TITH rules and compares the result.
///
/// Returns the reason a canonical conversion is unavailable, so the caller can
/// record it. Success means both that the reconstructed children are byte
/// identical to the originals and that the retained Signature verifies over
/// them, which section 3.1 requires separately.
fn self_check(
	candidate: &PackedMessage,
	context: &Context,
	read: &ReadMessage,
	resolver: &impl KeyResolver,
) -> Result<(), String> {
	let children = reconstruct(candidate, context, read).map_err(|error| error.to_string())?;
	if children != read.signing.signed_region {
		return Err("the reconstructed signed region differs from the original bytes".to_owned());
	}
	let signature = read
		.signing
		.signature
		.ok_or_else(|| "no Signature to verify".to_owned())?;
	// The effective signer is SignedOrigin when present, else Origin. A
	// non-anonymous address carries no inline key, so it comes from the resolver
	// exactly as validation would obtain it.
	let effective = read
		.signing
		.signed_origin
		.as_ref()
		.unwrap_or(&read.signing.origin);
	let key = read
		.signing
		.signed_origin_key
		.or(read.signing.origin_key)
		.or_else(|| resolver.public_key(effective))
		.ok_or_else(|| "no signer key is available to verify the reconstruction".to_owned())?;
	match verify_tlv(&children, &signature, &key) {
		Ok(true) => Ok(()),
		Ok(false) => {
			Err("the retained Signature does not verify over the reconstruction".to_owned())
		}
		Err(error) => Err(error.to_string()),
	}
}

/// Rebuilds the encoded Message children a canonical import would produce.
///
/// Only the children the Signature covers are produced, in the TTS-0005 order,
/// stopping before the Signature itself. Everything after it is outside the
/// signature and is rebuilt from current legacy state instead.
fn reconstruct(
	message: &PackedMessage,
	context: &Context,
	read: &ReadMessage,
) -> Result<Vec<u8>, ConvertError> {
	let mut children: Vec<OwnedTlv> = Vec::new();
	let named = |name: &str| {
		message
			.controls
			.iter()
			.find(|control| control.name.eq_ignore_ascii_case(name))
	};
	let push = |children: &mut Vec<OwnedTlv>, type_code: u64, value: Vec<u8>| {
		OwnedTlv::new(type_code, value)
			.map(|value| children.push(value))
			.map_err(|_| ConvertError::Unrepresentable("a reconstructed child"))
	};

	// Origin: the resolved legacy author, from the MSGID origin.
	let origin = named("MSGID")
		.and_then(|control| control.value.split(' ').next())
		.ok_or(ConvertError::Missing("a MSGID to resolve Origin from"))?;
	let origin: Address = origin
		.parse()
		.map_err(|_| ConvertError::Unrepresentable("a MSGID origin which is not a TTS address"))?;
	push(
		&mut children,
		types::ORIGIN,
		origin.to_string().into_bytes(),
	)?;
	if let Some(key) = read.signing.origin_key {
		push(&mut children, types::PUBLIC_KEY, key.as_bytes().to_vec())?;
	}

	// SignedOrigin and its conditional key come back from TITHSIGN verbatim.
	let mut encoded = String::new();
	for control in &message.controls {
		if control.name.eq_ignore_ascii_case("TITHSIGN") {
			let chunk = control
				.value
				.strip_prefix("1 ")
				.ok_or(ConvertError::Unrepresentable("a TITHSIGN version"))?;
			let chunk = chunk
				.strip_prefix("+ ")
				.or_else(|| chunk.strip_prefix(". "))
				.ok_or(ConvertError::Unrepresentable("a TITHSIGN marker"))?;
			encoded.push_str(chunk);
		}
	}
	// The decoded bytes are already one or two encoded TLVs, so they are spliced
	// in rather than rebuilt. That is the whole point of TITHSIGN: SignedOrigin
	// and its conditional key have no traditional legacy field to map through.
	let signed_origin = if encoded.is_empty() {
		Vec::new()
	} else {
		STANDARD_NO_PAD
			.decode(&encoded)
			.map_err(|_| ConvertError::Unrepresentable("a TITHSIGN encoding"))?
	};
	finish_reconstruction(children, &signed_origin, message, context, read)
}

fn finish_reconstruction(
	mut children: Vec<OwnedTlv>,
	signed_origin: &[u8],
	message: &PackedMessage,
	context: &Context,
	read: &ReadMessage,
) -> Result<Vec<u8>, ConvertError> {
	let named = |name: &str| {
		message
			.controls
			.iter()
			.find(|control| control.name.eq_ignore_ascii_case(name))
	};
	let push = |children: &mut Vec<OwnedTlv>, type_code: u64, value: Vec<u8>| {
		OwnedTlv::new(type_code, value)
			.map(|value| children.push(value))
			.map_err(|_| ConvertError::Unrepresentable("a reconstructed child"))
	};

	if let Some(destination) = named("MSGTO") {
		let address: Address = destination
			.value
			.parse()
			.map_err(|_| ConvertError::Unrepresentable("a MSGTO which is not a TTS address"))?;
		push(
			&mut children,
			types::DESTINATION,
			address.to_string().into_bytes(),
		)?;
	}

	// Timestamp: the local DateTime less the TZUTC offset.
	let local = parse_date_time(&message.date_time)?;
	let offset = named("TZUTC")
		.and_then(|control| parse_timezone(&control.value))
		.ok_or(ConvertError::Missing("a TZUTC to resolve the Timestamp"))?;
	let timestamp = u64::try_from(local - offset)
		.map_err(|_| ConvertError::Unrepresentable("a Timestamp before the epoch"))?;
	push(
		&mut children,
		types::TIMESTAMP,
		tith_wire::encode_u64(timestamp),
	)?;
	push(
		&mut children,
		types::TO_USER_NAME,
		message.to_user.clone().into_bytes(),
	)?;
	push(
		&mut children,
		types::FROM_USER_NAME,
		message.from_user.clone().into_bytes(),
	)?;

	// Under TITHSIG the signed Subject and LegacyAttributes bit 4 select the
	// File children, so the Subject is the FileList when that bit is set.
	let attach = message.attributes & ATTRIBUTE_FILE_ATTACHED != 0;
	let subject = if attach {
		String::new()
	} else {
		message.subject.clone()
	};
	push(&mut children, types::SUBJECT, subject.into_bytes())?;
	let (text, tear_line, origin_line) = message_body_fields(message);
	push(&mut children, types::MESSAGE_TEXT, text.into_bytes())?;

	if let Some(tag) = &message.area {
		let name = context.native_area(tag).ok_or(ConvertError::Missing(
			"a native AreaName for this legacy tag",
		))?;
		let child = OwnedTlv::new(types::AREA_NAME, name.as_bytes().to_vec())
			.map_err(|_| ConvertError::Unrepresentable("AreaName"))?;
		push(&mut children, types::AREA, child.encode())?;
	}

	// Attachment contents are resolved through the trusted companion mapping,
	// which for a self-check is the exact staged bytes about to be published.
	if attach {
		let listed: Vec<&str> = message
			.subject
			.split(' ')
			.filter(|n| !n.is_empty())
			.collect();
		if listed.len() != read.data.attachments.len() {
			return Err(ConvertError::Unrepresentable(
				"a FileList which does not match the File children",
			));
		}
		for (name, attachment) in listed.iter().zip(&read.data.attachments) {
			if *name != attachment.filename {
				return Err(ConvertError::Unrepresentable("a reordered FileList"));
			}
			let mut file = OwnedTlv::new(types::FILENAME, name.as_bytes().to_vec())
				.map_err(|_| ConvertError::Unrepresentable("Filename"))?
				.encode();
			if let Some(timestamp) = attachment.timestamp {
				OwnedTlv::new(types::TIMESTAMP, tith_wire::encode_u64(timestamp))
					.map_err(|_| ConvertError::Unrepresentable("attached Timestamp"))?
					.write_to(&mut file)
					.map_err(|_| ConvertError::Unrepresentable("attached Timestamp"))?;
			}
			OwnedTlv::new(types::CONTENTS, attachment.contents.clone())
				.map_err(|_| ConvertError::Unrepresentable("Contents"))?
				.write_to(&mut file)
				.map_err(|_| ConvertError::Unrepresentable("Contents"))?;
			push(&mut children, types::FILE, file)?;
		}
	}

	// TSP-0003 section 4: import retains only the packet-persistent signed
	// subset. FileAttached is represented by File children; bookkeeping and
	// transport bits may be changed by conforming legacy software and therefore
	// cannot be part of the stable signed projection.
	let attributes = u64::from(message.attributes) & LEGACY_ATTRIBUTES_SIGNED_MASK;
	if attributes != 0 {
		push(
			&mut children,
			types::LEGACY_ATTRIBUTES,
			tith_wire::encode_u64(attributes),
		)?;
	}
	if offset != 0 {
		push(
			&mut children,
			types::TIMESTAMP_OFFSET,
			tith_wire::encode_i64(offset),
		)?;
	}
	if let Some(value) = tear_line {
		push(&mut children, types::TEAR_LINE, value.into_bytes())?;
	}
	if let Some(value) = origin_line {
		push(&mut children, types::ORIGIN_LINE, value.into_bytes())?;
	}
	if let Some(identifier) = named("MSGID") {
		push(
			&mut children,
			types::MESSAGE_ID,
			identifier.value.clone().into_bytes(),
		)?;
	}
	if let Some(reply) = named("REPLY") {
		let address = read
			.data
			.reply_to
			.as_ref()
			.map(|(address, _)| address.clone())
			.ok_or(ConvertError::Missing("a ReplyTo address"))?;
		let mut value = OwnedTlv::new(types::ADDRESS, address.to_string().into_bytes())
			.map_err(|_| ConvertError::Unrepresentable("ReplyTo Address"))?
			.encode();
		value.extend_from_slice(reply.value.as_bytes());
		push(&mut children, types::REPLY_TO, value)?;
	}

	let mut encoded = Vec::new();
	for (index, child) in children.iter().enumerate() {
		// SignedOrigin and its key are spliced in after Origin and its key.
		if index == origin_key_end(read) && !signed_origin.is_empty() {
			encoded.extend_from_slice(signed_origin);
		}
		child
			.write_to(&mut encoded)
			.map_err(|_| ConvertError::Unrepresentable("a reconstructed child"))?;
	}
	Ok(encoded)
}

/// The child index immediately after Origin and its conditional key.
fn origin_key_end(read: &ReadMessage) -> usize {
	1 + usize::from(read.signing.origin_key.is_some())
}

/// The user `MessageText`, and for `EchoMail` the tear and Origin line values.
///
/// TSP-0003 section 7: import removes AREA, SPTH, the optional footer lines,
/// SEEN-BY, and PATH from `MessageText`. Section 3 places `NetMail` Via
/// paragraphs after the body, so those are removed too.
#[must_use]
pub fn message_body_fields(message: &PackedMessage) -> (String, Option<String>, Option<String>) {
	if message.area.is_some() {
		let (text, footer) = split_footer(&message.text);
		let mut tear = None;
		let mut origin = None;
		for line in footer {
			if let Some(value) = line.strip_prefix(" * Origin: ") {
				origin = Some(value.to_owned());
			} else if let Some(value) = line.strip_prefix("---") {
				// A bare "---" is an empty TearLine, "--- x" carries x.
				tear = Some(value.strip_prefix(' ').unwrap_or(value).to_owned());
			}
		}
		return (tith_message_legacy::decode_body(text), tear, origin);
	}
	let mut body = message.text.as_str();
	// Via paragraphs follow the body, each a control terminated by 0x0D.
	while let Some(position) = body.rfind('\u{1}') {
		let paragraph = &body[position + 1..];
		let paragraph = paragraph.strip_suffix('\r').unwrap_or(paragraph);
		if paragraph.starts_with("Via ") && !paragraph.contains('\r') {
			body = &body[..position];
		} else {
			break;
		}
	}
	(tith_message_legacy::decode_body(body), None, None)
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::SigningKeyPair;
	use tith_wire::bundle::Identity;
	use tith_wire::item::{
		AttachmentData, ItemProvenance, MessageData, build_originated_message, read_message,
	};

	fn context() -> Context {
		Context {
			packet_origin: "fidonet#1:104/36".parse().unwrap(),
			packet_destination: "fidonet#1:104/1".parse().unwrap(),
			domain: "fidonet".to_owned(),
			product: "tith".to_owned(),
			version: "0.1".to_owned(),
			area_tags: [("SYNCHRONET".to_owned(), "SYNCHRONET".to_owned())]
				.into_iter()
				.collect(),
		}
	}

	fn signed(data: &MessageData) -> (ReadMessage, SigningKeyPair, Address) {
		signed_with(data, &[])
	}

	fn signed_with_seen_by(data: &MessageData) -> (ReadMessage, SigningKeyPair, Address) {
		signed_with(
			data,
			&[
				"fidonet#1:104/1".parse().unwrap(),
				"fidonet#1:104/36".parse().unwrap(),
			],
		)
	}

	fn signed_with(
		data: &MessageData,
		seen_by: &[Address],
	) -> (ReadMessage, SigningKeyPair, Address) {
		let keys = SigningKeyPair::from_seed(&[90; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let destination = data.destination.clone();
		let item = build_originated_message(
			data,
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: keys.public,
				}),
			},
			&keys.secret,
			7,
			1_755_500_000,
			"tith 0.1",
			seen_by,
		)
		.unwrap();
		let resolver = |address: &Address| {
			if address == &origin {
				Some(keys.public)
			} else {
				destination
					.as_ref()
					.filter(|identity| &identity.address == address)
					.map(|identity| identity.public_key)
			}
		};
		let read = read_message(&item, &resolver).unwrap();
		(read, keys, origin)
	}

	/// The nodelist a non-anonymous Origin's key would come from.
	fn resolver(keys: &SigningKeyPair) -> impl KeyResolver {
		let public = keys.public;
		move |address: &Address| {
			(address == &"fidonet#1:104/36".parse::<Address>().unwrap()).then_some(public)
		}
	}

	fn netmail(attachments: Vec<AttachmentData>, subject: &str) -> MessageData {
		let keys = SigningKeyPair::from_seed(&[91; 32]).unwrap();
		MessageData {
			destination: Some(Identity {
				address: "fidonet#1:104/1".parse().unwrap(),
				public_key: keys.public,
			}),
			timestamp: 1_755_518_400,
			to_user: "Recipient".to_owned(),
			from_user: "Sender".to_owned(),
			subject: subject.to_owned(),
			text: "Body line one\nline two\n".to_owned(),
			area: None,
			attachments,
			legacy_attributes: None,
			timestamp_offset: Some(-25_200),
			tear_line: None,
			origin_line: None,
			message_id: Some("fidonet#1:104/36 1a2b3c4d".to_owned()),
			reply_to: None,
			additional_kludge_lines: Vec::new(),
		}
	}

	#[test]
	fn a_canonical_netmail_reconstructs_its_signed_region() {
		let (read, keys, _) = signed(&netmail(Vec::new(), "Hello"));
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		assert_eq!(
			converted.fidelity,
			Fidelity::Canonical,
			"{:?}",
			converted.diagnostic
		);
		// TITHSIG is present exactly twice and TITHSIGN not at all, because this
		// Origin signed for itself.
		let tithsig = converted
			.message
			.controls
			.iter()
			.filter(|control| control.name == "TITHSIG")
			.count();
		assert_eq!(tithsig, 2);
		assert!(
			!converted
				.message
				.controls
				.iter()
				.any(|control| control.name == "TITHSIGN")
		);
		// The control block opens with CHRS.
		assert_eq!(converted.message.controls[0].raw, "CHRS: UTF-8 4");
	}

	#[test]
	fn retained_signing_rejects_an_interrupted_control_group() {
		let (read, keys, _) = signed(&netmail(Vec::new(), "Hello"));
		let mut converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		let second = converted
			.message
			.controls
			.iter()
			.position(|control| control.name == "TITHSIG")
			.expect("canonical output has TITHSIG")
			+ 1;
		let unrelated = converted.message.controls[0].clone();
		converted.message.controls.insert(second, unrelated);

		assert!(matches!(
			retained_signing(&converted.message.controls),
			Err(ConvertError::Unrepresentable(
				"a nonconsecutive TITHSIGN/TITHSIG group"
			))
		));
	}

	#[test]
	fn attachments_become_the_subject_filelist_and_set_bit_four() {
		// The signed Message carries no LegacyAttributes at all, which is what
		// native origination produces. TSP-0003 section 4 has export set bit 4
		// from File presence and import clear it again, so the reconstruction
		// does not gain a child.
		let data = netmail(
			vec![
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
			"",
		);
		let (read, keys, _) = signed(&data);
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		assert_eq!(converted.message.subject, "work.zip other.zip");
		assert!(converted.message.attributes & ATTRIBUTE_FILE_ATTACHED != 0);
		let assoc: Vec<&str> = converted
			.message
			.controls
			.iter()
			.filter(|control| control.name == "ASSOC")
			.map(|control| control.value.as_str())
			.collect();
		assert_eq!(assoc, ["work.zip", "other.zip"]);
		assert_eq!(
			converted.fidelity,
			Fidelity::Canonical,
			"{:?}",
			converted.diagnostic
		);
	}

	#[test]
	fn a_delivery_warning_forces_compatibility_output() {
		// TSP-0013 section 4: the diagnostic must not be in an object used to
		// reconstruct the item, and a packet record is the only object.
		let (read, keys, _) = signed(&netmail(Vec::new(), "Hello"));
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::SignedOriginValid,
			Some("NOTICE: This message was not signed by its Origin."),
			&resolver(&keys),
		)
		.unwrap();
		assert_eq!(converted.fidelity, Fidelity::Compatibility);
		assert!(
			!converted.message.controls.iter().any(is_signing_control),
			"compatibility output must not carry TITHSIG"
		);
		assert!(converted.message.text.starts_with("NOTICE:"));
	}

	#[test]
	fn an_unsigned_or_invalid_item_never_carries_tithsig() {
		// TSP-0003 section 10.1: "Invalid or Unsigned input is not eligible for a
		// canonical signed-region export."
		let (read, keys, _) = signed(&netmail(Vec::new(), "Hello"));
		for authentication in [
			ItemAuthentication::Unsigned,
			ItemAuthentication::OriginInvalid,
			ItemAuthentication::SignedOriginInvalid,
		] {
			let converted =
				to_legacy(&read, &context(), authentication, None, &resolver(&keys)).unwrap();
			assert_eq!(
				converted.fidelity,
				Fidelity::Compatibility,
				"{authentication:?}"
			);
			assert!(
				!converted.message.controls.iter().any(is_signing_control),
				"{authentication:?}"
			);
		}
	}

	#[test]
	fn a_message_carrying_neither_legacy_value_is_canonical() {
		// Export writes AttributeWord zero and TZUTC 0000 for the absent
		// children, and TSP-0003 section 4 has import reconstruct absence from
		// exactly those, so a Message a TSP-0006 submitter originated -- which
		// carries neither child -- reconstructs byte for byte.
		let mut data = netmail(Vec::new(), "Hello");
		data.legacy_attributes = None;
		data.timestamp_offset = None;
		let (read, keys, _) = signed(&data);
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		assert_eq!(
			converted.fidelity,
			Fidelity::Canonical,
			"{:?}",
			converted.diagnostic
		);
		assert_eq!(converted.diagnostic, None);
		// The legacy object still carries both values; only the native side
		// distinguishes absent from zero.
		assert_eq!(converted.message.attributes, 0);
		let tzutc = converted
			.message
			.controls
			.iter()
			.find(|control| control.name == "TZUTC")
			.unwrap();
		assert_eq!(tzutc.value, "0000");
	}

	#[test]
	fn a_netmail_tear_or_origin_line_stays_in_the_body() {
		// TSP-0003 section 3: those lines are EchoMail control information, so a
		// NetMail carrying them carries them as ordinary Message Text. They need
		// no mapping and must survive the round trip inside MessageText.
		let mut data = netmail(Vec::new(), "Hello");
		data.text = "Body line one\n--- tosser 1.0\n * Origin: A board (1:104/36)\n".to_owned();
		let (read, keys, _) = signed(&data);
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		assert_eq!(
			converted.fidelity,
			Fidelity::Canonical,
			"{:?}",
			converted.diagnostic
		);
		assert!(
			converted
				.message
				.text
				.starts_with("Body line one\r--- tosser 1.0\r * Origin: A board (1:104/36)\r"),
			"{:?}",
			converted.message.text
		);
	}

	fn echomail() -> MessageData {
		MessageData {
			destination: None,
			timestamp: 1_755_518_400,
			to_user: "All".to_owned(),
			from_user: "Sender".to_owned(),
			subject: "Hello".to_owned(),
			text: "Body line one\nline two\n".to_owned(),
			area: Some("SYNCHRONET".to_owned()),
			attachments: Vec::new(),
			legacy_attributes: None,
			timestamp_offset: Some(-25_200),
			tear_line: Some("TITH 0.1".to_owned()),
			origin_line: Some("A board (1:104/36)".to_owned()),
			message_id: Some("fidonet#1:104/36 1a2b3c4d".to_owned()),
			reply_to: None,
			additional_kludge_lines: Vec::new(),
		}
	}

	#[test]
	fn a_canonical_echomail_reconstructs_its_signed_region() {
		let (read, keys, _) = signed_with_seen_by(&echomail());
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		assert_eq!(
			converted.fidelity,
			Fidelity::Canonical,
			"{:?}",
			converted.diagnostic
		);
		assert_eq!(converted.message.area.as_deref(), Some("SYNCHRONET"));

		// TSP-0003 section 7 footer: tear line, Origin line, Tiny SEEN-BY.
		let body = converted.message.text.clone();
		assert!(body.contains("--- TITH 0.1\r"), "{body:?}");
		assert!(body.contains(" * Origin: A board (1:104/36)\r"), "{body:?}");
		assert!(body.contains("SEEN-BY: 104/1 36\r"), "{body:?}");
		// SPTH is a control, not a footer line.
		assert!(
			converted
				.message
				.controls
				.iter()
				.any(|control| control.name == "SPTH")
		);
		// An EchoMail carries no Destination controls.
		assert!(
			!converted
				.message
				.controls
				.iter()
				.any(|control| matches!(control.name.as_str(), "MSGTO" | "INTL" | "TOPT"))
		);
	}

	#[test]
	fn the_seen_by_collection_is_trimmed_and_sorted_numerically() {
		let mut data = echomail();
		data.subject = "Ordering".to_owned();
		let (read, keys, _) = signed_with(
			&data,
			&[
				"fidonet#1:104/36".parse().unwrap(),
				"fidonet#1:104/1".parse().unwrap(),
				"fidonet#1:104/23".parse().unwrap(),
				"fidonet#1:200/7".parse().unwrap(),
				// Another zone and a point are not representable in Tiny form.
				"fidonet#2:200/7".parse().unwrap(),
				"fidonet#1:104/9.1".parse().unwrap(),
			],
		);
		let converted = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap();
		let line = converted
			.message
			.text
			.split('\r')
			.find(|line| line.starts_with("SEEN-BY:"))
			.unwrap()
			.to_owned();
		// Numeric order, not lexical: 1 before 23 before 36.
		assert_eq!(line, "SEEN-BY: 104/1 23 36 200/7");
	}

	#[test]
	fn an_echomail_with_no_representable_recipient_is_refused() {
		let (read, keys, _) = signed_with(&echomail(), &["fidonet#2:200/7".parse().unwrap()]);
		let error = to_legacy(
			&read,
			&context(),
			ItemAuthentication::OriginValid,
			None,
			&resolver(&keys),
		)
		.unwrap_err();
		assert_eq!(
			error,
			ConvertError::Unrepresentable("an EchoMail with no representable SEEN-BY address")
		);
	}

	#[test]
	fn the_timezone_control_uses_the_documented_sign_rule() {
		assert_eq!(timezone(0).unwrap(), "0000");
		assert_eq!(timezone(-25_200).unwrap(), "-0700");
		assert_eq!(timezone(3600 * 5 + 1800).unwrap(), "0530");
		assert!(timezone(30).is_err());
		for text in ["0000", "-0700", "0530"] {
			assert_eq!(timezone(parse_timezone(text).unwrap()).unwrap(), text);
		}
		assert!(parse_timezone("070").is_none());
		assert!(parse_timezone("0099").is_none());
	}

	#[test]
	fn refuses_a_filename_which_is_not_a_safe_filespec() {
		for name in ["", "a b", "a,b", "a/b", "a\\b", ".", ".."] {
			assert!(validate_file_spec(name).is_err(), "{name:?}");
		}
		assert!(validate_file_spec("work.zip").is_ok());
	}
}
