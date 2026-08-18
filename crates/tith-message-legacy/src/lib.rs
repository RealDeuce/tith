//! Legacy stored `.msg` reading for outbound submission.
//!
//! TSP-0003 section 4 defines the canonical stored Message: a 190-byte header
//! followed by canonical Message Text and one NUL terminator. This crate reads
//! that object and resolves the pieces a submitter needs. It does not build IPC
//! documents and does not depend on the native protocol layer, because
//! conversion is a legacy boundary.

#![forbid(unsafe_code)]

mod attach;
mod packet;

use std::fmt;

pub use attach::{AttachError, AttachStyle, Attachment, Disposition, attachments, file_list};
pub use packet::{
	Endpoint, PACKED_HEADER_BYTES, PACKET_HEADER_BYTES, PackedMessage, Packet, PacketError,
};

/// Total size of the TSP-0003 section 4 stored header.
pub const HEADER_BYTES: usize = 190;

/// Byte offset of the `AttributeWord` within that header.
pub const ATTRIBUTE_OFFSET: usize = 186;

// FTS-0001.016 AttributeWord bits.
const ATTRIBUTE_SENT: u16 = 1 << 3;
const ATTRIBUTE_FILE_ATTACHED: u16 = 1 << 4;
const ATTRIBUTE_KILL_SENT: u16 = 1 << 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageError {
	/// Fewer than the 190 header bytes TSP-0003 requires.
	ShortHeader,
	/// No NUL terminating the Message Text. TSP-0003:872 requires one; the
	/// FTS-0001.016 blank line, 0x1A, and end-of-file terminators are accepted
	/// only under explicit compatibility policy.
	MissingTextTerminator,
	/// A field is not representable as text under the supported encodings.
	UnsupportedEncoding,
}

impl fmt::Display for MessageError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::ShortHeader => "stored message is shorter than its 190-byte header",
			Self::MissingTextTerminator => "stored message text has no NUL terminator",
			Self::UnsupportedEncoding => {
				"stored message is not ASCII or declared UTF-8; other character sets are not yet converted"
			}
		})
	}
}

impl std::error::Error for MessageError {}

/// One `0x01` prefixed, `0x0D` terminated control paragraph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control {
	/// The control name up to its first space or colon, such as `MSGID`.
	pub name: String,
	/// Everything after that name with one separating space removed.
	pub value: String,
	/// The complete payload without the leading `0x01`, for pass-through.
	pub raw: String,
}

/// A parsed stored `.msg`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMessage {
	pub from_user: String,
	pub to_user: String,
	/// The raw Subject field. When [`Self::has_file_attached`] is set this is an
	/// FTS-0001.016 `FileList` rather than a human subject.
	pub subject: String,
	pub date_time: String,
	pub attributes: u16,
	pub controls: Vec<Control>,
	/// Message Text with the leading control paragraphs removed.
	pub text: String,
}

fn field(bytes: &[u8], offset: usize, width: usize) -> Result<String, MessageError> {
	let raw = &bytes[offset..offset + width];
	let end = raw.iter().position(|byte| *byte == 0).unwrap_or(width);
	text(&raw[..end])
}

/// Decodes legacy bytes as text.
///
/// ASCII and valid UTF-8 are accepted. TSP-0003 section 3 also defines CP437,
/// LATIN-1, and other conversions which this crate does not implement yet, so
/// anything else is refused rather than decoded by guess.
pub(crate) fn text(bytes: &[u8]) -> Result<String, MessageError> {
	std::str::from_utf8(bytes)
		.map(str::to_owned)
		.map_err(|_| MessageError::UnsupportedEncoding)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
	u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Splits leading control paragraphs from the body.
pub(crate) fn split_controls(text: &str) -> (Vec<Control>, String) {
	let mut controls = Vec::new();
	let mut rest = text;
	while let Some(after) = rest.strip_prefix('\u{1}') {
		let (payload, remainder) = match after.find('\r') {
			Some(position) => (&after[..position], &after[position + 1..]),
			None => (after, ""),
		};
		let (name, value) = match payload.find([' ', ':']) {
			Some(position) => {
				let name = &payload[..position];
				let value = payload[position..]
					.trim_start_matches(':')
					.trim_start_matches(' ');
				(name, value)
			}
			None => (payload, ""),
		};
		controls.push(Control {
			name: name.to_owned(),
			value: value.to_owned(),
			raw: payload.to_owned(),
		});
		rest = remainder;
	}
	(controls, rest.to_owned())
}

impl StoredMessage {
	/// Reads the TSP-0003 section 4 stored form.
	pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
		if bytes.len() < HEADER_BYTES {
			return Err(MessageError::ShortHeader);
		}
		let body = &bytes[HEADER_BYTES..];
		let end = body
			.iter()
			.position(|byte| *byte == 0)
			.ok_or(MessageError::MissingTextTerminator)?;
		let (controls, text) = split_controls(&text(&body[..end])?);
		Ok(Self {
			from_user: field(bytes, 0, 36)?,
			to_user: field(bytes, 36, 36)?,
			subject: field(bytes, 72, 72)?,
			date_time: field(bytes, 144, 20)?,
			attributes: u16_at(bytes, ATTRIBUTE_OFFSET),
			controls,
			text,
		})
	}

	/// FTS-0001.016 bit 4. The Subject is a `FileList` when this is set.
	#[must_use]
	pub fn has_file_attached(&self) -> bool {
		self.attributes & ATTRIBUTE_FILE_ATTACHED != 0
	}

	/// FTS-0001.016 bit 7. Requests removal of the message, not its
	/// attachments; FSC-0053.002 KFS and TFS cover those separately.
	#[must_use]
	pub fn has_kill_sent(&self) -> bool {
		self.attributes & ATTRIBUTE_KILL_SENT != 0
	}

	/// FTS-0001.016 bit 3.
	#[must_use]
	pub fn has_sent(&self) -> bool {
		self.attributes & ATTRIBUTE_SENT != 0
	}

	/// The first control with this name, compared case insensitively.
	#[must_use]
	pub fn control(&self, name: &str) -> Option<&Control> {
		self.controls
			.iter()
			.find(|control| control.name.eq_ignore_ascii_case(name))
	}

	/// The whitespace separated FSC-0053.002 FLAGS payload.
	#[must_use]
	pub fn flags(&self) -> Vec<String> {
		self.control("FLAGS")
			.map(|control| {
				control
					.value
					.split_whitespace()
					.map(str::to_owned)
					.collect()
			})
			.unwrap_or_default()
	}

	/// FSC-0053.002 K/S, the FLAGS spelling of the `KillSent` attribute.
	#[must_use]
	pub fn requests_kill(&self) -> bool {
		self.has_kill_sent() || self.flags().iter().any(|flag| flag == "K/S")
	}

	/// Resolves the attachment list, empty when no file is attached.
	pub fn attachments(&self, style: AttachStyle) -> Result<Vec<Attachment>, AttachError> {
		if !self.has_file_attached() {
			return Ok(Vec::new());
		}
		attachments(&self.subject, &self.flags(), style)
	}

	/// The TSP-0006 Idempotency-Key for this message, when one is available.
	///
	/// FTS-0009.001 defines MSGID as a unique message identifier, so its exact
	/// payload is the natural key: no two messages from a system share a
	/// serial. It is also unaffected by an `AttributeWord` change, so setting the
	/// Sent bit does not turn a resubmission into new work.
	///
	/// No hash is used. Every hash context in `tith-crypto` is assigned by a
	/// standard and none covers a legacy stored message; a context is an
	/// assigned value and is not something to mint here.
	#[must_use]
	pub fn idempotency_key(&self) -> Option<String> {
		self.control("MSGID")
			.filter(|control| !control.value.is_empty())
			.map(|control| format!("msgid:{}", control.value))
	}
}

/// Overwrites the `AttributeWord` of a stored message in place.
///
/// The caller owns the bytes; the scanner only does this to a message it has
/// claimed under a private name.
pub fn set_attributes(bytes: &mut [u8], value: u16) -> Result<(), MessageError> {
	if bytes.len() < HEADER_BYTES {
		return Err(MessageError::ShortHeader);
	}
	bytes[ATTRIBUTE_OFFSET..ATTRIBUTE_OFFSET + 2].copy_from_slice(&value.to_le_bytes());
	Ok(())
}

/// Returns the `AttributeWord` with the Sent bit set.
#[must_use]
pub fn with_sent(attributes: u16) -> u16 {
	attributes | ATTRIBUTE_SENT
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Builds a stored message with the TSP-0003 section 4 layout.
	fn stored(subject: &str, attributes: u16, body: &str) -> Vec<u8> {
		let mut bytes = vec![0_u8; HEADER_BYTES];
		bytes[..6].copy_from_slice(b"Sender");
		bytes[36..45].copy_from_slice(b"Recipient");
		bytes[72..72 + subject.len()].copy_from_slice(subject.as_bytes());
		bytes[144..144 + 19].copy_from_slice(b"01 Jan 26  00:00:00");
		bytes[ATTRIBUTE_OFFSET..ATTRIBUTE_OFFSET + 2].copy_from_slice(&attributes.to_le_bytes());
		bytes.extend_from_slice(body.as_bytes());
		bytes.push(0);
		bytes
	}

	#[test]
	fn reads_fields_from_their_documented_offsets() {
		let message = StoredMessage::parse(&stored("Hello", 0, "Body text")).unwrap();
		assert_eq!(message.from_user, "Sender");
		assert_eq!(message.to_user, "Recipient");
		assert_eq!(message.subject, "Hello");
		assert_eq!(message.date_time, "01 Jan 26  00:00:00");
		assert_eq!(message.text, "Body text");
		assert!(message.controls.is_empty());
	}

	#[test]
	fn rejects_a_short_header_or_unterminated_text() {
		assert_eq!(
			StoredMessage::parse(&[0_u8; 100]),
			Err(MessageError::ShortHeader)
		);
		let mut bytes = stored("Hello", 0, "Body");
		bytes.pop();
		assert_eq!(
			StoredMessage::parse(&bytes),
			Err(MessageError::MissingTextTerminator)
		);
	}

	#[test]
	fn splits_leading_control_paragraphs_from_the_body() {
		let body = "\u{1}MSGID: 1:2/3 1a2b3c4d\r\u{1}FLAGS KFS\r\u{1}CHRS: UTF-8 4\rReal text\r\n";
		let message = StoredMessage::parse(&stored("s", 0, body)).unwrap();
		assert_eq!(message.controls.len(), 3);
		assert_eq!(message.control("MSGID").unwrap().value, "1:2/3 1a2b3c4d");
		assert_eq!(
			message.control("msgid").unwrap().raw,
			"MSGID: 1:2/3 1a2b3c4d"
		);
		assert_eq!(message.flags(), ["KFS"]);
		assert_eq!(message.text, "Real text\r\n");
	}

	#[test]
	fn reports_the_attribute_bits_it_acts_on() {
		let message = StoredMessage::parse(&stored("a.zip", 1 << 4, "")).unwrap();
		assert!(message.has_file_attached());
		assert!(!message.has_kill_sent());
		assert!(!message.has_sent());

		let message = StoredMessage::parse(&stored("s", 1 << 7, "")).unwrap();
		assert!(message.has_kill_sent());
		assert!(message.requests_kill());

		// FSC-0053.002 K/S is the FLAGS spelling of the same request.
		let message = StoredMessage::parse(&stored("s", 0, "\u{1}FLAGS K/S\r")).unwrap();
		assert!(!message.has_kill_sent());
		assert!(message.requests_kill());
	}

	#[test]
	fn resolves_attachments_only_when_the_attribute_is_set() {
		let attached = StoredMessage::parse(&stored("^a.zip", 1 << 4, "")).unwrap();
		assert_eq!(
			attached.attachments(AttachStyle::Binkley).unwrap()[0].name,
			"a.zip"
		);
		// Without bit 4 the Subject is a subject, not a FileList.
		let plain = StoredMessage::parse(&stored("^a.zip", 0, "")).unwrap();
		assert!(plain.attachments(AttachStyle::Binkley).unwrap().is_empty());
	}

	#[test]
	fn derives_the_idempotency_key_from_msgid() {
		let body = "\u{1}MSGID: 1:2/3 1a2b3c4d\r";
		let message = StoredMessage::parse(&stored("s", 0, body)).unwrap();
		assert_eq!(
			message.idempotency_key().as_deref(),
			Some("msgid:1:2/3 1a2b3c4d")
		);

		// The key must not move when the Sent bit is set, or a second run
		// would resubmit the message as new work.
		let sent = StoredMessage::parse(&stored("s", 1 << 3, body)).unwrap();
		assert_eq!(sent.idempotency_key(), message.idempotency_key());

		// No MSGID means no stable key; the caller generates one and accepts
		// that an interrupted run may submit the message twice.
		let none = StoredMessage::parse(&stored("s", 0, "text")).unwrap();
		assert_eq!(none.idempotency_key(), None);
	}

	#[test]
	fn rewrites_the_attribute_word_in_place() {
		let mut bytes = stored("s", 0, "text");
		set_attributes(&mut bytes, with_sent(0)).unwrap();
		let message = StoredMessage::parse(&bytes).unwrap();
		assert!(message.has_sent());
		assert_eq!(message.text, "text");
	}

	#[test]
	fn refuses_bytes_that_are_not_ascii_or_utf8() {
		let mut bytes = stored("s", 0, "text");
		bytes[0] = 0xff;
		assert_eq!(
			StoredMessage::parse(&bytes),
			Err(MessageError::UnsupportedEncoding)
		);
	}
}
