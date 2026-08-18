//! Type-2+ packets and the packed messages inside them.
//!
//! TSP-0003 section 6 defines the 58-byte FSC-0048.002 header and section 5
//! the 34-byte packed message header. A packet is the header, zero or more
//! packed Messages, and one 16-bit zero terminator; at a record boundary value
//! 2 begins a Message and value 0 ends the packet.

use std::fmt;

use crate::{Control, split_controls, text};

/// TSP-0003 section 6 header size.
pub const PACKET_HEADER_BYTES: usize = 58;

/// TSP-0003 section 5 header size.
pub const PACKED_HEADER_BYTES: usize = 34;

/// Record type beginning a packed Message.
const RECORD_MESSAGE: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
	/// Fewer bytes than the 58-byte header.
	ShortHeader,
	/// Packet type is not 2.
	NotTypeTwo,
	/// The capability word validation copy is not its byte swap, or capability
	/// bit zero is clear. TSP-0003 section 6 requires both for Type-2+.
	NotTypePlus,
	/// Origin point is nonzero with origin net 0xffff and no auxiliary net.
	MissingAuxiliaryNet,
	/// A record boundary held neither 2 nor 0.
	MalformedRecord,
	/// The packet ended without its 16-bit zero terminator.
	MissingTerminator,
	/// A packed message header was truncated.
	ShortMessage,
	/// A bounded NUL was not found before its maximum, or the text NUL was not
	/// found before the packet ended.
	MissingFieldTerminator,
}

impl fmt::Display for PacketError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::ShortHeader => "packet is shorter than its 58-byte header",
			Self::NotTypeTwo => "packet type is not 2",
			Self::NotTypePlus => "packet is not Type-2+: capability word validation failed",
			Self::MissingAuxiliaryNet => {
				"origin point is set with origin net 0xffff but no auxiliary net"
			}
			Self::MalformedRecord => "packet record boundary is neither a message nor the end",
			Self::MissingTerminator => "packet has no terminator",
			Self::ShortMessage => "packed message header is truncated",
			Self::MissingFieldTerminator => "packed message field has no NUL terminator",
		})
	}
}

impl std::error::Error for PacketError {}

/// The immediate legacy packet endpoints.
///
/// TSP-0003 section 6: these are the link endpoints from trusted
/// configuration, not necessarily any contained Message's author or ultimate
/// destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
	pub zone: u16,
	pub net: u16,
	pub node: u16,
	pub point: u16,
}

impl fmt::Display for Endpoint {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:{}/{}", self.zone, self.net, self.node)?;
		if self.point != 0 {
			write!(f, ".{}", self.point)?;
		}
		Ok(())
	}
}

/// One message inside a packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedMessage {
	pub origin: Endpoint,
	pub destination: Endpoint,
	pub attributes: u16,
	pub date_time: String,
	pub to_user: String,
	pub from_user: String,
	/// The Subject field, an FTS-0001.016 `FileList` when the attach attribute is
	/// set.
	pub subject: String,
	pub controls: Vec<Control>,
	/// Message Text with the leading controls and any AREA line removed.
	pub text: String,
	/// The TSP-0003 section 7 area name when this is `EchoMail`.
	pub area: Option<String>,
}

/// A parsed packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
	pub origin: Endpoint,
	pub destination: Endpoint,
	pub messages: Vec<PackedMessage>,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
	u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// TSP-0003 section 7: the area name is 1 to 60 bytes from ranges 33-96 and
/// 123-126, and does not begin with "+" or "-".
fn valid_area(name: &str) -> bool {
	let bytes = name.as_bytes();
	(1..=60).contains(&bytes.len())
		&& !matches!(bytes[0], b'+' | b'-')
		&& bytes
			.iter()
			.all(|byte| (33..=96).contains(byte) || (123..=126).contains(byte))
}

/// Splits a leading `AREA:` line, which has no Control-A prefix and is the
/// first text byte of an `EchoMail` message.
fn split_area(body: &str) -> (Option<String>, &str) {
	let Some(rest) = body.strip_prefix("AREA:") else {
		return (None, body);
	};
	let (name, remainder) = match rest.find(['\r', '\n']) {
		Some(position) => (&rest[..position], &rest[position + 1..]),
		None => (rest, ""),
	};
	if valid_area(name) {
		(Some(name.to_owned()), remainder)
	} else {
		(None, body)
	}
}

/// Reads one NUL-terminated field, refusing to scan past `maximum` bytes.
fn bounded(input: &[u8], maximum: usize) -> Result<(String, &[u8]), PacketError> {
	let limit = maximum.min(input.len());
	let end = input[..limit]
		.iter()
		.position(|byte| *byte == 0)
		.ok_or(PacketError::MissingFieldTerminator)?;
	let value = text(&input[..end]).map_err(|_| PacketError::MissingFieldTerminator)?;
	Ok((value, &input[end + 1..]))
}

/// Reads the NUL-terminated message text, which has no independent maximum.
fn unbounded(input: &[u8]) -> Result<(String, &[u8]), PacketError> {
	let end = input
		.iter()
		.position(|byte| *byte == 0)
		.ok_or(PacketError::MissingFieldTerminator)?;
	let value = text(&input[..end]).map_err(|_| PacketError::MissingFieldTerminator)?;
	Ok((value, &input[end + 1..]))
}

fn parse_packed<'a>(
	input: &'a [u8],
	header: &PacketHeader,
) -> Result<(PackedMessage, &'a [u8]), PacketError> {
	// `input` begins at the record type word, so every offset below is the one
	// TSP-0003 section 5 documents.
	if input.len() < PACKED_HEADER_BYTES {
		return Err(PacketError::ShortMessage);
	}
	let origin = Endpoint {
		zone: header.origin.zone,
		net: u16_at(input, 6),
		node: u16_at(input, 2),
		point: header.origin.point,
	};
	let destination = Endpoint {
		zone: header.destination.zone,
		net: u16_at(input, 8),
		node: u16_at(input, 4),
		point: header.destination.point,
	};
	let attributes = u16_at(input, 10);
	// Offset 12 is cost, which canonical output zeroes and TITH does not carry.
	let (date_time, rest) = bounded(&input[14..], 20)?;
	let (to_user, rest) = bounded(rest, 36)?;
	let (from_user, rest) = bounded(rest, 36)?;
	let (subject, rest) = bounded(rest, 72)?;
	let (body, rest) = unbounded(rest)?;

	// TSP-0003 section 7 puts AREA first, before the Control-A paragraphs.
	let (area, remainder) = split_area(&body);
	let (controls, text) = split_controls(remainder);
	Ok((
		PackedMessage {
			origin,
			destination,
			attributes,
			date_time,
			to_user,
			from_user,
			subject,
			controls,
			text,
			area,
		},
		rest,
	))
}

struct PacketHeader {
	origin: Endpoint,
	destination: Endpoint,
}

fn parse_header(input: &[u8]) -> Result<PacketHeader, PacketError> {
	if input.len() < PACKET_HEADER_BYTES {
		return Err(PacketError::ShortHeader);
	}
	if u16_at(input, 18) != 2 {
		return Err(PacketError::NotTypeTwo);
	}
	// TSP-0003 section 6: valid when the validation copy is the byte-swapped
	// capability word and capability bit zero is set.
	let capability = u16_at(input, 44);
	let validation = u16_at(input, 40);
	if validation != capability.swap_bytes() || capability & 1 == 0 {
		return Err(PacketError::NotTypePlus);
	}
	let origin_point = u16_at(input, 50);
	let origin_net_field = u16_at(input, 20);
	let auxiliary_net = u16_at(input, 38);
	let origin_net = if origin_point != 0 && origin_net_field == 0xffff {
		if auxiliary_net == 0 {
			return Err(PacketError::MissingAuxiliaryNet);
		}
		auxiliary_net
	} else {
		origin_net_field
	};
	Ok(PacketHeader {
		origin: Endpoint {
			zone: u16_at(input, 46),
			net: origin_net,
			node: u16_at(input, 0),
			point: origin_point,
		},
		destination: Endpoint {
			zone: u16_at(input, 48),
			net: u16_at(input, 22),
			node: u16_at(input, 2),
			point: u16_at(input, 52),
		},
	})
}

impl Packet {
	/// Reads a Type-2+ packet.
	///
	/// The FTS-0001 Type-2 and FSC-0045 Type-2.2 headers are not accepted:
	/// TSP-0003 section 6 permits them only under explicit compatibility policy
	/// and forbids guessing between layouts.
	pub fn parse(input: &[u8]) -> Result<Self, PacketError> {
		let header = parse_header(input)?;
		let mut rest = &input[PACKET_HEADER_BYTES..];
		let mut messages = Vec::new();
		loop {
			if rest.len() < 2 {
				return Err(PacketError::MissingTerminator);
			}
			match u16_at(rest, 0) {
				0 => break,
				RECORD_MESSAGE => {
					let (message, remainder) = parse_packed(rest, &header)?;
					messages.push(message);
					rest = remainder;
				}
				_ => return Err(PacketError::MalformedRecord),
			}
		}
		Ok(Self {
			origin: header.origin,
			destination: header.destination,
			messages,
		})
	}
}

impl PackedMessage {
	/// FTS-0001.016 bit 4.
	#[must_use]
	pub fn has_file_attached(&self) -> bool {
		self.attributes & (1 << 4) != 0
	}

	/// The first control with this name, compared case insensitively.
	#[must_use]
	pub fn control(&self, name: &str) -> Option<&Control> {
		self.controls
			.iter()
			.find(|control| control.name.eq_ignore_ascii_case(name))
	}

	/// The TSP-0006 Idempotency-Key, from the FTS-0009.001 MSGID.
	#[must_use]
	pub fn idempotency_key(&self) -> Option<String> {
		self.control("MSGID")
			.filter(|control| !control.value.is_empty())
			.map(|control| format!("msgid:{}", control.value))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn header(origin_point: u16, origin_net_field: u16, auxiliary: u16) -> Vec<u8> {
		let mut bytes = vec![0_u8; PACKET_HEADER_BYTES];
		let put = |bytes: &mut Vec<u8>, offset: usize, value: u16| {
			bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
		};
		put(&mut bytes, 0, 36); // origin node
		put(&mut bytes, 2, 24); // destination node
		put(&mut bytes, 18, 2); // packet type
		put(&mut bytes, 20, origin_net_field);
		put(&mut bytes, 22, 200); // destination net
		put(&mut bytes, 38, auxiliary);
		put(&mut bytes, 40, 0x0100); // validation copy
		put(&mut bytes, 44, 0x0001); // capability word
		put(&mut bytes, 46, 1); // origin zone
		put(&mut bytes, 48, 2); // destination zone
		put(&mut bytes, 50, origin_point);
		bytes
	}

	fn packed(attributes: u16, subject: &str, body: &str) -> Vec<u8> {
		let mut bytes = vec![0_u8; PACKED_HEADER_BYTES];
		let put = |bytes: &mut Vec<u8>, offset: usize, value: u16| {
			bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
		};
		put(&mut bytes, 0, 2);
		put(&mut bytes, 2, 36); // origin node
		put(&mut bytes, 4, 24); // destination node
		put(&mut bytes, 6, 104); // origin net
		put(&mut bytes, 8, 200); // destination net
		put(&mut bytes, 10, attributes);
		bytes[14..14 + 19].copy_from_slice(b"18 Aug 26  12:00:00");
		bytes[33] = 0;
		let mut out = bytes[2..].to_vec(); // the record type is written by the caller
		out.extend_from_slice(b"Recipient\0");
		out.extend_from_slice(b"Sender\0");
		out.extend_from_slice(subject.as_bytes());
		out.push(0);
		out.extend_from_slice(body.as_bytes());
		out.push(0);
		let mut record = 2_u16.to_le_bytes().to_vec();
		record.extend_from_slice(&out);
		record
	}

	fn packet(records: &[Vec<u8>]) -> Vec<u8> {
		let mut bytes = header(0, 104, 0);
		for record in records {
			bytes.extend_from_slice(record);
		}
		bytes.extend_from_slice(&0_u16.to_le_bytes());
		bytes
	}

	#[test]
	fn reads_endpoints_and_messages() {
		let bytes = packet(&[packed(
			0,
			"Hello",
			"\u{1}MSGID: 1:104/36 1a2b3c4d\rBody\r\n",
		)]);
		let parsed = Packet::parse(&bytes).unwrap();
		assert_eq!(parsed.origin.to_string(), "1:104/36");
		assert_eq!(parsed.destination.to_string(), "2:200/24");
		assert_eq!(parsed.messages.len(), 1);
		let message = &parsed.messages[0];
		assert_eq!(message.to_user, "Recipient");
		assert_eq!(message.from_user, "Sender");
		assert_eq!(message.subject, "Hello");
		assert_eq!(message.date_time, "18 Aug 26  12:00:00");
		assert_eq!(message.text, "Body\r\n");
		assert_eq!(
			message.idempotency_key().as_deref(),
			Some("msgid:1:104/36 1a2b3c4d")
		);
		assert_eq!(message.area, None);
	}

	#[test]
	fn detects_echomail_from_a_leading_area_line() {
		let bytes = packet(&[packed(
			0,
			"Subject",
			"AREA:GENERAL\r\u{1}MSGID: x y\rBody\r",
		)]);
		let parsed = Packet::parse(&bytes).unwrap();
		let message = &parsed.messages[0];
		assert_eq!(message.area.as_deref(), Some("GENERAL"));
		assert_eq!(message.control("MSGID").unwrap().value, "x y");
		assert_eq!(message.text, "Body\r");
	}

	#[test]
	fn refuses_an_area_name_outside_the_permitted_ranges() {
		// A space is outside ranges 33-96 and 123-126, so this is not an AREA
		// line and the text is left alone.
		let bytes = packet(&[packed(0, "Subject", "AREA:BAD NAME\rBody\r")]);
		let parsed = Packet::parse(&bytes).unwrap();
		assert_eq!(parsed.messages[0].area, None);
		assert!(parsed.messages[0].text.starts_with("AREA:BAD NAME"));

		let bytes = packet(&[packed(0, "Subject", "AREA:-LEADING\rBody\r")]);
		let parsed = Packet::parse(&bytes).unwrap();
		assert_eq!(parsed.messages[0].area, None);
	}

	#[test]
	fn accepts_an_empty_packet() {
		let parsed = Packet::parse(&packet(&[])).unwrap();
		assert!(parsed.messages.is_empty());
	}

	#[test]
	fn rejects_each_documented_header_defect() {
		assert_eq!(
			Packet::parse(&[0_u8; 20]).unwrap_err(),
			PacketError::ShortHeader
		);

		let mut bytes = packet(&[]);
		bytes[18..20].copy_from_slice(&3_u16.to_le_bytes());
		assert_eq!(Packet::parse(&bytes).unwrap_err(), PacketError::NotTypeTwo);

		// Validation copy is not the byte swap of the capability word.
		let mut bytes = packet(&[]);
		bytes[40..42].copy_from_slice(&0_u16.to_le_bytes());
		assert_eq!(Packet::parse(&bytes).unwrap_err(), PacketError::NotTypePlus);

		// Capability bit zero clear.
		let mut bytes = packet(&[]);
		bytes[44..46].copy_from_slice(&0x0002_u16.to_le_bytes());
		bytes[40..42].copy_from_slice(&0x0200_u16.to_le_bytes());
		assert_eq!(Packet::parse(&bytes).unwrap_err(), PacketError::NotTypePlus);
	}

	#[test]
	fn uses_the_auxiliary_net_for_an_origin_point() {
		let mut bytes = header(45, 0xffff, 104);
		bytes.extend_from_slice(&0_u16.to_le_bytes());
		let parsed = Packet::parse(&bytes).unwrap();
		assert_eq!(parsed.origin.net, 104);
		assert_eq!(parsed.origin.to_string(), "1:104/36.45");

		let mut bytes = header(45, 0xffff, 0);
		bytes.extend_from_slice(&0_u16.to_le_bytes());
		assert_eq!(
			Packet::parse(&bytes).unwrap_err(),
			PacketError::MissingAuxiliaryNet
		);
	}

	#[test]
	fn rejects_a_malformed_record_or_missing_terminator() {
		let mut bytes = header(0, 104, 0);
		bytes.extend_from_slice(&7_u16.to_le_bytes());
		bytes.extend_from_slice(&0_u16.to_le_bytes());
		assert_eq!(
			Packet::parse(&bytes).unwrap_err(),
			PacketError::MalformedRecord
		);

		let bytes = header(0, 104, 0);
		assert_eq!(
			Packet::parse(&bytes).unwrap_err(),
			PacketError::MissingTerminator
		);
	}

	#[test]
	fn requires_each_bounded_field_terminator() {
		// A Subject with no NUL inside its 72-byte maximum.
		let mut record = 2_u16.to_le_bytes().to_vec();
		let mut body = vec![0_u8; PACKED_HEADER_BYTES - 2];
		body[12..12 + 19].copy_from_slice(b"18 Aug 26  12:00:00");
		record.extend_from_slice(&body);
		record.extend_from_slice(b"To\0From\0");
		record.extend_from_slice(&[b'x'; 100]);
		record.push(0);
		let mut bytes = header(0, 104, 0);
		bytes.extend_from_slice(&record);
		bytes.extend_from_slice(&0_u16.to_le_bytes());
		assert_eq!(
			Packet::parse(&bytes).unwrap_err(),
			PacketError::MissingFieldTerminator
		);
	}
}
