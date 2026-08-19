//! Writing the TSP-0003 legacy objects.
//!
//! This is the inverse of the readers beside it and stays on the legacy side of
//! the boundary: everything here takes and returns legacy values, so the native
//! field mapping belongs to the adapter which owns both sides.
//!
//! Conversion is refused rather than made lossy. TSP-0003 section 10 requires
//! that a value which the selected legacy format cannot represent make the
//! conversion unavailable, so every bound below is checked instead of clamped.

use std::fmt;

use crate::packet::{Endpoint, PACKED_HEADER_BYTES, PACKET_HEADER_BYTES, PackedMessage, Packet};

/// Maximum bytes of a `ToUserName` or `FromUserName`, including its NUL.
const NAME_BYTES: usize = 36;

/// Maximum bytes of a Subject, including its NUL.
const SUBJECT_BYTES: usize = 72;

/// Size of the `DateTime` field, including its NUL.
const DATE_TIME_BYTES: usize = 20;

/// Maximum bytes of a packet password.
const PASSWORD_BYTES: usize = 8;

/// Base64 characters in one `TITHSIGN` chunk, and in each `TITHSIG` half.
const CHUNK: usize = 43;

const MONTHS: [&str; 12] = [
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportError {
	/// A field does not fit the fixed legacy width, including its NUL.
	TooLong {
		field: &'static str,
		maximum: usize,
		actual: usize,
	},
	/// A value contains a byte the legacy format cannot carry.
	Unrepresentable(&'static str),
	/// Outside the 1970-2069 interval the two-digit year can express.
	TimestampOutOfRange,
	/// A `DateTime` field is not the canonical `DD Mon YY  HH:MM:SS`.
	MalformedDateTime,
	/// A packed message endpoint disagrees with its packet header, which cannot
	/// carry a per-message zone or point.
	EndpointMismatch,
}

impl fmt::Display for ExportError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TooLong {
				field,
				maximum,
				actual,
			} => write!(
				f,
				"{field} needs {actual} bytes including its NUL but the legacy field holds {maximum}"
			),
			Self::Unrepresentable(what) => {
				write!(f, "{what} is not representable in the legacy format")
			}
			Self::TimestampOutOfRange => f.write_str(
				"timestamp is outside the 1970-2069 interval a two-digit year can express",
			),
			Self::MalformedDateTime => f.write_str("DateTime is not \"DD Mon YY  HH:MM:SS\""),
			Self::EndpointMismatch => {
				f.write_str("packed message zone or point disagrees with its packet header")
			}
		}
	}
}

impl std::error::Error for ExportError {}

/// A broken-down local date and time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CivilTime {
	pub year: i32,
	/// One through twelve, unlike the packet header's zero-based month.
	pub month: u32,
	pub day: u32,
	pub hour: u32,
	pub minute: u32,
	pub second: u32,
}

/// Days from 1970-01-01 to a proleptic Gregorian date, after Howard Hinnant's
/// `days_from_civil`. Rust truncates integer division toward zero exactly as
/// that algorithm assumes.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
	let year = i64::from(year) - i64::from(month <= 2);
	let month = i64::from(month);
	let era = if year >= 0 { year } else { year - 399 } / 400;
	let year_of_era = year - era * 400;
	let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
	let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	era * 146_097 + day_of_era - 719_468
}

/// The inverse, after Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
	let days = days + 719_468;
	let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
	let day_of_era = days - era * 146_097;
	let year_of_era =
		(day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
	let year = year_of_era + era * 400;
	let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
	let month_prime = (5 * day_of_year + 2) / 153;
	let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
	let month = month_prime + if month_prime < 10 { 3 } else { -9 };
	(
		i32::try_from(year + i64::from(month <= 2)).unwrap_or(i32::MAX),
		u32::try_from(month).expect("month is 1 through 12"),
		u32::try_from(day).expect("day is 1 through 31"),
	)
}

/// Breaks local seconds since the epoch into a civil date and time.
///
/// The input is a TSP-0003 section 3 local instant: native Timestamp plus
/// `TimestampOffset`, not UTC.
pub fn civil_from_local(local_seconds: i64) -> Result<CivilTime, ExportError> {
	let days = local_seconds.div_euclid(86_400);
	let within = local_seconds.rem_euclid(86_400);
	let (year, month, day) = civil_from_days(days);
	Ok(CivilTime {
		year,
		month,
		day,
		hour: u32::try_from(within / 3600).map_err(|_| ExportError::TimestampOutOfRange)?,
		minute: u32::try_from(within / 60 % 60).map_err(|_| ExportError::TimestampOutOfRange)?,
		second: u32::try_from(within % 60).map_err(|_| ExportError::TimestampOutOfRange)?,
	})
}

/// Formats the canonical `DD Mon YY  HH:MM:SS` `DateTime`.
///
/// TSP-0003 section 3 maps 70-99 to 1970-1999 and 00-69 to 2000-2069 to make
/// the two-digit year deterministic, so an instant outside 1970-2069 is not
/// canonically representable. Invalid calendar values are rejected, never
/// clamped.
pub fn format_date_time(local_seconds: i64) -> Result<String, ExportError> {
	let time = civil_from_local(local_seconds)?;
	if !(1970..=2069).contains(&time.year) {
		return Err(ExportError::TimestampOutOfRange);
	}
	let month = MONTHS[usize::try_from(time.month - 1).expect("month is 1 through 12")];
	Ok(format!(
		"{:02} {} {:02}  {:02}:{:02}:{:02}",
		time.day,
		month,
		time.year % 100,
		time.hour,
		time.minute,
		time.second
	))
}

/// Reads a canonical `DateTime` back into local seconds since the epoch.
pub fn parse_date_time(value: &str) -> Result<i64, ExportError> {
	let bytes = value.as_bytes();
	if bytes.len() != 19 || bytes[2] != b' ' || bytes[6] != b' ' {
		return Err(ExportError::MalformedDateTime);
	}
	// Two spaces separate the date from the time, and the time is colon
	// separated. Anything else is not the canonical form.
	if &value[9..11] != "  " || bytes[13] != b':' || bytes[16] != b':' {
		return Err(ExportError::MalformedDateTime);
	}
	let number = |text: &str| -> Result<u32, ExportError> {
		if text.bytes().all(|byte| byte.is_ascii_digit()) {
			text.parse().map_err(|_| ExportError::MalformedDateTime)
		} else {
			Err(ExportError::MalformedDateTime)
		}
	};
	let day = number(&value[0..2])?;
	let month = MONTHS
		.iter()
		.position(|name| *name == &value[3..6])
		.ok_or(ExportError::MalformedDateTime)?;
	let month = u32::try_from(month + 1).expect("month index is 0 through 11");
	let two_digit_year = number(&value[7..9])?;
	let year = if two_digit_year >= 70 {
		1900 + i32::try_from(two_digit_year).expect("two digits")
	} else {
		2000 + i32::try_from(two_digit_year).expect("two digits")
	};
	let hour = number(&value[11..13])?;
	let minute = number(&value[14..16])?;
	let second = number(&value[17..19])?;
	if day == 0 || hour > 23 || minute > 59 || second > 59 {
		return Err(ExportError::MalformedDateTime);
	}
	let days = days_from_civil(year, month, day);
	// Reject a day which does not exist in that month rather than rolling it
	// over into the next one.
	if civil_from_days(days) != (year, month, day) {
		return Err(ExportError::MalformedDateTime);
	}
	Ok(days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
}

/// Folds a native `MessageText` into a legacy body.
///
/// TSP-0003 section 3: each U+000A becomes one byte 0x0D and other UTF-8 bytes
/// are unchanged, so a conforming value arrives already terminated and nothing
/// is appended. U+0000 is not representable.
///
/// The remaining conversions are for a value which does not conform to TTS-0005:
/// each CRLF pair and each remaining CR also becomes one 0x0D, and the body is
/// followed by 0x0D when it is neither empty nor already terminated. Such a
/// value cannot be exported canonically, because [`decode_body`] returns the
/// terminator this supplied and the reconstruction then differs.
pub fn encode_body(text: &str) -> Result<String, ExportError> {
	if text.contains('\0') {
		return Err(ExportError::Unrepresentable("U+0000 in MessageText"));
	}
	let mut output = String::with_capacity(text.len() + 1);
	let mut characters = text.chars().peekable();
	while let Some(character) = characters.next() {
		match character {
			'\r' => {
				// Consume the LF of a CRLF pair so the two become one 0x0D.
				if characters.peek() == Some(&'\n') {
					characters.next();
				}
				output.push('\r');
			}
			'\n' => output.push('\r'),
			other => output.push(other),
		}
	}
	if !output.is_empty() && !output.ends_with('\r') {
		output.push('\r');
	}
	Ok(output)
}

/// The inverse: a legacy body's paragraphs, each terminated by U+000A.
///
/// Both sides terminate a paragraph rather than separate two. FTS-0001.016 says
/// a hard carriage return "marks the end of a paragraph, and must be preserved",
/// and TTS-0005 makes `MessageText` paragraphs each terminated by one U+000A, so
/// every 0x0D becomes one U+000A and none is dropped. Bytes 0x0A are ignored, as
/// TSP-0003 section 3 requires.
///
/// A legacy final paragraph may end at the NUL rather than at a hard carriage
/// return, so its terminator is supplied. That cannot disturb a section 3.1
/// reconstruction: a canonical body always carries the terminator already,
/// because the `MessageText` it came from ended in one.
#[must_use]
pub fn decode_body(body: &str) -> String {
	if body.is_empty() {
		return String::new();
	}
	let mut text = body.replace('\n', "").replace('\r', "\n");
	if !text.ends_with('\n') {
		text.push('\n');
	}
	text
}

/// Writes one control paragraph: byte 0x01, the payload, byte 0x0D.
///
/// The payload is the complete text after the Control-A, so a caller composes
/// `MSGID: <origin> <serial>` or the colonless `INTL <to> <from>` itself. Those
/// colonless forms are recognised only where an FTSC document defines them,
/// which is why this takes the whole payload rather than a name and value.
pub fn control(payload: &str) -> Result<String, ExportError> {
	if payload.contains(['\0', '\r', '\n', '\u{1}']) {
		return Err(ExportError::Unrepresentable("control paragraph payload"));
	}
	Ok(format!("\u{1}{payload}\r"))
}

/// The `TITHSIGN` group carrying an already base64 encoded child sequence.
///
/// TSP-0003 section 3.1: the sequence is split into 43-character chunks, every
/// continuation chunk is exactly 43 characters and marked "+", and the final
/// chunk is one through 43 characters and marked ".".
pub fn tithsign_controls(encoded: &str) -> Result<Vec<String>, ExportError> {
	if encoded.is_empty() {
		return Err(ExportError::Unrepresentable("empty TITHSIGN sequence"));
	}
	if !encoded.bytes().all(is_base64) {
		return Err(ExportError::Unrepresentable("TITHSIGN encoding"));
	}
	let chunks: Vec<&str> = encoded
		.as_bytes()
		.chunks(CHUNK)
		.map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
		.collect();
	let last = chunks.len() - 1;
	chunks
		.iter()
		.enumerate()
		.map(|(index, chunk)| {
			let marker = if index == last { '.' } else { '+' };
			control(&format!("TITHSIGN: 1 {marker} {chunk}"))
		})
		.collect()
}

/// The two `TITHSIG` controls carrying an already base64 encoded Signature.
///
/// TSP-0003 section 3.1: the 86 characters are split after character 43 and
/// each control carries one half.
pub fn tithsig_controls(signature: &str) -> Result<[String; 2], ExportError> {
	if signature.len() != CHUNK * 2 || !signature.bytes().all(is_base64) {
		return Err(ExportError::Unrepresentable("TITHSIG Signature encoding"));
	}
	Ok([
		control(&format!("TITHSIG: 1 {}", &signature[..CHUNK]))?,
		control(&format!("TITHSIG: 1 {}", &signature[CHUNK..]))?,
	])
}

const fn is_base64(byte: u8) -> bool {
	byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

fn put(bytes: &mut [u8], offset: usize, value: u16) {
	bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Writes a NUL-terminated field which must fit `maximum` bytes including it.
fn push_bounded(
	output: &mut Vec<u8>,
	field: &'static str,
	value: &str,
	maximum: usize,
) -> Result<(), ExportError> {
	if value.contains('\0') {
		return Err(ExportError::Unrepresentable(field));
	}
	let actual = value.len() + 1;
	if actual > maximum {
		return Err(ExportError::TooLong {
			field,
			maximum,
			actual,
		});
	}
	output.extend_from_slice(value.as_bytes());
	output.push(0);
	Ok(())
}

impl PackedMessage {
	/// The complete body: the `AREA` line, the control block, then the text.
	///
	/// TSP-0003 section 7 puts `AREA` first with no Control-A prefix. The text
	/// is written through verbatim, so trailing Via paragraphs and the `EchoMail`
	/// footer live there exactly as parsing left them.
	pub fn body(&self) -> Result<String, ExportError> {
		let mut output = String::new();
		if let Some(area) = &self.area {
			if !crate::packet::valid_area(area) {
				return Err(ExportError::Unrepresentable("AREA name"));
			}
			output.push_str("AREA:");
			output.push_str(area);
			output.push('\r');
		}
		for value in &self.controls {
			output.push_str(&control(&value.raw)?);
		}
		output.push_str(&self.text);
		Ok(output)
	}

	/// Writes this message as one packet record.
	///
	/// The record carries only net and node. Zone and point come from the packet
	/// header, which is why [`Packet::encode`] checks that they agree.
	pub fn encode(&self) -> Result<Vec<u8>, ExportError> {
		let mut header = vec![0_u8; PACKED_HEADER_BYTES];
		put(&mut header, 0, 2);
		put(&mut header, 2, self.origin.node);
		put(&mut header, 4, self.destination.node);
		put(&mut header, 6, self.origin.net);
		put(&mut header, 8, self.destination.net);
		put(&mut header, 10, self.attributes);
		// Offset 12 is cost, which TSP-0003 section 5 zeroes in canonical output.
		if self.date_time.len() >= DATE_TIME_BYTES {
			return Err(ExportError::TooLong {
				field: "DateTime",
				maximum: DATE_TIME_BYTES,
				actual: self.date_time.len() + 1,
			});
		}
		// Confirm the field is the canonical form before committing it.
		parse_date_time(&self.date_time)?;
		header[14..14 + self.date_time.len()].copy_from_slice(self.date_time.as_bytes());

		let mut output = header;
		push_bounded(&mut output, "ToUserName", &self.to_user, NAME_BYTES)?;
		push_bounded(&mut output, "FromUserName", &self.from_user, NAME_BYTES)?;
		push_bounded(&mut output, "Subject", &self.subject, SUBJECT_BYTES)?;
		let body = self.body()?;
		if body.contains('\0') {
			return Err(ExportError::Unrepresentable("U+0000 in MessageText"));
		}
		output.extend_from_slice(body.as_bytes());
		output.push(0);
		Ok(output)
	}
}

/// The packet header values which come from trusted link configuration rather
/// than from any contained Message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketOptions {
	/// Publication time in the configured local time of the legacy link.
	///
	/// TSP-0003 section 6: these are packet metadata and are not a source for
	/// any contained Message Timestamp.
	pub created: i64,
	pub product_code: u16,
	pub revision_major: u8,
	pub revision_minor: u8,
	/// At most eight bytes. Legacy link data, not TITH authentication.
	pub password: String,
	pub product_data: u32,
}

impl Packet {
	/// Writes a canonical Type-2+ packet.
	pub fn encode(&self, options: &PacketOptions) -> Result<Vec<u8>, ExportError> {
		let mut output = self.header(options)?;
		for message in &self.messages {
			if message.origin.zone != self.origin.zone
				|| message.origin.point != self.origin.point
				|| message.destination.zone != self.destination.zone
				|| message.destination.point != self.destination.point
			{
				return Err(ExportError::EndpointMismatch);
			}
			output.extend_from_slice(&message.encode()?);
		}
		output.extend_from_slice(&0_u16.to_le_bytes());
		Ok(output)
	}

	fn header(&self, options: &PacketOptions) -> Result<Vec<u8>, ExportError> {
		if options.password.len() > PASSWORD_BYTES {
			return Err(ExportError::TooLong {
				field: "packet password",
				maximum: PASSWORD_BYTES,
				actual: options.password.len(),
			});
		}
		if options.password.contains('\0') {
			return Err(ExportError::Unrepresentable("packet password"));
		}
		let created = civil_from_local(options.created)?;
		let year = u16::try_from(created.year).map_err(|_| ExportError::TimestampOutOfRange)?;
		let mut bytes = vec![0_u8; PACKET_HEADER_BYTES];
		put(&mut bytes, 0, self.origin.node);
		put(&mut bytes, 2, self.destination.node);
		put(&mut bytes, 4, year);
		// The header month is zero based, unlike CivilTime.
		put(&mut bytes, 6, month_index(created.month));
		put(&mut bytes, 8, narrow(created.day));
		put(&mut bytes, 10, narrow(created.hour));
		put(&mut bytes, 12, narrow(created.minute));
		put(&mut bytes, 14, narrow(created.second));
		// Offset 16 is baud, which TSP-0003 section 6 zeroes.
		put(&mut bytes, 18, 2);
		// TSP-0003 section 6: for an origin point, origin net is 0xffff and the
		// auxiliary net carries the actual net. Otherwise auxiliary net is zero.
		if self.origin.point == 0 {
			put(&mut bytes, 20, self.origin.net);
			put(&mut bytes, 38, 0);
		} else {
			put(&mut bytes, 20, 0xffff);
			put(&mut bytes, 38, self.origin.net);
		}
		put(&mut bytes, 22, self.destination.net);
		bytes[24] = (options.product_code & 0xff) as u8;
		bytes[25] = options.revision_major;
		bytes[26..26 + options.password.len()].copy_from_slice(options.password.as_bytes());
		// Both legacy zone fields repeat the corresponding current zone.
		put(&mut bytes, 34, self.origin.zone);
		put(&mut bytes, 36, self.destination.zone);
		put(&mut bytes, 40, 0x0100);
		bytes[42] = (options.product_code >> 8) as u8;
		bytes[43] = options.revision_minor;
		put(&mut bytes, 44, 0x0001);
		put(&mut bytes, 46, self.origin.zone);
		put(&mut bytes, 48, self.destination.zone);
		put(&mut bytes, 50, self.origin.point);
		put(&mut bytes, 52, self.destination.point);
		bytes[54..58].copy_from_slice(&options.product_data.to_le_bytes());
		Ok(bytes)
	}
}

fn month_index(month: u32) -> u16 {
	u16::try_from(month - 1).expect("month is 1 through 12")
}

fn narrow(value: u32) -> u16 {
	u16::try_from(value).expect("calendar components fit 16 bits")
}

/// Builds the endpoints a packet header carries for one legacy link.
#[must_use]
pub const fn endpoint(zone: u16, net: u16, node: u16, point: u16) -> Endpoint {
	Endpoint {
		zone,
		net,
		node,
		point,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Control;

	fn options() -> PacketOptions {
		PacketOptions {
			created: 1_755_518_400,
			product_code: 0xfe_dc,
			revision_major: 1,
			revision_minor: 2,
			password: "secret".to_owned(),
			product_data: 0,
		}
	}

	fn message(area: Option<&str>) -> PackedMessage {
		PackedMessage {
			origin: endpoint(1, 104, 36, 0),
			destination: endpoint(2, 200, 24, 0),
			attributes: 1 << 4,
			date_time: "18 Aug 26  12:00:00".to_owned(),
			to_user: "Recipient".to_owned(),
			from_user: "Sender".to_owned(),
			subject: "work.zip".to_owned(),
			controls: vec![Control {
				name: "MSGID".to_owned(),
				value: "1:104/36 1a2b3c4d".to_owned(),
				raw: "MSGID: 1:104/36 1a2b3c4d".to_owned(),
			}],
			text: "Body\r".to_owned(),
			area: area.map(str::to_owned),
		}
	}

	#[test]
	fn a_written_packet_parses_back_to_the_same_values() {
		let packet = Packet {
			origin: endpoint(1, 104, 36, 0),
			destination: endpoint(2, 200, 24, 0),
			messages: vec![message(None), message(Some("SYNCHRONET"))],
		};
		let bytes = packet.encode(&options()).unwrap();
		assert_eq!(Packet::parse(&bytes).unwrap(), packet);
	}

	#[test]
	fn an_origin_point_uses_the_auxiliary_net() {
		let packet = Packet {
			origin: endpoint(1, 104, 36, 45),
			destination: endpoint(2, 200, 24, 0),
			messages: Vec::new(),
		};
		let bytes = packet.encode(&options()).unwrap();
		assert_eq!(u16::from_le_bytes([bytes[20], bytes[21]]), 0xffff);
		assert_eq!(u16::from_le_bytes([bytes[38], bytes[39]]), 104);
		assert_eq!(Packet::parse(&bytes).unwrap().origin, packet.origin);
	}

	#[test]
	fn the_capability_word_and_its_validation_copy_are_canonical() {
		let packet = Packet {
			origin: endpoint(1, 104, 36, 0),
			destination: endpoint(1, 104, 1, 0),
			messages: Vec::new(),
		};
		let bytes = packet.encode(&options()).unwrap();
		assert_eq!(u16::from_le_bytes([bytes[44], bytes[45]]), 0x0001);
		assert_eq!(u16::from_le_bytes([bytes[40], bytes[41]]), 0x0100);
		assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 2);
		// Both legacy zone fields repeat the current zone.
		assert_eq!(u16::from_le_bytes([bytes[34], bytes[35]]), 1);
		assert_eq!(u16::from_le_bytes([bytes[36], bytes[37]]), 1);
		assert_eq!(&bytes[26..32], b"secret");
		assert_eq!(bytes[24], 0xdc);
		assert_eq!(bytes[42], 0xfe);
	}

	#[test]
	fn refuses_a_message_whose_zone_the_header_cannot_carry() {
		let packet = Packet {
			origin: endpoint(3, 104, 36, 0),
			destination: endpoint(2, 200, 24, 0),
			messages: vec![message(None)],
		};
		assert_eq!(
			packet.encode(&options()).unwrap_err(),
			ExportError::EndpointMismatch
		);
	}

	#[test]
	fn refuses_a_field_which_does_not_fit() {
		let mut long_subject = message(None);
		long_subject.subject = "x".repeat(72);
		assert!(matches!(
			long_subject.encode(),
			Err(ExportError::TooLong {
				field: "Subject",
				maximum: 72,
				actual: 73
			})
		));

		let mut long_name = message(None);
		long_name.to_user = "y".repeat(36);
		assert!(matches!(
			long_name.encode(),
			Err(ExportError::TooLong {
				field: "ToUserName",
				..
			})
		));
	}

	#[test]
	fn date_times_round_trip_across_the_century_split() {
		for (seconds, expected) in [
			(0_i64, "01 Jan 70  00:00:00"),
			(1_787_054_400, "18 Aug 26  12:00:00"),
			(3_155_759_999, "31 Dec 69  23:59:59"),
		] {
			assert_eq!(format_date_time(seconds).unwrap(), expected, "{seconds}");
			assert_eq!(parse_date_time(expected).unwrap(), seconds, "{expected}");
		}
	}

	#[test]
	fn refuses_a_timestamp_the_two_digit_year_cannot_express() {
		assert_eq!(
			format_date_time(-1).unwrap_err(),
			ExportError::TimestampOutOfRange
		);
		assert_eq!(
			format_date_time(3_155_760_000).unwrap_err(),
			ExportError::TimestampOutOfRange
		);
	}

	#[test]
	fn refuses_a_date_time_which_is_not_canonical() {
		for text in [
			"18 Aug 26 12:00:00",  // one space, not two
			"18 aug 26  12:00:00", // month case is significant
			"32 Aug 26  12:00:00", // no such day
			"29 Feb 26  12:00:00", // 2026 is not a leap year
			"18 Aug 26  24:00:00", // hour out of range
			"18 Aug 26  12:00:0",  // short
		] {
			assert_eq!(
				parse_date_time(text).unwrap_err(),
				ExportError::MalformedDateTime,
				"{text}"
			);
		}
		// A leap day which does exist is accepted.
		assert!(parse_date_time("29 Feb 24  12:00:00").is_ok());
	}

	#[test]
	fn a_body_folds_every_line_ending_to_one_carriage_return() {
		assert_eq!(encode_body("a\r\nb\nc\rd").unwrap(), "a\rb\rc\rd\r");
		assert_eq!(encode_body("").unwrap(), "");
		assert_eq!(encode_body("already\r").unwrap(), "already\r");
		assert_eq!(
			encode_body("a\0b").unwrap_err(),
			ExportError::Unrepresentable("U+0000 in MessageText")
		);
	}

	/// Both sides terminate a paragraph, so a conforming `MessageText` survives
	/// the round trip exactly and no two of them share a legacy encoding.
	#[test]
	fn a_terminated_body_round_trips_exactly() {
		for text in ["", "a\n", "a\nb\n", "\n", "\n\n", "a\n\nb\n"] {
			let legacy = encode_body(text).unwrap();
			assert_eq!(decode_body(&legacy), text, "{text:?} -> {legacy:?}");
		}
		// One paragraph per terminator, in both directions.
		assert_eq!(encode_body("a\nb\n").unwrap(), "a\rb\r");
		assert_eq!(decode_body("a\rb\r"), "a\nb\n");
		// A final paragraph which ended at the NUL is given its terminator, and
		// ignored line feeds do not become paragraphs.
		assert_eq!(decode_body("a\rb"), "a\nb\n");
		assert_eq!(decode_body("a\r\nb\r\n"), "a\nb\n");

		// A value which does not conform is exported with a terminator it did
		// not have, so it cannot come back unchanged and cannot be canonical.
		assert_eq!(encode_body("a").unwrap(), "a\r");
		assert_ne!(decode_body(&encode_body("a").unwrap()), "a");
	}

	#[test]
	fn tithsig_and_tithsign_controls_use_the_documented_chunking() {
		let half = "A".repeat(43);
		let signature = format!("{half}{}", "B".repeat(43));
		let controls = tithsig_controls(&signature).unwrap();
		assert_eq!(controls[0], format!("\u{1}TITHSIG: 1 {half}\r"));
		// Each complete paragraph is 56 bytes including Control-A and CR.
		assert_eq!(controls[0].len(), 56);
		assert!(tithsig_controls(&half).is_err());

		// One final control and zero or more continuations.
		let single = tithsign_controls(&"C".repeat(20)).unwrap();
		assert_eq!(single, [format!("\u{1}TITHSIGN: 1 . {}\r", "C".repeat(20))]);
		let group = tithsign_controls(&"D".repeat(50)).unwrap();
		assert_eq!(group.len(), 2);
		assert!(group[0].starts_with("\u{1}TITHSIGN: 1 + "));
		assert!(group[1].starts_with("\u{1}TITHSIGN: 1 . "));
		// TSP-0003 section 3.1: at most 59 bytes including Control-A and the
		// terminating carriage return.
		assert_eq!(group[0].len(), 59);
		assert!(tithsign_controls("").is_err());
		assert!(tithsign_controls("not base64!").is_err());
	}

	#[test]
	fn a_control_refuses_a_payload_it_would_have_to_split() {
		assert!(control("MSGID: 1:104/36 1a2b3c4d").is_ok());
		for payload in ["a\rb", "a\nb", "a\0b", "\u{1}a"] {
			assert!(control(payload).is_err(), "{payload:?}");
		}
	}
}
