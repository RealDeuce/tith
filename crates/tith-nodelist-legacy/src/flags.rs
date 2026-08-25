//! Independent FTS-5001.006 input recognition and TTS-5001 output spelling.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The TTS-5000 field to which one TTS-5001 category is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
	System,
	PstnIsdn,
	Internet,
	Email,
	Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlagError {
	Invalid,
	Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalFlag {
	pub field: Field,
	pub text: String,
	pub order: u32,
	pub extension: bool,
	pub known: bool,
}

const PSTN: &[(&str, &str)] = &[
	("V22", "V22"),
	("V29", "V29"),
	("V32", "V32"),
	("V32b", "V32b"),
	("V32B", "V32b"),
	("V34", "V34"),
	("V90C", "V90C"),
	("V90S", "V90S"),
	("V32T", "V32T"),
	("VFC", "VFC"),
	("HST", "HST"),
	("H14", "H14"),
	("H16", "H16"),
	("X2C", "X2C"),
	("X2S", "X2S"),
	("ZYX", "ZYX"),
	("Z19", "Z19"),
	("H96", "H96"),
	("PEP", "PEP"),
	("CSP", "CSP"),
	("MNP", "MNP"),
	("V42", "V42"),
	("V42b", "V42b"),
	("V42B", "V42b"),
	("V110L", "V110L"),
	("V110H", "V110H"),
	("V120L", "V120L"),
	("V120H", "V120H"),
	("X75", "X75"),
	("ISDN", "ISDN"),
];

const PSTN_CANONICAL: &[&str] = &[
	"V22", "V29", "V32", "V32b", "V34", "V90C", "V90S", "V32T", "VFC", "HST", "H14", "H16", "X2C",
	"X2S", "ZYX", "Z19", "H96", "PEP", "CSP", "MNP", "V42", "V42b", "V110L", "V110H", "V120L",
	"V120H", "X75", "ISDN",
];

const OTHER: &[&str] = &[
	"MO", "GUUCP", "PING", "TRACE", "ZEC", "REC", "NEC", "NC", "SDS", "SMH", "RPK", "NPK", "ENC",
	"CDP",
];

fn one(field: Field, text: impl Into<String>, order: u32) -> Vec<CanonicalFlag> {
	vec![CanonicalFlag {
		field,
		text: text.into(),
		order,
		extension: false,
		known: true,
	}]
}

fn fixed_rank(index: usize) -> u32 {
	u32::try_from(index).expect("the fixed flag registry fits in u32")
}

fn mail_periods(flag: &str) -> Option<Result<Vec<CanonicalFlag>, FlagError>> {
	let bytes = flag.as_bytes();
	if bytes
		.first()
		.is_none_or(|byte| !matches!(byte, b'#' | b'!'))
	{
		return None;
	}
	if bytes.is_empty() || !bytes.len().is_multiple_of(3) {
		return Some(Err(FlagError::Invalid));
	}
	let mut result = Vec::new();
	for chunk in bytes.chunks(3) {
		if !matches!(chunk[0], b'#' | b'!')
			|| !chunk[1].is_ascii_digit()
			|| !chunk[2].is_ascii_digit()
		{
			return Some(Err(FlagError::Invalid));
		}
		let hour = (chunk[1] - b'0') * 10 + chunk[2] - b'0';
		if hour > 23 {
			return Some(Err(FlagError::Invalid));
		}
		result.push(CanonicalFlag {
			field: Field::System,
			text: String::from_utf8(chunk.to_vec()).expect("ASCII flag"),
			order: 100 + u32::from(hour) * 2 + u32::from(chunk[0] == b'!'),
			extension: false,
			known: true,
		});
	}
	Some(Ok(result))
}

fn half_hour_index(byte: u8) -> Option<u8> {
	match byte {
		b'A'..=b'X' => Some((byte - b'A') * 2),
		b'a'..=b'x' => Some((byte - b'a') * 2 + 1),
		_ => None,
	}
}

fn online_period(flag: &str) -> Option<Result<Vec<CanonicalFlag>, FlagError>> {
	if !flag.starts_with('T') || flag.len() != 3 {
		return None;
	}
	let bytes = flag.as_bytes();
	let start = half_hour_index(bytes[1])?;
	let end = half_hour_index(bytes[2])?;
	Some(Ok(one(
		Field::System,
		flag,
		1000 + u32::from(start) * 48 + u32::from(end),
	)))
}

fn normalize_server(value: &str) -> Result<String, FlagError> {
	if let Some(inner) = value
		.strip_prefix('[')
		.and_then(|value| value.strip_suffix(']'))
	{
		let address: Ipv6Addr = inner.parse().map_err(|_| FlagError::Invalid)?;
		return Ok(format!("[{address}]"));
	}
	if let Ok(address) = value.parse::<Ipv4Addr>() {
		return Ok(address.to_string());
	}
	if value.is_empty()
		|| value.len() > 253
		|| !value.split('.').all(|label| {
			(1..=63).contains(&label.len())
				&& label
					.bytes()
					.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
				&& label
					.as_bytes()
					.first()
					.is_some_and(u8::is_ascii_alphanumeric)
				&& label
					.as_bytes()
					.last()
					.is_some_and(u8::is_ascii_alphanumeric)
		}) {
		return Err(FlagError::Invalid);
	}
	Ok(value.to_ascii_lowercase())
}

fn normalize_port(value: &str) -> Result<String, FlagError> {
	let port: u16 = value.parse().map_err(|_| FlagError::Invalid)?;
	if port == 0 {
		return Err(FlagError::Invalid);
	}
	Ok(port.to_string())
}

fn normalize_endpoint(value: &str, legacy: bool) -> Result<String, FlagError> {
	if value.is_empty() {
		return Ok(String::new());
	}
	if let Some(port) = value.strip_prefix(':') {
		return Ok(format!(":{}", normalize_port(port)?));
	}
	if value.starts_with('[') {
		let close = value.find(']').ok_or(FlagError::Invalid)?;
		let server = normalize_server(&value[..=close])?;
		let suffix = &value[close + 1..];
		return if suffix.is_empty() {
			Ok(server)
		} else {
			Ok(format!(
				"{server}:{}",
				normalize_port(suffix.strip_prefix(':').ok_or(FlagError::Invalid)?)?
			))
		};
	}
	if let Some((server, port)) = value.rsplit_once(':') {
		return Ok(format!(
			"{}:{}",
			normalize_server(server)?,
			normalize_port(port)?
		));
	}
	if legacy && value.bytes().all(|byte| byte.is_ascii_digit()) {
		return Err(FlagError::Ambiguous);
	}
	normalize_server(value)
}

fn internet_protocol(flag: &str) -> Option<Result<Vec<CanonicalFlag>, FlagError>> {
	for (index, name) in ["IBN", "IFC", "IFT", "ITN", "IVM", "IP"].iter().enumerate() {
		let Some(rest) = flag.strip_prefix(name) else {
			continue;
		};
		if !rest.is_empty() && !rest.starts_with(':') {
			continue;
		}
		let value = rest.strip_prefix(':').unwrap_or("");
		return Some(normalize_endpoint(value, true).map(|endpoint| {
			one(
				Field::Internet,
				format!(
					"{name}{}",
					if endpoint.is_empty() {
						String::new()
					} else {
						format!(":{endpoint}")
					}
				),
				2 + fixed_rank(index),
			)
		}));
	}
	None
}

fn valid_public_key(value: &str) -> bool {
	let base64_value = |byte: u8| match byte {
		b'A'..=b'Z' => Some(byte - b'A'),
		b'a'..=b'z' => Some(byte - b'a' + 26),
		b'0'..=b'9' => Some(byte - b'0' + 52),
		b'+' => Some(62),
		b'/' => Some(63),
		_ => None,
	};
	value.len() == 43
		&& value.bytes().all(|byte| base64_value(byte).is_some())
		&& value
			.as_bytes()
			.last()
			.and_then(|byte| base64_value(*byte))
			.is_some_and(|value| value.is_multiple_of(4))
}

fn iih(flag: &str) -> Option<Result<Vec<CanonicalFlag>, FlagError>> {
	let value = flag.strip_prefix("IIH:")?;
	let (endpoint, key) = value.rsplit_once(':').unwrap_or(("", value));
	if !valid_public_key(key) {
		return Some(Err(FlagError::Invalid));
	}
	Some(normalize_endpoint(endpoint, false).map(|endpoint| {
		one(
			Field::Internet,
			if endpoint.is_empty() {
				format!("IIH:{key}")
			} else {
				format!("IIH:{endpoint}:{key}")
			},
			1,
		)
	}))
}

fn email(flag: &str) -> Option<Result<Vec<CanonicalFlag>, FlagError>> {
	for (index, name) in ["IEM", "ITX", "IUC", "IMI", "ISE", "EVY", "EMA"]
		.iter()
		.enumerate()
	{
		let Some(rest) = flag.strip_prefix(name) else {
			continue;
		};
		if !rest.is_empty() && !rest.starts_with(':') {
			continue;
		}
		if let Some(address) = rest.strip_prefix(':')
			&& (address.is_empty()
				|| address
					.chars()
					.any(|character| character <= '\u{1f}' || matches!(character, '\u{7f}' | ',')))
		{
			return Some(Err(FlagError::Invalid));
		}
		return Some(Ok(one(Field::Email, flag, fixed_rank(index))));
	}
	None
}

/// Converts one legacy flag into one or more canonical TTS-5001 flags.
pub(crate) fn canonicalize(flag: &str) -> Result<Vec<CanonicalFlag>, FlagError> {
	let simple_system = ["CM", "LO", "MN", "ICM"];
	if let Some(index) = simple_system.iter().position(|name| *name == flag) {
		return Ok(one(Field::System, flag, fixed_rank(index)));
	}
	if let Some(index) = ["XA", "XB", "XC", "XP", "XR", "XW", "XX"]
		.iter()
		.position(|name| *name == flag)
	{
		return Ok(one(Field::System, flag, 10 + fixed_rank(index)));
	}
	if let Some(result) = mail_periods(flag) {
		return result;
	}
	if let Some(result) = online_period(flag) {
		return result;
	}
	if let Some((_, canonical)) = PSTN.iter().find(|(legacy, _)| *legacy == flag) {
		let order = PSTN_CANONICAL
			.iter()
			.position(|name| name == canonical)
			.expect("canonical PSTN flag is ranked");
		return Ok(one(Field::PstnIsdn, *canonical, fixed_rank(order)));
	}
	if matches!(flag, "INA" | "IIH") {
		return Err(FlagError::Invalid);
	}
	if let Some(server) = flag.strip_prefix("INA:") {
		return normalize_server(server)
			.map(|server| one(Field::Internet, format!("INA:{server}"), 0));
	}
	if let Some(result) = iih(flag) {
		return result;
	}
	if let Some(result) = internet_protocol(flag) {
		return result;
	}
	if flag == "INO4" {
		return Ok(one(Field::Internet, flag, 8));
	}
	if let Some(result) = email(flag) {
		return result;
	}
	if let Some(index) = OTHER.iter().position(|name| *name == flag) {
		return Ok(one(Field::Other, flag, fixed_rank(index)));
	}
	if (1..=32).contains(&flag.len()) && flag.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
		return Ok(vec![CanonicalFlag {
			field: Field::Other,
			text: flag.to_owned(),
			order: 1000,
			extension: true,
			known: false,
		}]);
	}
	Err(FlagError::Invalid)
}

#[must_use]
pub fn classify(flag: &str) -> Option<Field> {
	canonicalize(flag)
		.ok()
		.and_then(|flags| flags.first().map(|flag| flag.field))
}

pub(crate) fn publishes_contact(flag: &str) -> bool {
	match flag.split_once(':') {
		None => false,
		Some(("IIH", value)) => value.contains(':'),
		Some(_) => true,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn normalizes_registered_spellings_and_endpoints() {
		assert_eq!(canonicalize("V32B").unwrap()[0].text, "V32b");
		assert_eq!(
			canonicalize("IBN:MAIL.Example:024554").unwrap()[0].text,
			"IBN:mail.example:24554"
		);
		assert_eq!(
			canonicalize("INA:[2001:0DB8:0:0::1]").unwrap()[0].text,
			"INA:[2001:db8::1]"
		);
	}

	#[test]
	fn splits_legacy_concatenated_mail_periods() {
		let flags = canonicalize("#02#09").unwrap();
		assert_eq!(
			flags
				.iter()
				.map(|flag| flag.text.as_str())
				.collect::<Vec<_>>(),
			["#02", "#09"]
		);
	}

	#[test]
	fn refuses_an_ambiguous_numeric_internet_argument() {
		assert_eq!(canonicalize("IBN:24555"), Err(FlagError::Ambiguous));
		assert_eq!(canonicalize("IBN::24555").unwrap()[0].text, "IBN::24555");
	}

	#[test]
	fn trace_is_a_registered_robot_flag() {
		let flag = &canonicalize("TRACE").unwrap()[0];
		assert_eq!(flag.field, Field::Other);
		assert!(!flag.extension);
		assert!(flag.known);
		assert_eq!(flag.order, 3);
	}
}
