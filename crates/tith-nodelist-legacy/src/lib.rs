//! FTS-5000.005 to TTS-5000 nodelist conversion.
//!
//! This is the Rust port of the frozen `poc/nodelist.c` utility. It reads a
//! legacy nodelist and writes the tab separated, UTF-8, LF terminated form
//! defined by TTS-5000 section 5, which `tith-nodelist` parses.
//!
//! Conversion is a legacy boundary, so this crate deliberately lives outside
//! `tith-nodelist`, which implements the native TTS layer.

#![forbid(unsafe_code)]

mod flags;

use std::collections::BTreeMap;
use std::fmt;

use flags::publishes_contact;
pub use flags::{Field, classify};

/// A condition that stops conversion.
#[derive(Debug)]
pub struct ConvertError {
	/// One-based input line, or zero when the problem is not line specific.
	pub line: usize,
	pub kind: ConvertErrorKind,
}

#[derive(Debug)]
pub enum ConvertErrorKind {
	/// FTS-5000.005 specifies the 7-bit ASCII character set. Rather than guess
	/// at CP437 or decode lossily, a byte outside that range is refused.
	NonAscii,
	/// An override block began with a directive before any address line.
	OverrideWithoutAddress,
	/// An override address was not `zone:net/node`.
	InvalidOverrideAddress,
	/// An override directive was not one of `NN`, `LO`, `SN`, or `FL`.
	InvalidOverrideDirective,
	/// The same override directive was given twice for one address.
	DuplicateOverride,
}

impl fmt::Display for ConvertError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let reason = match self.kind {
			ConvertErrorKind::NonAscii => "input is not 7-bit ASCII as required by FTS-5000.005",
			ConvertErrorKind::OverrideWithoutAddress => {
				"override directive before any address line"
			}
			ConvertErrorKind::InvalidOverrideAddress => "override address is not zone:net/node",
			ConvertErrorKind::InvalidOverrideDirective => {
				"override directive is not NN, LO, SN, or FL"
			}
			ConvertErrorKind::DuplicateOverride => "duplicate override directive",
		};
		write!(f, "line {}: {reason}", self.line)
	}
}

impl std::error::Error for ConvertError {}

/// A condition that is reported but does not stop conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Warning {
	/// The keyword was not one TTS-5000 section 5.2 field 1 defines. The line
	/// is not converted.
	UnknownKeyword { line: usize, keyword: String },
	/// The node number was absent or outside the range TTS-5000 permits. The
	/// line is not converted.
	InvalidNodeNumber { line: usize, value: String },
	/// The normalized phone number did not have the TTS-5000 field 6 grammar.
	/// The line is not converted.
	InvalidPhone { line: usize, value: String },
	/// A member node appeared before any Zone line, so it has no address.
	MissingZone { line: usize },
	/// No table in `flags` matched, so the flag went to TTS-5000 field 11.
	UnknownFlag { line: usize, flag: String },
	/// TTS-5000 section 5.2 field 1 forbids a Pvt entry to publish a means of
	/// direct contact, and requires a converter to remove the keyword rather
	/// than the contact information. The entry became a normal node.
	PrivateKeywordStripped { line: usize },
}

impl fmt::Display for Warning {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownKeyword { line, keyword } => {
				write!(f, "line {line}: unknown keyword \"{keyword}\", skipping")
			}
			Self::InvalidNodeNumber { line, value } => {
				write!(f, "line {line}: invalid node number \"{value}\", skipping")
			}
			Self::InvalidPhone { line, value } => {
				write!(f, "line {line}: invalid phone number \"{value}\", skipping")
			}
			Self::MissingZone { line } => {
				write!(f, "line {line}: member node before any Zone, skipping")
			}
			Self::UnknownFlag { line, flag } => {
				write!(
					f,
					"line {line}: unrecognised flag \"{flag}\", placed in Other"
				)
			}
			Self::PrivateKeywordStripped { line } => write!(
				f,
				"line {line}: Pvt entry publishes contact information, keyword removed"
			),
		}
	}
}

/// A zone, net, and node triple, used only to match override blocks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LegacyAddress {
	zone: i32,
	net: i32,
	node: i32,
}

/// Replacement values for one address, read from an overrides file.
#[derive(Clone, Debug, Default)]
pub struct Override {
	pub node_name: Option<String>,
	pub location: Option<String>,
	pub sysop_name: Option<String>,
	/// Extra flags appended after the source flags and classified with them.
	pub extra_flags: Option<String>,
}

/// Every override block, keyed by address.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
	entries: BTreeMap<LegacyAddress, Override>,
}

impl Overrides {
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	#[must_use]
	pub fn len(&self) -> usize {
		self.entries.len()
	}
}

fn parse_legacy_address(value: &str) -> Option<LegacyAddress> {
	let (zone, rest) = value.split_once(':')?;
	let (net, node) = rest.split_once('/')?;
	Some(LegacyAddress {
		zone: zone.parse().ok()?,
		net: net.parse().ok()?,
		node: node.parse().ok()?,
	})
}

/// Reads one overrides file.
///
/// The format matches `poc/nodelist.c`: an address line in `zone:net/node`
/// form, followed by zero or more directive lines prefixed `NN`, `LO`, `SN`,
/// or `FL`.
pub fn load_overrides(input: &[u8], into: &mut Overrides) -> Result<(), ConvertError> {
	let text = ascii(input)?;
	let mut current: Option<LegacyAddress> = None;
	for (index, raw) in text.lines().enumerate() {
		let line = index + 1;
		let value = raw.trim_end();
		if value.is_empty() {
			continue;
		}
		if value.starts_with(|character: char| character.is_ascii_digit()) {
			let address = parse_legacy_address(value).ok_or(ConvertError {
				line,
				kind: ConvertErrorKind::InvalidOverrideAddress,
			})?;
			into.entries.entry(address).or_default();
			current = Some(address);
			continue;
		}
		let address = current.ok_or(ConvertError {
			line,
			kind: ConvertErrorKind::OverrideWithoutAddress,
		})?;
		let (directive, rest) = value.split_at_checked(2).ok_or(ConvertError {
			line,
			kind: ConvertErrorKind::InvalidOverrideDirective,
		})?;
		let entry = into.entries.entry(address).or_default();
		let slot = match directive {
			"NN" => &mut entry.node_name,
			"LO" => &mut entry.location,
			"SN" => &mut entry.sysop_name,
			"FL" => &mut entry.extra_flags,
			_ => {
				return Err(ConvertError {
					line,
					kind: ConvertErrorKind::InvalidOverrideDirective,
				});
			}
		};
		if slot.is_some() {
			return Err(ConvertError {
				line,
				kind: ConvertErrorKind::DuplicateOverride,
			});
		}
		*slot = Some(rest.to_owned());
	}
	Ok(())
}

fn ascii(input: &[u8]) -> Result<&str, ConvertError> {
	// Walking lines rather than scanning for the first offending byte gives the
	// reported line number directly.
	for (index, line) in input.split(|byte| *byte == b'\n').enumerate() {
		if !line.is_ascii() {
			return Err(ConvertError {
				line: index + 1,
				kind: ConvertErrorKind::NonAscii,
			});
		}
	}
	// Checked above, so this cannot fail.
	Ok(std::str::from_utf8(input).expect("ASCII input is valid UTF-8"))
}

/// TTS-5000 section 5.2 field 1.
fn valid_keyword(value: &str) -> bool {
	matches!(
		value,
		"" | "Pvt" | "Hold" | "Down" | "Zone" | "Region" | "Host" | "Hub"
	)
}

/// TTS-5000 section 5.2 field 2 accepts 1 through 32767 with no leading zero.
fn parse_node_number(value: &str) -> Option<i32> {
	if value.is_empty()
		|| value.starts_with('0')
		|| !value.bytes().all(|byte| byte.is_ascii_digit())
	{
		return None;
	}
	let number: i32 = value.parse().ok()?;
	(1..=32_767).contains(&number).then_some(number)
}

fn valid_phone(value: &str) -> bool {
	if value.is_empty() {
		return true;
	}
	if !(3..=29).contains(&value.len()) {
		return false;
	}
	let pieces: Vec<_> = value.split('-').collect();
	pieces.len() >= 2
		&& pieces
			.iter()
			.all(|piece| !piece.is_empty() && piece.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Tracks the branch so an override can be matched to a data line.
#[derive(Default)]
struct Hierarchy {
	zone: Option<i32>,
	net: Option<i32>,
}

impl Hierarchy {
	fn place(&mut self, keyword: &str, number: i32) -> Option<LegacyAddress> {
		match keyword {
			"Zone" => {
				self.zone = Some(number);
				self.net = Some(number);
				Some(LegacyAddress {
					zone: number,
					net: number,
					node: 0,
				})
			}
			"Region" | "Host" => {
				let zone = self.zone?;
				self.net = Some(number);
				Some(LegacyAddress {
					zone,
					net: number,
					node: 0,
				})
			}
			_ => {
				let zone = self.zone?;
				Some(LegacyAddress {
					zone,
					net: self.net.unwrap_or(zone),
					node: number,
				})
			}
		}
	}
}

fn underscores_to_spaces(value: &str) -> String {
	value.replace('_', " ")
}

/// Sorts one flag into its TTS-5000 field, reporting an unrecognised name.
fn place_flag(flag: &str, line: usize, buckets: &mut Buckets, warn: &mut dyn FnMut(Warning)) {
	let field = classify(flag).unwrap_or_else(|| {
		warn(Warning::UnknownFlag {
			line,
			flag: flag.to_owned(),
		});
		Field::Other
	});
	buckets.push(field, flag);
}

#[derive(Default)]
struct Buckets {
	system: Vec<String>,
	pstn_isdn: Vec<String>,
	internet: Vec<String>,
	email: Vec<String>,
	other: Vec<String>,
}

impl Buckets {
	fn push(&mut self, field: Field, flag: &str) {
		let target = match field {
			Field::System => &mut self.system,
			Field::PstnIsdn => &mut self.pstn_isdn,
			Field::Internet => &mut self.internet,
			Field::Email => &mut self.email,
			Field::Other => &mut self.other,
		};
		target.push(flag.to_owned());
	}
}

/// TTS-5000 field 9 requires INA to be first, and field 10 requires an IEM
/// carrying an address to be first.
fn hoist(list: &mut Vec<String>, prefix: &str) {
	if let Some(position) = list.iter().position(|flag| flag.starts_with(prefix))
		&& position != 0
	{
		let flag = list.remove(position);
		list.insert(0, flag);
	}
}

/// Converts an FTS-5000.005 nodelist into TTS-5000 form.
///
/// Comment lines pass through unchanged, including the FTS-5000.005 first line
/// with its day number and CRC: TTS-5000 section 5.1 gives a nodelist no header,
/// so that line becomes an ordinary comment recording the source nodelist, and
/// nothing reads the CRC it states. A `0x1A` at the start of a line ends the
/// input. Lines whose keyword or node number cannot be converted are reported
/// through `warn` and omitted.
pub fn convert(
	input: &[u8],
	overrides: &Overrides,
	warn: &mut dyn FnMut(Warning),
) -> Result<String, ConvertError> {
	let text = ascii(input)?;
	let mut output = String::new();
	let mut hierarchy = Hierarchy::default();
	for (index, raw) in text.split('\n').enumerate() {
		let line = index + 1;
		let value = raw.trim_end();
		if value.starts_with('\u{1a}') {
			break;
		}
		if value.starts_with(';') {
			output.push_str(value);
			output.push('\n');
			continue;
		}
		if value.is_empty() {
			continue;
		}
		let fields: Vec<&str> = value.split(',').map(str::trim_end).collect();
		let field = |index: usize| -> &str { fields.get(index).copied().unwrap_or("") };

		let keyword = field(0);
		if !valid_keyword(keyword) {
			warn(Warning::UnknownKeyword {
				line,
				keyword: keyword.to_owned(),
			});
			continue;
		}
		let Some(number) = parse_node_number(field(1)) else {
			warn(Warning::InvalidNodeNumber {
				line,
				value: field(1).to_owned(),
			});
			continue;
		};
		let Some(address) = hierarchy.place(keyword, number) else {
			warn(Warning::MissingZone { line });
			continue;
		};
		let entry = overrides.entries.get(&address);

		let node_name = entry
			.and_then(|entry| entry.node_name.clone())
			.unwrap_or_else(|| underscores_to_spaces(field(2)));
		let location = entry
			.and_then(|entry| entry.location.clone())
			.unwrap_or_else(|| underscores_to_spaces(field(3)));
		let sysop_name = entry
			.and_then(|entry| entry.sysop_name.clone())
			.unwrap_or_else(|| underscores_to_spaces(field(4)));
		let phone = if field(5) == "-Unpublished-" {
			""
		} else {
			field(5)
		};
		if !valid_phone(phone) {
			warn(Warning::InvalidPhone {
				line,
				value: field(5).to_owned(),
			});
			continue;
		}
		// Field 6 is the FTS-5000.005 DCE speed, which TTS-5000 does not carry.

		let mut buckets = Buckets::default();
		let mut seen_user_delimiter = false;
		let extra = entry.and_then(|entry| entry.extra_flags.as_deref());
		let source = fields.iter().skip(7).copied();
		let appended = extra.into_iter().flat_map(|value| value.split(','));
		for flag in source.chain(appended) {
			let flag = flag.trim_end();
			if flag.is_empty() {
				continue;
			}
			// FTS-5001.006 section 6.1: user flags follow a "U" delimiter, and
			// the deprecated attached form has the "U" joined to the first user
			// flag. TTS-5000 field 11 forbids carrying the delimiter through.
			if flag == "U" {
				seen_user_delimiter = true;
				continue;
			}
			if !seen_user_delimiter
				&& classify(flag).is_none()
				&& let Some(rest) = flag.strip_prefix('U')
				&& !rest.is_empty()
			{
				seen_user_delimiter = true;
				place_flag(rest, line, &mut buckets, warn);
				continue;
			}
			place_flag(flag, line, &mut buckets, warn);
		}
		hoist(&mut buckets.internet, "INA:");
		hoist(&mut buckets.email, "IEM:");

		// TTS-5000 section 5.2 field 1: the source nodelist contradicts its own
		// Pvt keyword, and it is the keyword which the converter removes.
		let mut keyword = keyword;
		if keyword == "Pvt"
			&& (!phone.is_empty()
				|| buckets
					.internet
					.iter()
					.chain(&buckets.email)
					.any(|flag| publishes_contact(flag)))
		{
			warn(Warning::PrivateKeywordStripped { line });
			keyword = "";
		}

		let record = [
			keyword,
			field(1),
			&node_name,
			&location,
			&sysop_name,
			phone,
			&buckets.system.join(","),
			&buckets.pstn_isdn.join(","),
			&buckets.internet.join(","),
			&buckets.email.join(","),
			&buckets.other.join(","),
		];
		output.push_str(&record.join("\t"));
		output.push('\n');
	}
	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn convert_ok(input: &str) -> (String, Vec<Warning>) {
		let mut warnings = Vec::new();
		let output = convert(input.as_bytes(), &Overrides::default(), &mut |warning| {
			warnings.push(warning);
		})
		.unwrap();
		(output, warnings)
	}

	#[test]
	fn writes_eleven_tab_separated_fields() {
		let (output, warnings) =
			convert_ok("Zone,1,Test_Zone,Somewhere,A_Sysop,-Unpublished-,9600,CM\r\n");
		assert_eq!(
			output,
			"Zone\t1\tTest Zone\tSomewhere\tA Sysop\t\tCM\t\t\t\t\n"
		);
		assert_eq!(output.lines().next().unwrap().split('\t').count(), 11);
		assert!(warnings.is_empty());
	}

	#[test]
	fn passes_comments_through_and_stops_at_the_end_marker() {
		let (output, _) =
			convert_ok(";A Comment line\r\nZone,1,N,L,S,,,\r\n\u{1a}\r\nZone,2,X,Y,Z,,,\r\n");
		assert!(output.starts_with(";A Comment line\n"));
		assert_eq!(output.lines().count(), 2);
	}

	#[test]
	fn drops_the_dce_speed_field() {
		let (output, _) = convert_ok("Zone,1,N,L,S,1-800-555-0100,300,CM\r\n");
		let fields: Vec<_> = output.trim_end().split('\t').collect();
		assert_eq!(fields[5], "1-800-555-0100");
		assert_eq!(fields[6], "CM");
	}

	#[test]
	fn node_numbers_use_the_canonical_tts_spelling() {
		for value in ["1", "9", "10", "32767"] {
			assert!(parse_node_number(value).is_some(), "{value}");
		}
		for value in ["", "0", "00", "01", "+1", " 1", "1 ", "32768"] {
			assert!(parse_node_number(value).is_none(), "{value}");
		}
	}

	#[test]
	fn refuses_a_source_phone_which_cannot_become_tts_5000() {
		let longest = format!("1-{}", "2".repeat(27));
		let too_long = format!("1-{}", "2".repeat(28));
		let (output, warnings) = convert_ok(&format!("Zone,1,N,L,S,{longest},300,CM\r\n"));
		assert_eq!(output.trim_end().split('\t').nth(5), Some(longest.as_str()));
		assert!(warnings.is_empty());

		for phone in [too_long.as_str(), "1--2"] {
			let (output, warnings) = convert_ok(&format!("Zone,1,N,L,S,{phone},300,CM\r\n"));
			assert!(output.is_empty(), "{phone}");
			assert_eq!(
				warnings,
				vec![Warning::InvalidPhone {
					line: 1,
					value: phone.to_owned(),
				}],
				"{phone}"
			);
		}
	}

	#[test]
	fn sorts_flags_into_their_tts_5000_fields() {
		let (output, warnings) =
			convert_ok("Zone,1,N,L,S,,,CM,V32b,IBN:example.org,IEM:s@example.org,MO\r\n");
		let fields: Vec<_> = output.trim_end().split('\t').collect();
		assert_eq!(fields[6], "CM");
		assert_eq!(fields[7], "V32b");
		assert_eq!(fields[8], "IBN:example.org");
		assert_eq!(fields[9], "IEM:s@example.org");
		assert_eq!(fields[10], "MO");
		assert!(warnings.is_empty());
	}

	#[test]
	fn hoists_ina_and_iem_to_the_front_of_their_fields() {
		let (output, _) =
			convert_ok("Zone,1,N,L,S,,,IBN,INA:example.org,ITX,IEM:s@example.org\r\n");
		let fields: Vec<_> = output.trim_end().split('\t').collect();
		assert_eq!(fields[8], "INA:example.org,IBN");
		assert_eq!(fields[9], "IEM:s@example.org,ITX");
	}

	#[test]
	fn removes_the_user_flag_delimiter_in_both_forms() {
		let (output, _) = convert_ok("Zone,1,N,L,S,,,U,NEC,ZEC\r\n");
		assert_eq!(output.trim_end().split('\t').nth(10).unwrap(), "NEC,ZEC");

		// FTS-5001.006 section 6.1 deprecated attached form.
		let (output, _) = convert_ok("Zone,1,N,L,S,,,UNEC,ZEC\r\n");
		assert_eq!(output.trim_end().split('\t').nth(10).unwrap(), "NEC,ZEC");
	}

	#[test]
	fn reports_an_unrecognised_flag_and_keeps_it_in_other() {
		let (output, warnings) = convert_ok("Zone,1,N,L,S,,,WIDGET\r\n");
		assert_eq!(output.trim_end().split('\t').nth(10).unwrap(), "WIDGET");
		assert_eq!(
			warnings,
			vec![Warning::UnknownFlag {
				line: 1,
				flag: "WIDGET".to_owned()
			}]
		);
	}

	#[test]
	fn strips_the_private_keyword_from_an_entry_which_publishes_contact_information() {
		for (line, published) in [
			("Pvt,20,N,L,S,,,IBN:example.org", "IBN:example.org"),
			("Pvt,20,N,L,S,,,INA:example.org", "INA:example.org"),
			(
				"Pvt,20,N,L,S,,,IEM:sysop@example.org",
				"IEM:sysop@example.org",
			),
			(
				"Pvt,20,N,L,S,,,IIH:example.org:24555:key",
				"IIH:example.org:24555:key",
			),
			("Pvt,20,N,L,S,,,IIH::24555:key", "IIH::24555:key"),
			("Pvt,20,N,L,S,1-616-555-0100,,", "1-616-555-0100"),
		] {
			let input = format!("Zone,1,N,L,S,,,\r\nHost,10,N,L,S,,,\r\n{line}\r\n");
			let (output, warnings) = convert_ok(&input);
			assert_eq!(
				warnings,
				vec![Warning::PrivateKeywordStripped { line: 3 }],
				"line {line}"
			);
			// The keyword went; the contact information the source published
			// stayed, because it is the keyword the entry contradicts.
			let last = output.lines().next_back().unwrap();
			let fields: Vec<_> = last.split('\t').collect();
			assert_eq!(fields[0], "", "line {line}");
			assert_eq!(fields[1], "20", "line {line}");
			assert!(last.contains(published), "line {line}: {last}");
		}
	}

	#[test]
	fn keeps_the_private_keyword_when_no_contact_information_is_published() {
		// TTS-5000 section 5.2 field 1 excepts the endpointless IIH form, so a
		// Pvt node keeps the key its Origin is authenticated with.
		for line in [
			"Pvt,20,N,L,S,-Unpublished-,,IIH:x8p4jN0PtHsr0nHxLmnw3Uy3v8kZfOZeMcxOWUeMOoo",
			"Pvt,20,N,L,S,,,IBN",
			"Pvt,20,N,L,S,,,ITX",
			"Pvt,20,N,L,S,,,",
		] {
			let input = format!("Zone,1,N,L,S,,,\r\nHost,10,N,L,S,,,\r\n{line}\r\n");
			let (output, warnings) = convert_ok(&input);
			assert!(warnings.is_empty(), "line {line}: {warnings:?}");
			let last = output.lines().next_back().unwrap();
			assert_eq!(last.split('\t').next().unwrap(), "Pvt", "line {line}");
		}
	}

	#[test]
	fn refuses_input_that_is_not_seven_bit_ascii() {
		let error = convert(
			b"Zone,1,N,L,S,,,\n\xc3\xa9\n",
			&Overrides::default(),
			&mut |_| {},
		)
		.unwrap_err();
		assert!(matches!(error.kind, ConvertErrorKind::NonAscii));
		assert_eq!(error.line, 2);
	}

	#[test]
	fn applies_overrides_to_the_matching_address() {
		let mut overrides = Overrides::default();
		load_overrides(
			b"1:10/20\nNNOverridden Name\nLONew Location\nSNNew Sysop\nFLXA,IBN\n",
			&mut overrides,
		)
		.unwrap();
		assert_eq!(overrides.len(), 1);
		let mut warnings = Vec::new();
		let output = convert(
			b"Zone,1,N,L,S,,,\nHost,10,N,L,S,,,\n,20,Original,Place,Sysop,,,CM\n",
			&overrides,
			&mut |warning| warnings.push(warning),
		)
		.unwrap();
		let last = output.lines().next_back().unwrap();
		let fields: Vec<_> = last.split('\t').collect();
		assert_eq!(fields[2], "Overridden Name");
		assert_eq!(fields[3], "New Location");
		assert_eq!(fields[4], "New Sysop");
		assert_eq!(fields[6], "CM,XA");
		assert_eq!(fields[8], "IBN");
		assert!(warnings.is_empty());
	}

	#[test]
	fn skips_a_line_with_an_unusable_keyword_or_number() {
		let (output, warnings) =
			convert_ok("Zone,1,N,L,S,,,\r\nBogus,5,N,L,S,,,\r\n,0,N,L,S,,,\r\n");
		assert_eq!(output.lines().count(), 1);
		assert_eq!(warnings.len(), 2);
		assert!(matches!(
			warnings[0],
			Warning::UnknownKeyword { line: 2, .. }
		));
		assert!(matches!(
			warnings[1],
			Warning::InvalidNodeNumber { line: 3, .. }
		));
	}
}
