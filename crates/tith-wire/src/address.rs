//! Canonical five-dimensional addresses from TTS-0004.

use std::cmp::Ordering;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressError {
	EmptyDomain,
	InvalidDomain,
	MissingZone,
	InvalidNumber,
	OutOfRange,
	NonCanonical,
	InvalidOrder,
	InvalidWildcard,
}

impl fmt::Display for AddressError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::EmptyDomain => "address domain is empty",
			Self::InvalidDomain => "address domain contains a prohibited value",
			Self::MissingZone => "address zone is missing",
			Self::InvalidNumber => "address component is not a canonical decimal number",
			Self::OutOfRange => "address component is out of range",
			Self::NonCanonical => "address contains an explicitly encoded default component",
			Self::InvalidOrder => "address components are out of order or repeated",
			Self::InvalidWildcard => "invalid address wildcard",
		})
	}
}

impl std::error::Error for AddressError {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address {
	domain: String,
	zone: i32,
	net: i32,
	node: i32,
	point: u16,
}

impl Address {
	pub fn new(
		domain: String,
		zone: i32,
		net: i32,
		node: i32,
		point: u16,
	) -> Result<Self, AddressError> {
		validate_domain(&domain)?;
		if domain == "p2p" && zone != -1 {
			return Err(AddressError::InvalidDomain);
		}
		if zone != -1 && !(1..=32_767).contains(&zone) {
			return Err(AddressError::OutOfRange);
		}
		if zone == -1 {
			if net != -1 || node != -1 || point != 0 {
				return Err(AddressError::OutOfRange);
			}
		} else if !(1..=32_767).contains(&net) || !(0..=32_767).contains(&node) {
			return Err(AddressError::OutOfRange);
		}
		Ok(Self {
			domain,
			zone,
			net,
			node,
			point,
		})
	}

	pub fn anonymous(domain: String) -> Result<Self, AddressError> {
		Self::new(domain, -1, -1, -1, 0)
	}

	#[must_use]
	pub fn domain(&self) -> &str {
		&self.domain
	}

	#[must_use]
	pub const fn zone(&self) -> i32 {
		self.zone
	}

	#[must_use]
	pub const fn net(&self) -> i32 {
		self.net
	}

	#[must_use]
	pub const fn node(&self) -> i32 {
		self.node
	}

	#[must_use]
	pub const fn point(&self) -> u16 {
		self.point
	}

	#[must_use]
	pub const fn is_anonymous(&self) -> bool {
		self.zone == -1
	}
}

fn validate_domain(domain: &str) -> Result<(), AddressError> {
	if domain.is_empty() {
		return Err(AddressError::EmptyDomain);
	}
	if domain.starts_with(tts_whitespace) || domain.ends_with(tts_whitespace) {
		return Err(AddressError::InvalidDomain);
	}
	if domain
		.chars()
		.any(|character| character.is_control() || matches!(character, '#' | '*' | ',' | '<' | '>'))
	{
		return Err(AddressError::InvalidDomain);
	}
	Ok(())
}

const fn tts_whitespace(character: char) -> bool {
	matches!(
		character,
		'\u{0009}'..='\u{000d}'
			| '\u{0020}'
			| '\u{0085}'
			| '\u{00a0}'
			| '\u{1680}'
			| '\u{2000}'..='\u{200a}'
			| '\u{2028}'
			| '\u{2029}'
			| '\u{202f}'
			| '\u{205f}'
			| '\u{3000}'
	)
}

fn parse_number(text: &str, allow_negative_one: bool) -> Result<i32, AddressError> {
	if allow_negative_one && text == "-1" {
		return Ok(-1);
	}
	if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
		return Err(AddressError::InvalidNumber);
	}
	text.parse().map_err(|_| AddressError::OutOfRange)
}

fn take_component<'a>(input: &mut &'a str, terminators: &[char]) -> &'a str {
	let end = input.find(terminators).unwrap_or(input.len());
	let value = &input[..end];
	*input = &input[end..];
	value
}

impl FromStr for Address {
	type Err = AddressError;

	fn from_str(text: &str) -> Result<Self, Self::Err> {
		let Some(hash) = text.find('#') else {
			return Err(AddressError::MissingZone);
		};
		let domain = &text[..hash];
		validate_domain(domain)?;
		let mut rest = &text[hash + 1..];
		let zone_text = take_component(&mut rest, &[':', '/', '.']);
		let zone = parse_number(zone_text, true)?;
		if zone != -1 && !(1..=32_767).contains(&zone) {
			return Err(AddressError::OutOfRange);
		}

		let mut net = if zone == -1 { -1 } else { zone };
		let mut node = if zone == -1 { -1 } else { 0 };
		let mut point = 0_u16;
		let mut last_prefix = 0;
		while !rest.is_empty() {
			// `take_component` leaves one of its ASCII terminators at the front.
			let prefix = char::from(rest.as_bytes()[0]);
			rest = &rest[1..];
			let order = if prefix == ':' {
				1
			} else if prefix == '/' {
				2
			} else {
				3
			};
			if order <= last_prefix {
				return Err(AddressError::InvalidOrder);
			}
			last_prefix = order;
			let value = take_component(&mut rest, &[':', '/', '.']);
			if prefix == ':' {
				net = parse_number(value, true)?;
				if net == zone {
					return Err(AddressError::NonCanonical);
				}
			} else if prefix == '/' {
				node = parse_number(value, true)?;
			} else {
				let parsed = parse_number(value, false)?;
				point = u16::try_from(parsed).map_err(|_| AddressError::OutOfRange)?;
			}
		}

		Self::new(domain.to_owned(), zone, net, node, point)
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}#{}", self.domain, self.zone)?;
		if self.net != self.zone {
			write!(f, ":{}", self.net)?;
		}
		if self.node != if self.zone == -1 { -1 } else { 0 } {
			write!(f, "/{}", self.node)?;
		}
		if self.point != 0 {
			write!(f, ".{}", self.point)?;
		}
		Ok(())
	}
}

impl Ord for Address {
	fn cmp(&self, other: &Self) -> Ordering {
		self.domain
			.as_bytes()
			.cmp(other.domain.as_bytes())
			.then_with(|| self.zone.cmp(&other.zone))
			.then_with(|| self.net.cmp(&other.net))
			.then_with(|| self.node.cmp(&other.node))
			.then_with(|| self.point.cmp(&other.point))
	}
}

impl PartialOrd for Address {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

#[must_use]
pub fn format_trimmed_list(addresses: &[Address]) -> String {
	let mut output = String::new();
	let mut previous: Option<&Address> = None;
	for address in addresses {
		if !output.is_empty() {
			output.push(',');
		}
		match previous {
			None => output.push_str(&address.to_string()),
			Some(prior) if prior.domain != address.domain => {
				output.push_str(&address.to_string());
			}
			Some(prior) if prior.zone != address.zone => {
				output.push('#');
				output.push_str(&address.zone.to_string());
				append_after_zone(&mut output, address);
			}
			Some(prior) if prior.net != address.net => {
				output.push(':');
				output.push_str(&address.net.to_string());
				append_after_net(&mut output, address);
			}
			Some(prior) if prior.node != address.node => {
				output.push('/');
				output.push_str(&address.node.to_string());
				if address.point != 0 {
					write!(&mut output, ".{}", address.point).expect("String writes cannot fail");
				}
			}
			Some(prior) if prior.point != address.point => {
				output.push('.');
				output.push_str(&address.point.to_string());
			}
			Some(_) => {
				output.push_str(&address.to_string());
			}
		}
		previous = Some(address);
	}
	output
}

fn append_after_zone(output: &mut String, address: &Address) {
	if address.net != address.zone {
		write!(output, ":{}", address.net).expect("String writes cannot fail");
	}
	append_after_net(output, address);
}

fn append_after_net(output: &mut String, address: &Address) {
	if address.node != if address.zone == -1 { -1 } else { 0 } {
		write!(output, "/{}", address.node).expect("String writes cannot fail");
	}
	if address.point != 0 {
		write!(output, ".{}", address.point).expect("String writes cannot fail");
	}
}

#[must_use]
pub fn format_trimmed_collection(addresses: &[Address]) -> String {
	let mut sorted = addresses.to_vec();
	sorted.sort();
	sorted.dedup();
	format_trimmed_list(&sorted)
}

/// The inverse of [`format_trimmed_list`].
///
/// An element which begins with a component prefix inherits every higher
/// component from the preceding address and defaults every lower one it does
/// not state. An empty string is an empty list.
///
/// The element is not a canonical address with its prefix removed, so it
/// cannot simply be reassembled and reparsed. A trimmed element encodes a
/// *change* from the previous address, and a component may change to the value
/// which the canonical form would omit: the TTS-0004 example itself contains
/// ":885" for a net equal to its zone. Components are therefore read directly.
pub fn parse_trimmed_list(value: &str) -> Result<Vec<Address>, AddressError> {
	let addresses = expand_trimmed(value)?;
	if format_trimmed_list(&addresses) != value {
		return Err(AddressError::NonCanonical);
	}
	Ok(addresses)
}

/// Parses one canonical TTS-0004 Trimmed Collection.
pub fn parse_trimmed_collection(value: &str) -> Result<Vec<Address>, AddressError> {
	let addresses = expand_trimmed(value)?;
	if format_trimmed_collection(&addresses) != value {
		return Err(AddressError::NonCanonical);
	}
	Ok(addresses)
}

fn expand_trimmed(value: &str) -> Result<Vec<Address>, AddressError> {
	if value.is_empty() {
		return Ok(Vec::new());
	}
	let mut addresses: Vec<Address> = Vec::new();
	for element in value.split(',') {
		let address = parse_trimmed_element(element, addresses.last())?;
		addresses.push(address);
	}
	Ok(addresses)
}

fn parse_trimmed_element(
	element: &str,
	previous: Option<&Address>,
) -> Result<Address, AddressError> {
	let mut rest = element;
	let prefix = rest.chars().next().ok_or(AddressError::InvalidNumber)?;
	let mut order = match prefix {
		'#' => 0,
		':' => 1,
		'/' => 2,
		'.' => 3,
		_ => return element.parse(),
	};
	let previous = previous.ok_or(AddressError::InvalidOrder)?;
	rest = &rest[prefix.len_utf8()..];
	let domain = previous.domain.clone();
	let mut zone = previous.zone;
	let mut net = previous.net;
	let mut node = previous.node;
	// Point alone is not inherited. Components are read in increasing order, so
	// any component above point is read before point could be, and each one
	// resets the inherited components below itself.
	let mut point = 0;
	loop {
		let text = take_component(&mut rest, &[':', '/', '.']);
		match order {
			0 => {
				zone = parse_trimmed_number(text, true)?;
				net = zone;
				node = if zone == -1 { -1 } else { 0 };
			}
			1 => {
				net = parse_trimmed_number(text, true)?;
				node = if zone == -1 { -1 } else { 0 };
			}
			2 => {
				node = parse_trimmed_number(text, true)?;
			}
			_ => {
				point = u16::try_from(parse_trimmed_number(text, false)?)
					.map_err(|_| AddressError::OutOfRange)?;
			}
		}
		let Some(separator) = rest.chars().next() else {
			break;
		};
		rest = &rest[separator.len_utf8()..];
		let following = if separator == ':' {
			1
		} else if separator == '/' {
			2
		} else {
			3
		};
		if following <= order {
			return Err(AddressError::InvalidOrder);
		}
		order = following;
	}
	Address::new(domain, zone, net, node, point)
}

/// A component of a trimmed element, which unlike a canonical address may
/// restate a value the canonical form would have omitted.
fn parse_trimmed_number(text: &str, allow_negative_one: bool) -> Result<i32, AddressError> {
	if text == "0" {
		return Ok(0);
	}
	parse_number(text, allow_negative_one)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DomainPattern {
	Any,
	Exact(String),
	List(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NumberPattern {
	Any,
	Exact(i32),
	List(Vec<(i32, i32)>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressPattern {
	domain: DomainPattern,
	zone: NumberPattern,
	net: NumberPattern,
	node: NumberPattern,
	point: NumberPattern,
}

impl AddressPattern {
	#[must_use]
	pub fn matches(&self, address: &Address) -> bool {
		match_domain(&self.domain, &address.domain)
			&& match_number(&self.zone, address.zone)
			&& match_number(&self.net, address.net)
			&& match_number(&self.node, address.node)
			&& match_number(&self.point, i32::from(address.point))
	}
}

fn match_domain(pattern: &DomainPattern, value: &str) -> bool {
	match pattern {
		DomainPattern::Any => true,
		DomainPattern::Exact(expected) => expected == value,
		DomainPattern::List(values) => values.iter().any(|expected| expected == value),
	}
}

fn match_number(pattern: &NumberPattern, value: i32) -> bool {
	match pattern {
		NumberPattern::Any => value != -1,
		NumberPattern::Exact(expected) => *expected == value,
		NumberPattern::List(ranges) => ranges
			.iter()
			.any(|(start, end)| (*start..=*end).contains(&value)),
	}
}

fn parse_domain_pattern(text: &str) -> Result<DomainPattern, AddressError> {
	if text == "*" {
		return Ok(DomainPattern::Any);
	}
	if let Some(inner) = text
		.strip_prefix('<')
		.and_then(|value| value.strip_suffix('>'))
	{
		let mut values = Vec::new();
		for value in inner.split(',') {
			validate_domain(value)?;
			values.push(value.to_owned());
		}
		return Ok(DomainPattern::List(values));
	}
	validate_domain(text)?;
	Ok(DomainPattern::Exact(text.to_owned()))
}

fn parse_number_pattern(
	text: &str,
	minimum: i32,
	maximum: i32,
) -> Result<NumberPattern, AddressError> {
	if text == "*" {
		return Ok(NumberPattern::Any);
	}
	let values = text
		.strip_prefix('<')
		.and_then(|value| value.strip_suffix('>'));
	if let Some(values) = values {
		let mut ranges = Vec::new();
		for value in values.split(',') {
			let range_at = value
				.char_indices()
				.skip(1)
				.find_map(|(index, character)| (character == '-').then_some(index));
			let (start, end) = if let Some(at) = range_at {
				(
					parse_pattern_number(&value[..at])?,
					parse_pattern_number(&value[at + 1..])?,
				)
			} else {
				let number = parse_pattern_number(value)?;
				(number, number)
			};
			if start < minimum || end > maximum || start > end {
				return Err(AddressError::InvalidWildcard);
			}
			ranges.push((start, end));
		}
		return Ok(NumberPattern::List(ranges));
	}
	let number = parse_pattern_number(text)?;
	if !(minimum..=maximum).contains(&number) {
		return Err(AddressError::OutOfRange);
	}
	Ok(NumberPattern::Exact(number))
}

fn parse_pattern_number(text: &str) -> Result<i32, AddressError> {
	if text == "0" {
		Ok(0)
	} else {
		parse_number(text, true)
	}
}

impl FromStr for AddressPattern {
	type Err = AddressError;

	fn from_str(text: &str) -> Result<Self, Self::Err> {
		if text == "*" {
			return Ok(Self {
				domain: DomainPattern::Any,
				zone: NumberPattern::Any,
				net: NumberPattern::Any,
				node: NumberPattern::Any,
				point: NumberPattern::Any,
			});
		}

		let first_prefix = text.find(['#', ':', '/', '.']);
		let (domain_text, mut rest) = match first_prefix {
			Some(index) => (&text[..index], &text[index..]),
			None => return Err(AddressError::InvalidWildcard),
		};
		let domain = parse_domain_pattern(domain_text)?;
		let mut zone = NumberPattern::Any;
		let mut net = NumberPattern::Any;
		let mut node = NumberPattern::Any;
		let mut point = NumberPattern::Any;
		let mut last = 0;
		let mut wildcard_seen = matches!(domain, DomainPattern::Any | DomainPattern::List(_));
		while !rest.is_empty() {
			// The initial search and `take_component` leave an ASCII prefix here.
			let prefix = char::from(rest.as_bytes()[0]);
			rest = &rest[1..];
			let order = if prefix == '#' {
				1
			} else if prefix == ':' {
				2
			} else if prefix == '/' {
				3
			} else {
				4
			};
			if order <= last {
				return Err(AddressError::InvalidOrder);
			}
			last = order;
			let value = take_component(&mut rest, &['#', ':', '/', '.']);
			let parsed = if prefix == '.' {
				parse_number_pattern(value, 0, 65_535)?
			} else {
				parse_number_pattern(value, -1, 32_767)?
			};
			wildcard_seen |= matches!(parsed, NumberPattern::Any | NumberPattern::List(_));
			if prefix == '#' {
				zone = parsed;
			} else if prefix == ':' {
				net = parsed;
			} else if prefix == '/' {
				node = parsed;
			} else {
				point = parsed;
			}
		}
		if !wildcard_seen {
			return Err(AddressError::InvalidWildcard);
		}
		Ok(Self {
			domain,
			zone,
			net,
			node,
			point,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn address(text: &str) -> Address {
		text.parse().unwrap()
	}

	#[test]
	fn canonical_examples_round_trip() {
		for text in [
			"fidonet#1",
			"fidonet#1:10",
			"fidonet#1/2",
			"fidonet#1.5",
			"fidonet#-1",
		] {
			assert_eq!(address(text).to_string(), text);
		}
	}

	#[test]
	fn public_address_api_and_errors_are_complete() {
		let value = address("fidonet#32767:1/32767.65535");
		assert_eq!(value.zone(), 32_767);
		assert_eq!(value.net(), 1);
		assert_eq!(value.node(), 32_767);
		assert_eq!(value.point(), 65_535);
		assert_eq!(
			value.partial_cmp(&address("fidonet#32767")),
			Some(Ordering::Less)
		);

		for (error, message) in [
			(AddressError::EmptyDomain, "address domain is empty"),
			(
				AddressError::InvalidDomain,
				"address domain contains a prohibited value",
			),
			(AddressError::MissingZone, "address zone is missing"),
			(
				AddressError::InvalidNumber,
				"address component is not a canonical decimal number",
			),
			(
				AddressError::OutOfRange,
				"address component is out of range",
			),
			(
				AddressError::NonCanonical,
				"address contains an explicitly encoded default component",
			),
			(
				AddressError::InvalidOrder,
				"address components are out of order or repeated",
			),
			(AddressError::InvalidWildcard, "invalid address wildcard"),
		] {
			assert_eq!(error.to_string(), message);
		}
		assert_eq!("fidonet".parse::<Address>(), Err(AddressError::MissingZone));
		assert_eq!(
			Address::new(String::new(), 1, 1, 0, 0),
			Err(AddressError::EmptyDomain)
		);
		assert_eq!(
			"fidonet#1/2:3".parse::<Address>(),
			Err(AddressError::InvalidOrder)
		);
	}

	#[test]
	fn display_propagates_every_formatter_failure() {
		struct FailAfter(usize);

		impl fmt::Write for FailAfter {
			fn write_str(&mut self, value: &str) -> fmt::Result {
				if self.0 == 0 {
					Err(fmt::Error)
				} else {
					self.0 -= 1;
					let _ = value;
					Ok(())
				}
			}
		}

		let value = address("fidonet#1:2/3.4");
		for successful_writes in 0..16 {
			let mut output = FailAfter(successful_writes);
			let _ = write!(&mut output, "{value}");
		}
	}

	#[test]
	fn domain_grammar_uses_the_exact_tts_code_point_sets() {
		for code in (0..=0x1f).chain(0x7f..=0x9f) {
			let character = char::from_u32(code).unwrap();
			let text = format!("a{character}b#1");
			assert!(text.parse::<Address>().is_err(), "U+{code:04X}");
		}
		for character in ['#', '*', ',', '<', '>'] {
			let text = format!("a{character}b#1");
			assert!(text.parse::<Address>().is_err(), "{text:?}");
		}
		for character in [
			'\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}',
			'\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
			'\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
			'\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
		] {
			assert!(format!("{character}a#1").parse::<Address>().is_err());
			assert!(format!("a{character}#1").parse::<Address>().is_err());
		}

		for domain in ["БорМер", "a b", "a\u{200b}", "a:b", "a/b", "a\\b"] {
			let text = format!("{domain}#1");
			assert_eq!(address(&text).domain(), domain);
		}
		assert_eq!("#1".parse::<Address>(), Err(AddressError::EmptyDomain));
	}

	#[test]
	fn numeric_components_enforce_every_boundary() {
		for text in ["fidonet#1", "fidonet#32767:1/32767.65535", "fidonet#-1"] {
			assert_eq!(address(text).to_string(), text);
		}
		for text in [
			"fidonet#0",
			"fidonet#32768",
			"fidonet#1:0",
			"fidonet#1:32768",
			"fidonet#1/-1",
			"fidonet#1/32768",
			"fidonet#1.65536",
			"fidonet#+1",
			"fidonet#01",
			"fidonet#-01",
			"fidonet#-2",
		] {
			assert!(text.parse::<Address>().is_err(), "{text}");
		}
		for (zone, net, node, point) in [
			(0, 1, 0, 0),
			(-1, 1, -1, 0),
			(-1, -1, 0, 0),
			(-1, -1, -1, 1),
			(1, 0, 0, 0),
			(1, 1, -1, 0),
		] {
			assert!(Address::new("fidonet".to_owned(), zone, net, node, point).is_err());
		}
	}

	#[test]
	fn p2p_has_only_its_anonymous_address() {
		assert_eq!(
			address("p2p#-1"),
			Address::anonymous("p2p".to_owned()).unwrap()
		);
		for text in ["p2p#1", "p2p#32767/32767.65535"] {
			assert!(text.parse::<Address>().is_err(), "{text}");
		}
		assert!(Address::new("p2p".to_owned(), 1, 1, 0, 0).is_err());
	}

	#[test]
	fn rejects_explicit_defaults_and_invalid_anonymous_suffixes() {
		for text in ["fidonet#1:1", "fidonet#1/0", "fidonet#1.0", "fidonet#-1/1"] {
			assert!(text.parse::<Address>().is_err(), "{text}");
		}
	}

	#[test]
	fn formats_standard_trimmed_examples() {
		let input = [
			"fidonet#1",
			"fidonet#1:2",
			"fidonet#1:2/103",
			"BBSDev#885:1/1",
			"fidonet#1:2/103.1",
			"BBSDev#885",
			"BBSDev#885:1",
			"BBSDev#885:1/1",
			"BBSDev#885:1/2",
		]
		.map(address);
		assert_eq!(
			format_trimmed_collection(&input),
			"BBSDev#885:1,/1,/2,:885,fidonet#1,:2,/103,.1"
		);
		assert_eq!(
			format_trimmed_list(&input),
			"fidonet#1,:2,/103,BBSDev#885:1/1,fidonet#1:2/103.1,BBSDev#885,:1,/1,/2"
		);
	}

	#[test]
	fn the_standard_trimmed_examples_parse_back() {
		// The TTS-0004 section 5 collection, which contains ":885" for a net
		// equal to its zone, and the section 6 list of the same addresses.
		assert_eq!(
			parse_trimmed_list("BBSDev#885:1,/1,/2,:885,fidonet#1,:2,/103,.1").unwrap(),
			[
				"BBSDev#885:1",
				"BBSDev#885:1/1",
				"BBSDev#885:1/2",
				"BBSDev#885",
				"fidonet#1",
				"fidonet#1:2",
				"fidonet#1:2/103",
				"fidonet#1:2/103.1",
			]
			.map(address)
		);
		assert_eq!(
			parse_trimmed_list(
				"fidonet#1,:2,/103,BBSDev#885:1/1,fidonet#1:2/103.1,BBSDev#885,:1,/1,/2"
			)
			.unwrap(),
			[
				"fidonet#1",
				"fidonet#1:2",
				"fidonet#1:2/103",
				"BBSDev#885:1/1",
				"fidonet#1:2/103.1",
				"BBSDev#885",
				"BBSDev#885:1",
				"BBSDev#885:1/1",
				"BBSDev#885:1/2",
			]
			.map(address)
		);
	}

	#[test]
	fn every_trimmed_list_round_trips() {
		for input in [
			vec!["fidonet#1/2", "fidonet#1"],
			vec!["fidonet#1:2/103.1", "fidonet#1:2/103"],
			vec!["fidonet#-1", "fidonet#1"],
			vec!["fidonet#1", "fidonet#-1"],
			vec!["a.b:c/d#1/2", "a.b:c/d#1/3"],
			vec!["fidonet#1", "other#1"],
		] {
			let addresses = input.iter().copied().map(address).collect::<Vec<_>>();
			let formatted = format_trimmed_list(&addresses);
			assert_eq!(
				parse_trimmed_list(&formatted).unwrap(),
				addresses,
				"{formatted}"
			);
		}
	}

	#[test]
	fn trimming_resets_and_reemits_every_lower_component() {
		let addresses = [
			"fidonet#1",
			"fidonet#2:3/4.5",
			"fidonet#2:4.6",
			"fidonet#2:4/7.8",
		]
		.map(address);
		let encoded = "fidonet#1,#2:3/4.5,:4.6,/7.8";
		assert_eq!(format_trimmed_list(&addresses), encoded);
		assert_eq!(parse_trimmed_list(encoded).unwrap(), addresses);
	}

	#[test]
	fn a_trimmed_element_may_restate_a_defaulted_component() {
		// format_trimmed_list writes the changed component even when it equals
		// the value a canonical address omits, so "/0" and ".0" are producible.
		let addresses = ["fidonet#1/2", "fidonet#1"].map(address);
		assert_eq!(format_trimmed_list(&addresses), "fidonet#1/2,/0");
		assert_eq!(parse_trimmed_list("fidonet#1/2,/0").unwrap(), addresses);
		let addresses = ["fidonet#1.5", "fidonet#1"].map(address);
		assert_eq!(format_trimmed_list(&addresses), "fidonet#1.5,.0");
		assert_eq!(parse_trimmed_list("fidonet#1.5,.0").unwrap(), addresses);
	}

	#[test]
	fn rejects_a_trimmed_list_which_cannot_inherit_or_is_misordered() {
		assert_eq!(parse_trimmed_list("").unwrap(), []);
		for text in [
			"/2",
			":2",
			".1",
			"#1",
			"fidonet#1,#x",
			"fidonet#1,/2:3",
			"fidonet#1,/x",
			"fidonet#1,.x",
			"fidonet#1,.65536",
		] {
			assert!(parse_trimmed_list(text).is_err(), "{text}");
		}
		assert!(parse_trimmed_collection("/2").is_err());
	}

	#[test]
	fn collections_deduplicate_but_lists_preserve_repetitions() {
		let input = ["fidonet#1/2", "fidonet#1/2"].map(address);
		assert_eq!(format_trimmed_collection(&input), "fidonet#1/2");
		assert_eq!(format_trimmed_list(&input), "fidonet#1/2,fidonet#1/2");
		assert_eq!(
			parse_trimmed_list("fidonet#1/2,fidonet#1/2").unwrap(),
			input
		);
	}

	#[test]
	fn trimmed_inputs_must_reproduce_their_exact_canonical_encoding() {
		let collection = "BBSDev#885:1,/1,/2,:885,fidonet#1,:2,/103,.1";
		assert_eq!(
			format_trimmed_collection(&parse_trimmed_collection(collection).unwrap()),
			collection
		);
		assert_eq!(parse_trimmed_collection("").unwrap(), []);

		for text in [
			"fidonet#1,fidonet#1/2",
			"fidonet#1/2,fidonet#1",
			"fidonet#1/2,fidonet#1/2",
		] {
			assert!(parse_trimmed_collection(text).is_err(), "{text}");
		}
		for text in [
			"fidonet#1,fidonet#2",
			"fidonet#1,fidonet#1/2",
			"fidonet#1,,/2",
			"fidonet#1,:",
			"fidonet#-1,:-1",
		] {
			assert!(parse_trimmed_list(text).is_err(), "{text}");
		}
	}

	#[test]
	fn wildcard_examples_match() {
		assert!(
			"*".parse::<AddressPattern>()
				.unwrap()
				.matches(&address("fidonet#1:2/3"))
		);
		assert!(
			!"*".parse::<AddressPattern>()
				.unwrap()
				.matches(&address("fidonet#-1"))
		);
		assert!(
			"BBSDev#*"
				.parse::<AddressPattern>()
				.unwrap()
				.matches(&address("BBSDev#885:1/2"))
		);
		assert!(
			"BBSDev#*/0"
				.parse::<AddressPattern>()
				.unwrap()
				.matches(&address("BBSDev#885"))
		);
		assert!(
			"*:1"
				.parse::<AddressPattern>()
				.unwrap()
				.matches(&address("fidonet#2:1/3"))
		);
		assert!(
			"*#<885,1-6>"
				.parse::<AddressPattern>()
				.unwrap()
				.matches(&address("fidonet#4"))
		);
		assert!(
			"<fidonet,fidonet>#*"
				.parse::<AddressPattern>()
				.unwrap()
				.matches(&address("fidonet#1"))
		);
	}

	#[test]
	fn malformed_unicode_wildcard_numbers_are_rejected_without_panicking() {
		for text in ["fidonet#<é>", "fidonet#<é-1>", "fidonet#<1-é>"] {
			assert!(text.parse::<AddressPattern>().is_err(), "{text}");
		}
	}

	#[test]
	fn wildcard_grammar_covers_each_component_and_failure_boundary() {
		let exact_domain: AddressPattern = "fidonet#1:*".parse().unwrap();
		assert!(exact_domain.matches(&address("fidonet#1:2/3.4")));
		assert!(!exact_domain.matches(&address("other#1:2/3.4")));

		let point: AddressPattern = "fidonet#1:2/3.*".parse().unwrap();
		assert!(point.matches(&address("fidonet#1:2/3.4")));
		assert!(!point.matches(&address("fidonet#3:2/3.4")));
		assert!(!point.matches(&address("fidonet#1:3/3.4")));
		assert!(!point.matches(&address("fidonet#1:2/4.4")));

		let zones: AddressPattern = "<fidonet,other>#<1-3,5>:2/3.4".parse().unwrap();
		assert!(zones.matches(&address("other#3:2/3.4")));
		assert!(!zones.matches(&address("another#3:2/3.4")));
		assert!(!zones.matches(&address("other#4:2/3.4")));

		for text in [
			"fidonet",
			"fidonet#1",
			"bad*domain#*",
			"<fidonet,>#*",
			"fidonet#x:*",
			"fidonet#32768:*",
			"fidonet#<3-1>",
			"fidonet#<1-32768>",
			"fidonet#*:*/3#1",
			"fidonet#*#1",
			"fidonet#1:2/3.<-1>",
		] {
			assert!(text.parse::<AddressPattern>().is_err(), "{text}");
		}
	}
}
