//! TTS-5000 nodelist parsing and lookup.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::PublicKey;
use tith_wire::address::{Address, AddressError};
use tith_wire::bundle::KeyResolver;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Keyword {
	Normal,
	Private,
	Hold,
	Down,
	Zone,
	Region,
	Host,
	Hub,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
	pub server: Option<String>,
	pub port: EndpointPort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPort {
	RegisteredDefault,
	Explicit(u16),
}

pub const REGISTERED_TITH_PORT: Option<u16> = None;

impl Endpoint {
	#[must_use]
	pub fn resolved_port(&self) -> Option<u16> {
		match self.port {
			EndpointPort::RegisteredDefault => REGISTERED_TITH_PORT,
			EndpointPort::Explicit(port) => Some(port),
		}
	}

	#[must_use]
	pub fn is_usable(&self) -> bool {
		self.server.is_some() && self.resolved_port().is_some()
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TithService {
	pub endpoints: Vec<Endpoint>,
	pub public_key: PublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Branch {
	pub zone: Address,
	pub region: Option<Address>,
	pub host: Option<Address>,
	pub hub: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
	pub keyword: Keyword,
	pub address: Address,
	pub node_name: String,
	pub location: String,
	pub sysop_name: String,
	pub phone: String,
	pub system_flags: Vec<String>,
	pub pstn_isdn_flags: Vec<String>,
	pub internet_flags: Vec<String>,
	pub email_flags: Vec<String>,
	pub other_flags: Vec<String>,
	pub tith: Option<TithService>,
	pub branch: Branch,
}

#[derive(Debug)]
pub enum NodelistErrorKind {
	MissingFinalLineFeed,
	ControlCharacter,
	WrongFieldCount,
	InvalidKeyword,
	InvalidNodeNumber,
	InvalidHierarchy,
	DuplicateAddress,
	InvalidPhone,
	InvalidFlag,
	InvalidPublicKey,
	InvalidEndpoint,
	Address(AddressError),
}

#[derive(Debug)]
pub struct NodelistError {
	pub line: usize,
	pub kind: NodelistErrorKind,
}

impl fmt::Display for NodelistError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "nodelist line {}: {:?}", self.line, self.kind)
	}
}

impl std::error::Error for NodelistError {}

#[derive(Clone, Debug, Default)]
pub struct Nodelist {
	entries: BTreeMap<Address, Entry>,
}

#[derive(Default)]
struct Hierarchy {
	zone: Option<i32>,
	region: Option<Address>,
	host: Option<Address>,
	hub: Option<Address>,
}

fn fail(line: usize, kind: NodelistErrorKind) -> NodelistError {
	NodelistError { line, kind }
}

fn parse_keyword(value: &str) -> Option<Keyword> {
	match value {
		"" => Some(Keyword::Normal),
		"Pvt" => Some(Keyword::Private),
		"Hold" => Some(Keyword::Hold),
		"Down" => Some(Keyword::Down),
		"Zone" => Some(Keyword::Zone),
		"Region" => Some(Keyword::Region),
		"Host" => Some(Keyword::Host),
		"Hub" => Some(Keyword::Hub),
		_ => None,
	}
}

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

fn flags(value: &str) -> Result<Vec<String>, NodelistErrorKind> {
	if value.is_empty() {
		return Ok(Vec::new());
	}
	let values: Vec<_> = value.split(',').map(str::to_owned).collect();
	if values.iter().any(String::is_empty) {
		Err(NodelistErrorKind::InvalidFlag)
	} else {
		Ok(values)
	}
}

fn parse_port(value: &str) -> Result<u16, NodelistErrorKind> {
	let port: u16 = value
		.parse()
		.map_err(|_| NodelistErrorKind::InvalidEndpoint)?;
	if port == 0 || port.to_string() != value {
		return Err(NodelistErrorKind::InvalidEndpoint);
	}
	Ok(port)
}

fn parse_server(value: &str) -> Result<String, NodelistErrorKind> {
	if let Some(address) = value
		.strip_prefix('[')
		.and_then(|value| value.strip_suffix(']'))
	{
		address
			.parse::<Ipv6Addr>()
			.map_err(|_| NodelistErrorKind::InvalidEndpoint)?;
	} else if value.parse::<Ipv4Addr>().is_err() && !valid_dns_name(value) {
		return Err(NodelistErrorKind::InvalidEndpoint);
	}
	Ok(value.to_owned())
}

fn valid_dns_name(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 253
		&& value.split('.').all(|label| {
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
		})
}

fn parse_endpoint(
	value: &str,
	default_server: Option<&str>,
) -> Result<Endpoint, NodelistErrorKind> {
	let (server, port) = if value.is_empty() {
		(None, EndpointPort::RegisteredDefault)
	} else if value.starts_with('[') {
		let close = value.find(']').ok_or(NodelistErrorKind::InvalidEndpoint)?;
		let server = parse_server(&value[..=close])?;
		let suffix = &value[close + 1..];
		let port = if suffix.is_empty() {
			EndpointPort::RegisteredDefault
		} else {
			EndpointPort::Explicit(parse_port(
				suffix
					.strip_prefix(':')
					.ok_or(NodelistErrorKind::InvalidEndpoint)?,
			)?)
		};
		(Some(server), port)
	} else if let Some((server, port)) = value.rsplit_once(':') {
		let server = if server.is_empty() {
			None
		} else {
			Some(parse_server(server)?)
		};
		(server, EndpointPort::Explicit(parse_port(port)?))
	} else {
		(Some(parse_server(value)?), EndpointPort::RegisteredDefault)
	};
	let server = match (server, default_server) {
		(Some(server), _) => Some(server),
		(None, Some(server)) => Some(parse_server(server)?),
		(None, None) => None,
	};
	Ok(Endpoint { server, port })
}

fn parse_iih(
	flag: &str,
	default_server: Option<&str>,
) -> Result<(Endpoint, PublicKey), NodelistErrorKind> {
	let value = flag
		.strip_prefix("IIH:")
		.ok_or(NodelistErrorKind::InvalidFlag)?;
	let (endpoint, key_text) = value.rsplit_once(':').unwrap_or(("", value));
	if key_text.len() != 43 || key_text.contains('=') {
		return Err(NodelistErrorKind::InvalidPublicKey);
	}
	let key: [u8; 32] = STANDARD_NO_PAD
		.decode(key_text)
		.map_err(|_| NodelistErrorKind::InvalidPublicKey)?
		.try_into()
		.map_err(|_| NodelistErrorKind::InvalidPublicKey)?;
	Ok((
		parse_endpoint(endpoint, default_server)?,
		PublicKey::from_bytes(key),
	))
}

fn validate_phone(phone: &str) -> bool {
	if phone.is_empty() {
		return true;
	}
	let pieces: Vec<_> = phone.split('-').collect();
	pieces.len() >= 2
		&& pieces
			.iter()
			.all(|piece| !piece.is_empty() && piece.bytes().all(|byte| byte.is_ascii_digit()))
}

impl Nodelist {
	pub fn parse(domain: &str, input: &str) -> Result<Self, NodelistError> {
		// Validate the domain independently before line-numbered processing.
		Address::new(domain.to_owned(), 1, 1, 0, 0)
			.map_err(|error| fail(0, NodelistErrorKind::Address(error)))?;
		if !input.is_empty() && !input.ends_with('\n') {
			return Err(fail(
				1 + input.bytes().filter(|byte| *byte == b'\n').count(),
				NodelistErrorKind::MissingFinalLineFeed,
			));
		}
		let mut entries = BTreeMap::new();
		let mut hierarchy = Hierarchy::default();
		for (line_index, raw_line) in input.split_terminator('\n').enumerate() {
			let line_number = line_index + 1;
			if raw_line.chars().any(|character| {
				(character.is_control() && character != '\t') || character == '\u{7f}'
			}) {
				return Err(fail(line_number, NodelistErrorKind::ControlCharacter));
			}
			if let Some(comment) = raw_line.strip_prefix(';') {
				let _interest_flags = comment
					.chars()
					.take_while(|character| character.is_alphabetic())
					.count();
				continue;
			}
			let fields: Vec<_> = raw_line.split('\t').collect();
			if fields.len() != 11 {
				return Err(fail(line_number, NodelistErrorKind::WrongFieldCount));
			}
			let keyword = parse_keyword(fields[0])
				.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidKeyword))?;
			let number = parse_node_number(fields[1])
				.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidNodeNumber))?;
			let address = match keyword {
				Keyword::Zone => {
					hierarchy.zone = Some(number);
					hierarchy.region = None;
					hierarchy.host = None;
					hierarchy.hub = None;
					Address::new(domain.to_owned(), number, number, 0, 0)
				}
				Keyword::Region => {
					let zone = hierarchy
						.zone
						.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidHierarchy))?;
					hierarchy.host = None;
					hierarchy.hub = None;
					let address = Address::new(domain.to_owned(), zone, number, 0, 0);
					hierarchy.region = address.as_ref().ok().cloned();
					address
				}
				Keyword::Host => {
					let zone = hierarchy
						.zone
						.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidHierarchy))?;
					hierarchy.hub = None;
					let address = Address::new(domain.to_owned(), zone, number, 0, 0);
					hierarchy.host = address.as_ref().ok().cloned();
					address
				}
				Keyword::Hub
				| Keyword::Normal
				| Keyword::Private
				| Keyword::Hold
				| Keyword::Down => {
					let zone = hierarchy
						.zone
						.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidHierarchy))?;
					let net = hierarchy.host.as_ref().map_or(zone, Address::net);
					if hierarchy.host.is_none()
						&& hierarchy.region.is_none()
						&& !matches!(keyword, Keyword::Hub)
					{
						// Zone-independent members are valid, so the active Zone itself
						// supplies the branch. The condition is intentionally documentary.
					}
					let address = Address::new(domain.to_owned(), zone, net, number, 0);
					if keyword == Keyword::Hub {
						hierarchy.hub = address.as_ref().ok().cloned();
					}
					address
				}
			}
			.map_err(|error| fail(line_number, NodelistErrorKind::Address(error)))?;
			if entries.contains_key(&address) {
				return Err(fail(line_number, NodelistErrorKind::DuplicateAddress));
			}
			if keyword == Keyword::Private && hierarchy.host.is_none() {
				return Err(fail(line_number, NodelistErrorKind::InvalidHierarchy));
			}
			if !validate_phone(fields[5]) {
				return Err(fail(line_number, NodelistErrorKind::InvalidPhone));
			}
			let system_flags = flags(fields[6]).map_err(|kind| fail(line_number, kind))?;
			let pstn_isdn_flags = flags(fields[7]).map_err(|kind| fail(line_number, kind))?;
			let internet_flags = flags(fields[8]).map_err(|kind| fail(line_number, kind))?;
			let email_flags = flags(fields[9]).map_err(|kind| fail(line_number, kind))?;
			let other_flags = flags(fields[10]).map_err(|kind| fail(line_number, kind))?;
			if let Some(position) = internet_flags
				.iter()
				.position(|flag| flag.starts_with("INA:"))
				&& position != 0
			{
				return Err(fail(line_number, NodelistErrorKind::InvalidFlag));
			}
			if let Some(position) = email_flags.iter().position(|flag| flag.starts_with("IEM:"))
				&& position != 0
			{
				return Err(fail(line_number, NodelistErrorKind::InvalidFlag));
			}
			let default_server = internet_flags
				.iter()
				.find_map(|flag| flag.strip_prefix("INA:"));
			let services = internet_flags
				.iter()
				.filter(|flag| flag.starts_with("IIH:"))
				.map(|flag| parse_iih(flag, default_server))
				.collect::<Result<Vec<_>, _>>()
				.map_err(|kind| fail(line_number, kind))?;
			let tith = if let Some((_, public_key)) = services.first() {
				if services.iter().any(|(_, key)| key != public_key) {
					return Err(fail(line_number, NodelistErrorKind::InvalidPublicKey));
				}
				Some(TithService {
					endpoints: services
						.iter()
						.map(|(endpoint, _)| endpoint.clone())
						.collect(),
					public_key: *public_key,
				})
			} else {
				None
			};
			let zone_address = Address::new(
				domain.to_owned(),
				hierarchy.zone.expect("a valid data line has a Zone"),
				hierarchy.zone.expect("a valid data line has a Zone"),
				0,
				0,
			)
			.expect("active Zone is valid");
			let entry = Entry {
				keyword,
				address: address.clone(),
				node_name: fields[2].to_owned(),
				location: fields[3].to_owned(),
				sysop_name: fields[4].to_owned(),
				phone: fields[5].to_owned(),
				system_flags,
				pstn_isdn_flags,
				internet_flags,
				email_flags,
				other_flags,
				tith,
				branch: Branch {
					zone: zone_address,
					region: hierarchy.region.clone(),
					host: hierarchy.host.clone(),
					hub: hierarchy.hub.clone(),
				},
			};
			entries.insert(address, entry);
		}
		Ok(Self { entries })
	}

	#[must_use]
	pub fn get(&self, address: &Address) -> Option<&Entry> {
		self.entries.get(address)
	}

	pub fn iter(&self) -> impl Iterator<Item = &Entry> {
		self.entries.values()
	}

	#[must_use]
	pub fn len(&self) -> usize {
		self.entries.len()
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}
}

impl KeyResolver for Nodelist {
	fn public_key(&self, address: &Address) -> Option<PublicKey> {
		self.get(address)?
			.tith
			.as_ref()
			.map(|service| service.public_key)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn line(keyword: &str, number: u16, internet: &str) -> String {
		format!("{keyword}\t{number}\tNode\tLocation\tSysop\t\tCM\t\t{internet}\t\t\n")
	}

	#[test]
	fn parses_hierarchy_and_tith_key() {
		let key = STANDARD_NO_PAD.encode([9; 32]);
		let input = [
			line("Zone", 1, ""),
			line("Region", 10, ""),
			line("Host", 100, ""),
			line("Hub", 20, ""),
			line("", 21, &format!("IIH:mail.example:24554:{key}")),
		]
		.concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1:100/21".parse().unwrap();
		let entry = list.get(&address).unwrap();
		assert_eq!(
			entry.branch.hub.as_ref().unwrap().to_string(),
			"fidonet#1:100/20"
		);
		assert_eq!(
			entry.tith.as_ref().unwrap().endpoints[0].port,
			EndpointPort::Explicit(24_554)
		);
		assert_eq!(
			list.public_key(&address),
			Some(PublicKey::from_bytes([9; 32]))
		);
	}

	#[test]
	fn rejects_missing_newline_and_duplicate_address() {
		assert!(matches!(
			Nodelist::parse("fidonet", "Zone\t1\tx\tx\tx\t\t\t\t\t\t"),
			Err(NodelistError {
				kind: NodelistErrorKind::MissingFinalLineFeed,
				..
			})
		));
		let input = [line("Zone", 1, ""), line("", 2, ""), line("", 2, "")].concat();
		assert!(matches!(
			Nodelist::parse("fidonet", &input),
			Err(NodelistError {
				kind: NodelistErrorKind::DuplicateAddress,
				..
			})
		));
	}

	#[test]
	fn parses_ordered_iih_endpoints_and_inherits_ina() {
		let key = STANDARD_NO_PAD.encode([10; 32]);
		let internet =
			format!("INA:default.example,IIH::1234:{key},IIH:[2001:db8::1]:5678:{key},IIH:{key}");
		let input = [line("Zone", 1, ""), line("", 2, &internet)].concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1/2".parse().unwrap();
		let service = list.get(&address).unwrap().tith.as_ref().unwrap();
		assert_eq!(
			service.endpoints,
			vec![
				Endpoint {
					server: Some("default.example".to_owned()),
					port: EndpointPort::Explicit(1234),
				},
				Endpoint {
					server: Some("[2001:db8::1]".to_owned()),
					port: EndpointPort::Explicit(5678),
				},
				Endpoint {
					server: Some("default.example".to_owned()),
					port: EndpointPort::RegisteredDefault,
				},
			]
		);
		assert!(service.endpoints[0].is_usable());
		assert!(!service.endpoints[2].is_usable());
	}

	#[test]
	fn rejects_unbracketed_ipv6_and_different_iih_keys() {
		let first_key = STANDARD_NO_PAD.encode([11; 32]);
		let second_key = STANDARD_NO_PAD.encode([12; 32]);
		let invalid_ipv6 = [
			line("Zone", 1, ""),
			line("", 2, &format!("IIH:2001:db8::1:1234:{first_key}")),
		]
		.concat();
		assert!(matches!(
			Nodelist::parse("fidonet", &invalid_ipv6),
			Err(NodelistError {
				kind: NodelistErrorKind::InvalidEndpoint,
				..
			})
		));

		let different_keys = [
			line("Zone", 1, ""),
			line(
				"",
				2,
				&format!("IIH:a.example:1234:{first_key},IIH:b.example:1234:{second_key}"),
			),
		]
		.concat();
		assert!(matches!(
			Nodelist::parse("fidonet", &different_keys),
			Err(NodelistError {
				kind: NodelistErrorKind::InvalidPublicKey,
				..
			})
		));
	}
}
