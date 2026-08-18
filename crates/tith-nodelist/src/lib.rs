//! TTS-5000 nodelist parsing and lookup.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

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
	pub port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TithService {
	pub endpoint: Endpoint,
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

fn parse_iih(flag: &str) -> Result<TithService, NodelistErrorKind> {
	let fields: Vec<_> = flag.split(':').collect();
	if fields.first() != Some(&"IIH") || !(2..=4).contains(&fields.len()) {
		return Err(NodelistErrorKind::InvalidFlag);
	}
	let key_text = fields.last().expect("length was checked");
	if key_text.len() != 43 || key_text.contains('=') {
		return Err(NodelistErrorKind::InvalidPublicKey);
	}
	let key: [u8; 32] = STANDARD_NO_PAD
		.decode(key_text)
		.map_err(|_| NodelistErrorKind::InvalidPublicKey)?
		.try_into()
		.map_err(|_| NodelistErrorKind::InvalidPublicKey)?;
	let (server, port) = match fields.as_slice() {
		[_, _] => (None, None),
		[_, server, _] if !server.is_empty() => (Some((*server).to_owned()), None),
		[_, server, port_text, _] if !server.is_empty() => {
			let port: u16 = port_text
				.parse()
				.map_err(|_| NodelistErrorKind::InvalidEndpoint)?;
			if port == 0 || port.to_string() != *port_text {
				return Err(NodelistErrorKind::InvalidEndpoint);
			}
			(Some((*server).to_owned()), Some(port))
		}
		_ => return Err(NodelistErrorKind::InvalidEndpoint),
	};
	Ok(TithService {
		endpoint: Endpoint { server, port },
		public_key: PublicKey::from_bytes(key),
	})
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
			let mut services = internet_flags
				.iter()
				.filter(|flag| flag.starts_with("IIH:"));
			let tith = services
				.next()
				.map(|flag| parse_iih(flag))
				.transpose()
				.map_err(|kind| fail(line_number, kind))?;
			if services.next().is_some() {
				return Err(fail(line_number, NodelistErrorKind::InvalidFlag));
			}
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
		assert_eq!(entry.tith.as_ref().unwrap().endpoint.port, Some(24_554));
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
}
