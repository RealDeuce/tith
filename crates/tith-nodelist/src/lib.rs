//! TTS-5000 nodelist parsing and TTS-5001 flag handling.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use tith_crypto::PublicKey;
use tith_wire::address::{Address, AddressError};
use tith_wire::bundle::KeyResolver;

mod flags;

pub use flags::{
	EmailAddress, EmailFlag, EndpointSpec, FileRequestFlag, HalfHour, InternetFlag, MailPeriod,
	OnlinePeriod, OtherFlag, PstnIsdnFlag, ServerAddress, SystemFlag,
};
use flags::{parse_email, parse_internet, parse_other, parse_pstn_isdn, parse_system};

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
	pub system_flags: Vec<SystemFlag>,
	pub pstn_isdn_flags: Vec<PstnIsdnFlag>,
	pub internet_flags: Vec<InternetFlag>,
	pub email_flags: Vec<EmailFlag>,
	pub other_flags: Vec<OtherFlag>,
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
	PrivateContact,
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

fn publishes_internet_contact(flag: &InternetFlag) -> bool {
	match flag {
		InternetFlag::DefaultServer(_) => true,
		InternetFlag::Tith { endpoint, .. }
		| InternetFlag::Binkp(endpoint)
		| InternetFlag::Ifcico(endpoint)
		| InternetFlag::Ftp(endpoint)
		| InternetFlag::Telnet(endpoint)
		| InternetFlag::Vmodem(endpoint)
		| InternetFlag::Unspecified(endpoint) => endpoint.server.is_some() || endpoint.port.is_some(),
		InternetFlag::NoIncomingIpv4 => false,
	}
}

fn publishes_email_contact(flag: &EmailFlag) -> bool {
	match flag {
		EmailFlag::Default(address)
		| EmailFlag::Transx(address)
		| EmailFlag::Uuencode(address)
		| EmailFlag::Mime(address)
		| EmailFlag::Seat(address)
		| EmailFlag::Voyager(address)
		| EmailFlag::OtherMethod(address) => address.is_some(),
	}
}

fn validate_phone(phone: &str) -> bool {
	if phone.is_empty() {
		return true;
	}
	if !(3..=29).contains(&phone.len()) {
		return false;
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
		let mut zones_with_zec = std::collections::BTreeSet::new();
		let mut regions_with_rec = std::collections::BTreeSet::new();
		let mut regions_with_rpk = std::collections::BTreeSet::new();
		let mut echomail_coordinator_nets = std::collections::BTreeSet::new();
		let mut pointlist_keeper_nets = std::collections::BTreeSet::new();
		let mut coordinator_override_nets = std::collections::BTreeSet::new();
		for (line_index, raw_line) in input.split_terminator('\n').enumerate() {
			let line_number = line_index + 1;
			if raw_line.chars().any(|character| {
				(character <= '\u{1f}' && character != '\t') || character == '\u{7f}'
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
					let net = hierarchy
						.host
						.as_ref()
						.or(hierarchy.region.as_ref())
						.map_or(zone, Address::net);
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
			let system_flags = parse_system(fields[6]).map_err(|kind| fail(line_number, kind))?;
			let pstn_isdn_flags =
				parse_pstn_isdn(fields[7]).map_err(|kind| fail(line_number, kind))?;
			let internet_flags =
				parse_internet(fields[8]).map_err(|kind| fail(line_number, kind))?;
			let email_flags = parse_email(fields[9]).map_err(|kind| fail(line_number, kind))?;
			let other_flags = parse_other(fields[10]).map_err(|kind| fail(line_number, kind))?;
			if keyword == Keyword::Private
				&& (!fields[5].is_empty()
					|| internet_flags.iter().any(publishes_internet_contact)
					|| email_flags.iter().any(publishes_email_contact))
			{
				return Err(fail(line_number, NodelistErrorKind::PrivateContact));
			}

			let file_request_count = system_flags
				.iter()
				.filter(|flag| matches!(flag, SystemFlag::FileRequest(_)))
				.count();
			let has_cm = system_flags.contains(&SystemFlag::ContinuousMail);
			if file_request_count > 1
				|| has_cm
					&& system_flags.iter().any(|flag| {
						matches!(
							flag,
							SystemFlag::InternetContinuousMail
								| SystemFlag::MailPeriod(_)
								| SystemFlag::OnlinePeriod(_)
						)
					}) {
				return Err(fail(line_number, NodelistErrorKind::InvalidFlag));
			}

			let zone = hierarchy.zone.expect("a valid data line has a Zone");
			let region = hierarchy.region.as_ref().map(Address::net);
			let net = address.net();
			for flag in &other_flags {
				let valid = match flag {
					OtherFlag::ZoneEchomailCoordinator => zones_with_zec.insert(zone),
					OtherFlag::RegionalEchomailCoordinator => {
						region.is_some_and(|region| regions_with_rec.insert((zone, region)))
					}
					OtherFlag::RegionalPointlistKeeper => {
						region.is_some_and(|region| regions_with_rpk.insert((zone, region)))
					}
					OtherFlag::NetworkEchomailCoordinator => {
						echomail_coordinator_nets.insert((zone, net))
					}
					OtherFlag::NetPointlistKeeper => pointlist_keeper_nets.insert((zone, net)),
					OtherFlag::NetworkCoordinator => {
						!matches!(keyword, Keyword::Zone | Keyword::Region | Keyword::Host)
							&& coordinator_override_nets.insert((zone, net))
					}
					_ => true,
				};
				if !valid {
					return Err(fail(line_number, NodelistErrorKind::InvalidFlag));
				}
			}

			let default_servers: Vec<_> = internet_flags
				.iter()
				.filter_map(|flag| match flag {
					InternetFlag::DefaultServer(server) => Some(server.as_str().to_owned()),
					_ => None,
				})
				.collect();
			let mut services = Vec::new();
			for flag in &internet_flags {
				let InternetFlag::Tith {
					endpoint,
					public_key,
				} = flag
				else {
					continue;
				};
				let port = endpoint
					.port
					.map_or(EndpointPort::RegisteredDefault, EndpointPort::Explicit);
				if let Some(server) = &endpoint.server {
					services.push((
						Endpoint {
							server: Some(server.as_str().to_owned()),
							port,
						},
						*public_key,
					));
				} else if default_servers.is_empty() {
					services.push((Endpoint { server: None, port }, *public_key));
				} else {
					services.extend(default_servers.iter().map(|server| {
						(
							Endpoint {
								server: Some(server.clone()),
								port,
							},
							*public_key,
						)
					}));
				}
			}
			let tith = if let Some((_, public_key)) = services.first() {
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
	use base64::Engine as _;
	use base64::engine::general_purpose::STANDARD_NO_PAD;

	fn line(keyword: &str, number: u16, internet: &str) -> String {
		format!("{keyword}\t{number}\tNode\tLocation\tSysop\t\tCM\t\t{internet}\t\t\n")
	}

	fn flagged_line(keyword: &str, number: u16, system: &str, other: &str) -> String {
		format!("{keyword}\t{number}\tNode\tLocation\tSysop\t\t{system}\t\t\t\t{other}\n")
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
	fn addresses_region_independent_nodes_in_the_regions_logical_net() {
		let input = [
			line("Zone", 1, ""),
			line("Region", 10, ""),
			line("", 21, ""),
		]
		.concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1:10/21".parse().unwrap();
		let entry = list
			.get(&address)
			.expect("Region Independent Node uses the Region's logical net");
		assert_eq!(entry.branch.region.as_ref().unwrap().net(), 10);
		assert!(list.get(&"fidonet#1/21".parse().unwrap()).is_none());
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
	fn node_numbers_use_the_canonical_decimal_spelling() {
		for value in ["1", "9", "10", "32767"] {
			assert!(parse_node_number(value).is_some(), "{value}");
		}
		for value in ["", "-1", "0", "00", "01", "+1", " 1", "1 ", "32768", "１"] {
			assert!(parse_node_number(value).is_none(), "{value}");
		}
	}

	#[test]
	fn phone_numbers_have_the_documented_grammar_and_bound() {
		let longest = format!("1-{}", "2".repeat(27));
		let too_long = format!("1-{}", "2".repeat(28));
		for value in ["", "1-1", "1-800-555-0100", &longest] {
			assert!(validate_phone(value), "{value}");
		}
		for value in ["1", "-1", "1-", "1--2", "1 2", "1-٢", &too_long] {
			assert!(!validate_phone(value), "{value}");
		}
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
	fn expands_each_default_server_without_losing_preference_order() {
		let key = STANDARD_NO_PAD.encode([15; 32]);
		let internet = format!("INA:first.example,INA:second.example,IIH::24555:{key}");
		let input = [line("Zone", 1, ""), line("", 2, &internet)].concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let service = list
			.get(&"fidonet#1/2".parse().unwrap())
			.unwrap()
			.tith
			.as_ref()
			.unwrap();
		assert_eq!(
			service.endpoints,
			[
				Endpoint {
					server: Some("first.example".to_owned()),
					port: EndpointPort::Explicit(24_555),
				},
				Endpoint {
					server: Some("second.example".to_owned()),
					port: EndpointPort::Explicit(24_555),
				},
			]
		);
	}

	#[test]
	fn enforces_nodelist_specific_flag_relationships() {
		for system in ["CM,ICM", "CM,#02", "CM,TAB", "XA,XB"] {
			let input = [
				flagged_line("Zone", 1, "", ""),
				flagged_line("", 2, system, ""),
			]
			.concat();
			assert!(
				matches!(
					Nodelist::parse("fidonet", &input),
					Err(NodelistError {
						kind: NodelistErrorKind::InvalidFlag,
						..
					})
				),
				"{system}"
			);
		}
	}

	#[test]
	fn enforces_coordinator_scope_and_cardinality() {
		let duplicate_zec = [
			flagged_line("Zone", 1, "", "ZEC"),
			flagged_line("", 2, "", "ZEC"),
		]
		.concat();
		assert!(Nodelist::parse("fidonet", &duplicate_zec).is_err());

		let rec_outside_region = flagged_line("Zone", 1, "", "REC");
		assert!(Nodelist::parse("fidonet", &rec_outside_region).is_err());

		let nc_on_host = [
			flagged_line("Zone", 1, "", ""),
			flagged_line("Host", 10, "", "NC"),
		]
		.concat();
		assert!(Nodelist::parse("fidonet", &nc_on_host).is_err());

		let valid = [
			flagged_line("Zone", 1, "", "ZEC"),
			flagged_line("Region", 2, "", "REC,RPK"),
			flagged_line("Host", 10, "", "NEC,NPK"),
			flagged_line("", 20, "", "NC"),
		]
		.concat();
		assert!(Nodelist::parse("fidonet", &valid).is_ok());
	}

	#[test]
	fn rejects_a_private_entry_which_publishes_contact_information() {
		let key = STANDARD_NO_PAD.encode([13; 32]);
		let prefix = [line("Zone", 1, ""), line("Host", 10, "")].concat();
		for field_9 in [
			"INA:example.org",
			"IBN:example.org:24554",
			&format!("IIH:example.org:24555:{key}"),
			&format!("IIH::24555:{key}"),
		] {
			let input = format!("{prefix}Pvt\t20\tNode\tLocation\tSysop\t\tCM\t\t{field_9}\t\t\n");
			assert!(
				matches!(
					Nodelist::parse("fidonet", &input),
					Err(NodelistError {
						kind: NodelistErrorKind::PrivateContact,
						line: 3,
					})
				),
				"field 9 {field_9}"
			);
		}

		// Field 10 and the phone number are the same rule.
		let with_email =
			format!("{prefix}Pvt\t20\tNode\tLocation\tSysop\t\t\t\t\tIEM:sysop@example.org\t\n");
		let with_phone =
			format!("{prefix}Pvt\t20\tNode\tLocation\tSysop\t1-616-555-0100\t\t\t\t\t\n");
		for input in [with_email, with_phone] {
			assert!(matches!(
				Nodelist::parse("fidonet", &input),
				Err(NodelistError {
					kind: NodelistErrorKind::PrivateContact,
					..
				})
			));
		}
	}

	#[test]
	fn accepts_a_private_entry_carrying_only_an_endpointless_iih_key() {
		// TTS-5000 section 5.2 field 1 excepts this form, so a Private node is
		// still authenticated from its own nodelist key.
		let key = STANDARD_NO_PAD.encode([14; 32]);
		let input = [
			line("Zone", 1, ""),
			line("Host", 10, ""),
			format!("Pvt\t20\tNode\tLocation\tSysop\t\tCM\t\tIIH:{key},IBN\t\t\n"),
		]
		.concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1:10/20".parse().unwrap();
		let entry = list.get(&address).unwrap();
		assert_eq!(entry.keyword, Keyword::Private);
		assert_eq!(
			list.public_key(&address),
			Some(PublicKey::from_bytes([14; 32]))
		);
		// The key is published, but it supplies no endpoint to contact.
		let service = entry.tith.as_ref().unwrap();
		assert!(!service.endpoints[0].is_usable());
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
