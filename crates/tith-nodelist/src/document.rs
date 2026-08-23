//! Streaming TTS-5000 records, hierarchy validation, and publication framing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufRead, Read, Write};

use tith_crypto::PublicKey;
use tith_wire::address::{Address, AddressError};
use tith_wire::bundle::KeyResolver;

use crate::{
	EmailFlag, EmailFlags, InternetFlags, InternetProtocol, OtherFlag, OtherFlags, PstnIsdnFlags,
	SystemFlag, SystemFlags,
};

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
	pub system_flags: SystemFlags,
	pub pstn_isdn_flags: PstnIsdnFlags,
	pub internet_flags: InternetFlags,
	pub email_flags: EmailFlags,
	pub other_flags: OtherFlags,
	pub tith: Option<TithService>,
	pub branch: Branch,
}

#[derive(Debug)]
pub enum NodelistErrorKind {
	Io,
	InvalidUtf8,
	MissingFinalLineFeed,
	ControlCharacter,
	InvalidComment,
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
	InvalidPublication,
	ApplicationKeyMismatch,
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

pub(crate) fn parse_node_number(value: &str) -> Option<i32> {
	if value.is_empty()
		|| value.starts_with('0')
		|| !value.bytes().all(|byte| byte.is_ascii_digit())
	{
		return None;
	}
	let number: i32 = value.parse().ok()?;
	(1..=32_767).contains(&number).then_some(number)
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

pub(crate) fn validate_phone(phone: &str) -> bool {
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
		Self::read(domain, std::io::Cursor::new(input.as_bytes()))
	}

	pub fn read<R: BufRead>(domain: &str, reader: R) -> Result<Self, NodelistError> {
		let mut entries = BTreeMap::new();
		for record in NodelistReader::distribution(domain.to_owned(), reader)? {
			insert_record(&mut entries, record?);
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

fn insert_record(entries: &mut BTreeMap<Address, Entry>, record: Record) {
	if let Record::Entry(entry) = record {
		entries.insert(entry.address.clone(), *entry);
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

/// One parsed nodelist record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record {
	Comment(Comment),
	Entry(Box<Entry>),
}

/// One comment's exact interest prefix and uninterpreted remainder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comment {
	pub interests: String,
	pub text: String,
}

/// The externally supplied hierarchy omitted by the first segment record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentContext {
	domain: String,
	initial: InitialContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InitialContext {
	Zone,
	WithinZone { zone: i32 },
	WithinLocalNet { zone: i32, net: i32 },
}

impl SegmentContext {
	/// A segment whose first data record is a Zone.
	pub fn zone(domain: impl Into<String>) -> Result<Self, NodelistError> {
		Self::validated(domain.into(), InitialContext::Zone)
	}

	/// A Region or Host segment within `zone`.
	pub fn within_zone(domain: impl Into<String>, zone: i32) -> Result<Self, NodelistError> {
		Self::validated(domain.into(), InitialContext::WithinZone { zone })
	}

	/// A Hub segment within the supplied local net.
	pub fn within_local_net(
		domain: impl Into<String>,
		zone: i32,
		net: i32,
	) -> Result<Self, NodelistError> {
		Self::validated(domain.into(), InitialContext::WithinLocalNet { zone, net })
	}

	fn validated(domain: String, initial: InitialContext) -> Result<Self, NodelistError> {
		let (zone, net) = match initial {
			InitialContext::Zone => (1, 1),
			InitialContext::WithinZone { zone } => (zone, zone),
			InitialContext::WithinLocalNet { zone, net } => (zone, net),
		};
		Address::new(domain.clone(), zone, net, 0, 0)
			.map_err(|error| fail(0, NodelistErrorKind::Address(error)))?;
		Ok(Self { domain, initial })
	}
}

#[derive(Default)]
struct Hierarchy {
	zone: Option<i32>,
	region: Option<Address>,
	host: Option<Address>,
	hub: Option<Address>,
}

struct Validator {
	domain: String,
	initial: InitialContext,
	requires_data: bool,
	first_data: bool,
	hierarchy: Hierarchy,
	addresses: BTreeSet<Address>,
	zones_with_zec: BTreeSet<i32>,
	regions_with_rec: BTreeSet<(i32, i32)>,
	regions_with_rpk: BTreeSet<(i32, i32)>,
	echomail_coordinator_nets: BTreeSet<(i32, i32)>,
	pointlist_keeper_nets: BTreeSet<(i32, i32)>,
	coordinator_override_nets: BTreeSet<(i32, i32)>,
}

impl Validator {
	fn distribution(domain: String) -> Result<Self, NodelistError> {
		Ok(Self::new(SegmentContext::zone(domain)?, false))
	}

	fn new(context: SegmentContext, requires_data: bool) -> Self {
		let mut hierarchy = Hierarchy::default();
		match context.initial {
			InitialContext::Zone => {}
			InitialContext::WithinZone { zone } => hierarchy.zone = Some(zone),
			InitialContext::WithinLocalNet { zone, net } => {
				hierarchy.zone = Some(zone);
				hierarchy.host = Some(
					Address::new(context.domain.clone(), zone, net, 0, 0).expect(
						"SegmentContext validates the supplied domain, zone, and local net",
					),
				);
			}
		}
		Self {
			domain: context.domain,
			initial: context.initial,
			requires_data,
			first_data: true,
			hierarchy,
			addresses: BTreeSet::new(),
			zones_with_zec: BTreeSet::new(),
			regions_with_rec: BTreeSet::new(),
			regions_with_rpk: BTreeSet::new(),
			echomail_coordinator_nets: BTreeSet::new(),
			pointlist_keeper_nets: BTreeSet::new(),
			coordinator_override_nets: BTreeSet::new(),
		}
	}

	fn parse_line(&mut self, line_number: usize, raw_line: &str) -> Result<Record, NodelistError> {
		if let Some(remainder) = raw_line.strip_prefix(';') {
			if raw_line.chars().any(prohibited_character) {
				return Err(fail(line_number, NodelistErrorKind::ControlCharacter));
			}
			let interest_len = remainder
				.bytes()
				.take_while(u8::is_ascii_alphabetic)
				.count();
			return Ok(Record::Comment(Comment {
				interests: remainder[..interest_len].to_owned(),
				text: remainder[interest_len..].to_owned(),
			}));
		}
		self.parse_data_line(line_number, raw_line)
			.map(|entry| Record::Entry(Box::new(entry)))
	}

	fn parse_data_line(
		&mut self,
		line_number: usize,
		raw_line: &str,
	) -> Result<Entry, NodelistError> {
		if raw_line
			.chars()
			.any(|character| prohibited_character(character) && character != '\t')
		{
			return Err(fail(line_number, NodelistErrorKind::ControlCharacter));
		}

		let fields: Vec<_> = raw_line.split('\t').collect();
		if fields.len() != 11 {
			return Err(fail(line_number, NodelistErrorKind::WrongFieldCount));
		}
		let keyword = parse_keyword(fields[0])
			.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidKeyword))?;
		if self.first_data {
			let valid = match self.initial {
				InitialContext::Zone => keyword == Keyword::Zone,
				InitialContext::WithinZone { .. } => {
					matches!(keyword, Keyword::Region | Keyword::Host)
				}
				InitialContext::WithinLocalNet { .. } => keyword == Keyword::Hub,
			};
			if !valid {
				return Err(fail(line_number, NodelistErrorKind::InvalidHierarchy));
			}
			self.first_data = false;
		}

		let number = parse_node_number(fields[1])
			.ok_or_else(|| fail(line_number, NodelistErrorKind::InvalidNodeNumber))?;
		let address = self.address_for(line_number, keyword, number)?;
		if !self.addresses.insert(address.clone()) {
			return Err(fail(line_number, NodelistErrorKind::DuplicateAddress));
		}
		if keyword == Keyword::Private && self.hierarchy.host.is_none() {
			return Err(fail(line_number, NodelistErrorKind::InvalidHierarchy));
		}
		if !validate_phone(fields[5]) {
			return Err(fail(line_number, NodelistErrorKind::InvalidPhone));
		}

		let system_flags: SystemFlags =
			fields[6].parse().map_err(|kind| fail(line_number, kind))?;
		let pstn_isdn_flags: PstnIsdnFlags =
			fields[7].parse().map_err(|kind| fail(line_number, kind))?;
		let internet_flags: InternetFlags =
			fields[8].parse().map_err(|kind| fail(line_number, kind))?;
		let email_flags: EmailFlags = fields[9].parse().map_err(|kind| fail(line_number, kind))?;
		let other_flags: OtherFlags = fields[10].parse().map_err(|kind| fail(line_number, kind))?;

		let usable_contact = !fields[5].is_empty()
			|| internet_flags
				.resolved_services()
				.iter()
				.flat_map(|service| &service.endpoints)
				.any(crate::ResolvedInternetEndpoint::is_usable)
			|| email_flags.iter().any(publishes_email_contact);
		if matches!(keyword, Keyword::Normal | Keyword::Private)
			&& (keyword == Keyword::Private) == usable_contact
		{
			return Err(fail(line_number, NodelistErrorKind::PrivateContact));
		}

		self.validate_flags(line_number, keyword, &address, &system_flags, &other_flags)?;
		let services: Vec<_> = internet_flags
			.resolved_services()
			.into_iter()
			.filter(|service| service.protocol == InternetProtocol::Tith)
			.collect();
		let tith = services.first().map(|service| TithService {
			endpoints: services
				.iter()
				.flat_map(|service| &service.endpoints)
				.map(|endpoint| Endpoint {
					server: endpoint.server.as_ref().map(ToString::to_string),
					port: endpoint
						.port
						.map_or(EndpointPort::RegisteredDefault, EndpointPort::Explicit),
				})
				.collect(),
			public_key: service
				.public_key
				.expect("a TITH service has one public key"),
		});
		let zone = self
			.hierarchy
			.zone
			.expect("a data record has an active Zone");
		let zone_address = Address::new(self.domain.clone(), zone, zone, 0, 0)
			.expect("validated hierarchy values remain valid");
		Ok(Entry {
			keyword,
			address,
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
				region: self.hierarchy.region.clone(),
				host: self.hierarchy.host.clone(),
				hub: self.hierarchy.hub.clone(),
			},
		})
	}

	fn address_for(
		&mut self,
		line: usize,
		keyword: Keyword,
		number: i32,
	) -> Result<Address, NodelistError> {
		let result = match keyword {
			Keyword::Zone => {
				self.hierarchy.zone = Some(number);
				self.hierarchy.region = None;
				self.hierarchy.host = None;
				self.hierarchy.hub = None;
				Address::new(self.domain.clone(), number, number, 0, 0)
					.expect("a canonical nodelist node number is a valid Zone")
			}
			Keyword::Region => {
				let zone = self
					.hierarchy
					.zone
					.expect("a Region follows an active Zone");
				self.hierarchy.host = None;
				self.hierarchy.hub = None;
				let address = Address::new(self.domain.clone(), zone, number, 0, 0)
					.expect("validated hierarchy values remain valid");
				self.hierarchy.region = Some(address.clone());
				address
			}
			Keyword::Host => {
				let zone = self.hierarchy.zone.expect("a Host follows an active Zone");
				self.hierarchy.hub = None;
				let address = Address::new(self.domain.clone(), zone, number, 0, 0)
					.expect("validated hierarchy values remain valid");
				self.hierarchy.host = Some(address.clone());
				address
			}
			Keyword::Hub => {
				let host = self
					.hierarchy
					.host
					.as_ref()
					.ok_or_else(|| fail(line, NodelistErrorKind::InvalidHierarchy))?;
				let address = Address::new(self.domain.clone(), host.zone(), host.net(), number, 0)
					.expect("validated hierarchy values remain valid");
				self.hierarchy.hub = Some(address.clone());
				address
			}
			Keyword::Normal | Keyword::Private | Keyword::Hold | Keyword::Down => {
				let zone = self
					.hierarchy
					.zone
					.expect("a member record follows an active Zone");
				let net = self
					.hierarchy
					.host
					.as_ref()
					.or(self.hierarchy.region.as_ref())
					.map_or(zone, Address::net);
				Address::new(self.domain.clone(), zone, net, number, 0)
					.expect("validated hierarchy values remain valid")
			}
		};
		Ok(result)
	}

	fn validate_flags(
		&mut self,
		line: usize,
		keyword: Keyword,
		address: &Address,
		system_flags: &SystemFlags,
		other_flags: &OtherFlags,
	) -> Result<(), NodelistError> {
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
			return Err(fail(line, NodelistErrorKind::InvalidFlag));
		}
		let zone = self
			.hierarchy
			.zone
			.expect("a data record has an active Zone");
		let region = self.hierarchy.region.as_ref().map(Address::net);
		let net = address.net();
		for flag in other_flags {
			let valid = match flag {
				OtherFlag::ZoneEchomailCoordinator => self.zones_with_zec.insert(zone),
				OtherFlag::RegionalEchomailCoordinator => {
					region.is_some_and(|region| self.regions_with_rec.insert((zone, region)))
				}
				OtherFlag::RegionalPointlistKeeper => {
					region.is_some_and(|region| self.regions_with_rpk.insert((zone, region)))
				}
				OtherFlag::NetworkEchomailCoordinator => {
					self.echomail_coordinator_nets.insert((zone, net))
				}
				OtherFlag::NetPointlistKeeper => self.pointlist_keeper_nets.insert((zone, net)),
				OtherFlag::NetworkCoordinator => {
					self.hierarchy.host.is_some()
						&& matches!(
							keyword,
							Keyword::Normal | Keyword::Private | Keyword::Hold | Keyword::Down
						) && self.coordinator_override_nets.insert((zone, net))
				}
				_ => true,
			};
			if !valid {
				return Err(fail(line, NodelistErrorKind::InvalidFlag));
			}
		}
		Ok(())
	}
}

fn prohibited_character(character: char) -> bool {
	character <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&character)
}

/// A streaming validated TTS-5000 record reader.
pub struct NodelistReader<R> {
	reader: R,
	state: ReaderState,
}

struct ReaderState {
	validator: Validator,
	buffer: Vec<u8>,
	line: usize,
	done: bool,
}

impl<R: BufRead> NodelistReader<R> {
	pub fn distribution(domain: impl Into<String>, reader: R) -> Result<Self, NodelistError> {
		Ok(Self {
			reader,
			state: ReaderState::new(Validator::distribution(domain.into())?),
		})
	}

	pub fn segment(context: SegmentContext, reader: R) -> Result<Self, NodelistError> {
		Ok(Self {
			reader,
			state: ReaderState::new(Validator::new(context, true)),
		})
	}
}

impl<R: BufRead> Iterator for NodelistReader<R> {
	type Item = Result<Record, NodelistError>;

	fn next(&mut self) -> Option<Self::Item> {
		self.state.next(&mut self.reader)
	}
}

impl ReaderState {
	fn new(validator: Validator) -> Self {
		Self {
			validator,
			buffer: Vec::new(),
			line: 0,
			done: false,
		}
	}

	fn next(&mut self, reader: &mut dyn BufRead) -> Option<Result<Record, NodelistError>> {
		if self.done {
			return None;
		}
		self.buffer.clear();
		match reader.read_until(b'\n', &mut self.buffer) {
			Ok(0) => {
				self.done = true;
				(self.validator.requires_data && self.validator.first_data)
					.then(|| Err(fail(self.line + 1, NodelistErrorKind::InvalidHierarchy)))
			}
			Ok(_) => {
				self.line += 1;
				if self.buffer.last() != Some(&b'\n') {
					self.done = true;
					return Some(Err(fail(
						self.line,
						NodelistErrorKind::MissingFinalLineFeed,
					)));
				}
				self.buffer.pop();
				let Ok(line) = std::str::from_utf8(&self.buffer) else {
					self.done = true;
					return Some(Err(fail(self.line, NodelistErrorKind::InvalidUtf8)));
				};
				let result = self.validator.parse_line(self.line, line);
				if result.is_err() {
					self.done = true;
				}
				Some(result)
			}
			Err(_) => {
				self.done = true;
				Some(Err(fail(self.line + 1, NodelistErrorKind::Io)))
			}
		}
	}
}

/// Validated producer fields for one data record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryInput {
	pub keyword: Keyword,
	pub number: u16,
	pub node_name: String,
	pub location: String,
	pub sysop_name: String,
	pub phone: String,
	pub system_flags: SystemFlags,
	pub pstn_isdn_flags: PstnIsdnFlags,
	pub internet_flags: InternetFlags,
	pub email_flags: EmailFlags,
	pub other_flags: OtherFlags,
}

/// External provenance needed for the first publication application-key rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationSource {
	Ordinary,
	FirstPublicationFromAnonymousApplication(PublicKey),
}

/// A streaming canonical TTS-5000 record writer.
pub struct NodelistWriter<W> {
	writer: W,
	validator: Validator,
	line: usize,
}

impl<W: Write> NodelistWriter<W> {
	pub fn distribution(domain: impl Into<String>, writer: W) -> Result<Self, NodelistError> {
		Ok(Self {
			writer,
			validator: Validator::distribution(domain.into())?,
			line: 0,
		})
	}

	pub fn segment(context: SegmentContext, writer: W) -> Result<Self, NodelistError> {
		Ok(Self {
			writer,
			validator: Validator::new(context, true),
			line: 0,
		})
	}

	pub fn write_comment(&mut self, comment: &Comment) -> Result<(), NodelistError> {
		validate_comment(comment, self.line + 1)?;
		let line = format!(";{}{}", comment.interests, comment.text);
		self.line += 1;
		self.validator.parse_line(self.line, &line)?;
		self.writer
			.write_all(format!("{line}\n").as_bytes())
			.map_err(|_| fail(self.line, NodelistErrorKind::Io))
	}

	pub fn write_entry(
		&mut self,
		input: &EntryInput,
		source: PublicationSource,
	) -> Result<Entry, NodelistError> {
		let line = format!(
			"{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
			keyword_text(input.keyword),
			input.number,
			input.node_name,
			input.location,
			input.sysop_name,
			input.phone,
			input.system_flags,
			input.pstn_isdn_flags,
			input.internet_flags,
			input.email_flags,
			input.other_flags,
		);
		self.line += 1;
		let entry = self.validator.parse_data_line(self.line, &line)?;
		validate_publication_source(&entry, source, self.line)?;
		self.writer
			.write_all(format!("{line}\n").as_bytes())
			.map_err(|_| fail(self.line, NodelistErrorKind::Io))?;
		Ok(entry)
	}

	pub fn finish(mut self) -> Result<W, NodelistError> {
		validate_writer_finish(&self.validator, self.line + 1)?;
		self.writer
			.flush()
			.map_err(|_| fail(self.line, NodelistErrorKind::Io))?;
		Ok(self.writer)
	}
}

fn validate_comment(comment: &Comment, line: usize) -> Result<(), NodelistError> {
	if !comment
		.interests
		.bytes()
		.all(|byte| byte.is_ascii_alphabetic())
		|| comment
			.text
			.bytes()
			.next()
			.is_some_and(|byte| byte.is_ascii_alphabetic())
	{
		return Err(fail(line, NodelistErrorKind::InvalidComment));
	}
	Ok(())
}

fn validate_publication_source(
	entry: &Entry,
	source: PublicationSource,
	line: usize,
) -> Result<(), NodelistError> {
	if let PublicationSource::FirstPublicationFromAnonymousApplication(application_key) = source
		&& entry.tith.as_ref().map(|service| service.public_key) != Some(application_key)
	{
		return Err(fail(line, NodelistErrorKind::ApplicationKeyMismatch));
	}
	Ok(())
}

fn validate_writer_finish(validator: &Validator, line: usize) -> Result<(), NodelistError> {
	if validator.requires_data && validator.first_data {
		return Err(fail(line, NodelistErrorKind::InvalidHierarchy));
	}
	Ok(())
}

fn keyword_text(keyword: Keyword) -> &'static str {
	match keyword {
		Keyword::Normal => "",
		Keyword::Private => "Pvt",
		Keyword::Hold => "Hold",
		Keyword::Down => "Down",
		Keyword::Zone => "Zone",
		Keyword::Region => "Region",
		Keyword::Host => "Host",
		Keyword::Hub => "Hub",
	}
}

/// Exact native publication filenames for one domain and ordinal day.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationName {
	domain: String,
	ordinal_day: u16,
}

impl PublicationName {
	pub fn new(domain: &str, ordinal_day: u16) -> Result<Self, NodelistErrorKind> {
		let domain = domain.to_owned();
		if Address::new(domain.clone(), 1, 1, 0, 0).is_err() || !(1..=366).contains(&ordinal_day) {
			return Err(NodelistErrorKind::InvalidPublication);
		}
		Ok(Self {
			domain,
			ordinal_day,
		})
	}

	#[must_use]
	pub fn text_filename(&self) -> String {
		format!("{}-nodelist.{:03}", self.domain, self.ordinal_day)
	}

	#[must_use]
	pub fn archive_filename(&self) -> String {
		format!("{}.zst", self.text_filename())
	}

	#[must_use]
	pub fn current_request_filename(&self) -> String {
		format!("{}-nodelist.zst", self.domain)
	}
}

/// Exact filename for a partial or alternate publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternatePublicationName {
	base: String,
	ordinal_day: u16,
}

impl AlternatePublicationName {
	pub fn new(domain: &str, base: &str, ordinal_day: u16) -> Result<Self, NodelistErrorKind> {
		let domain = domain.to_owned();
		let base = base.to_owned();
		if Address::new(domain.clone(), 1, 1, 0, 0).is_err()
			|| base.is_empty()
			|| base == format!("{domain}-nodelist")
			|| !(1..=366).contains(&ordinal_day)
		{
			return Err(NodelistErrorKind::InvalidPublication);
		}
		Ok(Self { base, ordinal_day })
	}

	#[must_use]
	pub fn text_filename(&self) -> String {
		format!("{}.{:03}", self.base, self.ordinal_day)
	}

	#[must_use]
	pub fn archive_filename(&self) -> String {
		format!("{}.zst", self.text_filename())
	}
}

/// Compresses exactly one dictionary-free Zstandard frame.
pub fn compress_zstd_frame<R: Read, W: Write>(mut input: R, output: W) -> io::Result<W> {
	let mut encoder = zstd::stream::write::Encoder::new(output, 0)?;
	io::copy(&mut input, &mut encoder)?;
	encoder.finish()
}

/// Decodes exactly one ordinary Zstandard frame and rejects trailing bytes.
pub fn decompress_zstd_frame<R: BufRead, W: Write>(input: R, mut output: W) -> io::Result<W> {
	let mut input = input;
	let mut magic = [0; 4];
	input.read_exact(&mut magic)?;
	require_zstandard_magic(magic)?;
	let input = io::Cursor::new(magic).chain(input);
	let mut decoder = zstd::stream::read::Decoder::with_buffer(input)?.single_frame();
	io::copy(&mut decoder, &mut output)?;
	let mut input = decoder.finish();
	require_no_trailing_data(!input.fill_buf()?.is_empty())?;
	Ok(output)
}

fn require_zstandard_magic(magic: [u8; 4]) -> io::Result<()> {
	const ZSTANDARD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
	if magic != ZSTANDARD_MAGIC {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"publication does not begin with an ordinary Zstandard frame",
		));
	}
	Ok(())
}

fn require_no_trailing_data(has_trailing_data: bool) -> io::Result<()> {
	if has_trailing_data {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"data follows the first Zstandard frame",
		));
	}
	Ok(())
}

#[cfg(test)]
mod qualification_tests {
	use crate as tith_nodelist;

	include!("../tests/tts5000.rs");
}
