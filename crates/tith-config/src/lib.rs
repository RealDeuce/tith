//! Atomic parsing and cross-validation for TSP-0002 configuration sets.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::PublicKey;
use tith_wire::address::{Address, AddressPattern};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
	pub file: &'static str,
	pub line: usize,
	pub message: String,
}

impl fmt::Display for ConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:{}: {}", self.file, self.line, self.message)
	}
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentityRef {
	Listed(Address),
	Peer(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
	pub server: String,
	pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Peer {
	pub name: String,
	pub address: Address,
	pub public_key: Option<PublicKey>,
	pub endpoints: Vec<Endpoint>,
	pub trust_on_first_use: bool,
	pub boss: Option<String>,
	pub hub: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Selector {
	All,
	Address(Address),
	AddressPattern(AddressPattern),
	Peer(String),
	Branch(BranchKind, Address),
	Independent(IndependentKind, Address),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchKind {
	Zone,
	Region,
	Host,
	Hub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndependentKind {
	Zone,
	Region,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteMethod {
	Via(String),
	Direct,
	Boss,
	Hub,
	Host,
	Region,
	Zone,
	Hold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
	DeadLetter,
	Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notification {
	None,
	Sender,
	OriginSysop,
	Both,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailurePolicy {
	pub disposition: Disposition,
	pub notification: Notification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
	Any,
	RelayDenied,
	Rejected,
	Authentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRule {
	pub destination: Selector,
	pub methods: Vec<RouteMethod>,
	pub on_failure: Option<FailurePolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayAction {
	Allow { on_failure: Option<FailurePolicy> },
	Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRule {
	pub action: RelayAction,
	pub from: Selector,
	pub origin: Selector,
	pub destination: Selector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureRule {
	pub kind: FailureKind,
	pub origin: Selector,
	pub destination: Selector,
	pub policy: FailurePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Routes {
	pub local: IdentityRef,
	pub routes: Vec<RouteRule>,
	pub relay: Vec<RelayRule>,
	pub failures: Vec<FailureRule>,
	pub failure_default: FailurePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AreaLink {
	pub peer: String,
	pub class: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Area {
	pub file_area: bool,
	pub name: String,
	pub receive_from: Vec<String>,
	pub send_to: Vec<AreaLink>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Areas {
	pub local: IdentityRef,
	pub areas: Vec<Area>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schedule {
	pub name: String,
	pub origin: IdentityRef,
	pub classes: Vec<String>,
	pub next_hops: Vec<Selector>,
	pub polls: Vec<String>,
	pub start_local: bool,
	pub start_minutes: u16,
	pub duration_minutes: u64,
	pub repeat_after_minutes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationSet {
	pub peers: BTreeMap<String, Peer>,
	pub routes: Vec<Routes>,
	pub areas: Vec<Areas>,
	pub schedules: Vec<Schedule>,
}

#[derive(Clone)]
/// One significant line of a TSP-0002 section 2 configuration file.
pub struct Line {
	pub number: usize,
	pub text: String,
}

fn err(file: &'static str, line: usize, message: impl Into<String>) -> ConfigError {
	ConfigError {
		file,
		line,
		message: message.into(),
	}
}

/// Splits a configuration file into its significant lines.
///
/// TSP-0002 section 2: UTF-8, every line ends with LF, no C0 control other than
/// a Horizontal Tab separator, an empty line is ignored, and a line whose first
/// non-separator code point is a Semicolon is a comment. Shared so an adapter
/// which needs its own blocks does not invent a second grammar.
pub fn lines(file: &'static str, input: &str) -> Result<Vec<Line>, ConfigError> {
	if !input.is_empty() && !input.ends_with('\n') {
		return Err(err(
			file,
			input.bytes().filter(|byte| *byte == b'\n').count() + 1,
			"missing final LF",
		));
	}
	let mut output = Vec::new();
	for (index, raw) in input.split_terminator('\n').enumerate() {
		if raw
			.chars()
			.any(|ch| (ch.is_control() && ch != '\t') || ch == '\u{7f}')
		{
			return Err(err(file, index + 1, "prohibited control character"));
		}
		let text = raw.trim_matches([' ', '\t']);
		if !text.is_empty() && !text.starts_with(';') {
			output.push(Line {
				number: index + 1,
				text: text.to_owned(),
			});
		}
	}
	Ok(output)
}

/// The separator-divided fields of a line.
#[must_use]
pub fn fields(line: &Line) -> Vec<&str> {
	line.text
		.split([' ', '\t'])
		.filter(|v| !v.is_empty())
		.collect()
}

fn valid_name(value: &str) -> bool {
	!value.is_empty() && !value.contains([' ', '\t', '@']) && !value.chars().any(char::is_control)
}

fn peer_ref(file: &'static str, line: usize, value: &str) -> Result<String, ConfigError> {
	let name = value
		.strip_prefix('@')
		.ok_or_else(|| err(file, line, "expected peer reference"))?;
	if valid_name(name) {
		Ok(name.to_owned())
	} else {
		Err(err(file, line, "invalid peer reference"))
	}
}

fn identity(file: &'static str, line: usize, value: &str) -> Result<IdentityRef, ConfigError> {
	if value.starts_with('@') {
		Ok(IdentityRef::Peer(peer_ref(file, line, value)?))
	} else {
		let address = Address::from_str(value).map_err(|e| err(file, line, e.to_string()))?;
		if address.is_unlisted() {
			Err(err(
				file,
				line,
				"unlisted local identity must be a peer reference",
			))
		} else {
			Ok(IdentityRef::Listed(address))
		}
	}
}

fn selector(
	file: &'static str,
	line: usize,
	values: &[&str],
) -> Result<(Selector, usize), ConfigError> {
	let bad = || err(file, line, "invalid selector");
	match values {
		["All", ..] => Ok((Selector::All, 1)),
		["Address", value, ..] => {
			if let Ok(address) = Address::from_str(value) {
				Ok((Selector::Address(address), 2))
			} else {
				Ok((
					Selector::AddressPattern(AddressPattern::from_str(value).map_err(|_| bad())?),
					2,
				))
			}
		}
		["Peer", value, ..] => Ok((Selector::Peer(peer_ref(file, line, value)?), 2)),
		["Branch", kind, address, ..] => {
			let kind = match *kind {
				"Zone" => BranchKind::Zone,
				"Region" => BranchKind::Region,
				"Host" => BranchKind::Host,
				"Hub" => BranchKind::Hub,
				_ => return Err(bad()),
			};
			let address = Address::from_str(address).map_err(|_| bad())?;
			if address.is_unlisted() {
				return Err(bad());
			}
			Ok((Selector::Branch(kind, address), 3))
		}
		["Independent", kind, address, ..] => {
			let kind = match *kind {
				"Zone" => IndependentKind::Zone,
				"Region" => IndependentKind::Region,
				_ => return Err(bad()),
			};
			let address = Address::from_str(address).map_err(|_| bad())?;
			if address.is_unlisted() {
				return Err(bad());
			}
			Ok((Selector::Independent(kind, address), 3))
		}
		_ => Err(bad()),
	}
}

fn policy(file: &'static str, line: usize, values: &[&str]) -> Result<FailurePolicy, ConfigError> {
	if values.len() != 3 || values[1] != "Notify" {
		return Err(err(file, line, "invalid failure policy"));
	}
	let disposition = match values[0] {
		"Dead-Letter" => Disposition::DeadLetter,
		"Discard" => Disposition::Discard,
		_ => return Err(err(file, line, "invalid disposition")),
	};
	let notification = match values[2] {
		"None" => Notification::None,
		"Sender" => Notification::Sender,
		"Origin-Sysop" => Notification::OriginSysop,
		"Both" => Notification::Both,
		_ => return Err(err(file, line, "invalid notification")),
	};
	Ok(FailurePolicy {
		disposition,
		notification,
	})
}

fn visit_peer(
	name: &str,
	peers: &BTreeMap<String, Peer>,
	active: &mut BTreeSet<String>,
	done: &mut BTreeSet<String>,
) -> bool {
	if done.contains(name) {
		return true;
	}
	if !active.insert(name.to_owned()) {
		return false;
	}
	let peer = &peers[name];
	if !peer
		.boss
		.iter()
		.chain(peer.hub.iter())
		.all(|next| visit_peer(next, peers, active, done))
	{
		return false;
	}
	active.remove(name);
	done.insert(name.to_owned());
	true
}

fn parse_peers(input: &str) -> Result<BTreeMap<String, Peer>, ConfigError> {
	let file = "peers";
	let input = lines(file, input)?;
	let mut index = 0;
	let mut peers = BTreeMap::new();
	let mut identities = BTreeSet::new();
	while index < input.len() {
		let start = fields(&input[index]);
		if start.len() != 2 || start[0] != "Peer" || !valid_name(start[1]) {
			return Err(err(file, input[index].number, "expected Peer <name>"));
		}
		let name = start[1].to_owned();
		if peers.contains_key(&name) {
			return Err(err(file, input[index].number, "duplicate peer name"));
		}
		index += 1;
		let mut address = None;
		let mut public_key = None;
		let mut endpoints = Vec::new();
		let mut trust_on_first_use = false;
		let mut boss = None;
		let mut hub = None;
		loop {
			let line = input.get(index).ok_or_else(|| {
				err(
					file,
					input.last().map_or(1, |v| v.number),
					"unterminated Peer block",
				)
			})?;
			let f = fields(line);
			if f == ["End"] {
				index += 1;
				break;
			}
			match f.as_slice() {
				["Address", value] if address.is_none() => {
					address = Some(
						Address::from_str(value)
							.map_err(|e| err(file, line.number, e.to_string()))?,
					);
				}
				["Public-Key", value] if public_key.is_none() => {
					if value.len() != 43 || value.contains('=') {
						return Err(err(file, line.number, "invalid public key"));
					}
					let bytes: [u8; 32] = STANDARD_NO_PAD
						.decode(value)
						.map_err(|_| err(file, line.number, "invalid public key"))?
						.try_into()
						.map_err(|_| err(file, line.number, "invalid public key"))?;
					public_key = Some(PublicKey::from_bytes(bytes));
				}
				["Endpoint", server, port] => {
					let port_text = *port;
					let port: u16 = port_text
						.parse()
						.map_err(|_| err(file, line.number, "invalid endpoint port"))?;
					if port == 0
						|| port.to_string() != port_text
						|| server.chars().any(char::is_control)
					{
						return Err(err(file, line.number, "invalid endpoint"));
					}
					let endpoint = Endpoint {
						server: (*server).to_owned(),
						port,
					};
					if endpoints.contains(&endpoint) {
						return Err(err(file, line.number, "duplicate Endpoint"));
					}
					endpoints.push(endpoint);
				}
				["Trust-On-First-Use"] if !trust_on_first_use => {
					trust_on_first_use = true;
				}
				["Boss", value] if boss.is_none() => {
					boss = Some(peer_ref(file, line.number, value)?);
				}
				["Hub", value] if hub.is_none() => hub = Some(peer_ref(file, line.number, value)?),
				_ => {
					return Err(err(
						file,
						line.number,
						"unknown, duplicate, or malformed Peer directive",
					));
				}
			}
			index += 1;
		}
		let address =
			address.ok_or_else(|| err(file, input[index - 1].number, "missing Address"))?;
		if address.is_unlisted() != public_key.is_some() {
			return Err(err(
				file,
				input[index - 1].number,
				"Public-Key must occur exactly for an unlisted address",
			));
		}
		if !address.is_unlisted() && (boss.is_some() || hub.is_some()) {
			return Err(err(
				file,
				input[index - 1].number,
				"Boss and Hub require an unlisted peer",
			));
		}
		if trust_on_first_use && (address.is_unlisted() || endpoints.is_empty()) {
			return Err(err(
				file,
				input[index - 1].number,
				"Trust-On-First-Use requires a listed address and an Endpoint",
			));
		}
		let key = (address.clone(), public_key.map(|value| *value.as_bytes()));
		if !identities.insert(key) {
			return Err(err(
				file,
				input[index - 1].number,
				"duplicate exact identity",
			));
		}
		peers.insert(
			name.clone(),
			Peer {
				name,
				address,
				public_key,
				endpoints,
				trust_on_first_use,
				boss,
				hub,
			},
		);
	}
	for peer in peers.values() {
		for name in peer.boss.iter().chain(peer.hub.iter()) {
			if !peers.contains_key(name) {
				return Err(err(file, 0, format!("undefined peer @{name}")));
			}
		}
	}
	let mut done = BTreeSet::new();
	for name in peers.keys() {
		if !visit_peer(name, &peers, &mut BTreeSet::new(), &mut done) {
			return Err(err(file, 0, "peer relationship cycle"));
		}
	}
	Ok(peers)
}

fn parse_methods(
	file: &'static str,
	line: usize,
	values: &[&str],
) -> Result<(Vec<RouteMethod>, Option<FailurePolicy>), ConfigError> {
	let failure_at = values.iter().position(|v| *v == "On-Failure");
	let (method_values, failure_values) = failure_at.map_or((values, None), |at| {
		(&values[..at], Some(&values[at + 1..]))
	});
	let mut methods = Vec::new();
	let mut index = 0;
	while index < method_values.len() {
		let method = match method_values[index] {
			"Via" => {
				index += 1;
				RouteMethod::Via(peer_ref(
					file,
					line,
					method_values
						.get(index)
						.ok_or_else(|| err(file, line, "missing Via peer"))?,
				)?)
			}
			"Direct" => RouteMethod::Direct,
			"Boss" => RouteMethod::Boss,
			"Hub" => RouteMethod::Hub,
			"Host" => RouteMethod::Host,
			"Region" => RouteMethod::Region,
			"Zone" => RouteMethod::Zone,
			"Hold" => RouteMethod::Hold,
			_ => return Err(err(file, line, "invalid route method")),
		};
		if methods.contains(&method) {
			return Err(err(file, line, "duplicate route method"));
		}
		methods.push(method);
		index += 1;
	}
	if methods.is_empty()
		|| methods
			.iter()
			.position(|v| *v == RouteMethod::Hold)
			.is_some_and(|at| at + 1 != methods.len())
	{
		return Err(err(file, line, "invalid method list"));
	}
	Ok((
		methods,
		failure_values.map(|v| policy(file, line, v)).transpose()?,
	))
}

fn parse_routes(input: &str) -> Result<Vec<Routes>, ConfigError> {
	let file = "routes";
	let input = lines(file, input)?;
	let mut index = 0;
	let mut output = Vec::new();
	let mut locals = BTreeSet::new();
	while index < input.len() {
		let start = fields(&input[index]);
		if start.len() != 2 || start[0] != "Routes" {
			return Err(err(
				file,
				input[index].number,
				"expected Routes <local-identity>",
			));
		}
		let local = identity(file, input[index].number, start[1])?;
		if !locals.insert(local.clone()) {
			return Err(err(file, input[index].number, "duplicate Routes identity"));
		}
		index += 1;
		let mut routes = Vec::new();
		let mut relay = Vec::new();
		let mut failures = Vec::new();
		let mut failure_default = None;
		loop {
			let line = input.get(index).ok_or_else(|| {
				err(
					file,
					input.last().map_or(1, |v| v.number),
					"unterminated Routes block",
				)
			})?;
			let f = fields(line);
			if f == ["End"] {
				index += 1;
				break;
			}
			match f.first().copied() {
				Some("Route") => {
					let (destination, used) = selector(file, line.number, &f[1..])?;
					if f.get(1 + used) != Some(&"Using") {
						return Err(err(file, line.number, "missing Using"));
					}
					let (methods, on_failure) = parse_methods(file, line.number, &f[used + 2..])?;
					let rule = RouteRule {
						destination,
						methods,
						on_failure,
					};
					if routes.contains(&rule) {
						return Err(err(file, line.number, "duplicate Route"));
					}
					routes.push(rule);
				}
				Some("Allow-Relay" | "Deny-Relay") => {
					if f.get(1) != Some(&"From") {
						return Err(err(file, line.number, "missing From"));
					}
					let (from, u1) = selector(file, line.number, &f[2..])?;
					let p2 = 2 + u1;
					if f.get(p2) != Some(&"Origin") {
						return Err(err(file, line.number, "missing Origin"));
					}
					let (origin, u2) = selector(file, line.number, &f[p2 + 1..])?;
					let p3 = p2 + 1 + u2;
					if f.get(p3) != Some(&"Destination") {
						return Err(err(file, line.number, "missing Destination"));
					}
					let (destination, u3) = selector(file, line.number, &f[p3 + 1..])?;
					let tail = &f[p3 + 1 + u3..];
					let on_failure = if tail.is_empty() {
						None
					} else if tail.first() == Some(&"On-Failure") {
						Some(policy(file, line.number, &tail[1..])?)
					} else {
						return Err(err(file, line.number, "invalid relay tail"));
					};
					let action = if f[0] == "Allow-Relay" {
						RelayAction::Allow { on_failure }
					} else if on_failure.is_none() {
						RelayAction::Deny
					} else {
						return Err(err(file, line.number, "Deny-Relay cannot carry On-Failure"));
					};
					let rule = RelayRule {
						action,
						from,
						origin,
						destination,
					};
					if relay.contains(&rule) {
						return Err(err(file, line.number, "duplicate relay rule"));
					}
					relay.push(rule);
				}
				Some("Failure-Default") if failure_default.is_none() => {
					failure_default = Some(policy(file, line.number, &f[1..])?);
				}
				Some("Failure") => {
					let kind = match f.get(1).copied() {
						Some("Any") => FailureKind::Any,
						Some("Relay-Denied") => FailureKind::RelayDenied,
						Some("Rejected") => FailureKind::Rejected,
						Some("Authentication") => FailureKind::Authentication,
						_ => return Err(err(file, line.number, "invalid failure kind")),
					};
					if f.get(2) != Some(&"Origin") {
						return Err(err(file, line.number, "missing Origin"));
					}
					let (origin, u1) = selector(file, line.number, &f[3..])?;
					let at = 3 + u1;
					if f.get(at) != Some(&"Destination") {
						return Err(err(file, line.number, "missing Destination"));
					}
					let (destination, u2) = selector(file, line.number, &f[at + 1..])?;
					let policy = policy(file, line.number, &f[at + 1 + u2..])?;
					let rule = FailureRule {
						kind,
						origin,
						destination,
						policy,
					};
					if failures.contains(&rule) {
						return Err(err(file, line.number, "duplicate Failure"));
					}
					failures.push(rule);
				}
				_ => {
					return Err(err(
						file,
						line.number,
						"unknown or malformed Routes directive",
					));
				}
			}
			index += 1;
		}
		output.push(Routes {
			local,
			routes,
			relay,
			failures,
			failure_default: failure_default.unwrap_or(FailurePolicy {
				disposition: Disposition::DeadLetter,
				notification: Notification::None,
			}),
		});
	}
	if output.is_empty() {
		return Err(err(file, 0, "at least one Routes block is required"));
	}
	Ok(output)
}

fn parse_areas(input: &str) -> Result<Vec<Areas>, ConfigError> {
	let file = "areas";
	let input = lines(file, input)?;
	let mut index = 0;
	let mut output = Vec::new();
	let mut locals = BTreeSet::new();
	while index < input.len() {
		let start = fields(&input[index]);
		if start.len() != 2 || start[0] != "Areas" {
			return Err(err(
				file,
				input[index].number,
				"expected Areas <local-identity>",
			));
		}
		let local = identity(file, input[index].number, start[1])?;
		if !locals.insert(local.clone()) {
			return Err(err(file, input[index].number, "duplicate Areas identity"));
		}
		index += 1;
		let mut areas = Vec::new();
		let mut names = BTreeSet::new();
		loop {
			let line = input.get(index).ok_or_else(|| {
				err(
					file,
					input.last().map_or(1, |v| v.number),
					"unterminated Areas block",
				)
			})?;
			if line.text == "End" {
				index += 1;
				break;
			}
			let (directive, remainder) = line
				.text
				.split_once([' ', '\t'])
				.ok_or_else(|| err(file, line.number, "expected area name"))?;
			let name = remainder.trim_matches([' ', '\t']);
			let file_area = if directive == "EchoArea" {
				false
			} else if directive == "FileArea" {
				true
			} else {
				return Err(err(
					file,
					line.number,
					"expected EchoArea, FileArea, or End",
				));
			};
			if name.is_empty() || !names.insert((file_area, name.to_owned())) {
				return Err(err(file, line.number, "empty or duplicate area"));
			}
			index += 1;
			let mut receive_from = Vec::new();
			let mut send_to = Vec::new();
			loop {
				let line = input.get(index).ok_or_else(|| {
					err(
						file,
						input.last().map_or(1, |v| v.number),
						"unterminated area block",
					)
				})?;
				let f = fields(line);
				if f == ["End"] {
					index += 1;
					break;
				}
				match f.as_slice() {
					["Receive-From", value] => {
						let peer = peer_ref(file, line.number, value)?;
						if receive_from.contains(&peer) {
							return Err(err(file, line.number, "duplicate Receive-From"));
						}
						receive_from.push(peer);
					}
					["Send-To", value] | ["Send-To", value, "Class", _] => {
						let peer = peer_ref(file, line.number, value)?;
						if send_to.iter().any(|v: &AreaLink| v.peer == peer) {
							return Err(err(file, line.number, "duplicate Send-To"));
						}
						let class = f.get(3).copied().unwrap_or("Normal");
						if !valid_name(class) {
							return Err(err(file, line.number, "invalid class"));
						}
						send_to.push(AreaLink {
							peer,
							class: class.to_owned(),
						});
					}
					_ => {
						return Err(err(
							file,
							line.number,
							"unknown or malformed area directive",
						));
					}
				}
				index += 1;
			}
			areas.push(Area {
				file_area,
				name: name.to_owned(),
				receive_from,
				send_to,
			});
		}
		output.push(Areas { local, areas });
	}
	Ok(output)
}

fn duration(file: &'static str, line: usize, value: &str) -> Result<u64, ConfigError> {
	let decimal = |text: &str| {
		text == "0" || (!text.starts_with('0') && text.bytes().all(|v| v.is_ascii_digit()))
	};
	if let Some((hours, minutes)) = value.split_once(':') {
		if !decimal(hours) || minutes.len() != 2 || !minutes.bytes().all(|v| v.is_ascii_digit()) {
			return Err(err(file, line, "invalid duration"));
		}
		let minutes: u64 = minutes
			.parse()
			.map_err(|_| err(file, line, "invalid duration"))?;
		if minutes > 59 {
			return Err(err(file, line, "invalid duration"));
		}
		hours
			.parse::<u64>()
			.ok()
			.and_then(|h| h.checked_mul(60))
			.and_then(|h| h.checked_add(minutes))
			.ok_or_else(|| err(file, line, "duration overflow"))
	} else if decimal(value) {
		value
			.parse()
			.map_err(|_| err(file, line, "duration overflow"))
	} else {
		Err(err(file, line, "invalid duration"))
	}
}

fn parse_schedules(input: &str) -> Result<Vec<Schedule>, ConfigError> {
	let file = "schedules";
	let input = lines(file, input)?;
	let mut index = 0;
	let mut output = Vec::new();
	let mut names = BTreeSet::new();
	while index < input.len() {
		let start = fields(&input[index]);
		if start.len() != 2
			|| start[0] != "Schedule"
			|| !valid_name(start[1])
			|| !names.insert(start[1].to_owned())
		{
			return Err(err(
				file,
				input[index].number,
				"invalid or duplicate Schedule name",
			));
		}
		let name = start[1].to_owned();
		index += 1;
		let mut origin = None;
		let mut classes = Vec::new();
		let mut next_hops = Vec::new();
		let mut polls = Vec::new();
		let mut start = None;
		let mut duration_value = None;
		let mut repeat = None;
		loop {
			let line = input.get(index).ok_or_else(|| {
				err(
					file,
					input.last().map_or(1, |v| v.number),
					"unterminated Schedule block",
				)
			})?;
			let f = fields(line);
			if f == ["End"] {
				index += 1;
				break;
			}
			match f.first().copied() {
				Some("Origin") if f.len() == 2 && origin.is_none() => {
					origin = Some(identity(file, line.number, f[1])?);
				}
				Some("Class") if f.len() == 2 && valid_name(f[1]) => {
					if classes.contains(&f[1].to_owned()) {
						return Err(err(file, line.number, "duplicate Class"));
					}
					classes.push(f[1].to_owned());
				}
				Some("Next-Hop") => {
					let (value, used) = selector(file, line.number, &f[1..])?;
					if used + 1 != f.len() || next_hops.contains(&value) {
						return Err(err(file, line.number, "invalid or duplicate Next-Hop"));
					}
					next_hops.push(value);
				}
				Some("Poll") if f.len() == 2 => {
					let value = peer_ref(file, line.number, f[1])?;
					if polls.contains(&value) {
						return Err(err(file, line.number, "duplicate Poll"));
					}
					polls.push(value);
				}
				Some("Start") if start.is_none() => {
					let (local, value) = match f.as_slice() {
						["Start", value] => (false, *value),
						["Start", "Local", value] => (true, *value),
						_ => return Err(err(file, line.number, "invalid Start")),
					};
					if value.len() != 5 || &value[2..3] != ":" {
						return Err(err(file, line.number, "invalid Start"));
					}
					let hour: u16 = value[..2]
						.parse()
						.map_err(|_| err(file, line.number, "invalid Start"))?;
					let minute: u16 = value[3..]
						.parse()
						.map_err(|_| err(file, line.number, "invalid Start"))?;
					if hour > 23 || minute > 59 {
						return Err(err(file, line.number, "invalid Start"));
					}
					start = Some((local, hour * 60 + minute));
				}
				Some("Duration") if f.len() == 2 && duration_value.is_none() => {
					duration_value = Some(duration(file, line.number, f[1])?);
				}
				Some("Repeat-After") if f.len() == 2 && repeat.is_none() => {
					let value = duration(file, line.number, f[1])?;
					if value == 0 {
						return Err(err(file, line.number, "Repeat-After must be positive"));
					}
					repeat = Some(value);
				}
				_ => {
					return Err(err(
						file,
						line.number,
						"unknown, duplicate, or malformed Schedule directive",
					));
				}
			}
			index += 1;
		}
		let origin = origin.ok_or_else(|| err(file, input[index - 1].number, "missing Origin"))?;
		let (start_local, start_minutes) = start.unwrap_or((false, 0));
		if classes.is_empty() {
			classes.push("Normal".to_owned());
		}
		if next_hops.is_empty() {
			next_hops.push(Selector::All);
		}
		output.push(Schedule {
			name,
			origin,
			classes,
			next_hops,
			polls,
			start_local,
			start_minutes,
			duration_minutes: duration_value.unwrap_or(0),
			repeat_after_minutes: repeat.unwrap_or(1),
		});
	}
	Ok(output)
}

fn selector_peers(selector: &Selector) -> impl Iterator<Item = &str> {
	match selector {
		Selector::Peer(name) => Some(name.as_str()),
		_ => None,
	}
	.into_iter()
}

impl ConfigurationSet {
	pub fn parse(
		peers: &str,
		routes: &str,
		areas: &str,
		schedules: &str,
	) -> Result<Self, ConfigError> {
		let peers = parse_peers(peers)?;
		let routes = parse_routes(routes)?;
		let areas = parse_areas(areas)?;
		let schedules = parse_schedules(schedules)?;
		let route_locals: BTreeSet<_> = routes.iter().map(|v| &v.local).collect();
		let check_identity = |file, value: &IdentityRef| -> Result<(), ConfigError> {
			if let IdentityRef::Peer(name) = value
				&& !peers.contains_key(name)
			{
				return Err(err(file, 0, format!("undefined peer @{name}")));
			}
			Ok(())
		};
		for route in &routes {
			check_identity("routes", &route.local)?;
			for rule in &route.routes {
				for name in
					selector_peers(&rule.destination).chain(rule.methods.iter().filter_map(|v| {
						if let RouteMethod::Via(name) = v {
							Some(name.as_str())
						} else {
							None
						}
					})) {
					if !peers.contains_key(name) {
						return Err(err("routes", 0, format!("undefined peer @{name}")));
					}
				}
			}
			for rule in &route.relay {
				for name in selector_peers(&rule.from)
					.chain(selector_peers(&rule.origin))
					.chain(selector_peers(&rule.destination))
				{
					if !peers.contains_key(name) {
						return Err(err("routes", 0, format!("undefined peer @{name}")));
					}
				}
			}
		}
		for group in &areas {
			check_identity("areas", &group.local)?;
			if !route_locals.contains(&group.local) {
				return Err(err("areas", 0, "Areas identity has no Routes block"));
			}
			for area in &group.areas {
				for name in area
					.receive_from
					.iter()
					.chain(area.send_to.iter().map(|v| &v.peer))
				{
					if !peers.contains_key(name) {
						return Err(err("areas", 0, format!("undefined peer @{name}")));
					}
				}
			}
		}
		for schedule in &schedules {
			check_identity("schedules", &schedule.origin)?;
			if !route_locals.contains(&schedule.origin) {
				return Err(err("schedules", 0, "Schedule origin has no Routes block"));
			}
			for name in schedule
				.polls
				.iter()
				.map(String::as_str)
				.chain(schedule.next_hops.iter().flat_map(selector_peers))
			{
				if !peers.contains_key(name) {
					return Err(err("schedules", 0, format!("undefined peer @{name}")));
				}
			}
		}
		Ok(Self {
			peers,
			routes,
			areas,
			schedules,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_atomic_set_and_defaults() {
		let config = ConfigurationSet::parse(
			"Peer nc\nAddress fidonet#1:123\nEndpoint nc.example 24555\nEnd\n",
			"Routes fidonet#1/2\nRoute All Using Via @nc Hold\nEnd\n",
			"Areas fidonet#1/2\nEchoArea General Chat\nSend-To @nc\nEnd\nEnd\n",
			"Schedule hourly\nOrigin fidonet#1/2\nPoll @nc\nEnd\n",
		)
		.unwrap();
		assert_eq!(config.schedules[0].classes, ["Normal"]);
		assert_eq!(config.schedules[0].repeat_after_minutes, 1);
	}

	#[test]
	fn trust_on_first_use_requires_a_listed_contact_endpoint() {
		let listed =
			"Peer nc\nAddress fidonet#1:123\nEndpoint nc.example 24555\nTrust-On-First-Use\nEnd\n";
		let peers = parse_peers(listed).unwrap();
		assert!(peers["nc"].trust_on_first_use);

		let no_endpoint = "Peer nc\nAddress fidonet#1:123\nTrust-On-First-Use\nEnd\n";
		assert!(parse_peers(no_endpoint).is_err());

		let unlisted = "Peer nc\nAddress p2p#-1\nPublic-Key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEndpoint nc.example 24555\nTrust-On-First-Use\nEnd\n";
		assert!(parse_peers(unlisted).is_err());
	}

	#[test]
	fn rejects_cross_file_and_cycle_errors() {
		let peers = "Peer a\nAddress p2p#-1\nPublic-Key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nBoss @a\nEnd\n";
		assert!(ConfigurationSet::parse(peers, "Routes fidonet#1\nEnd\n", "", "").is_err());
		assert!(
			ConfigurationSet::parse(
				"",
				"Routes fidonet#1\nEnd\n",
				"",
				"Schedule s\nOrigin fidonet#2\nEnd\n"
			)
			.is_err()
		);
	}

	#[test]
	fn relay_denials_cannot_carry_failure_policy() {
		let denied = "Routes fidonet#1\nDeny-Relay From All Origin All Destination All On-Failure Discard Notify Both\nEnd\n";
		assert!(ConfigurationSet::parse("", denied, "", "").is_err());

		let allowed = "Routes fidonet#1\nAllow-Relay From All Origin All Destination All On-Failure Discard Notify Both\nEnd\n";
		assert!(ConfigurationSet::parse("", allowed, "", "").is_ok());
	}

	#[test]
	fn precommit_routing_failures_are_not_delivery_policy_kinds() {
		for kind in ["Unroutable", "Loop"] {
			let routes = format!(
				"Routes fidonet#1\nFailure {kind} Origin All Destination All Dead-Letter Notify None\nEnd\n"
			);
			assert!(ConfigurationSet::parse("", &routes, "", "").is_err());
		}
	}
}
