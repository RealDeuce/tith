use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::PublicKey;

use crate::NodelistErrorKind;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServerAddress(String);

impl ServerAddress {
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl FromStr for ServerAddress {
	type Err = NodelistErrorKind;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		parse_server(value)
	}
}

impl fmt::Display for ServerAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EmailAddress(String);

impl EmailAddress {
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl FromStr for EmailAddress {
	type Err = NodelistErrorKind;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		parse_email_address(value)
	}
}

impl fmt::Display for EmailAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

/// An endpoint as written on an Internet flag. `None` means that the server
/// or port is inherited from the applicable registered default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSpec {
	server: Option<ServerAddress>,
	port: Option<u16>,
}

impl EndpointSpec {
	pub fn new(
		server: Option<ServerAddress>,
		port: Option<u16>,
	) -> Result<Self, NodelistErrorKind> {
		if port == Some(0) {
			return Err(NodelistErrorKind::InvalidEndpoint);
		}
		Ok(Self { server, port })
	}

	#[must_use]
	pub fn server(&self) -> Option<&ServerAddress> {
		self.server.as_ref()
	}

	#[must_use]
	pub fn port(&self) -> Option<u16> {
		self.port
	}
}

impl fmt::Display for EndpointSpec {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match (&self.server, self.port) {
			(None, None) => Ok(()),
			(Some(server), None) => write!(f, "{server}"),
			(None, Some(port)) => write!(f, ":{port}"),
			(Some(server), Some(port)) => write!(f, "{server}:{port}"),
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRequestFlag {
	Xa,
	Xb,
	Xc,
	Xp,
	Xr,
	Xw,
	Xx,
}

impl FileRequestFlag {
	fn name(self) -> &'static str {
		match self {
			Self::Xa => "XA",
			Self::Xb => "XB",
			Self::Xc => "XC",
			Self::Xp => "XP",
			Self::Xr => "XR",
			Self::Xw => "XW",
			Self::Xx => "XX",
		}
	}

	#[must_use]
	pub const fn supports_bark_file(self) -> bool {
		!matches!(self, Self::Xw | Self::Xx)
	}

	#[must_use]
	pub const fn supports_bark_update(self) -> bool {
		matches!(self, Self::Xa | Self::Xb | Self::Xp)
	}

	#[must_use]
	pub const fn supports_wazoo_file(self) -> bool {
		!matches!(self, Self::Xp)
	}

	#[must_use]
	pub const fn supports_wazoo_update(self) -> bool {
		matches!(self, Self::Xa | Self::Xc | Self::Xx)
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailPeriod {
	bell_212a: bool,
	hour: u8,
}

impl MailPeriod {
	pub fn new(bell_212a: bool, hour: u8) -> Result<Self, NodelistErrorKind> {
		if hour > 23 {
			return Err(NodelistErrorKind::InvalidFlag);
		}
		Ok(Self { bell_212a, hour })
	}

	#[must_use]
	pub fn bell_212a(self) -> bool {
		self.bell_212a
	}

	#[must_use]
	pub fn hour(self) -> u8 {
		self.hour
	}
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HalfHour(u8);

impl HalfHour {
	pub fn new(index: u8) -> Result<Self, NodelistErrorKind> {
		if index >= 48 {
			return Err(NodelistErrorKind::InvalidFlag);
		}
		Ok(Self(index))
	}

	#[must_use]
	pub fn index(self) -> u8 {
		self.0
	}

	#[must_use]
	pub fn minutes_after_midnight(self) -> u16 {
		u16::from(self.0) * 30
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnlinePeriod {
	start: HalfHour,
	end: HalfHour,
}

impl OnlinePeriod {
	#[must_use]
	pub const fn new(start: HalfHour, end: HalfHour) -> Self {
		Self { start, end }
	}

	#[must_use]
	pub const fn start(self) -> HalfHour {
		self.start
	}

	#[must_use]
	pub const fn end(self) -> HalfHour {
		self.end
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemFlag {
	ContinuousMail,
	ListedOnly,
	ManualPackets,
	InternetContinuousMail,
	FileRequest(FileRequestFlag),
	MailPeriod(MailPeriod),
	OnlinePeriod(OnlinePeriod),
}

impl SystemFlag {
	fn order(&self) -> u32 {
		match self {
			Self::ContinuousMail => 0,
			Self::ListedOnly => 1,
			Self::ManualPackets => 2,
			Self::InternetContinuousMail => 3,
			Self::FileRequest(flag) => {
				10 + match flag {
					FileRequestFlag::Xa => 0,
					FileRequestFlag::Xb => 1,
					FileRequestFlag::Xc => 2,
					FileRequestFlag::Xp => 3,
					FileRequestFlag::Xr => 4,
					FileRequestFlag::Xw => 5,
					FileRequestFlag::Xx => 6,
				}
			}
			Self::MailPeriod(period) => {
				100 + u32::from(period.hour) * 2 + u32::from(!period.bell_212a)
			}
			Self::OnlinePeriod(period) => {
				1000 + u32::from(period.start.0) * 48 + u32::from(period.end.0)
			}
		}
	}
}

impl fmt::Display for SystemFlag {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ContinuousMail => f.write_str("CM"),
			Self::ListedOnly => f.write_str("LO"),
			Self::ManualPackets => f.write_str("MN"),
			Self::InternetContinuousMail => f.write_str("ICM"),
			Self::FileRequest(flag) => f.write_str(flag.name()),
			Self::MailPeriod(period) => write!(
				f,
				"{}{:02}",
				if period.bell_212a { '#' } else { '!' },
				period.hour
			),
			Self::OnlinePeriod(period) => {
				write!(
					f,
					"T{}{}",
					half_hour_text(period.start),
					half_hour_text(period.end)
				)
			}
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PstnIsdnFlag {
	V22,
	V29,
	V32,
	V32Bis,
	V34,
	V90Client,
	V90Server,
	V32Terbo,
	VFastClass,
	Hst,
	H14,
	H16,
	X2Client,
	X2Server,
	Zyxel168,
	Zyxel192,
	HayesV9600,
	Pep,
	Csp,
	Mnp,
	V42,
	V42Bis,
	V110Low,
	V110High,
	V120Low,
	V120High,
	X75,
	Isdn,
}

impl PstnIsdnFlag {
	fn name(self) -> &'static str {
		match self {
			Self::V22 => "V22",
			Self::V29 => "V29",
			Self::V32 => "V32",
			Self::V32Bis => "V32b",
			Self::V34 => "V34",
			Self::V90Client => "V90C",
			Self::V90Server => "V90S",
			Self::V32Terbo => "V32T",
			Self::VFastClass => "VFC",
			Self::Hst => "HST",
			Self::H14 => "H14",
			Self::H16 => "H16",
			Self::X2Client => "X2C",
			Self::X2Server => "X2S",
			Self::Zyxel168 => "ZYX",
			Self::Zyxel192 => "Z19",
			Self::HayesV9600 => "H96",
			Self::Pep => "PEP",
			Self::Csp => "CSP",
			Self::Mnp => "MNP",
			Self::V42 => "V42",
			Self::V42Bis => "V42b",
			Self::V110Low => "V110L",
			Self::V110High => "V110H",
			Self::V120Low => "V120L",
			Self::V120High => "V120H",
			Self::X75 => "X75",
			Self::Isdn => "ISDN",
		}
	}

	fn order(self) -> u32 {
		let position = PSTN_NAMES
			.iter()
			.position(|name| *name == self.name())
			.expect("every typed PSTN flag has a registry position");
		u32::try_from(position).expect("the fixed registry fits in u32")
	}
}

impl fmt::Display for PstnIsdnFlag {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternetFlag {
	DefaultServer(ServerAddress),
	Tith {
		endpoint: EndpointSpec,
		public_key: PublicKey,
	},
	Binkp(EndpointSpec),
	Ifcico(EndpointSpec),
	Ftp(EndpointSpec),
	Telnet(EndpointSpec),
	Vmodem(EndpointSpec),
	Unspecified(EndpointSpec),
	NoIncomingIpv4,
}

impl InternetFlag {
	fn order(&self) -> u8 {
		match self {
			Self::DefaultServer(_) => 0,
			Self::Tith { .. } => 1,
			Self::Binkp(_) => 2,
			Self::Ifcico(_) => 3,
			Self::Ftp(_) => 4,
			Self::Telnet(_) => 5,
			Self::Vmodem(_) => 6,
			Self::Unspecified(_) => 7,
			Self::NoIncomingIpv4 => 8,
		}
	}

	#[must_use]
	pub fn registered_default_port(&self) -> Option<u16> {
		match self {
			Self::Binkp(_) => Some(24_554),
			Self::Ifcico(_) => Some(60_179),
			Self::Ftp(_) => Some(21),
			Self::Telnet(_) => Some(23),
			Self::Vmodem(_) => Some(3141),
			Self::DefaultServer(_)
			| Self::Tith { .. }
			| Self::Unspecified(_)
			| Self::NoIncomingIpv4 => None,
		}
	}
}

impl fmt::Display for InternetFlag {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::DefaultServer(server) => write!(f, "INA:{server}"),
			Self::Tith {
				endpoint,
				public_key,
			} => {
				let key = STANDARD_NO_PAD.encode(public_key.as_bytes());
				if endpoint.server.is_none() && endpoint.port.is_none() {
					write!(f, "IIH:{key}")
				} else {
					write!(f, "IIH:{endpoint}:{key}")
				}
			}
			Self::Binkp(endpoint) => display_protocol(f, "IBN", endpoint),
			Self::Ifcico(endpoint) => display_protocol(f, "IFC", endpoint),
			Self::Ftp(endpoint) => display_protocol(f, "IFT", endpoint),
			Self::Telnet(endpoint) => display_protocol(f, "ITN", endpoint),
			Self::Vmodem(endpoint) => display_protocol(f, "IVM", endpoint),
			Self::Unspecified(endpoint) => display_protocol(f, "IP", endpoint),
			Self::NoIncomingIpv4 => f.write_str("INO4"),
		}
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmailFlag {
	Default(Option<EmailAddress>),
	Transx(Option<EmailAddress>),
	Uuencode(Option<EmailAddress>),
	Mime(Option<EmailAddress>),
	Seat(Option<EmailAddress>),
	Voyager(Option<EmailAddress>),
	OtherMethod(Option<EmailAddress>),
}

impl EmailFlag {
	fn order(&self) -> u8 {
		match self {
			Self::Default(_) => 0,
			Self::Transx(_) => 1,
			Self::Uuencode(_) => 2,
			Self::Mime(_) => 3,
			Self::Seat(_) => 4,
			Self::Voyager(_) => 5,
			Self::OtherMethod(_) => 6,
		}
	}
}

impl fmt::Display for EmailFlag {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let (name, address) = match self {
			Self::Default(address) => ("IEM", address),
			Self::Transx(address) => ("ITX", address),
			Self::Uuencode(address) => ("IUC", address),
			Self::Mime(address) => ("IMI", address),
			Self::Seat(address) => ("ISE", address),
			Self::Voyager(address) => ("EVY", address),
			Self::OtherMethod(address) => ("EMA", address),
		};
		f.write_str(name)?;
		if let Some(address) = address {
			write!(f, ":{address}")?;
		}
		Ok(())
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OtherFlag {
	MailOnly,
	EmailGateway,
	Ping,
	Trace,
	ZoneEchomailCoordinator,
	RegionalEchomailCoordinator,
	NetworkEchomailCoordinator,
	NetworkCoordinator,
	SoftwareDistributionSystem,
	SecureMailHub,
	RegionalPointlistKeeper,
	NetPointlistKeeper,
	EncryptedMail,
	CdPoint,
	Extension(ExtensionFlag),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtensionFlag(String);

impl ExtensionFlag {
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl FromStr for ExtensionFlag {
	type Err = NodelistErrorKind;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		if (1..=32).contains(&value.len())
			&& value.bytes().all(|byte| byte.is_ascii_alphanumeric())
			&& !assigned_name(value)
		{
			Ok(Self(value.to_owned()))
		} else {
			Err(NodelistErrorKind::InvalidFlag)
		}
	}
}

impl fmt::Display for ExtensionFlag {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl OtherFlag {
	fn name(&self) -> &str {
		match self {
			Self::MailOnly => "MO",
			Self::EmailGateway => "GUUCP",
			Self::Ping => "PING",
			Self::Trace => "TRACE",
			Self::ZoneEchomailCoordinator => "ZEC",
			Self::RegionalEchomailCoordinator => "REC",
			Self::NetworkEchomailCoordinator => "NEC",
			Self::NetworkCoordinator => "NC",
			Self::SoftwareDistributionSystem => "SDS",
			Self::SecureMailHub => "SMH",
			Self::RegionalPointlistKeeper => "RPK",
			Self::NetPointlistKeeper => "NPK",
			Self::EncryptedMail => "ENC",
			Self::CdPoint => "CDP",
			Self::Extension(value) => value.as_str(),
		}
	}

	fn assigned_order(&self) -> Option<usize> {
		(!matches!(self, Self::Extension(_))).then(|| {
			OTHER_NAMES
				.iter()
				.position(|name| *name == self.name())
				.expect("every assigned Other flag has a registry position")
		})
	}
}

impl fmt::Display for OtherFlag {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

const PSTN_NAMES: &[&str] = &[
	"V22", "V29", "V32", "V32b", "V34", "V90C", "V90S", "V32T", "VFC", "HST", "H14", "H16", "X2C",
	"X2S", "ZYX", "Z19", "H96", "PEP", "CSP", "MNP", "V42", "V42b", "V110L", "V110H", "V120L",
	"V120H", "X75", "ISDN",
];

const OTHER_NAMES: &[&str] = &[
	"MO", "GUUCP", "PING", "TRACE", "ZEC", "REC", "NEC", "NC", "SDS", "SMH", "RPK", "NPK", "ENC",
	"CDP",
];

fn split_flags(value: &str) -> Result<Vec<&str>, NodelistErrorKind> {
	if value.is_empty() {
		return Ok(Vec::new());
	}
	let flags: Vec<_> = value.split(',').collect();
	if flags.iter().any(|flag| flag.is_empty()) {
		Err(NodelistErrorKind::InvalidFlag)
	} else {
		Ok(flags)
	}
}

fn check_order<T: fmt::Display>(
	flags: &[T],
	order: impl Fn(&T) -> u32,
) -> Result<(), NodelistErrorKind> {
	let mut previous = None;
	let mut seen = BTreeSet::new();
	for flag in flags {
		let current = order(flag);
		if previous.is_some_and(|previous| current < previous) || !seen.insert(flag.to_string()) {
			return Err(NodelistErrorKind::InvalidFlag);
		}
		previous = Some(current);
	}
	Ok(())
}

fn parse_half_hour(value: u8) -> Option<HalfHour> {
	match value {
		b'A'..=b'X' => Some(HalfHour((value - b'A') * 2)),
		b'a'..=b'x' => Some(HalfHour((value - b'a') * 2 + 1)),
		_ => None,
	}
}

fn half_hour_text(value: HalfHour) -> char {
	let hour = value.0 / 2;
	if value.0.is_multiple_of(2) {
		char::from(b'A' + hour)
	} else {
		char::from(b'a' + hour)
	}
}

pub(crate) fn parse_system(value: &str) -> Result<Vec<SystemFlag>, NodelistErrorKind> {
	let mut periods = BTreeSet::new();
	let flags = split_flags(value)?
		.into_iter()
		.map(|text| {
			let flag = match text {
				"CM" => SystemFlag::ContinuousMail,
				"LO" => SystemFlag::ListedOnly,
				"MN" => SystemFlag::ManualPackets,
				"ICM" => SystemFlag::InternetContinuousMail,
				"XA" => SystemFlag::FileRequest(FileRequestFlag::Xa),
				"XB" => SystemFlag::FileRequest(FileRequestFlag::Xb),
				"XC" => SystemFlag::FileRequest(FileRequestFlag::Xc),
				"XP" => SystemFlag::FileRequest(FileRequestFlag::Xp),
				"XR" => SystemFlag::FileRequest(FileRequestFlag::Xr),
				"XW" => SystemFlag::FileRequest(FileRequestFlag::Xw),
				"XX" => SystemFlag::FileRequest(FileRequestFlag::Xx),
				_ if text.len() == 3 && matches!(text.as_bytes()[0], b'#' | b'!') => {
					let hour: u8 = text[1..]
						.parse()
						.map_err(|_| NodelistErrorKind::InvalidFlag)?;
					if hour > 23 || !periods.insert(hour) {
						return Err(NodelistErrorKind::InvalidFlag);
					}
					SystemFlag::MailPeriod(MailPeriod {
						bell_212a: text.starts_with('#'),
						hour,
					})
				}
				_ if text.len() == 3 && text.starts_with('T') => {
					let bytes = text.as_bytes();
					SystemFlag::OnlinePeriod(OnlinePeriod {
						start: parse_half_hour(bytes[1]).ok_or(NodelistErrorKind::InvalidFlag)?,
						end: parse_half_hour(bytes[2]).ok_or(NodelistErrorKind::InvalidFlag)?,
					})
				}
				_ => return Err(NodelistErrorKind::InvalidFlag),
			};
			Ok(flag)
		})
		.collect::<Result<Vec<_>, _>>()?;
	check_order(&flags, SystemFlag::order)?;
	Ok(flags)
}

pub(crate) fn parse_pstn_isdn(value: &str) -> Result<Vec<PstnIsdnFlag>, NodelistErrorKind> {
	let flags = split_flags(value)?
		.into_iter()
		.map(|text| match text {
			"V22" => Ok(PstnIsdnFlag::V22),
			"V29" => Ok(PstnIsdnFlag::V29),
			"V32" => Ok(PstnIsdnFlag::V32),
			"V32b" => Ok(PstnIsdnFlag::V32Bis),
			"V34" => Ok(PstnIsdnFlag::V34),
			"V90C" => Ok(PstnIsdnFlag::V90Client),
			"V90S" => Ok(PstnIsdnFlag::V90Server),
			"V32T" => Ok(PstnIsdnFlag::V32Terbo),
			"VFC" => Ok(PstnIsdnFlag::VFastClass),
			"HST" => Ok(PstnIsdnFlag::Hst),
			"H14" => Ok(PstnIsdnFlag::H14),
			"H16" => Ok(PstnIsdnFlag::H16),
			"X2C" => Ok(PstnIsdnFlag::X2Client),
			"X2S" => Ok(PstnIsdnFlag::X2Server),
			"ZYX" => Ok(PstnIsdnFlag::Zyxel168),
			"Z19" => Ok(PstnIsdnFlag::Zyxel192),
			"H96" => Ok(PstnIsdnFlag::HayesV9600),
			"PEP" => Ok(PstnIsdnFlag::Pep),
			"CSP" => Ok(PstnIsdnFlag::Csp),
			"MNP" => Ok(PstnIsdnFlag::Mnp),
			"V42" => Ok(PstnIsdnFlag::V42),
			"V42b" => Ok(PstnIsdnFlag::V42Bis),
			"V110L" => Ok(PstnIsdnFlag::V110Low),
			"V110H" => Ok(PstnIsdnFlag::V110High),
			"V120L" => Ok(PstnIsdnFlag::V120Low),
			"V120H" => Ok(PstnIsdnFlag::V120High),
			"X75" => Ok(PstnIsdnFlag::X75),
			"ISDN" => Ok(PstnIsdnFlag::Isdn),
			_ => Err(NodelistErrorKind::InvalidFlag),
		})
		.collect::<Result<Vec<_>, _>>()?;
	check_order(&flags, |flag| flag.order())?;
	Ok(flags)
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

fn valid_dns_name(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 253
		&& !value.bytes().any(|byte| byte.is_ascii_uppercase())
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

fn canonical_ipv6(address: Ipv6Addr) -> String {
	let segments = address.segments();
	let mut best_start = None;
	let mut best_len = 0;
	let mut index = 0;
	while index < segments.len() {
		if segments[index] != 0 {
			index += 1;
			continue;
		}
		let start = index;
		while index < segments.len() && segments[index] == 0 {
			index += 1;
		}
		let len = index - start;
		if len >= 2 && len > best_len {
			best_start = Some(start);
			best_len = len;
		}
	}

	let mut output = String::new();
	let mut index = 0;
	while index < segments.len() {
		if best_start == Some(index) {
			output.push_str("::");
			index += best_len;
			continue;
		}
		if !output.is_empty() && !output.ends_with(':') {
			output.push(':');
		}
		write!(output, "{:x}", segments[index]).expect("writing to String cannot fail");
		index += 1;
	}
	output
}

fn parse_server(value: &str) -> Result<ServerAddress, NodelistErrorKind> {
	if let Some(inner) = value
		.strip_prefix('[')
		.and_then(|value| value.strip_suffix(']'))
	{
		let address: Ipv6Addr = inner
			.parse()
			.map_err(|_| NodelistErrorKind::InvalidEndpoint)?;
		if format!("[{}]", canonical_ipv6(address)) != value {
			return Err(NodelistErrorKind::InvalidEndpoint);
		}
	} else if value.parse::<Ipv4Addr>().is_ok() {
	} else if !valid_dns_name(value) {
		return Err(NodelistErrorKind::InvalidEndpoint);
	}
	Ok(ServerAddress(value.to_owned()))
}

fn parse_endpoint(value: &str) -> Result<EndpointSpec, NodelistErrorKind> {
	if value.is_empty() {
		return Ok(EndpointSpec {
			server: None,
			port: None,
		});
	}
	if let Some(port) = value.strip_prefix(':') {
		return Ok(EndpointSpec {
			server: None,
			port: Some(parse_port(port)?),
		});
	}
	if value.starts_with('[') {
		let close = value.find(']').ok_or(NodelistErrorKind::InvalidEndpoint)?;
		let server = parse_server(&value[..=close])?;
		let suffix = &value[close + 1..];
		let port = if suffix.is_empty() {
			None
		} else {
			Some(parse_port(
				suffix
					.strip_prefix(':')
					.ok_or(NodelistErrorKind::InvalidEndpoint)?,
			)?)
		};
		return Ok(EndpointSpec {
			server: Some(server),
			port,
		});
	}
	if let Some((server, port)) = value.rsplit_once(':') {
		return Ok(EndpointSpec {
			server: Some(parse_server(server)?),
			port: Some(parse_port(port)?),
		});
	}
	Ok(EndpointSpec {
		server: Some(parse_server(value)?),
		port: None,
	})
}

fn parse_protocol(text: &str, name: &str) -> Result<Option<EndpointSpec>, NodelistErrorKind> {
	let Some(rest) = text.strip_prefix(name) else {
		return Ok(None);
	};
	if rest.is_empty() {
		return Ok(Some(parse_endpoint("")?));
	}
	let value = rest
		.strip_prefix(':')
		.ok_or(NodelistErrorKind::InvalidFlag)?;
	Ok(Some(parse_endpoint(value)?))
}

fn parse_public_key(value: &str) -> Result<PublicKey, NodelistErrorKind> {
	if value.len() != 43 || value.contains('=') {
		return Err(NodelistErrorKind::InvalidPublicKey);
	}
	let bytes: [u8; 32] = STANDARD_NO_PAD
		.decode(value)
		.map_err(|_| NodelistErrorKind::InvalidPublicKey)?
		.try_into()
		.map_err(|_| NodelistErrorKind::InvalidPublicKey)?;
	Ok(PublicKey::from_bytes(bytes))
}

fn parse_iih(text: &str) -> Result<InternetFlag, NodelistErrorKind> {
	let value = text
		.strip_prefix("IIH:")
		.ok_or(NodelistErrorKind::InvalidFlag)?;
	let (endpoint, key) = value.rsplit_once(':').unwrap_or(("", value));
	Ok(InternetFlag::Tith {
		endpoint: parse_endpoint(endpoint)?,
		public_key: parse_public_key(key)?,
	})
}

fn display_protocol(
	f: &mut fmt::Formatter<'_>,
	name: &str,
	endpoint: &EndpointSpec,
) -> fmt::Result {
	f.write_str(name)?;
	if endpoint.server.is_some() || endpoint.port.is_some() {
		write!(f, ":{endpoint}")?;
	}
	Ok(())
}

pub(crate) fn parse_internet(value: &str) -> Result<Vec<InternetFlag>, NodelistErrorKind> {
	let flags = split_flags(value)?
		.into_iter()
		.map(|text| {
			let flag = if let Some(server) = text.strip_prefix("INA:") {
				InternetFlag::DefaultServer(parse_server(server)?)
			} else if text.starts_with("IIH:") {
				parse_iih(text)?
			} else if let Some(endpoint) = parse_protocol(text, "IBN")? {
				InternetFlag::Binkp(endpoint)
			} else if let Some(endpoint) = parse_protocol(text, "IFC")? {
				InternetFlag::Ifcico(endpoint)
			} else if let Some(endpoint) = parse_protocol(text, "IFT")? {
				InternetFlag::Ftp(endpoint)
			} else if let Some(endpoint) = parse_protocol(text, "ITN")? {
				InternetFlag::Telnet(endpoint)
			} else if let Some(endpoint) = parse_protocol(text, "IVM")? {
				InternetFlag::Vmodem(endpoint)
			} else if let Some(endpoint) = parse_protocol(text, "IP")? {
				InternetFlag::Unspecified(endpoint)
			} else if text == "INO4" {
				InternetFlag::NoIncomingIpv4
			} else {
				return Err(NodelistErrorKind::InvalidFlag);
			};
			if flag.to_string() != text {
				return Err(NodelistErrorKind::InvalidFlag);
			}
			Ok(flag)
		})
		.collect::<Result<Vec<_>, _>>()?;
	check_order(&flags, |flag| u32::from(flag.order()))?;
	let mut key = None;
	for flag in &flags {
		if let InternetFlag::Tith { public_key, .. } = flag {
			if key.is_some_and(|key| key != *public_key) {
				return Err(NodelistErrorKind::InvalidPublicKey);
			}
			key = Some(*public_key);
		}
	}
	Ok(flags)
}

fn parse_email_address(value: &str) -> Result<EmailAddress, NodelistErrorKind> {
	if value.is_empty()
		|| value
			.chars()
			.any(|character| character <= '\u{1f}' || matches!(character, '\u{7f}' | ','))
	{
		return Err(NodelistErrorKind::InvalidFlag);
	}
	Ok(EmailAddress(value.to_owned()))
}

enum EmailMatch {
	NoMatch,
	Bare,
	Address(EmailAddress),
}

type EmailConstructor = fn(Option<EmailAddress>) -> EmailFlag;

fn parse_email_flag(text: &str, name: &str) -> Result<EmailMatch, NodelistErrorKind> {
	let Some(rest) = text.strip_prefix(name) else {
		return Ok(EmailMatch::NoMatch);
	};
	if rest.is_empty() {
		return Ok(EmailMatch::Bare);
	}
	let address = rest
		.strip_prefix(':')
		.ok_or(NodelistErrorKind::InvalidFlag)?;
	Ok(EmailMatch::Address(parse_email_address(address)?))
}

fn assigned_name(text: &str) -> bool {
	matches!(
		text,
		"CM" | "LO"
			| "MN" | "ICM"
			| "XA" | "XB"
			| "XC" | "XP"
			| "XR" | "XW"
			| "XX" | "INA"
			| "IIH" | "IBN"
			| "IFC" | "IFT"
			| "ITN" | "IVM"
			| "IP" | "INO4"
			| "IEM" | "ITX"
			| "IUC" | "IMI"
			| "ISE" | "EVY"
			| "EMA"
	) || PSTN_NAMES.contains(&text)
		|| OTHER_NAMES.contains(&text)
		|| (text.len() == 3
			&& text.starts_with('T')
			&& parse_half_hour(text.as_bytes()[1]).is_some()
			&& parse_half_hour(text.as_bytes()[2]).is_some())
}

pub(crate) fn parse_email(value: &str) -> Result<Vec<EmailFlag>, NodelistErrorKind> {
	let flags = split_flags(value)?
		.into_iter()
		.map(|text| {
			let constructors: &[(&str, EmailConstructor)] = &[
				("IEM", EmailFlag::Default),
				("ITX", EmailFlag::Transx),
				("IUC", EmailFlag::Uuencode),
				("IMI", EmailFlag::Mime),
				("ISE", EmailFlag::Seat),
				("EVY", EmailFlag::Voyager),
				("EMA", EmailFlag::OtherMethod),
			];
			let mut flag = None;
			for (name, construct) in constructors {
				match parse_email_flag(text, name)? {
					EmailMatch::NoMatch => {}
					EmailMatch::Bare => {
						flag = Some(construct(None));
						break;
					}
					EmailMatch::Address(address) => {
						flag = Some(construct(Some(address)));
						break;
					}
				}
			}
			let flag = flag.ok_or(NodelistErrorKind::InvalidFlag)?;
			Ok(flag)
		})
		.collect::<Result<Vec<_>, _>>()?;
	check_order(&flags, |flag| u32::from(flag.order()))?;
	Ok(flags)
}

pub(crate) fn parse_other(value: &str) -> Result<Vec<OtherFlag>, NodelistErrorKind> {
	let flags = split_flags(value)?
		.into_iter()
		.map(|text| {
			let flag = match text {
				"MO" => OtherFlag::MailOnly,
				"GUUCP" => OtherFlag::EmailGateway,
				"PING" => OtherFlag::Ping,
				"TRACE" => OtherFlag::Trace,
				"ZEC" => OtherFlag::ZoneEchomailCoordinator,
				"REC" => OtherFlag::RegionalEchomailCoordinator,
				"NEC" => OtherFlag::NetworkEchomailCoordinator,
				"NC" => OtherFlag::NetworkCoordinator,
				"SDS" => OtherFlag::SoftwareDistributionSystem,
				"SMH" => OtherFlag::SecureMailHub,
				"RPK" => OtherFlag::RegionalPointlistKeeper,
				"NPK" => OtherFlag::NetPointlistKeeper,
				"ENC" => OtherFlag::EncryptedMail,
				"CDP" => OtherFlag::CdPoint,
				_ => OtherFlag::Extension(text.parse()?),
			};
			Ok(flag)
		})
		.collect::<Result<Vec<_>, _>>()?;

	let mut previous_assigned = None;
	let mut previous_extension: Option<&str> = None;
	for flag in &flags {
		if let Some(order) = flag.assigned_order() {
			if previous_extension.is_some()
				|| previous_assigned.is_some_and(|previous| order <= previous)
			{
				return Err(NodelistErrorKind::InvalidFlag);
			}
			previous_assigned = Some(order);
		} else {
			let value = flag.name();
			if previous_extension.is_some_and(|previous| value <= previous) {
				return Err(NodelistErrorKind::InvalidFlag);
			}
			previous_extension = Some(value);
		}
	}
	Ok(flags)
}

fn list_text<T: fmt::Display>(values: &[T]) -> String {
	values
		.iter()
		.map(ToString::to_string)
		.collect::<Vec<_>>()
		.join(",")
}

fn validate_list<T: fmt::Display + PartialEq>(
	values: &[T],
	parse: fn(&str) -> Result<Vec<T>, NodelistErrorKind>,
) -> Result<(), NodelistErrorKind> {
	parse(&list_text(values)).map(drop)
}

macro_rules! flag_list {
	($list:ident, $item:ty, $parse:ident) => {
		#[derive(Clone, Debug, Default, Eq, PartialEq)]
		pub struct $list(Vec<$item>);

		impl $list {
			#[must_use]
			pub fn into_vec(self) -> Vec<$item> {
				self.0
			}
		}

		impl TryFrom<Vec<$item>> for $list {
			type Error = NodelistErrorKind;

			fn try_from(values: Vec<$item>) -> Result<Self, Self::Error> {
				validate_list(&values, $parse)?;
				Ok(Self(values))
			}
		}

		impl FromStr for $list {
			type Err = NodelistErrorKind;

			fn from_str(value: &str) -> Result<Self, Self::Err> {
				Ok(Self($parse(value)?))
			}
		}

		impl Deref for $list {
			type Target = [$item];

			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}

		impl AsRef<[$item]> for $list {
			fn as_ref(&self) -> &[$item] {
				&self.0
			}
		}

		impl<'a> IntoIterator for &'a $list {
			type Item = &'a $item;
			type IntoIter = std::slice::Iter<'a, $item>;

			fn into_iter(self) -> Self::IntoIter {
				self.0.iter()
			}
		}

		impl fmt::Display for $list {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str(&list_text(&self.0))
			}
		}
	};
}

flag_list!(SystemFlags, SystemFlag, parse_system);
flag_list!(PstnIsdnFlags, PstnIsdnFlag, parse_pstn_isdn);
flag_list!(InternetFlags, InternetFlag, parse_internet);
flag_list!(EmailFlags, EmailFlag, parse_email);
flag_list!(OtherFlags, OtherFlag, parse_other);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternetProtocol {
	Tith,
	Binkp,
	Ifcico,
	Ftp,
	Telnet,
	Vmodem,
	Unspecified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInternetEndpoint {
	pub server: Option<ServerAddress>,
	pub port: Option<u16>,
}

impl ResolvedInternetEndpoint {
	#[must_use]
	pub const fn is_usable(&self) -> bool {
		self.server.is_some() && self.port.is_some()
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInternetService {
	pub protocol: InternetProtocol,
	pub public_key: Option<PublicKey>,
	pub endpoints: Vec<ResolvedInternetEndpoint>,
}

fn resolved_endpoints(
	endpoint: &EndpointSpec,
	defaults: &[ServerAddress],
	default_port: Option<u16>,
) -> Vec<ResolvedInternetEndpoint> {
	let port = endpoint.port.or(default_port);
	if let Some(server) = &endpoint.server {
		return vec![ResolvedInternetEndpoint {
			server: Some(server.clone()),
			port,
		}];
	}
	if defaults.is_empty() {
		return vec![ResolvedInternetEndpoint { server: None, port }];
	}
	defaults
		.iter()
		.cloned()
		.map(|server| ResolvedInternetEndpoint {
			server: Some(server),
			port,
		})
		.collect()
}

impl InternetFlags {
	#[must_use]
	pub fn no_incoming_ipv4(&self) -> bool {
		self.iter()
			.any(|flag| matches!(flag, InternetFlag::NoIncomingIpv4))
	}

	#[must_use]
	pub fn resolved_services(&self) -> Vec<ResolvedInternetService> {
		let defaults: Vec<_> = self
			.iter()
			.filter_map(|flag| match flag {
				InternetFlag::DefaultServer(server) => Some(server.clone()),
				_ => None,
			})
			.collect();
		self.iter()
			.filter_map(|flag| {
				let (protocol, public_key, endpoint, default_port) = match flag {
					InternetFlag::DefaultServer(_) | InternetFlag::NoIncomingIpv4 => return None,
					InternetFlag::Tith {
						endpoint,
						public_key,
					} => (InternetProtocol::Tith, Some(*public_key), endpoint, None),
					InternetFlag::Binkp(endpoint) => {
						(InternetProtocol::Binkp, None, endpoint, Some(24_554))
					}
					InternetFlag::Ifcico(endpoint) => {
						(InternetProtocol::Ifcico, None, endpoint, Some(60_179))
					}
					InternetFlag::Ftp(endpoint) => {
						(InternetProtocol::Ftp, None, endpoint, Some(21))
					}
					InternetFlag::Telnet(endpoint) => {
						(InternetProtocol::Telnet, None, endpoint, Some(23))
					}
					InternetFlag::Vmodem(endpoint) => {
						(InternetProtocol::Vmodem, None, endpoint, Some(3141))
					}
					InternetFlag::Unspecified(endpoint) => {
						(InternetProtocol::Unspecified, None, endpoint, None)
					}
				};
				Some(ResolvedInternetService {
					protocol,
					public_key,
					endpoints: resolved_endpoints(endpoint, &defaults, default_port),
				})
			})
			.collect()
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailMethod {
	Unspecified,
	Transx,
	Uuencode,
	Mime,
	Seat,
	Voyager,
	Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEmailMethod {
	pub method: EmailMethod,
	pub address: Option<EmailAddress>,
}

impl EmailFlags {
	#[must_use]
	pub fn resolved_methods(&self) -> Vec<ResolvedEmailMethod> {
		let defaults: Vec<_> = self
			.iter()
			.filter_map(|flag| match flag {
				EmailFlag::Default(Some(address)) => Some(address.clone()),
				_ => None,
			})
			.collect();
		let mut methods = Vec::new();
		for flag in self {
			if matches!(flag, EmailFlag::Default(None)) {
				methods.push(ResolvedEmailMethod {
					method: EmailMethod::Unspecified,
					address: None,
				});
				continue;
			}
			let (method, address): (EmailMethod, Option<&EmailAddress>) = match flag {
				EmailFlag::Default(_) => continue,
				EmailFlag::Transx(address) => (EmailMethod::Transx, address.as_ref()),
				EmailFlag::Uuencode(address) => (EmailMethod::Uuencode, address.as_ref()),
				EmailFlag::Mime(address) => (EmailMethod::Mime, address.as_ref()),
				EmailFlag::Seat(address) => (EmailMethod::Seat, address.as_ref()),
				EmailFlag::Voyager(address) => (EmailMethod::Voyager, address.as_ref()),
				EmailFlag::OtherMethod(address) => (EmailMethod::Other, address.as_ref()),
			};
			if let Some(address) = address {
				methods.push(ResolvedEmailMethod {
					method,
					address: Some(address.clone()),
				});
			} else if defaults.is_empty() {
				methods.push(ResolvedEmailMethod {
					method,
					address: None,
				});
			} else {
				methods.extend(defaults.iter().cloned().map(|address| ResolvedEmailMethod {
					method,
					address: Some(address),
				}));
			}
		}
		methods
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn text<T: fmt::Display>(flags: &[T]) -> Vec<String> {
		flags.iter().map(ToString::to_string).collect()
	}

	#[test]
	fn parses_every_assigned_simple_flag_in_canonical_order() {
		let system = "CM,LO,MN,ICM,XA,#02,!09,TAB,TuB";
		assert_eq!(text(&parse_system(system).unwrap()).join(","), system);

		let pstn = PSTN_NAMES.join(",");
		assert_eq!(text(&parse_pstn_isdn(&pstn).unwrap()).join(","), pstn);

		let other = OTHER_NAMES.join(",");
		assert_eq!(text(&parse_other(&other).unwrap()).join(","), other);
		for name in OTHER_NAMES {
			assert!(name.parse::<ExtensionFlag>().is_err(), "{name}");
		}
	}

	#[test]
	fn parses_internet_and_email_registries() {
		let key = STANDARD_NO_PAD.encode([7; 32]);
		let internet = format!(
			"INA:a.example,INA:b.example,IIH:{key},IBN,IFC::60180,IFT:ftp.example,ITN,IVM,IP::9,INO4"
		);
		let parsed = parse_internet(&internet).unwrap();
		assert_eq!(text(&parsed).join(","), internet);
		assert_eq!(parsed[2].registered_default_port(), None);
		assert_eq!(parsed[3].registered_default_port(), Some(24_554));
		assert_eq!(parsed[4].registered_default_port(), Some(60_179));

		let email = "IEM:sysop@example.org,ITX,IUC:u@example.org,IMI,ISE,EVY,EMA";
		assert_eq!(text(&parse_email(email).unwrap()).join(","), email);
	}

	#[test]
	fn rejects_wrong_categories_order_duplicates_and_alternate_case() {
		for (parser, value) in [
			(
				parse_system as fn(&str) -> Result<Vec<SystemFlag>, _>,
				"V22",
			),
			(parse_system, "LO,CM"),
			(parse_system, "CM,CM"),
			(parse_system, "#24"),
			(parse_system, "#02,!02"),
			(parse_system, "#02#09"),
		] {
			assert!(parser(value).is_err(), "{value}");
		}
		for value in ["V32B", "V42B", "V29,V22", "V22,V22", "TRACE"] {
			assert!(parse_pstn_isdn(value).is_err(), "{value}");
		}
		for value in ["IBN,INA:a.example", "IBN,IBN", "INA:A.example", "IIH:key"] {
			assert!(parse_internet(value).is_err(), "{value}");
		}
		for value in ["ITX,IEM:a@example", "IEM:", "ITX,ITX"] {
			assert!(parse_email(value).is_err(), "{value}");
		}
		for value in [
			"ZEC,PING",
			"WIDGET,ABC",
			"ABC,ABC",
			"bad-flag",
			"CM",
			"V22",
			"INA",
			"IBN",
			"IEM",
			"TAB",
		] {
			assert!(parse_other(value).is_err(), "{value}");
		}
	}

	#[test]
	fn endpoint_grammar_is_canonical_and_unambiguous() {
		for value in [
			"IBN",
			"IBN:24555",
			"IBN::24555",
			"IBN:mail.example:24555",
			"IBN:192.0.2.1",
			"IBN:[2001:db8::1]:24555",
		] {
			assert_eq!(text(&parse_internet(value).unwrap()), [value], "{value}");
		}
		for value in [
			"IBN:MAIL.example",
			"IBN:mail.example:024555",
			"IBN:[2001:0db8::1]",
			"IBN:2001:db8::1",
			"IBN::0",
		] {
			assert!(parse_internet(value).is_err(), "{value}");
		}

		let numeric = parse_internet("IBN:24555").unwrap();
		assert_eq!(
			numeric,
			[InternetFlag::Binkp(EndpointSpec {
				server: Some(ServerAddress("24555".to_owned())),
				port: None,
			})]
		);
		let port_only = parse_internet("IBN::24555").unwrap();
		assert_eq!(
			port_only,
			[InternetFlag::Binkp(EndpointSpec {
				server: None,
				port: Some(24_555),
			})]
		);
	}

	#[test]
	fn other_extensions_have_one_deterministic_slot() {
		let parsed = parse_other("MO,CDP,ABC,AThing,V32B,V42B,z9").unwrap();
		assert_eq!(
			text(&parsed),
			["MO", "CDP", "ABC", "AThing", "V32B", "V42B", "z9"]
		);
		for value in [
			"U,ABC",
			"ABC,MO",
			"AThing,ABC",
			"",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
		] {
			if value.is_empty() {
				assert!(parse_other(value).unwrap().is_empty());
			} else {
				assert!(parse_other(value).is_err(), "{value}");
			}
		}
	}
}
