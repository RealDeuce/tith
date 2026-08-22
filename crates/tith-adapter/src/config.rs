//! The adapter's trusted local policy.
//!
//! TSP-0013 leaves this as "trusted local policy" without specifying a format,
//! so it reuses the TSP-0002 section 2 grammar rather than inventing a second
//! one: UTF-8, LF line endings, Space or Horizontal Tab separators, `;`
//! comments, and `End`-terminated blocks.
//!
//! ```text
//! Inbound /sbbs/fido/inbound
//! Ledger  /var/db/tith/adapter.redb
//! Domain  fidonet
//! Domain-Case Preserve
//! Product tith 0.1
//! Orphan-Notice NetMail Sysop
//!
//! Link uplink
//!     Peer     fidonet#1:104/1
//!     Local    fidonet#1:104/36
//!     Listed   Yes
//!     Password secret
//! End
//!
//! Area SYNCHRONET
//!     Tag SYNCHRONET
//! End
//!
//! Policy
//!     Unsigned              Deliver-Warn
//!     `SignedOrigin`-Valid    Deliver-Warn
//!     `SignedOrigin`-Invalid  Orphan
//!     Origin-Invalid        Orphan
//!     Unconvertible         Reject
//! End
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_config::{ConfigError, fields, lines};
use tith_crypto::{PUBLIC_KEY_BYTES, PublicKey};
use tith_wire::Address;

use crate::policy::{Action, Disposition, Policy, Refusals};

/// Whether an orphan produces a terminal local administrative `NetMail`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrphanNotice {
	Disabled,
	NetMail(String),
}

/// TSP-0003 section 2 policy for the one configured legacy domain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DomainCase {
	#[default]
	Preserve,
	Lowercase,
}

impl DomainCase {
	#[must_use]
	pub fn apply(self, domain: &str) -> String {
		let mut domain = domain.to_owned();
		if self == Self::Lowercase {
			domain.make_ascii_lowercase();
		}
		domain
	}
}

/// One configured legacy link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
	pub peer: Address,
	pub local: Address,
	/// The authenticated immediate identity key required for anonymous peers.
	pub peer_key: Option<PublicKey>,
	/// Observer-relative listing state; independent of anonymous address syntax.
	pub listed: bool,
	/// The packet password. Legacy link data, never TITH authentication.
	pub password: String,
}

/// The complete adapter configuration.
#[derive(Clone, Debug)]
pub struct Configuration {
	pub inbound: PathBuf,
	pub ledger: PathBuf,
	pub domain: String,
	pub domain_case: DomainCase,
	pub product: String,
	pub version: String,
	/// Links by the peer address a claim reports.
	pub links: BTreeMap<String, Link>,
	/// Legacy tag by native `AreaName`.
	pub area_tags: BTreeMap<String, String>,
	pub policy: Policy,
	pub refusals: Refusals,
	/// Optional local notification after the exact item is safely quarantined.
	pub orphan_notice: OrphanNotice,
	/// The FSC-0086 request processor, when one is configured.
	pub request_processor: Option<PathBuf>,
}

const FILE: &str = "adapter";

fn fail(line: usize, message: impl Into<String>) -> ConfigError {
	ConfigError {
		file: FILE,
		line,
		message: message.into(),
	}
}

fn address(line: usize, value: &str) -> Result<Address, ConfigError> {
	value
		.parse()
		.map_err(|_| fail(line, format!("{value:?} is not a canonical address")))
}

fn action(line: usize, value: &str) -> Result<Action, ConfigError> {
	Ok(match value {
		"Deliver-Warn" => Action::DeliverWarn,
		"Orphan" => Action::Orphan,
		_ => return Err(fail(line, "expected Deliver-Warn or Orphan")),
	})
}

fn disposition(line: usize, value: &str) -> Result<Disposition, ConfigError> {
	Ok(match value {
		"Defer" => Disposition::Defer,
		"Reject" => Disposition::Reject,
		_ => return Err(fail(line, "expected Defer or Reject")),
	})
}

impl Configuration {
	/// Parses the adapter configuration.
	pub fn parse(input: &str) -> Result<Self, ConfigError> {
		let parsed = lines(FILE, input)?;
		let mut inbound = None;
		let mut ledger = None;
		let mut domain = None;
		let mut domain_case = DomainCase::default();
		let mut product = None;
		let mut version = None;
		let mut links: BTreeMap<String, Link> = BTreeMap::new();
		let mut area_tags: BTreeMap<String, String> = BTreeMap::new();
		let mut policy = Policy::default();
		let mut refusals = Refusals::default();
		let mut request_processor = None;
		let mut orphan_notice = OrphanNotice::NetMail("Sysop".to_owned());

		let mut index = 0;
		while index < parsed.len() {
			let line = &parsed[index];
			let values = fields(line);
			index += 1;
			match values.as_slice() {
				["Inbound", path] => inbound = Some(PathBuf::from(path)),
				["Ledger", path] => ledger = Some(PathBuf::from(path)),
				["Domain", value] => domain = Some((*value).to_owned()),
				["Domain-Case", value] => {
					domain_case = match *value {
						"Preserve" => DomainCase::Preserve,
						"Lowercase" => DomainCase::Lowercase,
						_ => return Err(fail(line.number, "expected Preserve or Lowercase")),
					};
				}
				["Product", name, number] => {
					product = Some((*name).to_owned());
					version = Some((*number).to_owned());
				}
				["Orphan-Notice", "Disabled"] => orphan_notice = OrphanNotice::Disabled,
				["Orphan-Notice", "NetMail", user @ ..] => {
					let user = user.join(" ");
					if user.is_empty() || user.len() > 35 || user.contains('\0') {
						return Err(fail(
							line.number,
							"Orphan-Notice NetMail user must be 1 through 35 bytes",
						));
					}
					orphan_notice = OrphanNotice::NetMail(user);
				}
				["Request-Processor", path] => request_processor = Some(PathBuf::from(path)),
				["Link", name] => {
					let (configured, next) = parse_link(&parsed, index)?;
					index = next;
					if links.insert((*name).to_owned(), configured).is_some() {
						return Err(fail(line.number, format!("duplicate Link {name}")));
					}
				}
				["Area", name] => {
					let (tag, next) = parse_area(&parsed, index)?;
					index = next;
					// TSP-0003 section 7 requires one unique legacy tag per native
					// AreaName and rejects a configured collision.
					if area_tags.values().any(|existing| existing == &tag) {
						return Err(fail(
							line.number,
							format!("legacy tag {tag} is already used"),
						));
					}
					if area_tags.insert((*name).to_owned(), tag).is_some() {
						return Err(fail(line.number, format!("duplicate Area {name}")));
					}
				}
				["Policy"] => {
					let next = parse_policy(&parsed, index, &mut policy, &mut refusals)?;
					index = next;
				}
				_ => return Err(fail(line.number, "unknown directive")),
			}
		}

		let domain = domain.ok_or_else(|| fail(0, "Domain is required"))?;
		Address::anonymous(domain.clone())
			.map_err(|_| fail(0, "Domain is not a valid TTS-0004 Domain"))?;
		Ok(Self {
			inbound: inbound.ok_or_else(|| fail(0, "Inbound is required"))?,
			ledger: ledger.ok_or_else(|| fail(0, "Ledger is required"))?,
			domain,
			domain_case,
			product: product.unwrap_or_else(|| "tith".to_owned()),
			version: version.unwrap_or_else(|| "0.1".to_owned()),
			links,
			area_tags,
			policy,
			refusals,
			orphan_notice,
			request_processor,
		})
	}

	/// The link whose peer matches this claim's `Peer`.
	#[must_use]
	pub fn link_for(&self, peer: &Address, peer_key: &PublicKey) -> Option<&Link> {
		self.links.values().find(|link| {
			link.peer == *peer
				&& link
					.peer_key
					.is_none_or(|configured| configured == *peer_key)
		})
	}
}

fn public_key(line: usize, value: &str) -> Result<PublicKey, ConfigError> {
	let bytes: [u8; PUBLIC_KEY_BYTES] = STANDARD_NO_PAD
		.decode(value)
		.map_err(|_| fail(line, "Peer-Key is not canonical base 64"))?
		.try_into()
		.map_err(|_| fail(line, "Peer-Key is not 32 bytes"))?;
	if STANDARD_NO_PAD.encode(bytes) != value {
		return Err(fail(line, "Peer-Key is not canonical base 64"));
	}
	Ok(PublicKey::from_bytes(bytes))
}

fn parse_link(
	parsed: &[tith_config::Line],
	mut index: usize,
) -> Result<(Link, usize), ConfigError> {
	let mut peer: Option<Address> = None;
	let mut local: Option<Address> = None;
	let mut peer_key: Option<PublicKey> = None;
	let mut listed = None;
	let mut password = String::new();
	while index < parsed.len() {
		let line = &parsed[index];
		let values = fields(line);
		index += 1;
		match values.as_slice() {
			["End"] => {
				let peer = peer.ok_or_else(|| fail(line.number, "Link needs a Peer"))?;
				if peer.is_anonymous() && peer_key.is_none() {
					return Err(fail(line.number, "an anonymous Link needs a Peer-Key"));
				}
				return Ok((
					Link {
						peer,
						local: local.ok_or_else(|| fail(line.number, "Link needs a Local"))?,
						peer_key,
						listed: listed.ok_or_else(|| fail(line.number, "Link needs Listed"))?,
						password,
					},
					index,
				));
			}
			["Peer", value] => peer = Some(address(line.number, value)?),
			["Local", value] => local = Some(address(line.number, value)?),
			["Peer-Key", value] => peer_key = Some(public_key(line.number, value)?),
			["Listed", value] => {
				listed = Some(match *value {
					"Yes" => true,
					"No" => false,
					_ => return Err(fail(line.number, "expected Yes or No")),
				});
			}
			["Password", value] => {
				if value.len() > 8 {
					return Err(fail(
						line.number,
						"a packet password is at most eight bytes",
					));
				}
				(*value).clone_into(&mut password);
			}
			_ => return Err(fail(line.number, "unknown Link directive")),
		}
	}
	Err(fail(0, "Link block is not terminated"))
}

fn parse_area(
	parsed: &[tith_config::Line],
	mut index: usize,
) -> Result<(String, usize), ConfigError> {
	let mut tag = None;
	while index < parsed.len() {
		let line = &parsed[index];
		let values = fields(line);
		index += 1;
		match values.as_slice() {
			["End"] => {
				return Ok((
					tag.ok_or_else(|| fail(line.number, "Area needs a Tag"))?,
					index,
				));
			}
			["Tag", value] => tag = Some((*value).to_owned()),
			_ => return Err(fail(line.number, "unknown Area directive")),
		}
	}
	Err(fail(0, "Area block is not terminated"))
}

fn parse_policy(
	parsed: &[tith_config::Line],
	mut index: usize,
	policy: &mut Policy,
	refusals: &mut Refusals,
) -> Result<usize, ConfigError> {
	while index < parsed.len() {
		let line = &parsed[index];
		let values = fields(line);
		index += 1;
		match values.as_slice() {
			["End"] => return Ok(index),
			["Unsigned", value] => policy.unsigned = action(line.number, value)?,
			["SignedOrigin-Valid", value] => {
				policy.signed_origin_valid = action(line.number, value)?;
			}
			["SignedOrigin-Invalid", value] => {
				policy.signed_origin_invalid = action(line.number, value)?;
			}
			["Origin-Invalid", value] => policy.origin_invalid = action(line.number, value)?,
			["Reply-Origin", value] => {
				policy.reply_origin = match *value {
					"Enabled" => true,
					"Disabled" => false,
					_ => return Err(fail(line.number, "expected Enabled or Disabled")),
				};
			}
			["Unconvertible", value] => {
				refusals.unconvertible = disposition(line.number, value)?;
			}
			_ => return Err(fail(line.number, "unknown Policy directive")),
		}
	}
	Err(fail(0, "Policy block is not terminated"))
}

#[cfg(test)]
mod tests {
	use super::*;

	const SAMPLE: &str = "\
; The adapter's trusted local policy.
Inbound /sbbs/fido/inbound
Ledger  /var/db/tith/adapter.redb
Domain  fidonet
Domain-Case Preserve
Product tith 0.1

Link uplink
\tPeer     fidonet#1:104/1
\tLocal    fidonet#1:104/36
\tListed   Yes
\tPassword secret
End

Area SYNCHRONET
\tTag SYNCHRONET
End

Policy
\tUnsigned             Orphan
\tUnconvertible        Reject
End
";

	#[test]
	fn the_sample_configuration_parses() {
		let configuration = Configuration::parse(SAMPLE).unwrap();
		assert_eq!(configuration.inbound, PathBuf::from("/sbbs/fido/inbound"));
		assert_eq!(configuration.domain, "fidonet");
		assert_eq!(configuration.product, "tith");
		assert_eq!(configuration.version, "0.1");
		let key = PublicKey::from_bytes([0; PUBLIC_KEY_BYTES]);
		let link = configuration
			.link_for(&"fidonet#1:104/1".parse().unwrap(), &key)
			.unwrap();
		assert_eq!(link.password, "secret");
		assert!(link.listed);
		assert_eq!(link.local.to_string(), "fidonet#1:104/36");
		assert_eq!(configuration.domain_case, DomainCase::Preserve);
		assert_eq!(
			configuration
				.area_tags
				.get("SYNCHRONET")
				.map(String::as_str),
			Some("SYNCHRONET")
		);
		// A stated policy overrides its default; an unstated one keeps it.
		assert_eq!(configuration.policy.unsigned, Action::Orphan);
		assert_eq!(
			configuration.policy.signed_origin_valid,
			Action::DeliverWarn
		);
		assert!(!configuration.policy.reply_origin);
		assert_eq!(configuration.refusals.unconvertible, Disposition::Reject);
		assert_eq!(
			configuration.orphan_notice,
			OrphanNotice::NetMail("Sysop".to_owned())
		);
	}

	#[test]
	fn an_orphan_notice_can_be_disabled_or_addressed_to_another_user() {
		let disabled = format!("{SAMPLE}Orphan-Notice Disabled\n");
		assert_eq!(
			Configuration::parse(&disabled).unwrap().orphan_notice,
			OrphanNotice::Disabled
		);
		let addressed = format!("{SAMPLE}Orphan-Notice NetMail Security Sysop\n");
		assert_eq!(
			Configuration::parse(&addressed).unwrap().orphan_notice,
			OrphanNotice::NetMail("Security Sysop".to_owned())
		);
	}

	#[test]
	fn distribution_is_not_a_configurable_legacy_compatibility_mode() {
		for value in ["Native", "Legacy"] {
			let input = SAMPLE.replace(
				"\tUnconvertible        Reject",
				&format!("\tDistribution         {value}"),
			);
			let error = Configuration::parse(&input).unwrap_err();
			assert_eq!(error.message, "unknown Policy directive");
		}
	}

	#[test]
	fn a_duplicate_area_tag_is_rejected() {
		// TSP-0003 section 7 maps each native AreaName to one unique legacy tag
		// and rejects configured collisions.
		let input = format!("{SAMPLE}Area OTHER\n\tTag SYNCHRONET\nEnd\n");
		let error = Configuration::parse(&input).unwrap_err();
		assert!(error.message.contains("already used"), "{}", error.message);
	}

	#[test]
	fn every_required_directive_and_terminator_is_enforced() {
		assert!(Configuration::parse("Domain fidonet\n").is_err());
		assert!(Configuration::parse("Inbound /a\nLedger /b\n").is_err());
		assert!(Configuration::parse("Inbound /a\nLedger /b\nDomain d\n").is_ok());
		// An unterminated block, an unknown directive, and a bad value.
		assert!(Configuration::parse("Inbound /a\nLedger /b\nDomain d\nLink x\n").is_err());
		assert!(Configuration::parse("Inbound /a\nLedger /b\nDomain d\nNonsense z\n").is_err());
		assert!(
			Configuration::parse("Inbound /a\nLedger /b\nDomain d\nPolicy\n\tUnsigned Yes\nEnd\n")
				.is_err()
		);
		// A packet password is at most eight bytes.
		assert!(
			Configuration::parse(
				"Inbound /a\nLedger /b\nDomain d\nLink x\n\tPeer fidonet#1\n\tLocal fidonet#2\n\tPassword toolongpassword\nEnd\n"
			)
			.is_err()
		);
	}

	#[test]
	fn domain_case_is_explicit_and_ascii_only() {
		let lowercase = SAMPLE.replace("Domain-Case Preserve", "Domain-Case Lowercase");
		let configuration = Configuration::parse(&lowercase).unwrap();
		assert_eq!(configuration.domain_case, DomainCase::Lowercase);
		assert_eq!(configuration.domain_case.apply("BBSДОМ"), "bbsДОМ");

		let defaulted = SAMPLE.replace("Domain-Case Preserve\n", "");
		assert_eq!(
			Configuration::parse(&defaulted).unwrap().domain_case,
			DomainCase::Preserve
		);
		let invalid = SAMPLE.replace("Domain-Case Preserve", "Domain-Case Fold");
		assert!(Configuration::parse(&invalid).is_err());
	}

	#[test]
	fn anonymous_links_require_and_match_the_exact_peer_key() {
		let encoded = STANDARD_NO_PAD.encode([7_u8; PUBLIC_KEY_BYTES]);
		let anonymous = SAMPLE.replace("fidonet#1:104/1", "p2p#-1").replace(
			"\tListed   Yes",
			&format!("\tPeer-Key {encoded}\n\tListed   No"),
		);
		let configuration = Configuration::parse(&anonymous).unwrap();
		let peer: Address = "p2p#-1".parse().unwrap();
		let matching = PublicKey::from_bytes([7; PUBLIC_KEY_BYTES]);
		let other = PublicKey::from_bytes([8; PUBLIC_KEY_BYTES]);
		let link = configuration.link_for(&peer, &matching).unwrap();
		assert!(!link.listed);
		assert!(configuration.link_for(&peer, &other).is_none());

		let missing = SAMPLE
			.replace("fidonet#1:104/1", "p2p#-1")
			.replace("\tListed   Yes", "\tListed   No");
		assert!(Configuration::parse(&missing).is_err());
		let malformed = anonymous.replace(&encoded, "AA");
		assert!(Configuration::parse(&malformed).is_err());
	}
}
