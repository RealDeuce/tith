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
//! Product tith 0.1
//!
//! Link uplink
//!     Peer     fidonet#1:104/1
//!     Local    fidonet#1:104/36
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
//!     Distribution          Native
//! End
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use tith_config::{ConfigError, fields, lines};
use tith_wire::Address;

use crate::policy::{Action, Disposition, Distribution, Policy, Refusals};

/// One configured legacy link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
	pub peer: Address,
	pub local: Address,
	/// The packet password. Legacy link data, never TITH authentication.
	pub password: String,
}

/// The complete adapter configuration.
#[derive(Clone, Debug)]
pub struct Configuration {
	pub inbound: PathBuf,
	pub ledger: PathBuf,
	pub domain: String,
	pub product: String,
	pub version: String,
	/// Links by the peer address a claim reports.
	pub links: BTreeMap<String, Link>,
	/// Legacy tag by native `AreaName`.
	pub area_tags: BTreeMap<String, String>,
	pub policy: Policy,
	pub refusals: Refusals,
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
		let mut product = None;
		let mut version = None;
		let mut links: BTreeMap<String, Link> = BTreeMap::new();
		let mut area_tags: BTreeMap<String, String> = BTreeMap::new();
		let mut policy = Policy::default();
		let mut refusals = Refusals::default();
		let mut request_processor = None;

		let mut index = 0;
		while index < parsed.len() {
			let line = &parsed[index];
			let values = fields(line);
			index += 1;
			match values.as_slice() {
				["Inbound", path] => inbound = Some(PathBuf::from(path)),
				["Ledger", path] => ledger = Some(PathBuf::from(path)),
				["Domain", value] => domain = Some((*value).to_owned()),
				["Product", name, number] => {
					product = Some((*name).to_owned());
					version = Some((*number).to_owned());
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

		Ok(Self {
			inbound: inbound.ok_or_else(|| fail(0, "Inbound is required"))?,
			ledger: ledger.ok_or_else(|| fail(0, "Ledger is required"))?,
			domain: domain.ok_or_else(|| fail(0, "Domain is required"))?,
			product: product.unwrap_or_else(|| "tith".to_owned()),
			version: version.unwrap_or_else(|| "0.1".to_owned()),
			links,
			area_tags,
			policy,
			refusals,
			request_processor,
		})
	}

	/// The link whose peer matches this claim's `Peer`.
	#[must_use]
	pub fn link_for(&self, peer: &str) -> Option<&Link> {
		self.links
			.values()
			.find(|link| link.peer.to_string() == peer)
	}
}

fn parse_link(
	parsed: &[tith_config::Line],
	mut index: usize,
) -> Result<(Link, usize), ConfigError> {
	let mut peer = None;
	let mut local = None;
	let mut password = String::new();
	while index < parsed.len() {
		let line = &parsed[index];
		let values = fields(line);
		index += 1;
		match values.as_slice() {
			["End"] => {
				return Ok((
					Link {
						peer: peer.ok_or_else(|| fail(line.number, "Link needs a Peer"))?,
						local: local.ok_or_else(|| fail(line.number, "Link needs a Local"))?,
						password,
					},
					index,
				));
			}
			["Peer", value] => peer = Some(address(line.number, value)?),
			["Local", value] => local = Some(address(line.number, value)?),
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
			["Distribution", value] => {
				policy.distribution = match *value {
					"Native" => Distribution::Native,
					"Legacy" => Distribution::Legacy,
					_ => return Err(fail(line.number, "expected Native or Legacy")),
				};
			}
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
Product tith 0.1

Link uplink
\tPeer     fidonet#1:104/1
\tLocal    fidonet#1:104/36
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
		let link = configuration.link_for("fidonet#1:104/1").unwrap();
		assert_eq!(link.password, "secret");
		assert_eq!(link.local.to_string(), "fidonet#1:104/36");
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
		assert_eq!(configuration.policy.distribution, Distribution::Native);
		assert_eq!(configuration.refusals.unconvertible, Disposition::Reject);
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
}
