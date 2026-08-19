//! The TSP-0013 section 4 inbound conversion, driven by one claim at a time.
//!
//! This owns the ordering the standard requires and nothing else: the daemon
//! supplies the IPC binding and the clock, and this decides what to publish and
//! when the item may be acknowledged.

use std::collections::BTreeMap;

use tith_ledger::{Ledger, LedgerError, Object, Record, State};
use tith_message_legacy::{Packet, PacketOptions, endpoint};
use tith_wire::bundle::KeyResolver;
use tith_wire::item::{ItemAuthentication, read_message, read_standalone_file};
use tith_wire::{OwnedTlv, types};

use crate::config::Configuration;
use crate::convert::{Context, Fidelity, to_legacy};
use crate::policy::{Action, Disposition, Refusal, diagnostic};
use crate::publish::{Publication, digest, publish};
use crate::tic::{TicOptions, to_tic, transfer_name};

/// What the adapter decided to do with one claimed item.
#[derive(Clone, Debug)]
pub enum Outcome {
	/// Objects are staged and ready to publish, then acknowledge.
	Publish {
		objects: Vec<Publication>,
		note: String,
	},
	/// Nothing is published. The payload is taken into administrative ownership
	/// and the item acknowledged.
	Orphan { reason: String },
	/// The item cannot be converted. `disposition` says whether that is
	/// terminal.
	Refuse {
		refusal: Refusal,
		disposition: Disposition,
	},
}

/// The identity a claim carries which the adapter needs.
#[derive(Clone, Debug)]
pub struct Claimed {
	pub inbound_id: String,
	pub payload_hash: [u8; 32],
	pub claim_token: String,
	pub peer: String,
	pub authentication: ItemAuthentication,
}

#[derive(Debug)]
pub enum InboundError {
	Ledger(LedgerError),
	/// The payload is not a decodable item.
	Payload(String),
	/// No link is configured for the claim's peer.
	UnknownPeer(String),
}

impl std::fmt::Display for InboundError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Ledger(error) => write!(f, "{error}"),
			Self::Payload(reason) => write!(f, "payload is not a usable item: {reason}"),
			Self::UnknownPeer(peer) => {
				write!(f, "no Link is configured for peer {peer}")
			}
		}
	}
}

impl std::error::Error for InboundError {}

impl From<LedgerError> for InboundError {
	fn from(value: LedgerError) -> Self {
		Self::Ledger(value)
	}
}

/// Decides what one claimed item becomes.
///
/// The ledger is consulted for `InboundID` before anything is converted, so a
/// redelivered item is recognised as already published rather than published a
/// second time.
pub fn plan(
	claim: &Claimed,
	payload: &[u8],
	configuration: &Configuration,
	ledger: &Ledger,
	resolver: &impl KeyResolver,
) -> Result<Option<Outcome>, InboundError> {
	// TSP-0013 section 4: if the ledger shows this exact InboundID and
	// PayloadHash were already published and transferred to adapter ownership,
	// the adapter does not publish a duplicate.
	if let Some(record) = ledger.get(&claim.inbound_id)?
		&& record.payload_hash == claim.payload_hash
		&& matches!(
			record.state,
			State::Published | State::Acknowledged | State::Retired
		) {
		return Ok(None);
	}

	let link = configuration
		.link_for(&claim.peer)
		.ok_or_else(|| InboundError::UnknownPeer(claim.peer.clone()))?;
	let context = Context {
		packet_origin: link.peer.clone(),
		packet_destination: link.local.clone(),
		domain: configuration.domain.clone(),
		product: configuration.product.clone(),
		version: configuration.version.clone(),
		area_tags: configuration.area_tags.clone(),
	};

	// The payload is exactly one encoded item TLV.
	let mut values = tith_wire::tlv::parse_sequence(payload)
		.map_err(|error| InboundError::Payload(error.to_string()))?;
	if values.len() != 1 {
		return Err(InboundError::Payload(format!(
			"payload holds {} values, not one item",
			values.len()
		)));
	}
	let item = values.remove(0);
	match item.type_code {
		types::MESSAGE => plan_message(claim, &item, configuration, &context, ledger, resolver),
		types::FILE => plan_file(claim, &item, configuration, &context, ledger),
		types::FILE_REQUEST => Ok(Some(Outcome::Refuse {
			refusal: Refusal::FileRequestUnsubmittable,
			disposition: configuration
				.refusals
				.disposition(&Refusal::FileRequestUnsubmittable),
		})),
		other => Err(InboundError::Payload(format!(
			"item type {other} is not deliverable to a tosser"
		))),
	}
}

fn plan_message(
	claim: &Claimed,
	item: &OwnedTlv,
	configuration: &Configuration,
	context: &Context,
	ledger: &Ledger,
	resolver: &impl KeyResolver,
) -> Result<Option<Outcome>, InboundError> {
	let read =
		read_message(item, resolver).map_err(|error| InboundError::Payload(error.to_string()))?;

	if configuration.policy.action(claim.authentication) == Action::Orphan {
		return Ok(Some(Outcome::Orphan {
			reason: format!(
				"policy orphans {:?}: {}",
				claim.authentication,
				diagnostic(claim.authentication).unwrap_or("no diagnostic")
			),
		}));
	}
	let warning = match configuration.policy.action(claim.authentication) {
		Action::DeliverWarn => diagnostic(claim.authentication),
		_ => None,
	};

	let converted = match to_legacy(&read, context, claim.authentication, warning, resolver) {
		Ok(converted) => converted,
		Err(error) => {
			let refusal = Refusal::Unconvertible(error.to_string());
			let disposition = configuration.refusals.disposition(&refusal);
			return Ok(Some(Outcome::Refuse {
				refusal,
				disposition,
			}));
		}
	};

	// Companions first, then the packet which names them.
	let mut objects = Vec::new();
	for attachment in &read.data.attachments {
		let identity = ledger.next_identity("object")?;
		let name = transfer_name(&attachment.filename, truncate(identity));
		objects.push(Publication {
			name,
			contents: attachment.contents.clone(),
		});
	}

	let packet = Packet {
		origin: endpoint_of(context, true),
		destination: endpoint_of(context, false),
		messages: vec![converted.message],
	};
	let identity = ledger.next_identity("object")?;
	let options = PacketOptions {
		created: current_local(),
		product_code: 0,
		revision_major: 0,
		revision_minor: 1,
		password: configuration
			.link_for(&claim.peer)
			.map(|link| link.password.clone())
			.unwrap_or_default(),
		product_data: 0,
	};
	let bytes = packet
		.encode(&options)
		.map_err(|error| InboundError::Payload(error.to_string()))?;
	objects.push(Publication {
		name: format!("{:08x}.pkt", truncate(identity)),
		contents: bytes,
	});

	let note = match converted.fidelity {
		Fidelity::Canonical => "canonical, TITHSIG retained".to_owned(),
		Fidelity::Compatibility => format!(
			"compatibility output: {}",
			converted.diagnostic.unwrap_or_default()
		),
	};
	Ok(Some(Outcome::Publish { objects, note }))
}

fn plan_file(
	claim: &Claimed,
	item: &OwnedTlv,
	configuration: &Configuration,
	context: &Context,
	ledger: &Ledger,
) -> Result<Option<Outcome>, InboundError> {
	let read =
		read_standalone_file(item).map_err(|error| InboundError::Payload(error.to_string()))?;

	if configuration.policy.action(claim.authentication) == Action::Orphan {
		return Ok(Some(Outcome::Orphan {
			reason: format!("policy orphans {:?}", claim.authentication),
		}));
	}

	let identity = ledger.next_identity("object")?;
	let name = transfer_name(&read.data.filename, truncate(identity));
	let tic = match to_tic(
		&read,
		context,
		&TicOptions {
			transfer_name: name.clone(),
			to: None,
			password: None,
		},
	) {
		Ok(tic) => tic,
		Err(error) => {
			let refusal = Refusal::Unconvertible(error.to_string());
			let disposition = configuration.refusals.disposition(&refusal);
			return Ok(Some(Outcome::Refuse {
				refusal,
				disposition,
			}));
		}
	};

	// The companion is published before the TIC which names it.
	let stem = name.split('.').next().unwrap_or("file").to_owned();
	Ok(Some(Outcome::Publish {
		objects: vec![
			Publication {
				name,
				contents: read.data.contents.clone(),
			},
			Publication {
				name: format!("{stem}.tic"),
				contents: tic.into_bytes(),
			},
		],
		note: "TIC distribution".to_owned(),
	}))
}

fn endpoint_of(context: &Context, origin: bool) -> tith_message_legacy::Endpoint {
	let address = if origin {
		&context.packet_origin
	} else {
		&context.packet_destination
	};
	crate::address::endpoint(address).unwrap_or_else(|_| endpoint(0, 0, 0, 0))
}

const fn truncate(identity: u64) -> u32 {
	(identity & 0xffff_ffff) as u32
}

fn current_local() -> i64 {
	i64::try_from(
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_or(0, |since| since.as_secs()),
	)
	.unwrap_or(0)
}

/// Stages the ledger record, publishes, and reports whether it succeeded.
///
/// The record is durable before publication, and the state advances to
/// Published only once every object is durable under its final name. Only then
/// may the caller acknowledge.
pub fn commit(
	claim: &Claimed,
	outcome: &Outcome,
	configuration: &Configuration,
	ledger: &Ledger,
) -> Result<Result<(), String>, InboundError> {
	let (objects, note) = match outcome {
		Outcome::Publish { objects, note } => (objects.clone(), note.clone()),
		Outcome::Orphan { reason } => {
			ledger.stage(&Record {
				inbound_id: claim.inbound_id.clone(),
				payload_hash: claim.payload_hash,
				state: State::Retired,
				objects: Vec::new(),
				note: format!("orphan: {reason}"),
				claim_token: claim.claim_token.clone(),
			})?;
			return Ok(Ok(()));
		}
		Outcome::Refuse { refusal, .. } => {
			return Ok(Err(refusal.to_string()));
		}
	};

	ledger.stage(&Record {
		inbound_id: claim.inbound_id.clone(),
		payload_hash: claim.payload_hash,
		state: State::Staged,
		objects: objects
			.iter()
			.map(|object| Object {
				name: object.name.clone(),
				digest: digest(&object.contents),
			})
			.collect(),
		note,
		claim_token: claim.claim_token.clone(),
	})?;

	match publish(&configuration.inbound, &objects) {
		Ok(Ok(())) => {
			ledger.advance(&claim.inbound_id, State::Published)?;
			Ok(Ok(()))
		}
		Ok(Err(taken)) => Ok(Err(format!("the name {taken} is already in use"))),
		Err(error) => Ok(Err(error.to_string())),
	}
}

/// Groups planned outcomes by their legacy link, for batched publication.
#[must_use]
pub fn group(outcomes: Vec<(Claimed, Outcome)>) -> BTreeMap<String, Vec<(Claimed, Outcome)>> {
	let mut grouped: BTreeMap<String, Vec<(Claimed, Outcome)>> = BTreeMap::new();
	for (claim, outcome) in outcomes {
		grouped
			.entry(claim.peer.clone())
			.or_default()
			.push((claim, outcome));
	}
	grouped
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::Configuration;
	use tith_crypto::SigningKeyPair;
	use tith_wire::Address;
	use tith_wire::bundle::Identity;
	use tith_wire::item::{ItemProvenance, MessageData, build_originated_message};

	const CONFIGURATION: &str = "\
Inbound INBOUND
Ledger  LEDGER
Domain  fidonet
Link uplink
\tPeer  fidonet#1:104/1
\tLocal fidonet#1:104/36
End
";

	struct Fixture {
		_directory: std::path::PathBuf,
		configuration: Configuration,
		ledger: Ledger,
		inbound: std::path::PathBuf,
	}

	fn fixture(name: &str) -> Fixture {
		let directory = std::env::temp_dir().join(format!(
			"tith-inbound-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = std::fs::remove_dir_all(&directory);
		let inbound = directory.join("inbound");
		std::fs::create_dir_all(&inbound).unwrap();
		let text = CONFIGURATION
			.replace("INBOUND", inbound.to_str().unwrap())
			.replace("LEDGER", directory.join("ledger.redb").to_str().unwrap());
		let configuration = Configuration::parse(&text).unwrap();
		let ledger = Ledger::open(&configuration.ledger).unwrap();
		Fixture {
			_directory: directory,
			configuration,
			ledger,
			inbound,
		}
	}

	fn message_item() -> (Vec<u8>, SigningKeyPair, Address) {
		let keys = SigningKeyPair::from_seed(&[99; 32]).unwrap();
		let origin: Address = "fidonet#1:104/1".parse().unwrap();
		let destination = Identity {
			address: "fidonet#1:104/36".parse().unwrap(),
			public_key: keys.public,
		};
		let item = build_originated_message(
			MessageData {
				destination: Some(destination),
				timestamp: 1_755_518_400,
				to_user: "Recipient".to_owned(),
				from_user: "Sender".to_owned(),
				subject: "Hello".to_owned(),
				text: "Body".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: Some(0),
				timestamp_offset: Some(0),
				tear_line: None,
				origin_line: None,
				message_id: Some("fidonet#1:104/1 1a2b3c4d".to_owned()),
				reply_to: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: keys.public,
				}),
			},
			&keys.secret,
			7,
			1_755_518_400,
			"tith 0.1",
			&[],
		)
		.unwrap();
		(item.encode(), keys, origin)
	}

	fn claimed(authentication: ItemAuthentication) -> Claimed {
		Claimed {
			inbound_id: "I1".to_owned(),
			payload_hash: [7; 32],
			claim_token: "T1".to_owned(),
			peer: "fidonet#1:104/1".to_owned(),
			authentication,
		}
	}

	#[test]
	fn a_message_becomes_a_published_packet() {
		let fixture = fixture("publish");
		let (payload, keys, origin) = message_item();
		// The Destination key is resolved from the nodelist too, so the test
		// resolver must answer for both addresses.
		let resolver = move |address: &Address| {
			(address == &origin || address.to_string() == "fidonet#1:104/36").then_some(keys.public)
		};
		let claim = claimed(ItemAuthentication::OriginValid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.unwrap();
		let Outcome::Publish { .. } = &outcome else {
			panic!("expected a publication, got {outcome:?}");
		};
		assert!(
			commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
				.unwrap()
				.is_ok()
		);
		// Exactly one packet appeared, and the ledger says so.
		let published: Vec<_> = std::fs::read_dir(&fixture.inbound)
			.unwrap()
			.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
			.collect();
		assert_eq!(published.len(), 1, "{published:?}");
		assert!(
			std::path::Path::new(&published[0])
				.extension()
				.is_some_and(|extension| extension == "pkt"),
			"{published:?}"
		);
		assert_eq!(
			fixture.ledger.get("I1").unwrap().unwrap().state,
			State::Published
		);
		// The packet parses back.
		let bytes = std::fs::read(fixture.inbound.join(&published[0])).unwrap();
		let packet = Packet::parse(&bytes).unwrap();
		assert_eq!(packet.messages.len(), 1);
		assert_eq!(packet.messages[0].to_user, "Recipient");
	}

	#[test]
	fn a_redelivered_item_is_recognised_and_not_published_again() {
		let fixture = fixture("redeliver");
		let (payload, keys, origin) = message_item();
		// The Destination key is resolved from the nodelist too, so the test
		// resolver must answer for both addresses.
		let resolver = move |address: &Address| {
			(address == &origin || address.to_string() == "fidonet#1:104/36").then_some(keys.public)
		};
		let claim = claimed(ItemAuthentication::OriginValid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.unwrap();
		commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();

		// The same InboundID and PayloadHash arrive again.
		assert!(
			plan(
				&claim,
				&payload,
				&fixture.configuration,
				&fixture.ledger,
				&resolver
			)
			.unwrap()
			.is_none(),
			"a redelivery must not plan a second publication"
		);
		assert_eq!(std::fs::read_dir(&fixture.inbound).unwrap().count(), 1);
	}

	#[test]
	fn an_invalid_item_is_orphaned_and_publishes_nothing() {
		let fixture = fixture("orphan");
		let (payload, keys, origin) = message_item();
		// The Destination key is resolved from the nodelist too, so the test
		// resolver must answer for both addresses.
		let resolver = move |address: &Address| {
			(address == &origin || address.to_string() == "fidonet#1:104/36").then_some(keys.public)
		};
		let claim = claimed(ItemAuthentication::OriginInvalid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.unwrap();
		assert!(matches!(outcome, Outcome::Orphan { .. }), "{outcome:?}");
		commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		assert_eq!(std::fs::read_dir(&fixture.inbound).unwrap().count(), 0);
		assert_eq!(
			fixture.ledger.get("I1").unwrap().unwrap().state,
			State::Retired
		);
	}

	#[test]
	fn a_file_request_is_refused_with_the_blocking_issue() {
		let fixture = fixture("request");
		let request = OwnedTlv::new(types::FILE_REQUEST, {
			let mut value = OwnedTlv::new(types::FILENAME, b"wanted.zip".to_vec())
				.unwrap()
				.encode();
			OwnedTlv::new(types::REQUEST_IDENTIFIER, tith_wire::encode_u64(1))
				.unwrap()
				.write_to(&mut value)
				.unwrap();
			value
		})
		.unwrap()
		.encode();
		let claim = claimed(ItemAuthentication::Transport);
		let resolver = |_: &Address| None;
		let outcome = plan(
			&claim,
			&request,
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.unwrap();
		let Outcome::Refuse {
			refusal,
			disposition,
		} = &outcome
		else {
			panic!("expected a refusal, got {outcome:?}");
		};
		assert_eq!(*refusal, Refusal::FileRequestUnsubmittable);
		// The default is to defer, because this becomes possible the moment the
		// blocking issue is resolved.
		assert_eq!(*disposition, Disposition::Defer);
		let reported = commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap_err();
		assert!(reported.contains("issue 16"), "{reported}");
		assert_eq!(std::fs::read_dir(&fixture.inbound).unwrap().count(), 0);
	}

	#[test]
	fn an_unknown_peer_is_an_error_rather_than_a_guess() {
		let fixture = fixture("peer");
		let (payload, keys, origin) = message_item();
		// The Destination key is resolved from the nodelist too, so the test
		// resolver must answer for both addresses.
		let resolver = move |address: &Address| {
			(address == &origin || address.to_string() == "fidonet#1:104/36").then_some(keys.public)
		};
		let mut claim = claimed(ItemAuthentication::OriginValid);
		claim.peer = "fidonet#2:200/7".to_owned();
		let error = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap_err();
		assert!(matches!(error, InboundError::UnknownPeer(_)), "{error}");
	}
}
