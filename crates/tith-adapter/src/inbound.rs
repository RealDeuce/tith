//! The TSP-0013 section 4 inbound conversion, driven by one claim at a time.
//!
//! This owns the ordering the standard requires and nothing else: the daemon
//! supplies the IPC binding and the clock, and this decides what to publish and
//! when the item may be acknowledged.

use std::collections::BTreeMap;

use tith_crypto::PublicKey;
use tith_ledger::{Ledger, LedgerError, Object, QuarantineObject, Record, State};
use tith_message_legacy::{
	PackedMessage, Packet, PacketOptions, encode_body, endpoint, format_date_time,
};
use tith_wire::bundle::KeyResolver;
use tith_wire::item::{ItemAuthentication, read_file_request, read_message, read_standalone_file};
use tith_wire::{Address, OwnedTlv, types};

use crate::config::{Configuration, OrphanNotice};
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
		/// The legacy area tag when this item carries a distribution
		/// obligation, which TSP-0013 section 4 requires the ledger record.
		distribution: Option<String>,
		/// Whether that obligation can be discharged with a native
		/// `Job Forward`. TSP-0006 section 6 refuses one for an Unsigned or
		/// Invalid item, which is final-delivery work with no onward copy.
		forwardable: bool,
	},
	/// Nothing is published. The payload is taken into administrative ownership
	/// and the item acknowledged.
	Orphan {
		reason: String,
		authentication: String,
		payload: Vec<u8>,
		recovery: Vec<Publication>,
		/// A terminal local administrative `NetMail`, when configured.
		notice: Option<Publication>,
	},
	/// A `FileRequest`. Nothing is published; the caller runs the FSC-0086.001
	/// processor and submits each answering file as a TSP-0006 `Job Peer-File`
	/// addressed back to the requesting peer.
	ServeRequest {
		filename: String,
		/// The TTS-0005 condition: answer only if the file is newer than this.
		newer_than: Option<u64>,
	},
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
	pub peer: Address,
	pub peer_key: PublicKey,
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
	{
		match record.state {
			State::Acknowledged => return Ok(None),
			State::Retired => {
				if let Some(outcome) = pending_orphan_notice(ledger, &claim.inbound_id)? {
					return Ok(Some(outcome));
				}
				return Ok(None);
			}
			State::Published => {
				// Publication and the external action it creates are separate crash
				// boundaries. A native distribution remains owed until its Forward Job
				// is recorded, and a FileRequest reply is idempotently resubmitted until
				// the inbound claim can be acknowledged.
				if !record.distribution.is_empty() && record.forward_job.is_empty() {
					return Ok(Some(Outcome::Publish {
						objects: Vec::new(),
						note: record.note,
						distribution: Some(record.distribution),
						forwardable: is_forwardable(claim.authentication),
					}));
				}
				let mut values = tith_wire::tlv::parse_sequence(payload)
					.map_err(|error| InboundError::Payload(error.to_string()))?;
				if values.len() == 1 && values[0].type_code == types::FILE_REQUEST {
					return plan_file_request(&values.remove(0), configuration);
				}
				return Ok(None);
			}
			State::Staged => {
				if let Some(outcome) = pending_orphan_notice(ledger, &claim.inbound_id)? {
					return Ok(Some(outcome));
				}
			}
		}
	}

	let link = configuration
		.link_for(&claim.peer, &claim.peer_key)
		.ok_or_else(|| InboundError::UnknownPeer(claim.peer.to_string()))?;
	let context = Context {
		packet_origin: link.peer.clone(),
		packet_destination: link.local.clone(),
		domain: configuration.domain.clone(),
		domain_case: configuration.domain_case,
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
		types::MESSAGE => plan_message(
			claim,
			payload,
			&item,
			configuration,
			&context,
			ledger,
			resolver,
		),
		types::FILE => plan_file(claim, payload, &item, configuration, &context, ledger),
		types::FILE_REQUEST => plan_file_request(&item, configuration),
		other => Err(InboundError::Payload(format!(
			"item type {other} is not deliverable to a tosser"
		))),
	}
}

fn pending_orphan_notice(
	ledger: &Ledger,
	inbound_id: &str,
) -> Result<Option<Outcome>, InboundError> {
	let Some(orphan) = ledger.orphan(inbound_id)? else {
		return Ok(None);
	};
	if orphan.notice_published || orphan.notice.is_none() {
		return Ok(None);
	}
	Ok(Some(Outcome::Orphan {
		reason: orphan
			.reason
			.strip_prefix("orphan: ")
			.unwrap_or(&orphan.reason)
			.to_owned(),
		authentication: orphan.authentication,
		payload: orphan.payload,
		recovery: orphan
			.objects
			.into_iter()
			.map(|object| Publication {
				name: object.name,
				contents: object.contents,
			})
			.collect(),
		notice: orphan.notice.map(|notice| Publication {
			name: notice.name,
			contents: notice.contents,
		}),
	}))
}

/// A `FileRequest` is served by the configured FSC-0086.001 processor.
///
/// TSP-0011 section 5.1 says a receiver unwilling to serve one refuses it with
/// TTS-0005 Rejected before transport acceptance, and that once it is an inbound
/// item the ordinary consumer outcomes apply. A node with no processor is that
/// second case: it will never serve this request, so it is refused rather than
/// deferred forever.
fn plan_file_request(
	item: &OwnedTlv,
	configuration: &Configuration,
) -> Result<Option<Outcome>, InboundError> {
	let read = read_file_request(item).map_err(|error| InboundError::Payload(error.to_string()))?;
	if configuration.request_processor.is_none() {
		let refusal = Refusal::Unconvertible(
			"no Request-Processor is configured to serve a FileRequest".to_owned(),
		);
		let disposition = configuration.refusals.disposition(&refusal);
		return Ok(Some(Outcome::Refuse {
			refusal,
			disposition,
		}));
	}
	Ok(Some(Outcome::ServeRequest {
		filename: read.filename,
		newer_than: read.timestamp,
	}))
}

fn plan_message(
	claim: &Claimed,
	payload: &[u8],
	item: &OwnedTlv,
	configuration: &Configuration,
	context: &Context,
	ledger: &Ledger,
	resolver: &impl KeyResolver,
) -> Result<Option<Outcome>, InboundError> {
	let read =
		read_message(item, resolver).map_err(|error| InboundError::Payload(error.to_string()))?;
	let action = configuration.policy.action(claim.authentication);
	let notice = if action == Action::Orphan {
		configured_orphan_notice(
			claim,
			configuration,
			context,
			ledger,
			"Message",
			&read.data.subject,
		)?
	} else {
		None
	};
	let warning = match action {
		Action::DeliverWarn | Action::Orphan => diagnostic(claim.authentication),
		Action::Deliver => None,
	};

	let converted = match to_legacy(&read, context, claim.authentication, warning, resolver) {
		Ok(converted) => converted,
		Err(error) => {
			if action == Action::Orphan {
				return Ok(Some(orphaned(
					claim,
					payload,
					format!("policy orphan; no recovery conversion: {error}"),
					Vec::new(),
					notice,
				)));
			}
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

	let converted_area = converted.message.area.clone();
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
			.link_for(&claim.peer, &claim.peer_key)
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
	if action == Action::Orphan {
		return Ok(Some(orphaned(
			claim,
			payload,
			format!(
				"policy orphans {:?}: {}",
				claim.authentication,
				diagnostic(claim.authentication).unwrap_or("no diagnostic")
			),
			objects,
			notice,
		)));
	}
	let distribution = converted_area
		.clone()
		.filter(|_| is_forwardable(claim.authentication));
	Ok(Some(Outcome::Publish {
		objects,
		note,
		forwardable: distribution.is_some(),
		distribution,
	}))
}

/// TSP-0006 section 6: a Forward Job requires `Origin-Valid` or
/// `SignedOrigin-Valid`.
const fn is_forwardable(authentication: ItemAuthentication) -> bool {
	matches!(
		authentication,
		ItemAuthentication::OriginValid | ItemAuthentication::SignedOriginValid
	)
}

fn plan_file(
	claim: &Claimed,
	payload: &[u8],
	item: &OwnedTlv,
	configuration: &Configuration,
	context: &Context,
	ledger: &Ledger,
) -> Result<Option<Outcome>, InboundError> {
	let read =
		read_standalone_file(item).map_err(|error| InboundError::Payload(error.to_string()))?;
	let action = configuration.policy.action(claim.authentication);

	let identity = ledger.next_identity("object")?;
	let name = transfer_name(&read.data.filename, truncate(identity));
	let notice = match action {
		Action::DeliverWarn => Some(administrative_notice(
			claim,
			context,
			ledger,
			"Sysop",
			"TITH File authentication warning",
			"File",
			&name,
		)?),
		Action::Orphan => {
			configured_orphan_notice(claim, configuration, context, ledger, "File", &name)?
		}
		Action::Deliver => None,
	};

	// A peer-addressed File belongs to no area, so it has no TIC and owes no
	// onward copy. It is published on its own for the local sysop; an ARCmail
	// bundle handed to this node is the ordinary case.
	if read.data.area.is_none() {
		let objects = vec![Publication {
			name,
			contents: read.data.contents.clone(),
		}];
		if action == Action::Orphan {
			return Ok(Some(orphaned(
				claim,
				payload,
				format!("policy orphans {:?}", claim.authentication),
				objects,
				notice,
			)));
		}
		let mut objects = objects;
		if let Some(notice) = notice {
			objects.push(notice);
		}
		return Ok(Some(Outcome::Publish {
			objects,
			note: "peer-addressed File".to_owned(),
			distribution: None,
			forwardable: false,
		}));
	}

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
			if action == Action::Orphan {
				let recovery = vec![Publication {
					name,
					contents: read.data.contents.clone(),
				}];
				return Ok(Some(orphaned(
					claim,
					payload,
					format!("policy orphan; no recovery conversion: {error}"),
					recovery,
					notice,
				)));
			}
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
	let mut objects = vec![
		Publication {
			name,
			contents: read.data.contents.clone(),
		},
		Publication {
			name: format!("{stem}.tic"),
			contents: tic.into_bytes(),
		},
	];
	if action == Action::Orphan {
		return Ok(Some(orphaned(
			claim,
			payload,
			format!("policy orphans {:?}", claim.authentication),
			objects,
			notice,
		)));
	}
	if let Some(notice) = notice {
		objects.push(notice);
	}
	let forwardable = is_forwardable(claim.authentication);
	let distribution = if forwardable {
		Some(
			context
				.area_tag(read.data.area.as_deref().expect("area checked above"))
				.map_err(|error| InboundError::Payload(error.to_string()))?
				.to_owned(),
		)
	} else {
		None
	};
	Ok(Some(Outcome::Publish {
		objects,
		note: "TIC distribution".to_owned(),
		distribution,
		forwardable,
	}))
}

fn orphaned(
	claim: &Claimed,
	payload: &[u8],
	reason: String,
	recovery: Vec<Publication>,
	notice: Option<Publication>,
) -> Outcome {
	Outcome::Orphan {
		reason,
		authentication: authentication_name(claim.authentication).to_owned(),
		payload: payload.to_vec(),
		recovery,
		notice,
	}
}

fn configured_orphan_notice(
	claim: &Claimed,
	configuration: &Configuration,
	context: &Context,
	ledger: &Ledger,
	kind: &str,
	label: &str,
) -> Result<Option<Publication>, InboundError> {
	match &configuration.orphan_notice {
		OrphanNotice::Disabled => Ok(None),
		OrphanNotice::NetMail(user) => administrative_notice(
			claim,
			context,
			ledger,
			user,
			&format!("TITH orphaned {kind}"),
			kind,
			label,
		)
		.map(Some),
	}
}

fn administrative_notice(
	claim: &Claimed,
	context: &Context,
	ledger: &Ledger,
	recipient: &str,
	subject: &str,
	kind: &str,
	label: &str,
) -> Result<Publication, InboundError> {
	let diagnostic = diagnostic(claim.authentication).unwrap_or("no authentication diagnostic");
	let label = label.replace(['\0', '\r', '\n'], " ");
	let text = encode_body(&format!(
		"{diagnostic}\n\nAffected {kind}: {label}\nInboundID: {}\n",
		claim.inbound_id
	))
	.map_err(|error| InboundError::Payload(error.to_string()))?;
	let local = endpoint_of(context, false);
	let message = PackedMessage {
		origin: local,
		destination: local,
		attributes: 1,
		date_time: format_date_time(current_local())
			.map_err(|error| InboundError::Payload(error.to_string()))?,
		to_user: recipient.to_owned(),
		from_user: "TITH".to_owned(),
		subject: subject.to_owned(),
		controls: Vec::new(),
		text,
		area: None,
	};
	let packet = Packet {
		origin: local,
		destination: local,
		messages: vec![message],
	};
	let bytes = packet
		.encode(&PacketOptions {
			created: current_local(),
			product_code: 0,
			revision_major: 0,
			revision_minor: 1,
			password: String::new(),
			product_data: 0,
		})
		.map_err(|error| InboundError::Payload(error.to_string()))?;
	let identity = ledger.next_identity("object")?;
	Ok(Publication {
		name: format!("{:08x}.pkt", truncate(identity)),
		contents: bytes,
	})
}

const fn authentication_name(authentication: ItemAuthentication) -> &'static str {
	match authentication {
		ItemAuthentication::Unsigned => "Unsigned",
		ItemAuthentication::SignedOriginInvalid => "SignedOrigin-Invalid",
		ItemAuthentication::SignedOriginValid => "SignedOrigin-Valid",
		ItemAuthentication::OriginInvalid => "Origin-Invalid",
		ItemAuthentication::OriginValid => "Origin-Valid",
		ItemAuthentication::Transport => "Transport",
	}
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
	let (objects, note, distribution) = match outcome {
		Outcome::Publish {
			objects,
			note,
			distribution,
			..
		} => (
			objects.clone(),
			note.clone(),
			distribution.clone().unwrap_or_default(),
		),
		Outcome::Orphan {
			reason,
			authentication,
			payload,
			recovery,
			notice,
		} => {
			let record = Record {
				inbound_id: claim.inbound_id.clone(),
				payload_hash: claim.payload_hash,
				state: if notice.is_some() {
					State::Staged
				} else {
					State::Retired
				},
				objects: Vec::new(),
				note: format!("orphan: {reason}"),
				claim_token: claim.claim_token.clone(),
				distribution: String::new(),
				forward_job: String::new(),
				cleanup: Vec::new(),
			};
			let recovery = recovery
				.iter()
				.map(|object| QuarantineObject {
					name: object.name.clone(),
					contents: object.contents.clone(),
				})
				.collect::<Vec<_>>();
			let notice = notice.as_ref().map(|notice| QuarantineObject {
				name: notice.name.clone(),
				contents: notice.contents.clone(),
			});
			ledger.stage_orphan(&record, authentication, payload, &recovery, notice.as_ref())?;
			if let Some(notice) = notice {
				let publication = Publication {
					name: notice.name,
					contents: notice.contents,
				};
				let published =
					match publish(&configuration.inbound, std::slice::from_ref(&publication)) {
						Ok(Ok(())) => true,
						Ok(Err(taken)) if taken == publication.name => {
							let exact =
								std::fs::read(configuration.inbound.join(&publication.name))
									.is_ok_and(|contents| contents == publication.contents);
							if exact {
								let staged = configuration
									.inbound
									.join(format!(".tith-staging-{}", publication.name));
								if let Err(error) = std::fs::remove_file(staged)
									&& error.kind() != std::io::ErrorKind::NotFound
								{
									return Ok(Err(error.to_string()));
								}
							}
							exact
						}
						Ok(Err(taken)) => {
							return Ok(Err(format!("the name {taken} is already in use")));
						}
						Err(error) => return Ok(Err(error.to_string())),
					};
				if !published {
					return Ok(Err(format!(
						"the name {} is already in use",
						publication.name
					)));
				}
				ledger.mark_orphan_notice_published(&claim.inbound_id)?;
				ledger.advance(&claim.inbound_id, State::Retired)?;
			}
			return Ok(Ok(()));
		}
		// The record is durable before the processor runs, so a redelivery is
		// recognised rather than served twice. Submission itself is idempotent by
		// its key, which is derived from InboundID.
		Outcome::ServeRequest { filename, .. } => {
			ledger.stage(&Record {
				inbound_id: claim.inbound_id.clone(),
				payload_hash: claim.payload_hash,
				state: State::Published,
				objects: Vec::new(),
				note: format!("file request for {filename}"),
				claim_token: claim.claim_token.clone(),
				distribution: String::new(),
				forward_job: String::new(),
				cleanup: Vec::new(),
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
		distribution,
		forward_job: String::new(),
		cleanup: Vec::new(),
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
			.entry(claim.peer.to_string())
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
	use tith_wire::item::{
		ItemProvenance, MessageData, StandaloneFileData, build_originated_file,
		build_originated_message,
	};

	const CONFIGURATION: &str = "\
Inbound INBOUND
Ledger  LEDGER
Domain  fidonet
Link uplink
\tPeer  fidonet#1:104/1
\tLocal fidonet#1:104/36
\tListed Yes
End
Area SYNCHRONET
\tTag SYNCHRONET
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
			&MessageData {
				destination: Some(destination),
				timestamp: 1_755_518_400,
				to_user: "Recipient".to_owned(),
				from_user: "Sender".to_owned(),
				subject: "Hello".to_owned(),
				text: "Body\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
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

	fn echomail_item() -> (Vec<u8>, SigningKeyPair, Address) {
		let keys = SigningKeyPair::from_seed(&[98; 32]).unwrap();
		let origin: Address = "fidonet#1:104/1".parse().unwrap();
		let item = build_originated_message(
			&MessageData {
				destination: None,
				timestamp: 1_755_518_400,
				to_user: "All".to_owned(),
				from_user: "Sender".to_owned(),
				subject: "Hello".to_owned(),
				text: "Body\n".to_owned(),
				area: Some("SYNCHRONET".to_owned()),
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: Some("TITH".to_owned()),
				origin_line: Some("A board (1:104/1)".to_owned()),
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
			8,
			1_755_518_400,
			"tith 0.1",
			&["fidonet#1:104/36".parse().unwrap()],
		)
		.unwrap();
		(item.encode(), keys, origin)
	}

	fn distribution_file_item() -> Vec<u8> {
		let keys = SigningKeyPair::from_seed(&[97; 32]).unwrap();
		let origin: Address = "fidonet#1:104/1".parse().unwrap();
		build_originated_file(
			StandaloneFileData {
				filename: "work.zip".to_owned(),
				timestamp: Some(1_755_400_000),
				contents: b"file payload".to_vec(),
				area: Some("SYNCHRONET".to_owned()),
				short_description: Some("A file".to_owned()),
				long_description_lines: Vec::new(),
				tear_line: None,
				magic_word: None,
				replaces: None,
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin,
					public_key: keys.public,
				}),
			},
			&keys.secret,
			9,
			1_755_500_001,
			"tith 0.1",
			&["fidonet#1:104/36".parse().unwrap()],
		)
		.unwrap()
		.encode()
	}

	fn claimed(authentication: ItemAuthentication) -> Claimed {
		Claimed {
			inbound_id: "I1".to_owned(),
			payload_hash: [7; 32],
			claim_token: "T1".to_owned(),
			peer: "fidonet#1:104/1".parse().unwrap(),
			peer_key: PublicKey::from_bytes([0; 32]),
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
	fn an_invalid_message_is_quarantined_and_only_its_notice_is_published() {
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
		let published = std::fs::read_dir(&fixture.inbound)
			.unwrap()
			.map(|entry| entry.unwrap().path())
			.collect::<Vec<_>>();
		assert_eq!(published.len(), 1, "only the notice is locally delivered");
		let notice = Packet::parse(&std::fs::read(&published[0]).unwrap()).unwrap();
		assert_eq!(notice.messages[0].to_user, "Sysop");
		assert!(notice.messages[0].text.starts_with("ERROR:"));
		assert_eq!(
			fixture.ledger.get("I1").unwrap().unwrap().state,
			State::Retired
		);
		let orphan = fixture
			.ledger
			.orphan("I1")
			.unwrap()
			.expect("the exact orphan is retained");
		assert_eq!(orphan.authentication, "Origin-Invalid");
		assert_eq!(orphan.payload, payload);
		assert_eq!(orphan.objects.len(), 1, "the recovery packet is retained");
		let packet = Packet::parse(&orphan.objects[0].contents).unwrap();
		assert!(packet.messages[0].text.starts_with("ERROR:"));
	}

	#[test]
	fn a_deliver_warn_file_gets_an_adjacent_sysop_netmail_without_changing_contents() {
		let fixture = fixture("file-warning");
		let payload = distribution_file_item();
		let claim = claimed(ItemAuthentication::SignedOriginValid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&|_: &Address| None,
		)
		.unwrap()
		.unwrap();
		let Outcome::Publish { objects, .. } = &outcome else {
			panic!("expected publication, got {outcome:?}");
		};
		assert_eq!(
			objects
				.iter()
				.find(|object| {
					std::path::Path::new(&object.name)
						.extension()
						.is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
				})
				.unwrap()
				.contents,
			b"file payload"
		);
		let notice = objects
			.iter()
			.find(|object| {
				std::path::Path::new(&object.name)
					.extension()
					.is_some_and(|extension| extension.eq_ignore_ascii_case("pkt"))
			})
			.expect("adjacent notice packet");
		let packet = Packet::parse(&notice.contents).unwrap();
		assert_eq!(packet.messages.len(), 1);
		assert_eq!(packet.messages[0].to_user, "Sysop");
		assert!(packet.messages[0].text.starts_with("NOTICE:"));
		assert!(packet.messages[0].text.contains("work.zip"));
		assert!(packet.messages[0].text.contains("I1"));
	}

	#[test]
	fn an_orphaned_file_publishes_only_its_configured_notice() {
		let fixture = fixture("file-orphan-notice");
		let payload = distribution_file_item();
		let claim = claimed(ItemAuthentication::OriginInvalid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&|_: &Address| None,
		)
		.unwrap()
		.unwrap();
		let Outcome::Orphan { notice, .. } = &outcome else {
			panic!("expected orphan, got {outcome:?}");
		};
		assert!(notice.is_some());
		commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		let published = std::fs::read_dir(&fixture.inbound)
			.unwrap()
			.map(|entry| entry.unwrap().path())
			.collect::<Vec<_>>();
		assert_eq!(published.len(), 1, "only the notice is locally delivered");
		let packet = Packet::parse(&std::fs::read(&published[0]).unwrap()).unwrap();
		assert_eq!(packet.messages[0].to_user, "Sysop");
		assert!(packet.messages[0].text.starts_with("ERROR:"));
		let orphan = fixture.ledger.orphan("I1").unwrap().unwrap();
		assert_eq!(orphan.payload, payload);
		assert_eq!(orphan.objects.len(), 2, "the file and TIC stay quarantined");
		assert!(orphan.notice_published);
	}

	#[test]
	fn disabling_orphan_notice_keeps_every_legacy_object_out_of_the_inbound() {
		let mut fixture = fixture("file-orphan-silent");
		fixture.configuration.orphan_notice = OrphanNotice::Disabled;
		let payload = distribution_file_item();
		let claim = claimed(ItemAuthentication::OriginInvalid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&|_: &Address| None,
		)
		.unwrap()
		.unwrap();
		let Outcome::Orphan { notice, .. } = &outcome else {
			panic!("expected orphan, got {outcome:?}");
		};
		assert!(notice.is_none());
		commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		assert_eq!(std::fs::read_dir(&fixture.inbound).unwrap().count(), 0);
		assert!(fixture.ledger.orphan("I1").unwrap().is_some());
	}

	#[test]
	fn an_interrupted_orphan_notice_reuses_its_durable_name() {
		let fixture = fixture("file-orphan-resume");
		let payload = distribution_file_item();
		let claim = claimed(ItemAuthentication::OriginInvalid);
		let outcome = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&|_: &Address| None,
		)
		.unwrap()
		.unwrap();
		let Outcome::Orphan {
			reason,
			authentication,
			payload: retained,
			recovery,
			notice: Some(notice),
		} = outcome
		else {
			panic!("expected an orphan with a notice");
		};
		let record = Record {
			inbound_id: claim.inbound_id.clone(),
			payload_hash: claim.payload_hash,
			state: State::Staged,
			objects: Vec::new(),
			note: format!("orphan: {reason}"),
			claim_token: claim.claim_token.clone(),
			distribution: String::new(),
			forward_job: String::new(),
			cleanup: Vec::new(),
		};
		let recovery = recovery
			.into_iter()
			.map(|object| QuarantineObject {
				name: object.name,
				contents: object.contents,
			})
			.collect::<Vec<_>>();
		let durable_notice = QuarantineObject {
			name: notice.name.clone(),
			contents: notice.contents.clone(),
		};
		fixture
			.ledger
			.stage_orphan(
				&record,
				&authentication,
				&retained,
				&recovery,
				Some(&durable_notice),
			)
			.unwrap();
		// The notice reached its final name, but the process stopped before it
		// could record that fact.
		std::fs::write(fixture.inbound.join(&notice.name), &notice.contents).unwrap();

		let resumed = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&|_: &Address| None,
		)
		.unwrap()
		.unwrap();
		let Outcome::Orphan {
			notice: Some(resumed_notice),
			..
		} = &resumed
		else {
			panic!("the pending notice was not resumed");
		};
		assert_eq!(resumed_notice.name, notice.name);
		commit(&claim, &resumed, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		let orphan = fixture.ledger.orphan("I1").unwrap().unwrap();
		assert!(orphan.notice_published);
		assert_eq!(
			fixture.ledger.get("I1").unwrap().unwrap().state,
			State::Retired
		);
		assert_eq!(std::fs::read_dir(&fixture.inbound).unwrap().count(), 1);
	}

	/// One encoded `FileRequest` for `wanted.zip`.
	fn file_request() -> Vec<u8> {
		OwnedTlv::new(types::FILE_REQUEST, {
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
		.encode()
	}

	#[test]
	fn a_file_request_is_served_when_a_processor_is_configured() {
		let mut fixture = fixture("request");
		fixture.configuration.request_processor =
			Some(std::path::PathBuf::from("/usr/local/bin/frq"));
		let claim = claimed(ItemAuthentication::Transport);
		let resolver = |_: &Address| None;
		let outcome = plan(
			&claim,
			&file_request(),
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.unwrap();
		let Outcome::ServeRequest {
			filename,
			newer_than,
		} = &outcome
		else {
			panic!("expected a request to serve, got {outcome:?}");
		};
		assert_eq!(filename, "wanted.zip");
		assert_eq!(*newer_than, None);
		// Nothing is published: the answer is submitted, not laid down for a
		// tosser. The ledger record still lands, so a redelivery is recognised.
		commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		assert_eq!(std::fs::read_dir(&fixture.inbound).unwrap().count(), 0);
		let resumed = plan(
			&claim,
			&file_request(),
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.expect("a published request still needs its reply committed");
		assert!(matches!(resumed, Outcome::ServeRequest { .. }));

		fixture
			.ledger
			.advance(&claim.inbound_id, State::Acknowledged)
			.unwrap();
		assert!(
			plan(
				&claim,
				&file_request(),
				&fixture.configuration,
				&fixture.ledger,
				&resolver,
			)
			.unwrap()
			.is_none(),
			"an acknowledged request must not be served twice"
		);
	}

	#[test]
	fn a_file_request_is_refused_when_no_processor_can_serve_it() {
		// TSP-0011 section 5.1: a receiver unwilling to serve one refuses it
		// before transport acceptance, and once it is an inbound item the ordinary
		// consumer outcomes apply. With no processor this node never will.
		let fixture = fixture("norequest");
		let claim = claimed(ItemAuthentication::Transport);
		let resolver = |_: &Address| None;
		let outcome = plan(
			&claim,
			&file_request(),
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
		assert!(refusal.to_string().contains("Request-Processor"));
		assert_eq!(*disposition, Disposition::Reject);
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
		claim.peer = "fidonet#2:200/7".parse().unwrap();
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

	#[test]
	fn an_echomail_records_its_distribution_obligation() {
		// TSP-0013 section 4: "For EchoMail or file distribution, the ledger also
		// records every applicable routing or distribution obligation."
		let fixture = fixture("distribution");
		let (payload, keys, origin) = echomail_item();
		let resolver = move |address: &Address| (address == &origin).then_some(keys.public);
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
		let Outcome::Publish {
			distribution,
			forwardable,
			..
		} = &outcome
		else {
			panic!("expected a publication, got {outcome:?}");
		};
		assert_eq!(distribution.as_deref(), Some("SYNCHRONET"));
		assert!(*forwardable, "an Origin-Valid EchoMail can be forwarded");
		commit(&claim, &outcome, &fixture.configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		assert_eq!(
			fixture.ledger.get("I1").unwrap().unwrap().distribution,
			"SYNCHRONET"
		);
		let resumed = plan(
			&claim,
			&payload,
			&fixture.configuration,
			&fixture.ledger,
			&resolver,
		)
		.unwrap()
		.expect("a published distribution still needs forwarding");
		let Outcome::Publish {
			distribution,
			forwardable,
			..
		} = resumed
		else {
			panic!("expected a resumed publication");
		};
		assert_eq!(distribution.as_deref(), Some("SYNCHRONET"));
		assert!(forwardable);
	}

	#[test]
	fn an_item_the_service_will_not_forward_owes_no_native_copy() {
		// TSP-0006 section 6 refuses a Forward Job for Unsigned and both Invalid
		// states, so those are final-delivery work. Marking them forwardable
		// would make the adapter request a Job the service must reject.
		let fixture = fixture("unforwardable");
		let (payload, keys, origin) = echomail_item();
		let resolver = move |address: &Address| (address == &origin).then_some(keys.public);
		let mut configuration = fixture.configuration.clone();
		configuration.policy.unsigned = crate::policy::Action::DeliverWarn;
		let claim = claimed(ItemAuthentication::Unsigned);
		let outcome = plan(&claim, &payload, &configuration, &fixture.ledger, &resolver)
			.unwrap()
			.unwrap();
		let Outcome::Publish {
			distribution,
			forwardable,
			..
		} = &outcome
		else {
			panic!("expected a publication, got {outcome:?}");
		};
		assert_eq!(
			distribution, &None,
			"final-delivery work must not record an onward obligation"
		);
		assert!(!*forwardable);
		commit(&claim, &outcome, &configuration, &fixture.ledger)
			.unwrap()
			.unwrap();
		assert!(
			fixture
				.ledger
				.get("I1")
				.unwrap()
				.unwrap()
				.distribution
				.is_empty()
		);
	}
}
