use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::now;
use tith_config::{ConfigurationSet, IdentityRef};
use tith_crypto::{SECRET_KEY_BYTES, SecretKey, TlvHash, hash_tlv, sign_tlv, verify_tlv};
use tith_exchange::ServerReply;
use tith_nodelist::Nodelist;
use tith_store::{DeliveryClaim, DeliveryOutcome, InboundStore, JobKind, OutboundStore};
use tith_wire::address::Address;
use tith_wire::bundle::{
	BundleError, Identity, KeyResolver, unauthenticated_signed_data, verify_signed_tlv,
};

use crate::accept::Acceptance;
use crate::deliver::{LocalIdentity, Outbound};
use crate::framing::{IncomingBundle, read_header};
use crate::schedule::{Activation, Scheduler};
use tith_wire::item::{
	ItemKind, RejectionReason, ValidatedItem, accepted, rejected, request_identifier,
	set_request_identifier, validate_item,
};
use tith_wire::tlv::{OwnedTlv, TlvReader, parse_sequence};
use tith_wire::types;

pub fn write_secret(path: &Path, secret: &SecretKey) -> Result<(), Box<dyn Error>> {
	let mut file = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)?;
	file.write_all(secret.as_bytes())?;
	file.sync_all()?;
	Ok(())
}

pub fn read_secret(path: &Path) -> Result<SecretKey, Box<dyn Error>> {
	let metadata = fs::metadata(path)?;
	if metadata.permissions().mode() & 0o077 != 0 {
		return Err("node secret key file is accessible by group or other users".into());
	}
	let bytes: [u8; SECRET_KEY_BYTES] = fs::read(path)?
		.try_into()
		.map_err(|_| "node secret key file has the wrong length")?;
	Ok(SecretKey::from_bytes(bytes))
}

pub struct LocalNode {
	pub reference: IdentityRef,
	pub identity: Identity,
	pub secret: SecretKey,
}

/// How outbound delivery behaves for this node.
pub struct OutboundOptions {
	/// A listen-only node never connects out and never polls.
	pub enabled: bool,
	/// Seconds east of UTC, required only by a schedule using `Start Local`.
	pub local_offset: Option<i64>,
	/// The connect and read timeout for one outbound connection.
	pub timeout: Duration,
}

pub fn serve(
	address: SocketAddr,
	database: &Path,
	application: String,
	configuration: ConfigurationSet,
	nodelist: Nodelist,
	local_node: LocalNode,
	outbound: &OutboundOptions,
) -> Result<(), Box<dyn Error>> {
	let signature = sign_tlv(b"", &local_node.secret)?;
	if !verify_tlv(b"", &signature, &local_node.identity.public_key)? {
		return Err("node secret key does not match the configured local public key".into());
	}
	let listener = TcpListener::bind(address)?;
	let store = Arc::new(InboundStore::create(database)?);
	let configuration = Arc::new(configuration);
	let nodelist = Arc::new(nodelist);
	let secret = Arc::new(local_node.secret);
	if outbound.enabled {
		start_outbound(
			&store,
			&application,
			&configuration,
			&nodelist,
			&local_node.reference,
			&local_node.identity,
			&secret,
			outbound,
		)?;
	}
	let mailer = Arc::new(Mailer {
		store,
		application,
		configuration,
		nodelist,
		local_ref: local_node.reference,
		local: local_node.identity,
		local_secret: secret,
	});
	for connection in listener.incoming() {
		match connection {
			Ok(stream) => {
				let mailer = Arc::clone(&mailer);
				std::thread::spawn(move || {
					if let Err(error) = transaction(stream, &mailer) {
						eprintln!("tithd: mail transaction failed: {error}");
					}
				});
			}
			Err(error) => eprintln!("tithd: mail accept failed: {error}"),
		}
	}
	Ok(())
}

struct Mailer {
	store: Arc<InboundStore>,
	application: String,
	configuration: Arc<ConfigurationSet>,
	nodelist: Arc<Nodelist>,
	local_ref: IdentityRef,
	local: Identity,
	local_secret: Arc<SecretKey>,
}

impl Mailer {
	fn acceptance(&self) -> Acceptance<'_> {
		Acceptance {
			store: &self.store,
			application: &self.application,
			configuration: &self.configuration,
			nodelist: &self.nodelist,
			local_ref: &self.local_ref,
			local: &self.local,
		}
	}
}

impl KeyResolver for Mailer {
	fn public_key(&self, address: &Address) -> Option<tith_crypto::PublicKey> {
		self.nodelist.public_key(address)
	}
}

/// How long the driver waits between looks at the clock.
///
/// An activation with a nonzero Duration may claim work which appears during
/// the interval, so the driver has to come back while one is open; when none
/// is, it only has to notice the next beginning.
const IDLE_TICK: Duration = Duration::from_secs(15);
const ACTIVE_TICK: Duration = Duration::from_secs(5);

/// Starts the schedule-driven outbound driver beside the listener.
#[allow(clippy::too_many_arguments)]
fn start_outbound(
	store: &Arc<InboundStore>,
	application: &str,
	configuration: &Arc<ConfigurationSet>,
	nodelist: &Arc<Nodelist>,
	local_ref: &IdentityRef,
	local: &Identity,
	secret: &Arc<SecretKey>,
	options: &OutboundOptions,
) -> Result<(), Box<dyn Error>> {
	let schedules = configuration.schedules.clone();
	if schedules.is_empty() {
		return Ok(());
	}
	// A copy left Active by a previous run is claimed by a worker which no
	// longer exists, so it is returned to the queue before anything else runs.
	let recovered = store
		.outbound()?
		.recover_active(now(), now(), "recovered after restart")?;
	if recovered > 0 {
		eprintln!("tithd: recovered {recovered} interrupted delivery job(s)");
	}
	let driver = Outbound::new(
		Arc::clone(store),
		application.to_owned(),
		Arc::clone(configuration),
		Arc::clone(nodelist),
		vec![LocalIdentity {
			reference: local_ref.clone(),
			identity: local.clone(),
			secret: Arc::clone(secret),
		}],
		options.timeout,
	)?;
	let mut clock = Scheduler::new(&schedules, now(), options.local_offset)?;
	std::thread::spawn(move || {
		let mut open: Vec<Activation> = Vec::new();
		loop {
			open.extend(clock.poll(&schedules, now()));
			let mut still_open = Vec::new();
			for activation in open.drain(..) {
				let schedule = &schedules[activation.schedule];
				let next_attempt = clock
					.next_beginning(activation.schedule)
					.unwrap_or_else(|| now().saturating_add(60));
				run_activation(&driver, schedule, next_attempt);
				if activation.is_open(now()) {
					still_open.push(activation);
				} else {
					clock.finished(&activation, now());
				}
			}
			open = still_open;
			// While an activation is open there may be new work at any moment; when
			// none is, there is nothing to do until the next nominal beginning.
			let ceiling = if open.is_empty() {
				IDLE_TICK
			} else {
				ACTIVE_TICK
			};
			let until_next = clock.next_wakeup().map_or(ceiling, |wakeup| {
				Duration::from_secs(wakeup.saturating_sub(now()))
			});
			std::thread::sleep(until_next.min(ceiling).max(Duration::from_secs(1)));
		}
	});
	Ok(())
}

fn run_activation(driver: &Outbound, schedule: &tith_config::Schedule, next_attempt: u64) {
	let polled = driver.run_polls(schedule, now());
	if polled.attempted > 0 {
		eprintln!(
			"tithd: schedule {} polled {} peer(s), received {} value(s), {} failed",
			schedule.name, polled.attempted, polled.received, polled.failed
		);
	}
	match driver.run_pass(schedule, now(), next_attempt) {
		Ok(summary) if summary.connections > 0 => eprintln!(
			"tithd: schedule {} made {} connection(s): {} delivered, {} retained, {} failed",
			schedule.name, summary.connections, summary.delivered, summary.retained, summary.failed
		),
		Ok(_) => {}
		Err(error) => eprintln!("tithd: schedule {} delivery failed: {error}", schedule.name),
	}
}

/// A delivery copy returned in a poll snapshot, awaiting its response.
///
/// The copy stays claimed until the peer's final Reply Bundle says what became
/// of it, so a connection which dies mid-transfer does not lose the item.
struct PollHold {
	signed_tlv_hash: TlvHash,
	request_identifier: u64,
	claim: DeliveryClaim,
}

fn transaction(stream: TcpStream, mailer: &Mailer) -> Result<(), Box<dyn Error>> {
	let mut writer = stream.try_clone()?;
	let mut reader = TlvReader::new(stream);
	let request = read_header(&mut reader, None, mailer)?.ok_or("empty mail connection")?;
	let reply =
		ServerReply::for_request(&request.bundle, &mailer.local, &mailer.local_secret, now())?;
	writer.write_all(reply.prefix())?;
	writer.flush()?;

	let mut holds = Vec::new();
	let result = respond(
		&mut reader,
		&mut writer,
		&request,
		&reply,
		mailer,
		&mut holds,
	);
	// Whatever happened, every copy this connection claimed needs an outcome.
	// TSP-0002 section 6: a request with no complete response remains eligible
	// and does not invoke permanent failure policy.
	release_holds(&holds, mailer)?;
	result?;
	writer.shutdown(Shutdown::Write)?;
	Ok(())
}

fn respond(
	reader: &mut TlvReader<TcpStream>,
	writer: &mut TcpStream,
	request: &IncomingBundle,
	reply: &ServerReply,
	mailer: &Mailer,
	holds: &mut Vec<PollHold>,
) -> Result<(), Box<dyn Error>> {
	while let Some(value) = reader.read_next()? {
		let value = value.read_owned()?;
		match value.type_code {
			types::SIGNED_TLV => {
				let (responses, returned) = payload_responses(&value, request, mailer)?;
				if !responses.is_empty() {
					let encoded = reply.payload(responses, &mailer.local_secret)?;
					writer.write_all(&encoded)?;
					writer.flush()?;
					// The peer answers a returned value by naming the SignedTLV it
					// arrived in, which is the one just written.
					let signed_tlv_hash = hash_tlv(&encoded)?;
					holds.extend(returned.into_iter().map(|(request_identifier, claim)| {
						PollHold {
							signed_tlv_hash,
							request_identifier,
							claim,
						}
					}));
				}
			}
			types::ORIGIN => {
				validate_final_reply(reader, value, request, mailer, holds)?;
				break;
			}
			type_code if types::is_defined(type_code) => {
				return Err("unexpected defined top-level value".into());
			}
			_ => {}
		}
	}
	Ok(())
}

/// Retains every copy still held when the connection ends.
fn release_holds(holds: &[PollHold], mailer: &Mailer) -> Result<(), Box<dyn Error>> {
	if holds.is_empty() {
		return Ok(());
	}
	let outbound = mailer.store.outbound()?;
	for hold in holds {
		outbound.finish_delivery(
			&hold.claim.job_id,
			hold.claim.delivery_index,
			&hold.claim.worker_token,
			now(),
			DeliveryOutcome::Deferred {
				retry_at: now(),
				result: "poll ended without a response for this value".to_owned(),
			},
		)?;
	}
	Ok(())
}

/// The responses to one payload `SignedTLV`, and any copies a Poll returned.
type PayloadResponses = (Vec<OwnedTlv>, Vec<(u64, DeliveryClaim)>);

fn payload_responses(
	value: &OwnedTlv,
	request: &IncomingBundle,
	mailer: &Mailer,
) -> Result<PayloadResponses, Box<dyn Error>> {
	let response_to = hash_tlv(&value.encode())?;
	let payload = match verify_signed_tlv(value, Some(&request.bundle.origin), mailer) {
		Ok(payload) => payload,
		Err(BundleError::InvalidSignature) => {
			return Ok((unauthenticated_responses(value, response_to)?, Vec::new()));
		}
		Err(error) => return Err(error.into()),
	};
	let correct_header = payload.data.first().is_some_and(|first| {
		first.type_code == types::TLV_HASH
			&& first.value.as_slice() == request.header_hash.as_bytes()
	});
	let mut responses = Vec::new();
	let mut returned = Vec::new();
	let request_values = if payload
		.data
		.first()
		.is_some_and(|first| first.type_code == types::TLV_HASH)
	{
		&payload.data[1..]
	} else {
		payload.data.as_slice()
	};
	for value in request_values {
		if matches!(value.type_code, types::ACCEPTED | types::REJECTED) {
			return Err("an initial Bundle contains a response value".into());
		}
		if !types::is_request(value.type_code) {
			if types::is_defined(value.type_code) {
				return Err("unexpected defined payload value".into());
			}
			continue;
		}
		if !correct_header {
			responses.push(malformed_rejection(value, response_to)?);
			continue;
		}
		match validate_item(value, mailer) {
			Ok(Some(item)) => {
				if let Some(kinds) = poll_kinds(item.kind) {
					let claims = poll_snapshot(kinds, request, mailer)?;
					// TTS-0005 section 3: every value in the snapshot is returned in
					// the same `SignedTLV` as the Accepted, which is the one these
					// responses are about to be built into.
					for (offset, claim) in claims.into_iter().enumerate() {
						let identifier = u64::try_from(offset)? + 1;
						responses.push(set_request_identifier(
							&single_value(&claim.item)?,
							identifier,
						)?);
						returned.push((identifier, claim));
					}
					responses.push(accepted(item.request_identifier, response_to)?);
				} else {
					responses.push(mailer.acceptance().dispatch(
						&item,
						response_to,
						&request.bundle.origin,
					)?);
				}
			}
			Ok(None) => unreachable!("request types always produce an item"),
			Err(_) => responses.push(malformed_rejection(value, response_to)?),
		}
	}
	Ok((responses, returned))
}

/// The spool kinds a Poll value asks for.
///
/// `PollFileRequests` has no spool kind because a `FileRequest` cannot yet be
/// submitted; TTS-0005 section 3 accepts an empty snapshot with no returned
/// values, which is exactly what an empty kind list produces.
fn poll_kinds(kind: ItemKind) -> Option<&'static [JobKind]> {
	match kind {
		ItemKind::PollMessages => Some(&[JobKind::NetMail, JobKind::EchoMail]),
		ItemKind::PollFiles => Some(&[JobKind::File]),
		ItemKind::PollFileRequests => Some(&[]),
		_ => None,
	}
}

/// Atomically claims everything held for the authenticated Bundle Origin.
fn poll_snapshot(
	kinds: &[JobKind],
	request: &IncomingBundle,
	mailer: &Mailer,
) -> Result<Vec<DeliveryClaim>, Box<dyn Error>> {
	if kinds.is_empty() {
		return Ok(Vec::new());
	}
	let origin = &request.bundle.origin;
	// An unlisted Origin is only identified together with its PublicKey, so the
	// key is part of the match rather than the address alone.
	let key = origin.address.is_unlisted().then_some(&origin.public_key);
	Ok(mailer.store.outbound()?.claim_poll_snapshot(
		&origin.address.to_string(),
		key,
		kinds,
		now(),
	)?)
}

fn single_value(encoded: &[u8]) -> Result<OwnedTlv, Box<dyn Error>> {
	let mut values = parse_sequence(encoded)?;
	if values.len() != 1 {
		return Err("spooled item is not a single TLV value".into());
	}
	Ok(values.remove(0))
}

fn unauthenticated_responses(
	value: &OwnedTlv,
	response_to: TlvHash,
) -> Result<Vec<OwnedTlv>, Box<dyn Error>> {
	let data = unauthenticated_signed_data(value)?;
	if data
		.iter()
		.any(|value| matches!(value.type_code, types::ACCEPTED | types::REJECTED))
	{
		return Err("unauthenticated SignedData contains a response".into());
	}
	let mut responses = Vec::new();
	for value in data
		.iter()
		.filter(|value| types::is_request(value.type_code))
	{
		let identifier = request_identifier(value)
			.ok_or("unauthenticated request has no valid RequestIdentifier")?;
		responses.push(rejected(
			identifier,
			response_to,
			None,
			RejectionReason::Authentication,
			"payload SignedTLV authentication failed",
		)?);
	}
	Ok(responses)
}

fn malformed_rejection(value: &OwnedTlv, response_to: TlvHash) -> Result<OwnedTlv, Box<dyn Error>> {
	let identifier = request_identifier(value)
		.ok_or("authenticated malformed request has no valid RequestIdentifier")?;
	// Retrying the same authenticated malformed value cannot make it valid;
	// the sender must construct a corrected TLV value.
	Ok(rejected(
		identifier,
		response_to,
		None,
		RejectionReason::Permanent,
		"authenticated request has a data error",
	)?)
}

fn validate_final_reply(
	reader: &mut TlvReader<TcpStream>,
	first: OwnedTlv,
	request: &IncomingBundle,
	mailer: &Mailer,
	holds: &mut Vec<PollHold>,
) -> Result<(), Box<dyn Error>> {
	let reply = read_header(reader, Some(first), mailer)?.ok_or("missing final Reply Bundle")?;
	if reply.bundle.origin != request.bundle.origin || reply.bundle.destination != mailer.local {
		return Err("final Reply Bundle has the wrong identities".into());
	}
	let outbound = mailer.store.outbound()?;
	while let Some(value) = reader.read_next()? {
		let value = value.read_owned()?;
		if value.type_code == types::SIGNED_TLV {
			let payload = verify_signed_tlv(&value, Some(&reply.bundle.origin), mailer)?;
			let correct_header = payload.data.first().is_some_and(|first| {
				first.type_code == types::TLV_HASH
					&& first.value.as_slice() == reply.header_hash.as_bytes()
			});
			if !correct_header {
				return Err("final Reply Bundle payload has the wrong header hash".into());
			}
			for value in payload.data.iter().skip(1) {
				// A Poll returns values which the peer must answer here; nothing
				// else belongs in a final Reply Bundle.
				if !matches!(value.type_code, types::ACCEPTED | types::REJECTED) {
					if types::is_defined(value.type_code) {
						return Err("unexpected value in final Reply Bundle".into());
					}
					continue;
				}
				let Some(item) = validate_item(value, mailer)? else {
					return Err("unreadable response in final Reply Bundle".into());
				};
				resolve_hold(&item, holds, &outbound)?;
			}
		} else if types::is_defined(value.type_code) {
			return Err("unexpected top-level value after final Reply Header".into());
		}
	}
	Ok(())
}

/// Applies one peer response to the copy it answers.
///
/// A response naming nothing this connection returned is ignored rather than
/// fatal: the peer may be answering a value from an exchange which has already
/// been retired, and refusing the whole connection would strand the rest.
fn resolve_hold(
	item: &ValidatedItem,
	holds: &mut Vec<PollHold>,
	outbound: &OutboundStore,
) -> Result<(), Box<dyn Error>> {
	let Some(response_to) = item.response_to else {
		return Ok(());
	};
	let Some(position) = holds.iter().position(|hold| {
		hold.signed_tlv_hash == response_to && hold.request_identifier == item.request_identifier
	}) else {
		return Ok(());
	};
	let hold = holds.remove(position);
	let outcome = match item.kind {
		ItemKind::Accepted => DeliveryOutcome::Delivered("accepted by poll".to_owned()),
		_ => crate::deliver::rejection_outcome(item.rejection.as_ref(), now()),
	};
	outbound.finish_delivery(
		&hold.claim.job_id,
		hold.claim.delivery_index,
		&hold.claim.worker_token,
		now(),
		outcome,
	)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use base64::Engine as _;
	use base64::engine::general_purpose::STANDARD_NO_PAD;
	use std::io::{Read, Write};
	use std::sync::Arc;
	use std::time::{SystemTime, UNIX_EPOCH};
	use tith_crypto::{SigningKeyPair, sign_tlv};
	use tith_ipc::{Document, EnvelopeKind};

	use tith_store::{ClaimResult, ItemAuthentication};
	use tith_wire::bundle::Bundle;
	use tith_wire::bundle::{build_bundle, build_signed_tlv};
	use tith_wire::integer::{decode_u64_prefix, encode_u64};
	use tith_wire::item::ItemKind;
	use tith_wire::item::validate_payload;
	use tith_wire::tlv::parse_sequence;

	use super::*;

	fn container(type_code: u64, children: &[OwnedTlv]) -> OwnedTlv {
		let mut value = Vec::new();
		for child in children {
			child.write_to(&mut value).unwrap();
		}
		OwnedTlv::new(type_code, value).unwrap()
	}

	fn standalone_file(identity: &Identity, secret: &SecretKey, request_id: u64) -> OwnedTlv {
		let mut children = vec![
			OwnedTlv::new(types::FILENAME, b"hello.txt".to_vec()).unwrap(),
			OwnedTlv::new(types::CONTENTS, b"hello\n".to_vec()).unwrap(),
			OwnedTlv::new(types::ORIGIN, identity.address.to_string().into_bytes()).unwrap(),
		];
		let mut signed = Vec::new();
		for child in &children {
			child.write_to(&mut signed).unwrap();
		}
		let signature = sign_tlv(&signed, secret).unwrap();
		children.push(OwnedTlv::new(types::SIGNATURE, signature.as_bytes().to_vec()).unwrap());
		children.push(OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(request_id)).unwrap());
		container(types::FILE, &children)
	}

	fn netmail(
		origin: &Identity,
		secret: &SecretKey,
		destination: &Identity,
		request_id: u64,
	) -> OwnedTlv {
		let mut children = vec![
			OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap(),
			OwnedTlv::new(
				types::DESTINATION,
				destination.address.to_string().into_bytes(),
			)
			.unwrap(),
			OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
			OwnedTlv::new(types::TO_USER_NAME, b"Sysop".to_vec()).unwrap(),
			OwnedTlv::new(types::FROM_USER_NAME, b"Remote".to_vec()).unwrap(),
			OwnedTlv::new(types::SUBJECT, b"Hello".to_vec()).unwrap(),
			OwnedTlv::new(types::MESSAGE_TEXT, b"Native TITH mail".to_vec()).unwrap(),
		];
		let mut signed = Vec::new();
		for child in &children {
			child.write_to(&mut signed).unwrap();
		}
		let signature = sign_tlv(&signed, secret).unwrap();
		children.push(OwnedTlv::new(types::SIGNATURE, signature.as_bytes().to_vec()).unwrap());
		children.push(OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(request_id)).unwrap());
		let mut via = Vec::new();
		OwnedTlv::new(types::ADDRESS, origin.address.to_string().into_bytes())
			.unwrap()
			.write_to(&mut via)
			.unwrap();
		OwnedTlv::new(types::TIMESTAMP, encode_u64(1))
			.unwrap()
			.write_to(&mut via)
			.unwrap();
		via.extend_from_slice(b"tith test");
		children.push(OwnedTlv::new(types::VIA, via).unwrap());
		container(types::MESSAGE, &children)
	}

	fn nodelist(local_key: &[u8; 32], peer_key: &[u8; 32]) -> Nodelist {
		let line = |keyword: &str, number: u16, key: &[u8; 32]| {
			format!(
				"{keyword}\t{number}\tNode\tLocation\tSysop\t\tCM\t\tIIH:mail.example:24555:{}\t\t\n",
				STANDARD_NO_PAD.encode(key)
			)
		};
		Nodelist::parse(
			"fidonet",
			&[line("Zone", 1, local_key), line("", 2, peer_key)].concat(),
		)
		.unwrap()
	}

	fn setup() -> (
		Arc<Mailer>,
		SigningKeyPair,
		Identity,
		Identity,
		std::path::PathBuf,
	) {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let database = std::env::temp_dir().join(format!("tith-mail-{unique}.redb"));
		let local_keys = SigningKeyPair::from_seed(&[41; 32]).unwrap();
		let peer_keys = SigningKeyPair::from_seed(&[42; 32]).unwrap();
		let local = Identity {
			address: "fidonet#1".parse().unwrap(),
			public_key: local_keys.public,
		};
		let peer = Identity {
			address: "fidonet#1/2".parse().unwrap(),
			public_key: peer_keys.public,
		};
		let configuration = ConfigurationSet::parse(
			"Peer remote\nAddress fidonet#1/2\nEnd\n",
			"Routes fidonet#1\nEnd\n",
			"",
			"",
		)
		.unwrap();
		let mailer = Arc::new(Mailer {
			store: Arc::new(InboundStore::create(&database).unwrap()),
			application: "tosser".to_owned(),
			configuration: Arc::new(configuration),
			nodelist: Arc::new(nodelist(
				local.public_key.as_bytes(),
				peer.public_key.as_bytes(),
			)),
			local_ref: IdentityRef::Listed(local.address.clone()),
			local: local.clone(),
			local_secret: Arc::new(local_keys.secret),
		});
		(mailer, peer_keys, peer, local, database)
	}

	fn exchange(request: &[u8], mailer: &Arc<Mailer>) -> (Vec<u8>, bool) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server_mailer = Arc::clone(mailer);
		let server = std::thread::spawn(move || {
			let (stream, _) = listener.accept().unwrap();
			transaction(stream, &server_mailer).is_ok()
		});
		let mut client = TcpStream::connect(address).unwrap();
		client.write_all(request).unwrap();
		client.shutdown(Shutdown::Write).unwrap();
		let mut response = Vec::new();
		client.read_to_end(&mut response).unwrap();
		(response, server.join().unwrap())
	}

	fn response_kind(response: &[u8], mailer: &Mailer) -> ItemKind {
		let reply = Bundle::parse(response, mailer).unwrap();
		validate_payload(&reply.payloads[0], mailer).unwrap()[0].kind
	}

	fn rejected_reason(response: &[u8], mailer: &Mailer) -> u64 {
		let reply = Bundle::parse(response, mailer).unwrap();
		let item = validate_payload(&reply.payloads[0], mailer)
			.unwrap()
			.remove(0);
		assert_eq!(item.kind, ItemKind::Rejected);
		let mut suffix = item.raw.value.as_slice();
		for _ in 0..2 {
			let (_, type_bytes) = decode_u64_prefix(suffix).unwrap();
			let (length, length_bytes) = decode_u64_prefix(&suffix[type_bytes..]).unwrap();
			let used = type_bytes + length_bytes + usize::try_from(length).unwrap();
			suffix = &suffix[used..];
		}
		decode_u64_prefix(suffix).unwrap().0
	}

	#[test]
	fn accepts_once_and_acknowledges_a_signed_file_duplicate() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let file = standalone_file(&peer, &peer_keys.secret, 7);
		let expected_payload = file.encode();
		let request = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![file]]).unwrap();
		for _ in 0..2 {
			let (response, completed) = exchange(&request, &mailer);
			assert!(completed);
			assert_eq!(response_kind(&response, &mailer), ItemKind::Accepted);
		}
		let exports = database.with_extension("exports");
		fs::create_dir(&exports).unwrap();
		let claim_request = b"TITH-IPC 1\nClaim-Inbound \"tosser\" Now\nClaim-Key \"first\"\nPresentation Path\nEnd\n";
		let service =
			crate::ipc::IpcService::from_store(Arc::clone(&mailer.store), exports.clone());
		let principal = crate::ipc::Principal::single("test", "tosser");
		let claim_result = service.process_request(claim_request, Some(&principal));
		let claim_document = Document::parse(&claim_result, EnvelopeKind::Result).unwrap();
		assert_eq!(claim_document.lines[0].fields[0].text, "Claim-Inbound");
		assert_eq!(claim_document.lines[0].fields[1].text, "Completed");
		assert_eq!(
			claim_document
				.lines
				.iter()
				.find(|line| line.fields[0].text == "Item-Authentication")
				.unwrap()
				.fields[1]
				.text,
			"Origin-Valid"
		);
		let payload_path = claim_document
			.lines
			.iter()
			.find(|line| line.fields[0].text == "Payload-Path")
			.unwrap()
			.fields[1]
			.text
			.clone();
		assert_eq!(fs::read(payload_path).unwrap(), expected_payload);
		let claim_time = now().saturating_add(1);
		assert!(matches!(
			mailer
				.store
				.claim("tosser", "second", claim_time, 60)
				.unwrap(),
			ClaimResult::Empty
		));
		drop(mailer);
		fs::remove_file(database).unwrap();
		fs::remove_dir_all(exports).unwrap();
	}

	#[test]
	fn accepts_a_local_netmail_with_a_raw_via_software_suffix() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let message = netmail(&peer, &peer_keys.secret, &local, 12);
		let request =
			build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![message]]).unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Accepted);
		let ClaimResult::Completed(claim) = mailer
			.store
			.claim("tosser", "message", now().saturating_add(1), 60)
			.unwrap()
		else {
			panic!("stored Message was not claimable")
		};
		assert_eq!(claim.record.kind, tith_store::ItemKind::Message);
		assert_eq!(claim.record.authentication, ItemAuthentication::OriginValid);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn rejects_an_unauthenticated_payload_without_storing_it() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let file = standalone_file(&peer, &peer_keys.secret, 8);
		let request = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![file]]).unwrap();
		let mut top = parse_sequence(&request).unwrap();
		*top.last_mut().unwrap().value.last_mut().unwrap() ^= 1;
		let request = top.iter().flat_map(OwnedTlv::encode).collect::<Vec<_>>();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Rejected);
		assert_eq!(
			rejected_reason(&response, &mailer),
			RejectionReason::Authentication as u64
		);
		assert!(matches!(
			mailer
				.store
				.claim("tosser", "none", now().saturating_add(1), 60)
				.unwrap(),
			ClaimResult::Empty
		));
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn accepts_but_marks_an_invalid_end_to_end_file_signature() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let file = standalone_file(&peer, &peer_keys.secret, 9);
		let mut children = file.children().unwrap();
		let signature = children
			.iter_mut()
			.find(|value| value.type_code == types::SIGNATURE)
			.unwrap();
		*signature.value.last_mut().unwrap() ^= 1;
		let file = container(types::FILE, &children);
		let request = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![file]]).unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Accepted);
		let ClaimResult::Completed(claim) = mailer
			.store
			.claim("tosser", "invalid", now().saturating_add(1), 60)
			.unwrap()
		else {
			panic!("invalidly signed file was not retained")
		};
		assert_eq!(
			claim.record.authentication,
			ItemAuthentication::OriginInvalid
		);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn accepts_an_unsigned_item_only_inside_an_authenticated_bundle() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let signed_file = standalone_file(&peer, &peer_keys.secret, 72);
		let children = parse_sequence(&signed_file.value).unwrap();
		let unsigned_children = children
			.into_iter()
			.filter(|child| child.type_code != types::SIGNATURE)
			.collect::<Vec<_>>();
		let file = container(types::FILE, &unsigned_children);
		let request = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![file]]).unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Accepted);
		let ClaimResult::Completed(claim) = mailer
			.store
			.claim("tosser", "unsigned", now().saturating_add(1), 60)
			.unwrap()
		else {
			panic!("unsigned file was not retained")
		};
		assert_eq!(claim.record.authentication, ItemAuthentication::Unsigned);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn returns_a_permanent_rejection_for_authenticated_malformed_requests() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let malformed_poll = container(
			types::POLL_MESSAGES,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(10)).unwrap(),
				OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
			],
		);
		let request = build_bundle(
			&peer,
			&peer_keys.secret,
			&local,
			1,
			vec![vec![malformed_poll]],
		)
		.unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Rejected);
		assert_eq!(
			rejected_reason(&response, &mailer),
			RejectionReason::Permanent as u64
		);

		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(11)).unwrap()],
		);
		let prefix = build_bundle(&peer, &peer_keys.secret, &local, 1, Vec::new()).unwrap();
		let mut top = parse_sequence(&prefix).unwrap();
		top.push(build_signed_tlv(&[poll], None, &peer_keys.secret).unwrap());
		let request = top.iter().flat_map(OwnedTlv::encode).collect::<Vec<_>>();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Rejected);
		assert_eq!(
			rejected_reason(&response, &mailer),
			RejectionReason::Permanent as u64
		);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn closes_without_a_reply_for_bad_headers_and_wrong_destinations() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let request = build_bundle(&peer, &peer_keys.secret, &local, 1, Vec::new()).unwrap();
		let mut top = parse_sequence(&request).unwrap();
		*top[1].value.last_mut().unwrap() ^= 1;
		let request = top.iter().flat_map(OwnedTlv::encode).collect::<Vec<_>>();
		let (response, completed) = exchange(&request, &mailer);
		assert!(!completed);
		assert!(response.is_empty());

		let other_keys = SigningKeyPair::from_seed(&[43; 32]).unwrap();
		let other = Identity {
			address: Address::unlisted("p2p".to_owned()).unwrap(),
			public_key: other_keys.public,
		};
		let request = build_bundle(&peer, &peer_keys.secret, &other, 1, Vec::new()).unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(!completed);
		assert!(response.is_empty());
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	/// A node with its own store, identity, and configuration.
	struct Node {
		mailer: Arc<Mailer>,
		database: std::path::PathBuf,
	}

	impl Drop for Node {
		fn drop(&mut self) {
			let _ = fs::remove_file(&self.database);
		}
	}

	fn temporary_database(name: &str) -> std::path::PathBuf {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		std::env::temp_dir().join(format!("tith-{name}-{unique}.redb"))
	}

	fn node(
		name: &str,
		address: &str,
		keys: SigningKeyPair,
		peers: &str,
		routes: &str,
		nodelist: &Arc<Nodelist>,
	) -> Node {
		let database = temporary_database(name);
		let address: Address = address.parse().unwrap();
		let mailer = Arc::new(Mailer {
			store: Arc::new(InboundStore::create(&database).unwrap()),
			application: "tosser".to_owned(),
			configuration: Arc::new(ConfigurationSet::parse(peers, routes, "", "").unwrap()),
			nodelist: Arc::clone(nodelist),
			local_ref: IdentityRef::Listed(address.clone()),
			local: Identity {
				address,
				public_key: keys.public,
			},
			local_secret: Arc::new(keys.secret),
		});
		Node { mailer, database }
	}

	/// Accepts `count` connections on `listener` and runs each transaction.
	fn accept(
		listener: TcpListener,
		mailer: &Arc<Mailer>,
		count: usize,
	) -> std::thread::JoinHandle<()> {
		let mailer = Arc::clone(mailer);
		std::thread::spawn(move || {
			for _ in 0..count {
				let (stream, _) = listener.accept().unwrap();
				transaction(stream, &mailer).unwrap();
			}
		})
	}

	fn driver(node: &Node) -> Outbound {
		Outbound::new(
			Arc::clone(&node.mailer.store),
			node.mailer.application.clone(),
			Arc::clone(&node.mailer.configuration),
			Arc::clone(&node.mailer.nodelist),
			vec![LocalIdentity {
				reference: node.mailer.local_ref.clone(),
				identity: node.mailer.local.clone(),
				secret: Arc::clone(&node.mailer.local_secret),
			}],
			Duration::from_secs(10),
		)
		.unwrap()
	}

	fn schedule(origin: &IdentityRef, polls: Vec<String>) -> tith_config::Schedule {
		tith_config::Schedule {
			name: "test".to_owned(),
			origin: origin.clone(),
			classes: vec!["Normal".to_owned()],
			next_hops: vec![tith_config::Selector::All],
			polls,
			start_local: false,
			start_minutes: 0,
			duration_minutes: 0,
			repeat_after_minutes: 1,
		}
	}

	/// Submits one `NetMail` and returns its job identifier.
	fn submit(node: &Node, destination: &str, next_hop: &str, key: &str) -> String {
		let engine = crate::submission::SubmissionEngine::new(
			Arc::clone(&node.mailer.configuration),
			Arc::clone(&node.mailer.nodelist),
			[(
				node.mailer.local.address.to_string(),
				crate::submission::LocalSigner {
					reference: node.mailer.local_ref.clone(),
					identity: node.mailer.local.clone(),
					secret: Arc::clone(&node.mailer.local_secret),
				},
			)],
		);
		let request = tith_ipc::SubmissionRequest::parse(
			format!(
				"TITH-IPC 1\nSubmit\nJob\nApplication \"tosser\"\nIdempotency-Key \"{key}\"\nOrigin \"{}\"\nDestination \"{destination}\"\nTo-User \"You\"\nFrom-User \"Me\"\nSubject \"Hello\"\nMessage-Text \"Native TITH mail\"\nNext-Hop {next_hop}\nEnd\nEnd\n",
				node.mailer.local.address
			)
			.as_bytes(),
		)
		.unwrap();
		let store = node.mailer.store.outbound().unwrap();
		let tith_store::BatchCommit::Committed(outcomes) = engine.submit(&request, &store).unwrap()
		else {
			panic!("commit expected")
		};
		let tith_store::CommitOutcome::New { job_id, .. } = &outcomes[0] else {
			panic!("new job expected")
		};
		job_id.clone()
	}

	fn job_state(node: &Node, job_id: &str) -> tith_store::JobState {
		node.mailer
			.store
			.outbound()
			.unwrap()
			.query(job_id)
			.unwrap()
			.state
	}

	fn stored_item(node: &Node, key: &str) -> Option<Vec<u8>> {
		let ClaimResult::Completed(claim) = node
			.mailer
			.store
			.claim("tosser", key, now().saturating_add(1), 60)
			.unwrap()
		else {
			return None;
		};
		Some(
			node.mailer
				.store
				.claimed_payload("tosser", &claim.inbound_id, &claim.claim_token, now())
				.unwrap(),
		)
	}

	/// The real check: two live nodes, one connection, and a retired copy.
	#[test]
	fn delivers_a_netmail_over_a_live_connection() {
		let sender_keys = SigningKeyPair::from_seed(&[51; 32]).unwrap();
		let receiver_keys = SigningKeyPair::from_seed(&[52; 32]).unwrap();
		let list = Arc::new(nodelist(
			sender_keys.public.as_bytes(),
			receiver_keys.public.as_bytes(),
		));
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let port = listener.local_addr().unwrap().port();

		let receiver = node(
			"deliver-receiver",
			"fidonet#1/2",
			receiver_keys,
			"Peer sender\nAddress fidonet#1\nEnd\n",
			"Routes fidonet#1/2\nEnd\n",
			&list,
		);
		let server = accept(listener, &receiver.mailer, 1);

		let sender = node(
			"deliver-sender",
			"fidonet#1",
			sender_keys,
			&format!("Peer remote\nAddress fidonet#1/2\nEndpoint 127.0.0.1 {port}\nEnd\n"),
			"Routes fidonet#1\nEnd\n",
			&list,
		);
		let job = submit(&sender, "fidonet#1/2", "Active \"@remote\"", "one");
		assert_eq!(job_state(&sender, &job), tith_store::JobState::Queued);

		let schedule = schedule(&sender.mailer.local_ref, Vec::new());
		let summary = driver(&sender)
			.run_pass(&schedule, now(), now() + 3600)
			.unwrap();
		server.join().unwrap();

		assert_eq!(summary.connections, 1, "one connection for one next hop");
		assert_eq!(summary.delivered, 1);
		assert_eq!(job_state(&sender, &job), tith_store::JobState::Delivered);
		let stored = stored_item(&receiver, "check").expect("the peer stored the NetMail");
		let values = parse_sequence(&stored).unwrap();
		assert_eq!(values[0].type_code, types::MESSAGE);
	}

	/// A three node line: mail transits the middle node without an application.
	#[test]
	fn a_hub_relays_netmail_it_is_not_the_destination_of() {
		let sender_keys = SigningKeyPair::from_seed(&[61; 32]).unwrap();
		let hub_keys = SigningKeyPair::from_seed(&[62; 32]).unwrap();
		let far_keys = SigningKeyPair::from_seed(&[63; 32]).unwrap();
		let hub_listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let hub_port = hub_listener.local_addr().unwrap().port();
		let far_listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let far_port = far_listener.local_addr().unwrap().port();
		let line = |keyword: &str, number: u16, key: &SigningKeyPair, port: u16| {
			format!(
				"{keyword}\t{number}\tNode\tLocation\tSysop\t\tCM\t\tIIH:127.0.0.1:{port}:{}\t\t\n",
				STANDARD_NO_PAD.encode(key.public.as_bytes())
			)
		};
		let list = Arc::new(
			Nodelist::parse(
				"fidonet",
				&[
					line("Zone", 1, &sender_keys, 1),
					line("", 2, &hub_keys, hub_port),
					line("", 3, &far_keys, far_port),
				]
				.concat(),
			)
			.unwrap(),
		);

		// The hub authorizes the relay and routes onward by the default methods.
		let hub = node(
			"relay-hub",
			"fidonet#1/2",
			hub_keys,
			"Peer sender\nAddress fidonet#1\nEnd\n",
			"Routes fidonet#1/2\nAllow-Relay From All Origin All Destination All\nEnd\n",
			&list,
		);
		let far = node(
			"relay-far",
			"fidonet#1/3",
			far_keys,
			"Peer hub\nAddress fidonet#1/2\nEnd\n",
			"Routes fidonet#1/3\nEnd\n",
			&list,
		);
		let hub_server = accept(hub_listener, &hub.mailer, 1);
		let far_server = accept(far_listener, &far.mailer, 1);

		let sender = node(
			"relay-sender",
			"fidonet#1",
			sender_keys,
			&format!("Peer hub\nAddress fidonet#1/2\nEndpoint 127.0.0.1 {hub_port}\nEnd\n"),
			"Routes fidonet#1\nEnd\n",
			&list,
		);
		// Addressed to the far node but committed to the hub, which is the whole
		// point: the sender has no route of its own to fidonet#1/3.
		let job = submit(&sender, "fidonet#1/3", "Active \"@hub\"", "relayed");
		let sending = schedule(&sender.mailer.local_ref, Vec::new());
		let summary = driver(&sender)
			.run_pass(&sending, now(), now() + 3600)
			.unwrap();
		hub_server.join().unwrap();
		assert_eq!(summary.delivered, 1, "the hub accepted the relay");
		assert_eq!(job_state(&sender, &job), tith_store::JobState::Delivered);

		// The hub spooled it rather than storing it for a consumer.
		assert!(
			stored_item(&hub, "probe").is_none(),
			"a relayed item never becomes an inbound item"
		);
		let hub_outbound = hub.mailer.store.outbound().unwrap();
		let relayed_jobs: Vec<_> = hub_outbound
			.events("tithd-relay")
			.unwrap()
			.into_iter()
			.map(|event| hub_outbound.query(&event.job_id).unwrap())
			.collect();
		assert_eq!(relayed_jobs.len(), 1);
		assert_eq!(
			relayed_jobs[0].deliveries[0].next_hop, "fidonet#1/3",
			"Direct is eligible for the far node"
		);

		// Now let the hub send it on.
		let hub_schedule = schedule(&hub.mailer.local_ref, Vec::new());
		let hub_summary = driver(&hub)
			.run_pass(&hub_schedule, now(), now() + 3600)
			.unwrap();
		far_server.join().unwrap();
		assert_eq!(hub_summary.delivered, 1);

		let arrived = stored_item(&far, "check").expect("the far node stored the relayed NetMail");
		let value = parse_sequence(&arrived).unwrap().remove(0);
		let vias = tith_wire::item::item_vias(&value).unwrap();
		assert_eq!(
			vias.last().unwrap().address,
			"fidonet#1/2".parse::<Address>().unwrap(),
			"the hub recorded itself in a Via"
		);
		// The end-to-end signature still validates against the original signer,
		// which is the entire reason a relay rebuilds only the routing suffix.
		let validated = tith_wire::item::validate_item(&value, far.mailer.as_ref())
			.unwrap()
			.unwrap();
		assert_eq!(
			validated.authentication,
			Some(tith_store::ItemAuthentication::OriginValid)
		);
	}

	/// The Passive half: a held copy only moves when the peer asks for it.
	#[test]
	fn a_poll_collects_a_held_copy_and_retires_it() {
		let poller_keys = SigningKeyPair::from_seed(&[53; 32]).unwrap();
		let holder_keys = SigningKeyPair::from_seed(&[54; 32]).unwrap();
		let list = Arc::new(nodelist(
			poller_keys.public.as_bytes(),
			holder_keys.public.as_bytes(),
		));
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let port = listener.local_addr().unwrap().port();

		let holder = node(
			"poll-holder",
			"fidonet#1/2",
			holder_keys,
			"Peer poller\nAddress fidonet#1\nEnd\n",
			"Routes fidonet#1/2\nEnd\n",
			&list,
		);
		// Held for the poller, so nothing a schedule runs will ever send it.
		let job = submit(&holder, "fidonet#1", "Passive \"@poller\"", "held");
		assert_eq!(job_state(&holder, &job), tith_store::JobState::Queued);
		let idle = schedule(&holder.mailer.local_ref, Vec::new());
		assert_eq!(
			driver(&holder)
				.run_pass(&idle, now(), now() + 3600)
				.unwrap()
				.connections,
			0,
			"a Passive copy is never claimed by a schedule"
		);
		let server = accept(listener, &holder.mailer, 1);

		let poller = node(
			"poll-poller",
			"fidonet#1",
			poller_keys,
			&format!("Peer remote\nAddress fidonet#1/2\nEndpoint 127.0.0.1 {port}\nEnd\n"),
			"Routes fidonet#1\nEnd\n",
			&list,
		);
		let schedule = schedule(&poller.mailer.local_ref, vec!["remote".to_owned()]);
		let summary = driver(&poller).run_polls(&schedule, now());
		server.join().unwrap();

		assert_eq!(summary.attempted, 1);
		assert_eq!(summary.failed, 0);
		assert_eq!(summary.received, 1, "the poll returned the held Message");
		assert_eq!(
			job_state(&holder, &job),
			tith_store::JobState::Delivered,
			"the peer's Accepted retires the held copy"
		);
		let stored = stored_item(&poller, "check").expect("the poller stored the Message");
		assert_eq!(
			parse_sequence(&stored).unwrap()[0].type_code,
			types::MESSAGE
		);
	}
}
