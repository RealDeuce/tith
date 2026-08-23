use std::error::Error;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::now;
use tith_config::{ConfigurationSet, IdentityRef};
use tith_crypto::{SECRET_KEY_BYTES, SecretKey, sign_tlv, verify_tlv};
use tith_nodelist::Nodelist;
use tith_store::InboundStore;
use tith_wire::address::Address;
use tith_wire::bundle::{Identity, KeyResolver};

use crate::accept::Acceptance;
use crate::deliver::{LocalIdentity, Outbound};
use crate::schedule::{Activation, Scheduler};
use crate::server_exchange::transaction;
#[cfg(test)]
use crate::server_exchange::{PollHold, validate_final_reply};

pub fn write_secret(path: &Path, secret: &SecretKey) -> Result<(), Box<dyn Error>> {
	crate::owner_only::write_file(path, secret.as_bytes())?;
	Ok(())
}

pub fn read_secret(path: &Path) -> Result<SecretKey, Box<dyn Error>> {
	let bytes: [u8; SECRET_KEY_BYTES] = crate::owner_only::read_file(path)?
		.try_into()
		.map_err(|_| "node secret key file has the wrong length")?;
	Ok(SecretKey::from_bytes(bytes))
}

pub struct LocalNode {
	pub reference: IdentityRef,
	pub identity: Identity,
	pub secret: SecretKey,
	pub retired_secrets: Vec<SecretKey>,
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
	let retired_secrets = local_node
		.retired_secrets
		.into_iter()
		.map(Arc::new)
		.collect();
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
		retired_secrets,
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

pub(super) struct Mailer {
	pub(super) store: Arc<InboundStore>,
	pub(super) application: String,
	pub(super) configuration: Arc<ConfigurationSet>,
	pub(super) nodelist: Arc<Nodelist>,
	pub(super) local_ref: IdentityRef,
	pub(super) local: Identity,
	pub(super) local_secret: Arc<SecretKey>,
	pub(super) retired_secrets: Vec<Arc<SecretKey>>,
}

impl Mailer {
	pub(super) fn acceptance(&self) -> Acceptance<'_> {
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
		if address == &self.local.address {
			return Some(self.local.public_key);
		}
		let nodelist_key = self.nodelist.public_key(address);
		self.store
			.key_pins()
			.resolve(address, nodelist_key)
			.ok()
			.flatten()
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
		let mut open: Vec<(Activation, bool)> = Vec::new();
		loop {
			open.extend(
				clock
					.poll(&schedules, now())
					.into_iter()
					.map(|activation| (activation, true)),
			);
			let mut still_open = Vec::new();
			for (activation, poll) in open.drain(..) {
				let schedule = &schedules[activation.schedule];
				let next_attempt = clock
					.next_beginning(activation.schedule)
					.unwrap_or_else(|| now().saturating_add(60));
				run_activation(&driver, schedule, next_attempt, poll);
				if activation.is_open(now()) {
					still_open.push((activation, false));
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

fn run_activation(
	driver: &Outbound,
	schedule: &tith_config::Schedule,
	next_attempt: u64,
	poll: bool,
) {
	let mut combined = crate::deliver::PassSummary::default();
	if poll {
		let (polled, pass) = driver.run_polls(schedule, now(), next_attempt);
		combined.add(pass);
		if polled.attempted > 0 {
			eprintln!(
				"tithd: schedule {} polled {} peer(s), received {} value(s), {} failed",
				schedule.name, polled.attempted, polled.received, polled.failed
			);
		}
	}
	match driver.run_pass(schedule, now(), next_attempt) {
		Ok(summary) => {
			combined.add(summary);
			if combined.connections == 0 {
				return;
			}
			eprintln!(
				"tithd: schedule {} made {} connection(s): {} delivered, {} retained, {} failed",
				schedule.name,
				combined.connections,
				combined.delivered,
				combined.retained,
				combined.failed
			);
		}
		Err(error) => eprintln!("tithd: schedule {} delivery failed: {error}", schedule.name),
	}
}

#[cfg(test)]
mod tests {
	use base64::Engine as _;
	use base64::engine::general_purpose::STANDARD_NO_PAD;
	use std::fs;
	use std::io::{Cursor, Read, Write};
	use std::net::{Shutdown, TcpStream};
	use std::sync::Arc;
	use std::time::{SystemTime, UNIX_EPOCH};
	use tith_crypto::{SigningKeyPair, TlvHash, hash_tlv, sign_tlv};
	use tith_ipc::{Document, EnvelopeKind};

	use tith_store::{ClaimResult, ItemAuthentication, JobKind};
	use tith_wire::bundle::Bundle;
	use tith_wire::bundle::{BundleError, build_bundle, build_signed_tlv, verify_signed_tlv};
	use tith_wire::integer::{decode_u64_prefix, encode_u64};
	use tith_wire::item::{ItemKind, RejectionReason, accepted, validate_payload};
	use tith_wire::tlv::{OwnedTlv, TlvReader, parse_sequence};
	use tith_wire::types;

	use crate::framing::{IncomingBundle, read_header};

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
			OwnedTlv::new(types::MESSAGE_TEXT, b"Native TITH mail\n".to_vec()).unwrap(),
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
			local_ref: IdentityRef::Address(local.address.clone()),
			local: local.clone(),
			local_secret: Arc::new(local_keys.secret),
			retired_secrets: Vec::new(),
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
		if let Err(error) = client.shutdown(Shutdown::Write) {
			assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
		}
		let mut response = Vec::new();
		client.read_to_end(&mut response).unwrap();
		(response, server.join().unwrap())
	}

	fn response_kind(response: &[u8], mailer: &Mailer) -> ItemKind {
		let reply = Bundle::parse(response, mailer).unwrap();
		validate_payload(&reply.payloads[0], mailer).unwrap()[0].kind
	}

	fn encoded_values(values: &[OwnedTlv]) -> Vec<u8> {
		let mut encoded = Vec::new();
		for value in values {
			value.write_to(&mut encoded).unwrap();
		}
		encoded
	}

	fn direct_client_exchange(
		make_reply: impl FnOnce(&Identity, &SecretKey, &Identity, u64, TlvHash) -> Vec<u8>
		+ Send
		+ 'static,
	) -> Result<(), Box<dyn Error>> {
		let (mailer, peer_keys, peer, local, database) = setup();
		let request_value = netmail(&local, &mailer.local_secret, &peer, 1);
		let encoded = build_bundle(
			&local,
			&mailer.local_secret,
			&peer,
			1,
			vec![vec![request_value]],
		)
		.unwrap();
		let request = Bundle::parse(&encoded, mailer.as_ref()).unwrap();
		let tracker =
			tith_exchange::ResponseTracker::for_bundle(&request, mailer.as_ref()).unwrap();
		let outstanding = tracker.outstanding()[0].clone();
		let reply = make_reply(
			&peer,
			&peer_keys.secret,
			&local,
			outstanding.request_identifier,
			outstanding.signed_tlv_hash,
		);

		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let request_len = encoded.len();
		let server = std::thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = vec![0; request_len];
			stream.read_exact(&mut request).unwrap();
			stream.write_all(&reply).unwrap();
			stream.shutdown(Shutdown::Write).unwrap();
		});

		let outbound = Outbound::new(
			Arc::clone(&mailer.store),
			mailer.application.clone(),
			Arc::clone(&mailer.configuration),
			Arc::clone(&mailer.nodelist),
			Vec::new(),
			Duration::from_secs(1),
		)
		.unwrap();
		let local_identity = LocalIdentity {
			reference: mailer.local_ref.clone(),
			identity: local.clone(),
			secret: Arc::clone(&mailer.local_secret),
		};
		let mut session = tith_exchange::ClientSession::new(tracker);
		let mut stream = TcpStream::connect(address).unwrap();
		let result = outbound
			.converse(&mut stream, &encoded, &mut session, &local_identity, &peer)
			.map(|_| ());
		server.join().unwrap();
		drop(outbound);
		drop(mailer);
		fs::remove_file(database).unwrap();
		result
	}

	#[test]
	fn client_reply_framing_rejects_early_end_defined_values_and_wrong_hashes() {
		assert!(
			direct_client_exchange(|peer, secret, local, _, _| {
				let reply = build_bundle(peer, secret, local, 2, Vec::new()).unwrap();
				encoded_values(&parse_sequence(&reply).unwrap()[..2])
			})
			.is_err()
		);
		assert!(
			direct_client_exchange(|peer, secret, local, identifier, response_to| {
				let reply = build_bundle(
					peer,
					secret,
					local,
					2,
					vec![vec![accepted(identifier, response_to).unwrap()]],
				)
				.unwrap();
				let mut values = parse_sequence(&reply).unwrap();
				values.insert(2, OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap());
				encoded_values(&values)
			})
			.is_err()
		);
		assert!(
			direct_client_exchange(|peer, secret, local, identifier, response_to| {
				let reply = build_bundle(
					peer,
					secret,
					local,
					2,
					vec![vec![accepted(identifier, response_to).unwrap()]],
				)
				.unwrap();
				let mut values = parse_sequence(&reply).unwrap();
				values.insert(2, OwnedTlv::new(31, b"extension".to_vec()).unwrap());
				encoded_values(&values)
			})
			.is_ok()
		);
		assert!(
			direct_client_exchange(|peer, secret, local, identifier, response_to| {
				let reply = build_bundle(
					peer,
					secret,
					local,
					2,
					vec![vec![accepted(identifier, response_to).unwrap()]],
				)
				.unwrap();
				let mut values = parse_sequence(&reply).unwrap();
				values[2] = build_signed_tlv(
					&[
						OwnedTlv::new(types::TLV_HASH, [9; 32].to_vec()).unwrap(),
						accepted(identifier, response_to).unwrap(),
					],
					None,
					secret,
				)
				.unwrap();
				encoded_values(&values)
			})
			.is_err()
		);
	}

	#[test]
	fn client_rejects_malformed_values_returned_by_a_poll() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(1)).unwrap()],
		);
		let encoded =
			build_bundle(&local, &mailer.local_secret, &peer, 1, vec![vec![poll]]).unwrap();
		let request = Bundle::parse(&encoded, mailer.as_ref()).unwrap();
		let tracker =
			tith_exchange::ResponseTracker::for_bundle(&request, mailer.as_ref()).unwrap();
		let outstanding = tracker.outstanding()[0].clone();
		let malformed = container(
			types::POLL_MESSAGES,
			&[
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(9)).unwrap(),
				OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap(),
			],
		);
		let reply = build_bundle(
			&peer,
			&peer_keys.secret,
			&local,
			2,
			vec![vec![
				malformed,
				accepted(outstanding.request_identifier, outstanding.signed_tlv_hash).unwrap(),
			]],
		)
		.unwrap();

		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let request_len = encoded.len();
		let server = std::thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = vec![0; request_len];
			stream.read_exact(&mut request).unwrap();
			stream.write_all(&reply).unwrap();
			stream.flush().unwrap();
			let mut final_reply = Vec::new();
			stream.read_to_end(&mut final_reply).unwrap();
			assert!(!final_reply.is_empty());
		});

		let outbound = Outbound::new(
			Arc::clone(&mailer.store),
			mailer.application.clone(),
			Arc::clone(&mailer.configuration),
			Arc::clone(&mailer.nodelist),
			Vec::new(),
			Duration::from_secs(1),
		)
		.unwrap();
		let local_identity = LocalIdentity {
			reference: mailer.local_ref.clone(),
			identity: local,
			secret: Arc::clone(&mailer.local_secret),
		};
		let mut session = tith_exchange::ClientSession::new(tracker);
		let mut stream = TcpStream::connect(address).unwrap();
		let exchange = outbound
			.converse(&mut stream, &encoded, &mut session, &local_identity, &peer)
			.unwrap();
		assert_eq!(exchange.returned, 1);
		server.join().unwrap();
		drop(outbound);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn retired_secret_certifies_the_current_key_for_a_dedicated_probe() {
		let (mut mailer, peer_keys, peer, local, database) = setup();
		let retired = SigningKeyPair::from_seed(&[44; 32]).unwrap();
		let retired_public = retired.public;
		Arc::get_mut(&mut mailer)
			.unwrap()
			.retired_secrets
			.push(Arc::new(retired.secret));
		let request = tith_wire::bundle::build_public_key_probe(
			&peer,
			&peer_keys.secret,
			&local.address,
			Some(retired_public),
			1,
			1,
		)
		.unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		let reply =
			Bundle::parse_public_key_reply(&response, mailer.as_ref(), Some(retired_public))
				.unwrap();
		let accepted = validate_payload(&reply.payloads[0], mailer.as_ref())
			.unwrap()
			.remove(0);
		assert_eq!(accepted.response_public_key, Some(local.public_key));
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn unavailable_predecessor_gets_a_current_key_signed_permanent_refusal() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let unavailable = SigningKeyPair::from_seed(&[45; 32]).unwrap().public;
		let request = tith_wire::bundle::build_public_key_probe(
			&peer,
			&peer_keys.secret,
			&local.address,
			Some(unavailable),
			1,
			9,
		)
		.unwrap();
		let (response, completed) = exchange(&request, &mailer);
		assert!(completed);
		assert!(matches!(
			Bundle::parse_public_key_reply(&response, mailer.as_ref(), Some(unavailable)),
			Err(BundleError::InvalidSignature)
		));

		let top = parse_sequence(&response).unwrap();
		assert_eq!(top[1].type_code, types::PUBLIC_KEY);
		assert_eq!(top[1].value, local.public_key.as_bytes());
		let header = verify_signed_tlv(&top[2], Some(&local), mailer.as_ref()).unwrap();
		assert_eq!(header.identity, local);
		let payload = verify_signed_tlv(&top[3], Some(&local), mailer.as_ref()).unwrap();
		let item = validate_payload(&payload, mailer.as_ref())
			.unwrap()
			.remove(0);
		assert_eq!(item.kind, ItemKind::Rejected);
		let rejection = item.rejection.unwrap();
		assert_eq!(rejection.reason, RejectionReason::Permanent);
		assert_eq!(rejection.retry_after, None);
		assert_eq!(
			rejection.description,
			"requested predecessor private key is unavailable"
		);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn server_rejects_extra_dedicated_probe_data_and_defined_top_level_values() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let mut probe = tith_wire::bundle::build_public_key_probe(
			&peer,
			&peer_keys.secret,
			&local.address,
			Some(local.public_key),
			1,
			1,
		)
		.unwrap();
		probe.extend_from_slice(&OwnedTlv::new(31, b"extra".to_vec()).unwrap().encode());
		let (_, completed) = exchange(&probe, &mailer);
		assert!(!completed);

		let request = build_bundle(
			&peer,
			&peer_keys.secret,
			&local,
			1,
			vec![vec![netmail(&peer, &peer_keys.secret, &local, 2)]],
		)
		.unwrap();
		let mut defined = request.clone();
		defined.extend_from_slice(&OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap().encode());
		let (_, completed) = exchange(&defined, &mailer);
		assert!(!completed);

		let mut extended = request;
		extended.extend_from_slice(&OwnedTlv::new(31, b"extension".to_vec()).unwrap().encode());
		let (_, completed) = exchange(&extended, &mailer);
		assert!(completed);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn server_rejects_a_response_in_an_initial_bundle() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let request = build_bundle(
			&peer,
			&peer_keys.secret,
			&local,
			1,
			vec![vec![accepted(1, TlvHash::from_bytes([1; 32])).unwrap()]],
		)
		.unwrap();
		let (_, completed) = exchange(&request, &mailer);
		assert!(!completed);
		drop(mailer);
		fs::remove_file(database).unwrap();
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
			RejectionReason::Permanent as u64
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
		assert!(
			!completed,
			"the reason-1 response is sent before the required close"
		);
		assert_eq!(response_kind(&response, &mailer), ItemKind::Rejected);
		assert_eq!(
			rejected_reason(&response, &mailer),
			RejectionReason::Permanent as u64
		);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn duplicate_request_identifiers_close_without_responses() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let duplicate_polls = || {
			[types::POLL_MESSAGES, types::POLL_FILES]
				.into_iter()
				.map(|type_code| {
					container(
						type_code,
						&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(10)).unwrap()],
					)
				})
				.collect::<Vec<_>>()
		};

		let authenticated =
			build_bundle(&peer, &peer_keys.secret, &local, 1, vec![duplicate_polls()]).unwrap();
		let (response, completed) = exchange(&authenticated, &mailer);
		assert!(!completed);
		assert!(
			Bundle::parse(&response, mailer.as_ref())
				.unwrap()
				.payloads
				.is_empty()
		);

		let unauthenticated =
			build_bundle(&peer, &peer_keys.secret, &local, 1, vec![duplicate_polls()]).unwrap();
		let mut top = parse_sequence(&unauthenticated).unwrap();
		*top.last_mut().unwrap().value.last_mut().unwrap() ^= 1;
		let unauthenticated = top.iter().flat_map(OwnedTlv::encode).collect::<Vec<_>>();
		let (response, completed) = exchange(&unauthenticated, &mailer);
		assert!(!completed);
		assert!(
			Bundle::parse(&response, mailer.as_ref())
				.unwrap()
				.payloads
				.is_empty()
		);

		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn a_poll_build_error_releases_every_claimed_copy() {
		let (mailer, peer_keys, peer, local, database) = setup();
		// The store owns only the outer item kind. This deliberately malformed
		// Message reaches the exchange's parser after the Poll snapshot has been
		// atomically claimed, which is the failure boundary this test exercises.
		let item = OwnedTlv::new(types::MESSAGE, vec![0x80]).unwrap().encode();
		let identity = tith_store::SubmissionIdentity {
			application: "test".to_owned(),
			idempotency_key: "malformed-held".to_owned(),
			digest: hash_tlv(&item).unwrap(),
		};
		let job = tith_store::NewOutboundJob {
			identity: identity.clone(),
			kind: JobKind::NetMail,
			target: tith_store::JobTarget::Destination(peer.address.to_string()),
			local_identity: local.address.to_string(),
			item,
			deliveries: vec![tith_store::NewDelivery {
				local_identity: local.address.to_string(),
				next_hop: peer.address.to_string(),
				next_hop_key: None,
				mode: tith_store::DeliveryMode::Passive,
				class: "Normal".to_owned(),
				retry_at: None,
				policies: std::array::from_fn(|_| tith_store::FailurePolicy::default()),
			}],
			sources: Vec::new(),
			created: now(),
			forward_inbound: None,
			forward_claim_token: None,
		};
		let outbound = mailer.store.outbound().unwrap();
		let tith_store::BatchCommit::Committed(committed) = outbound
			.commit_batch(std::slice::from_ref(&identity), |_, _| Ok(vec![job]))
			.unwrap()
		else {
			panic!("job must commit")
		};
		let job_id = match &committed[0] {
			tith_store::CommitOutcome::New { job_id, .. } => job_id.clone(),
			tith_store::CommitOutcome::Existing { .. } => panic!("job must be new"),
		};

		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(1)).unwrap()],
		);
		let request = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![poll]]).unwrap();
		let (_, completed) = exchange(&request, &mailer);
		assert!(
			!completed,
			"the malformed spool item must fail the exchange"
		);
		assert_eq!(
			outbound.query(&job_id).unwrap().state,
			tith_store::JobState::Deferred,
			"the failed exchange must release its Poll snapshot without a restart"
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
			address: Address::anonymous("p2p".to_owned()).unwrap(),
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
			local_ref: IdentityRef::Address(address.clone()),
			local: Identity {
				address,
				public_key: keys.public,
			},
			local_secret: Arc::new(keys.secret),
			retired_secrets: Vec::new(),
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

	/// Accepts the stale-key exchange followed by its probe and retry.
	///
	/// The Client stops reading as soon as the stale key fails to authenticate
	/// the Reply Header. Windows may consequently report the Server's pending
	/// write as an aborted connection; that is an expected form of the Client's
	/// active close, but every later transaction still has to complete.
	fn is_expected_stale_close(error: &(dyn std::error::Error + 'static)) -> bool {
		let kind = error
			.downcast_ref::<std::io::Error>()
			.map(std::io::Error::kind)
			.or_else(
				|| match error.downcast_ref::<tith_exchange::ExchangeError>() {
					Some(tith_exchange::ExchangeError::Io(error)) => Some(error.kind()),
					_ => None,
				},
			);
		kind.is_some_and(|kind| {
			matches!(
				kind,
				std::io::ErrorKind::ConnectionAborted
					| std::io::ErrorKind::ConnectionReset
					| std::io::ErrorKind::BrokenPipe
			)
		})
	}

	fn accept_stale_key_retry(
		listener: TcpListener,
		mailer: &Arc<Mailer>,
	) -> std::thread::JoinHandle<()> {
		let mailer = Arc::clone(mailer);
		std::thread::spawn(move || {
			for connection in 0..3 {
				let (stream, _) = listener.accept().unwrap();
				let result = transaction(stream, &mailer);
				if connection == 0
					&& result
						.as_ref()
						.is_err_and(|error| is_expected_stale_close(error.as_ref()))
				{
					continue;
				}
				result.unwrap();
			}
		})
	}

	#[test]
	fn expected_stale_close_recognises_a_wrapped_exchange_io_error() {
		let wrapped = tith_exchange::ExchangeError::Io(std::io::Error::new(
			std::io::ErrorKind::ConnectionAborted,
			"the Client actively closed",
		));
		assert!(is_expected_stale_close(&wrapped));
		let unrelated = tith_exchange::ExchangeError::Io(std::io::Error::new(
			std::io::ErrorKind::PermissionDenied,
			"not a close",
		));
		assert!(!is_expected_stale_close(&unrelated));
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
			[crate::submission::LocalSigner {
				reference: node.mailer.local_ref.clone(),
				identity: node.mailer.local.clone(),
				secret: Arc::clone(&node.mailer.local_secret),
			}],
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

	#[test]
	fn authentication_failure_probes_the_predecessor_and_retries_once() {
		let sender_keys = SigningKeyPair::from_seed(&[53; 32]).unwrap();
		let retired = SigningKeyPair::from_seed(&[54; 32]).unwrap();
		let retired_public = retired.public;
		let receiver_keys = SigningKeyPair::from_seed(&[55; 32]).unwrap();
		let receiver_public = receiver_keys.public;
		let list = Arc::new(nodelist(
			sender_keys.public.as_bytes(),
			retired_public.as_bytes(),
		));
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let port = listener.local_addr().unwrap().port();

		let mut receiver = node(
			"rotate-receiver",
			"fidonet#1/2",
			receiver_keys,
			"Peer sender\nAddress fidonet#1\nEnd\n",
			"Routes fidonet#1/2\nEnd\n",
			&list,
		);
		Arc::get_mut(&mut receiver.mailer)
			.unwrap()
			.retired_secrets
			.push(Arc::new(retired.secret));
		let server = accept_stale_key_retry(listener, &receiver.mailer);

		let sender = node(
			"rotate-sender",
			"fidonet#1",
			sender_keys,
			&format!("Peer remote\nAddress fidonet#1/2\nEndpoint 127.0.0.1 {port}\nEnd\n"),
			"Routes fidonet#1\nEnd\n",
			&list,
		);
		let job = submit(&sender, "fidonet#1/2", "Active \"@remote\"", "rotated");
		let summary = driver(&sender)
			.run_pass(
				&schedule(&sender.mailer.local_ref, Vec::new()),
				now(),
				now() + 3600,
			)
			.unwrap();
		server.join().unwrap();

		assert_eq!(summary.delivered, 1);
		assert_eq!(job_state(&sender, &job), tith_store::JobState::Delivered);
		assert_eq!(
			sender
				.mailer
				.store
				.key_pins()
				.resolve(&"fidonet#1/2".parse().unwrap(), Some(retired_public))
				.unwrap(),
			Some(receiver_public)
		);
	}

	#[test]
	fn trusted_first_contact_pins_then_routes_operational_mail() {
		let sender_keys = SigningKeyPair::from_seed(&[56; 32]).unwrap();
		let receiver_keys = SigningKeyPair::from_seed(&[57; 32]).unwrap();
		let receiver_public = receiver_keys.public;
		let list = Arc::new(
			Nodelist::parse(
				"fidonet",
				&format!(
					"Zone\t1\tNode\tLocation\tSysop\t\tCM\t\tIIH:sender.example:24555:{}\t\t\n",
					STANDARD_NO_PAD.encode(sender_keys.public.as_bytes())
				),
			)
			.unwrap(),
		);
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let port = listener.local_addr().unwrap().port();
		let receiver = node(
			"tofu-receiver",
			"fidonet#1/2",
			receiver_keys,
			"Peer sender\nAddress fidonet#1\nEnd\n",
			"Routes fidonet#1/2\nEnd\n",
			&list,
		);
		let server = accept(listener, &receiver.mailer, 3);
		let sender = node(
			"tofu-sender",
			"fidonet#1",
			sender_keys,
			&format!(
				"Peer remote\nAddress fidonet#1/2\nEndpoint 127.0.0.1 {port}\nTrust-On-First-Use\nEnd\n"
			),
			"Routes fidonet#1\nRoute All Using Via @remote\nEnd\n",
			&list,
		);
		let polling = schedule(&sender.mailer.local_ref, vec!["remote".to_owned()]);
		let (poll, _) = driver(&sender).run_polls(&polling, now(), now() + 60);
		assert_eq!(poll.failed, 0);
		assert_eq!(
			sender
				.mailer
				.store
				.key_pins()
				.resolve(&"fidonet#1/2".parse().unwrap(), None)
				.unwrap(),
			Some(receiver_public)
		);

		let job = submit(&sender, "fidonet#1/2", "Route", "after-tofu");
		let sent = driver(&sender)
			.run_pass(
				&schedule(&sender.mailer.local_ref, Vec::new()),
				now(),
				now() + 60,
			)
			.unwrap();
		server.join().unwrap();
		assert_eq!(sent.delivered, 1);
		assert_eq!(job_state(&sender, &job), tith_store::JobState::Delivered);
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

	#[test]
	fn a_denied_relay_leaves_responsibility_with_the_sender() {
		let sender_keys = SigningKeyPair::from_seed(&[64; 32]).unwrap();
		let hub_keys = SigningKeyPair::from_seed(&[65; 32]).unwrap();
		let far_keys = SigningKeyPair::from_seed(&[66; 32]).unwrap();
		let hub_listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let hub_port = hub_listener.local_addr().unwrap().port();
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
					line("", 3, &far_keys, 1),
				]
				.concat(),
			)
			.unwrap(),
		);

		let hub = node(
			"relay-deny-hub",
			"fidonet#1/2",
			hub_keys,
			"Peer sender\nAddress fidonet#1\nEnd\n",
			"Routes fidonet#1/2\nEnd\n",
			&list,
		);
		let hub_server = accept(hub_listener, &hub.mailer, 1);
		let sender = node(
			"relay-deny-sender",
			"fidonet#1",
			sender_keys,
			&format!("Peer hub\nAddress fidonet#1/2\nEndpoint 127.0.0.1 {hub_port}\nEnd\n"),
			"Routes fidonet#1\nEnd\n",
			&list,
		);
		let job = submit(&sender, "fidonet#1/3", "Active \"@hub\"", "denied-relay");
		let summary = driver(&sender)
			.run_pass(
				&schedule(&sender.mailer.local_ref, Vec::new()),
				now(),
				now() + 3600,
			)
			.unwrap();
		hub_server.join().unwrap();

		assert_eq!(summary.failed, 1);
		assert_eq!(job_state(&sender, &job), tith_store::JobState::Rejected);
		let record = sender.mailer.store.outbound().unwrap().query(&job).unwrap();
		assert_eq!(
			record.deliveries[0].last_failure,
			Some(tith_store::PermanentFailureKind::RelayDenied)
		);
		assert!(stored_item(&hub, "none").is_none());
		assert!(
			hub.mailer
				.store
				.outbound()
				.unwrap()
				.events("tithd-relay")
				.unwrap()
				.is_empty()
		);
	}

	/// Two Polls in one request payload must not reuse returned-value identifiers.
	#[test]
	fn returned_requests_use_the_reverse_direction_identifier_namespace() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let message_job = submit(
			&Node {
				mailer: Arc::clone(&mailer),
				database: database.with_extension("unused"),
			},
			&peer.address.to_string(),
			"Passive \"@remote\"",
			"held-message",
		);
		assert_eq!(
			mailer
				.store
				.outbound()
				.unwrap()
				.query(&message_job)
				.unwrap()
				.state,
			tith_store::JobState::Queued
		);

		let file = standalone_file(&local, &mailer.local_secret, 99);
		let encoded = file.encode();
		let identity = tith_store::SubmissionIdentity {
			application: "test".to_owned(),
			idempotency_key: "held-file".to_owned(),
			digest: hash_tlv(&encoded).unwrap(),
		};
		let file_job = tith_store::NewOutboundJob {
			identity: identity.clone(),
			kind: JobKind::PeerFile,
			target: tith_store::JobTarget::Destination(peer.address.to_string()),
			local_identity: local.address.to_string(),
			item: encoded,
			deliveries: vec![tith_store::NewDelivery {
				local_identity: local.address.to_string(),
				next_hop: peer.address.to_string(),
				next_hop_key: None,
				mode: tith_store::DeliveryMode::Passive,
				class: "Normal".to_owned(),
				retry_at: None,
				policies: std::array::from_fn(|_| tith_store::FailurePolicy::default()),
			}],
			sources: Vec::new(),
			created: now(),
			forward_inbound: None,
			forward_claim_token: None,
		};
		let outbound = mailer.store.outbound().unwrap();
		assert!(matches!(
			outbound
				.commit_batch(&[identity], |_, _| Ok(vec![file_job]))
				.unwrap(),
			tith_store::BatchCommit::Committed(_)
		));

		let poll_messages = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(1)).unwrap()],
		);
		let poll_files = container(
			types::POLL_FILES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(2)).unwrap()],
		);
		let request = build_bundle(
			&peer,
			&peer_keys.secret,
			&local,
			1,
			vec![vec![poll_messages, poll_files]],
		)
		.unwrap();
		let (response, _) = exchange(&request, &mailer);
		let reply = Bundle::parse(&response, mailer.as_ref()).unwrap();
		let items = validate_payload(&reply.payloads[0], mailer.as_ref()).unwrap();
		assert_eq!(
			items.iter().map(|item| item.kind).collect::<Vec<_>>(),
			vec![
				ItemKind::NetMail,
				ItemKind::Accepted,
				ItemKind::File,
				ItemKind::Accepted,
			],
			"each Poll's returned request must precede its Accepted response"
		);
		let identifiers: Vec<_> = items
			.iter()
			.filter(|item| {
				matches!(
					item.kind,
					ItemKind::NetMail | ItemKind::EchoMail | ItemKind::File
				)
			})
			.map(|item| item.request_identifier)
			.collect();
		assert_eq!(identifiers, vec![1, 2]);
		let statuses = items
			.iter()
			.filter(|item| matches!(item.kind, ItemKind::Accepted | ItemKind::Rejected))
			.map(|item| item.request_identifier)
			.collect::<Vec<_>>();
		assert_eq!(statuses, vec![1, 2]);
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	#[test]
	fn a_client_reply_can_start_another_server_reply_round() {
		let (mailer, peer_keys, peer, local, database) = setup();
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server_mailer = Arc::clone(&mailer);
		let server = std::thread::spawn(move || {
			let (stream, _) = listener.accept().unwrap();
			transaction(stream, &server_mailer).unwrap();
		});
		let mut client = TcpStream::connect(address).unwrap();
		let mut reader = TlvReader::new(client.try_clone().unwrap());

		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(1)).unwrap()],
		);
		let initial = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![poll]]).unwrap();
		client.write_all(&initial).unwrap();
		client.flush().unwrap();

		let first_reply = read_header(&mut reader, None, mailer.as_ref())
			.unwrap()
			.unwrap();
		let first_payload = reader.read_next().unwrap().unwrap().read_owned().unwrap();
		let mut first_bytes = first_reply.prefix;
		first_bytes.extend_from_slice(&first_payload.encode());
		assert_eq!(
			response_kind(&first_bytes, mailer.as_ref()),
			ItemKind::Accepted
		);

		// The required Client Reply also carries a new Poll. The Server must
		// answer it and wait for another Client Reply rather than imposing a
		// round-count limit.
		let next_poll = container(
			types::POLL_FILES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(2)).unwrap()],
		);
		let next =
			build_bundle(&peer, &peer_keys.secret, &local, 2, vec![vec![next_poll]]).unwrap();
		client.write_all(&next).unwrap();
		client.flush().unwrap();

		let second_reply = read_header(&mut reader, None, mailer.as_ref())
			.unwrap()
			.unwrap();
		let second_payload = reader.read_next().unwrap().unwrap().read_owned().unwrap();
		let mut second_bytes = second_reply.prefix;
		second_bytes.extend_from_slice(&second_payload.encode());
		assert_eq!(
			response_kind(&second_bytes, mailer.as_ref()),
			ItemKind::Accepted
		);

		let message = netmail(&peer, &peer_keys.secret, &local, 3);
		let third = build_bundle(&peer, &peer_keys.secret, &local, 3, vec![vec![message]]).unwrap();
		client.write_all(&third).unwrap();
		client.flush().unwrap();
		client.shutdown(Shutdown::Write).unwrap();
		let third_reply = read_header(&mut reader, None, mailer.as_ref())
			.unwrap()
			.unwrap();
		let third_payload = reader.read_next().unwrap().unwrap().read_owned().unwrap();
		let mut third_bytes = third_reply.prefix;
		third_bytes.extend_from_slice(&third_payload.encode());
		assert_eq!(
			response_kind(&third_bytes, mailer.as_ref()),
			ItemKind::Accepted
		);
		drop(reader);
		drop(client);
		server.join().unwrap();

		assert!(matches!(
			mailer
				.store
				.claim("tosser", "continued", now().saturating_add(1), 60)
				.unwrap(),
			ClaimResult::Completed(_)
		));
		drop(mailer);
		fs::remove_file(database).unwrap();
	}

	fn final_reply_fixture() -> (
		Node,
		SigningKeyPair,
		Identity,
		IncomingBundle,
		TlvHash,
		Vec<PollHold>,
	) {
		let (mailer, peer_keys, peer, local, database) = setup();
		let node = Node {
			mailer: Arc::clone(&mailer),
			database,
		};
		submit(
			&node,
			&peer.address.to_string(),
			"Passive \"@remote\"",
			"held-first",
		);
		submit(
			&node,
			&peer.address.to_string(),
			"Passive \"@remote\"",
			"held-second",
		);
		let claims = mailer
			.store
			.outbound()
			.unwrap()
			.claim_poll_snapshot(&peer.address.to_string(), None, &[JobKind::NetMail], now())
			.unwrap();
		assert_eq!(claims.len(), 2);
		let response_to = TlvHash::from_bytes([7; 32]);
		let holds = claims
			.into_iter()
			.enumerate()
			.map(|(index, claim)| PollHold {
				signed_tlv_hash: response_to,
				request_identifier: u64::try_from(index + 1).unwrap(),
				relayed: false,
				claim,
			})
			.collect::<Vec<_>>();

		let poll = container(
			types::POLL_MESSAGES,
			&[OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(10)).unwrap()],
		);
		let initial = build_bundle(&peer, &peer_keys.secret, &local, 1, vec![vec![poll]]).unwrap();
		let mut initial_reader = TlvReader::new(Cursor::new(initial));
		let request = read_header(&mut initial_reader, None, mailer.as_ref())
			.unwrap()
			.unwrap();
		(node, peer_keys, peer, request, response_to, holds)
	}

	fn check_final_reply(
		node: &Node,
		peer_keys: &SigningKeyPair,
		peer: &Identity,
		request: &IncomingBundle,
		holds: &mut Vec<PollHold>,
		responses: Vec<OwnedTlv>,
		trailing: &[u8],
	) -> Result<(), Box<dyn Error>> {
		let final_reply = build_bundle(
			peer,
			&peer_keys.secret,
			&node.mailer.local,
			2,
			vec![responses],
		)
		.unwrap();
		let mut final_reply = final_reply;
		final_reply.extend_from_slice(trailing);
		let mut final_reader = TlvReader::new(Cursor::new(final_reply));
		let first = final_reader
			.read_next()
			.unwrap()
			.unwrap()
			.read_owned()
			.unwrap();
		validate_final_reply(
			&mut final_reader,
			first,
			request,
			node.mailer.as_ref(),
			holds,
		)
	}

	#[test]
	fn final_reply_responses_may_reverse_the_returned_value_order() {
		let (node, peer_keys, peer, request, response_to, mut holds) = final_reply_fixture();
		check_final_reply(
			&node,
			&peer_keys,
			&peer,
			&request,
			&mut holds,
			vec![
				accepted(2, response_to).unwrap(),
				accepted(1, response_to).unwrap(),
			],
			&[],
		)
		.unwrap();
		assert!(holds.is_empty());
	}

	#[test]
	fn final_reply_must_answer_every_returned_value() {
		let (node, peer_keys, peer, request, response_to, mut holds) = final_reply_fixture();
		assert!(
			check_final_reply(
				&node,
				&peer_keys,
				&peer,
				&request,
				&mut holds,
				vec![accepted(1, response_to).unwrap()],
				&[],
			)
			.is_err()
		);
		assert_eq!(holds.len(), 1);
	}

	#[test]
	fn final_reply_must_not_answer_a_returned_value_twice() {
		let (node, peer_keys, peer, request, response_to, mut holds) = final_reply_fixture();
		assert!(
			check_final_reply(
				&node,
				&peer_keys,
				&peer,
				&request,
				&mut holds,
				vec![
					accepted(1, response_to).unwrap(),
					accepted(1, response_to).unwrap(),
				],
				&[],
			)
			.is_err()
		);
		assert_eq!(holds.len(), 1);
	}

	#[test]
	fn final_reply_completes_without_waiting_past_the_last_response() {
		let (node, peer_keys, peer, request, response_to, mut holds) = final_reply_fixture();
		check_final_reply(
			&node,
			&peer_keys,
			&peer,
			&request,
			&mut holds,
			vec![
				accepted(1, response_to).unwrap(),
				accepted(2, response_to).unwrap(),
			],
			// An unterminated integer makes any read past the complete Reply fail.
			&[0x80],
		)
		.unwrap();
		assert!(holds.is_empty());
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
		let outbound_job = submit(
			&poller,
			"fidonet#1/2",
			"Active \"@remote\"",
			"sent-with-poll",
		);
		let schedule = schedule(&poller.mailer.local_ref, vec!["remote".to_owned()]);
		let (summary, pass) = driver(&poller).run_polls(&schedule, now(), now() + 3600);
		server.join().unwrap();

		assert_eq!(summary.attempted, 1);
		assert_eq!(summary.failed, 0);
		assert_eq!(summary.received, 1, "the poll returned the held Message");
		assert_eq!(
			pass.connections, 1,
			"queued work shared the Poll connection"
		);
		assert_eq!(pass.delivered, 1);
		assert_eq!(
			job_state(&poller, &outbound_job),
			tith_store::JobState::Delivered
		);
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
		assert!(
			stored_item(&holder, "combined").is_some(),
			"the second payload SignedTLV delivered queued work"
		);
	}
}
