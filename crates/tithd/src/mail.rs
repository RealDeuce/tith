use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tith_config::{ConfigurationSet, IdentityRef};
use tith_crypto::{SECRET_KEY_BYTES, SecretKey, TlvHash, hash_tlv, sign_tlv, verify_tlv};
use tith_exchange::ServerReply;
use tith_nodelist::Nodelist;
use tith_store::{AcceptResult, InboundStore, NewInbound};
use tith_wire::address::Address;
use tith_wire::bundle::{
	Bundle, BundleError, Identity, KeyResolver, unauthenticated_signed_data, verify_signed_tlv,
};
use tith_wire::item::{
	ItemKind, RejectionReason, ValidatedItem, accepted, rejected, request_identifier, validate_item,
};
use tith_wire::tlv::{OwnedTlv, TlvReader};
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

pub fn serve(
	address: SocketAddr,
	database: &Path,
	application: String,
	configuration: ConfigurationSet,
	nodelist: Nodelist,
	local_node: LocalNode,
) -> Result<(), Box<dyn Error>> {
	let signature = sign_tlv(b"", &local_node.secret)?;
	if !verify_tlv(b"", &signature, &local_node.identity.public_key)? {
		return Err("node secret key does not match the configured local public key".into());
	}
	let listener = TcpListener::bind(address)?;
	let mailer = Arc::new(Mailer {
		store: Arc::new(InboundStore::create(database)?),
		application,
		configuration,
		nodelist,
		local_ref: local_node.reference,
		local: local_node.identity,
		local_secret: local_node.secret,
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
	configuration: ConfigurationSet,
	nodelist: Nodelist,
	local_ref: IdentityRef,
	local: Identity,
	local_secret: SecretKey,
}

impl KeyResolver for Mailer {
	fn public_key(&self, address: &Address) -> Option<tith_crypto::PublicKey> {
		self.nodelist.public_key(address)
	}
}

struct IncomingBundle {
	bundle: Bundle,
	header_hash: TlvHash,
}

fn read_header(
	reader: &mut TlvReader<TcpStream>,
	first: Option<OwnedTlv>,
	resolver: &impl KeyResolver,
) -> Result<Option<IncomingBundle>, Box<dyn Error>> {
	let first = if let Some(value) = first {
		value
	} else {
		let Some(value) = reader.read_next()? else {
			return Ok(None);
		};
		value.read_owned()?
	};
	if first.type_code != types::ORIGIN {
		return Err("Bundle does not begin with Origin".into());
	}
	let mut prefix = first.encode();
	loop {
		let value = reader
			.read_next()?
			.ok_or("connection ended before the Header SignedTLV")?
			.read_owned()?;
		prefix.extend_from_slice(&value.encode());
		if value.type_code == types::SIGNED_TLV {
			let bundle = Bundle::parse(&prefix, resolver)?;
			let header_hash = hash_tlv(&bundle.header.encoded)?;
			return Ok(Some(IncomingBundle {
				bundle,
				header_hash,
			}));
		}
	}
}

fn transaction(stream: TcpStream, mailer: &Mailer) -> Result<(), Box<dyn Error>> {
	let mut writer = stream.try_clone()?;
	let mut reader = TlvReader::new(stream);
	let request = read_header(&mut reader, None, mailer)?.ok_or("empty mail connection")?;
	let reply =
		ServerReply::for_request(&request.bundle, &mailer.local, &mailer.local_secret, now())?;
	writer.write_all(reply.prefix())?;
	writer.flush()?;

	while let Some(value) = reader.read_next()? {
		let value = value.read_owned()?;
		match value.type_code {
			types::SIGNED_TLV => {
				let responses = payload_responses(&value, &request, mailer)?;
				if !responses.is_empty() {
					writer.write_all(&reply.payload(responses, &mailer.local_secret)?)?;
					writer.flush()?;
				}
			}
			types::ORIGIN => {
				validate_final_reply(&mut reader, value, &request, mailer)?;
				break;
			}
			type_code if types::is_defined(type_code) => {
				return Err("unexpected defined top-level value".into());
			}
			_ => {}
		}
	}
	writer.shutdown(Shutdown::Write)?;
	Ok(())
}

fn payload_responses(
	value: &OwnedTlv,
	request: &IncomingBundle,
	mailer: &Mailer,
) -> Result<Vec<OwnedTlv>, Box<dyn Error>> {
	let response_to = hash_tlv(&value.encode())?;
	let payload = match verify_signed_tlv(value, Some(&request.bundle.origin), mailer) {
		Ok(payload) => payload,
		Err(BundleError::InvalidSignature) => {
			return unauthenticated_responses(value, response_to);
		}
		Err(error) => return Err(error.into()),
	};
	let correct_header = payload.data.first().is_some_and(|first| {
		first.type_code == types::TLV_HASH
			&& first.value.as_slice() == request.header_hash.as_bytes()
	});
	let mut responses = Vec::new();
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
			Ok(Some(item)) => responses.push(dispatch_item(&item, response_to, request, mailer)?),
			Ok(None) => unreachable!("request types always produce an item"),
			Err(_) => responses.push(malformed_rejection(value, response_to)?),
		}
	}
	Ok(responses)
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

fn dispatch_item(
	item: &ValidatedItem,
	response_to: TlvHash,
	request: &IncomingBundle,
	mailer: &Mailer,
) -> Result<OwnedTlv, Box<dyn Error>> {
	let rejection = match item.kind {
		ItemKind::NetMail if item.destination.as_ref() != Some(&mailer.local) => {
			Some("relay delivery is not implemented")
		}
		ItemKind::EchoMail if !area_allowed(item, false, &request.bundle.origin, mailer) => {
			Some("EchoMail area is not authorized for this peer")
		}
		ItemKind::File
			if item.area.is_some() && !area_allowed(item, true, &request.bundle.origin, mailer) =>
		{
			Some("file area is not authorized for this peer")
		}
		ItemKind::FileRequest
		| ItemKind::PollMessages
		| ItemKind::PollFiles
		| ItemKind::PollFileRequests => Some("request type is not implemented"),
		ItemKind::Accepted | ItemKind::Rejected => {
			return Err("an initial Bundle contains a response value".into());
		}
		ItemKind::NetMail | ItemKind::EchoMail | ItemKind::File => None,
	};
	if let Some(description) = rejection {
		let permanent = matches!(item.kind, ItemKind::EchoMail)
			|| matches!(item.kind, ItemKind::File) && item.area.is_some();
		return Ok(rejected(
			item.request_identifier,
			response_to,
			None,
			if permanent {
				RejectionReason::Permanent
			} else {
				RejectionReason::Temporary
			},
			description,
		)?);
	}

	let authentication = item
		.authentication
		.ok_or("locally delivered item has no authentication state")?;
	let result = mailer.store.accept(
		NewInbound {
			application: &mailer.application,
			local_identity: &mailer.local.address.to_string(),
			peer: &request.bundle.origin.address.to_string(),
			peer_key: request.bundle.origin.public_key,
			received: now(),
			authentication,
			payload: &item.raw.encode(),
		},
		item.duplicate_identity.as_ref(),
	)?;
	match result {
		AcceptResult::Stored(_) | AcceptResult::Duplicate { .. } => {
			Ok(accepted(item.request_identifier, response_to)?)
		}
	}
}

fn area_allowed(item: &ValidatedItem, file_area: bool, peer: &Identity, mailer: &Mailer) -> bool {
	let Some(area_name) = item.area.as_deref() else {
		return false;
	};
	let Some(peer_name) = mailer
		.configuration
		.peers
		.iter()
		.find_map(|(name, configured)| {
			(configured.address == peer.address
				&& (!peer.address.is_unlisted() || configured.public_key == Some(peer.public_key)))
			.then_some(name.as_str())
		})
	else {
		return false;
	};
	mailer
		.configuration
		.areas
		.iter()
		.find(|areas| areas.local == mailer.local_ref)
		.and_then(|areas| {
			areas
				.areas
				.iter()
				.find(|area| area.file_area == file_area && area.name == area_name)
		})
		.is_some_and(|area| area.receive_from.iter().any(|name| name == peer_name))
}

fn validate_final_reply(
	reader: &mut TlvReader<TcpStream>,
	first: OwnedTlv,
	request: &IncomingBundle,
	mailer: &Mailer,
) -> Result<(), Box<dyn Error>> {
	let reply = read_header(reader, Some(first), mailer)?.ok_or("missing final Reply Bundle")?;
	if reply.bundle.origin != request.bundle.origin || reply.bundle.destination != mailer.local {
		return Err("final Reply Bundle has the wrong identities".into());
	}
	while let Some(value) = reader.read_next()? {
		let value = value.read_owned()?;
		if value.type_code == types::SIGNED_TLV {
			let payload = verify_signed_tlv(&value, Some(&reply.bundle.origin), mailer)?;
			let correct_header = payload.data.first().is_some_and(|first| {
				first.type_code == types::TLV_HASH
					&& first.value.as_slice() == reply.header_hash.as_bytes()
			});
			if !correct_header
				|| payload
					.data
					.iter()
					.skip(1)
					.any(|value| types::is_defined(value.type_code))
			{
				return Err("unexpected value in final Reply Bundle".into());
			}
		} else if types::is_defined(value.type_code) {
			return Err("unexpected top-level value after final Reply Header".into());
		}
	}
	Ok(())
}

fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

#[cfg(test)]
mod tests {
	use std::io::{Read, Write};
	use std::sync::Arc;

	use base64::Engine as _;
	use base64::engine::general_purpose::STANDARD_NO_PAD;
	use tith_crypto::{SigningKeyPair, sign_tlv};
	use tith_ipc::{Document, EnvelopeKind};
	use tith_store::{ClaimResult, ItemAuthentication};
	use tith_wire::bundle::{build_bundle, build_signed_tlv};
	use tith_wire::integer::{decode_u64_prefix, encode_u64};
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
			configuration,
			nodelist: nodelist(local.public_key.as_bytes(), peer.public_key.as_bytes()),
			local_ref: IdentityRef::Listed(local.address.clone()),
			local: local.clone(),
			local_secret: local_keys.secret,
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
}
