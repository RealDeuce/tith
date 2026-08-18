use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use crate::ipc::{IpcService, Principal};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::{KX_SECRET_KEY_BYTES, KxKeyPair, KxPublicKey, KxSecretKey};
use tith_ipc::EnvelopeKind;
use tith_ipc_tcp::SecureChannel;

pub fn write_secret(path: &Path, secret: &KxSecretKey) -> Result<(), Box<dyn Error>> {
	let mut file = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)?;
	file.write_all(secret.as_bytes())?;
	file.sync_all()?;
	Ok(())
}

pub fn read_secret(path: &Path) -> Result<KxSecretKey, Box<dyn Error>> {
	let metadata = fs::metadata(path)?;
	if metadata.permissions().mode() & 0o077 != 0 {
		return Err("IPC secret key file is accessible by group or other users".into());
	}
	let bytes = fs::read(path)?;
	let bytes: [u8; KX_SECRET_KEY_BYTES] = bytes
		.try_into()
		.map_err(|_| "IPC secret key file has the wrong length")?;
	Ok(KxSecretKey::from_bytes(bytes))
}

pub fn serve(
	address: SocketAddr,
	database: &Path,
	exports: &Path,
	application: String,
	server_keys: KxKeyPair,
	client_public: KxPublicKey,
) -> Result<(), Box<dyn Error>> {
	if !address.ip().is_loopback() {
		return Err("refusing to bind TCP IPC to a nonloopback address".into());
	}
	fs::create_dir_all(exports)?;
	fs::set_permissions(exports, fs::Permissions::from_mode(0o700))?;
	let listener = TcpListener::bind(address)?;
	if !listener.local_addr()?.ip().is_loopback() {
		return Err("TCP IPC listener is not bound to loopback".into());
	}
	let service = Arc::new(IpcService::create(database, exports)?);
	let principal = Arc::new(Principal::single(
		STANDARD_NO_PAD.encode(client_public.as_bytes()),
		application,
	));
	let server_keys = Arc::new(server_keys);
	for connection in listener.incoming() {
		match connection {
			Ok(stream) if stream.peer_addr()?.ip().is_loopback() => {
				let service = Arc::clone(&service);
				let principal = Arc::clone(&principal);
				let server_keys = Arc::clone(&server_keys);
				std::thread::spawn(move || {
					if let Err(error) =
						transaction(stream, &service, &principal, &server_keys, client_public)
					{
						eprintln!("tithd: TCP IPC transaction failed: {error}");
					}
				});
			}
			Ok(_) => eprintln!("tithd: rejected nonloopback TCP IPC peer"),
			Err(error) => eprintln!("tithd: TCP IPC accept failed: {error}"),
		}
	}
	Ok(())
}

fn transaction(
	stream: TcpStream,
	service: &IpcService,
	principal: &Principal,
	server_keys: &KxKeyPair,
	client_public: KxPublicKey,
) -> Result<(), Box<dyn Error>> {
	let (mut channel, ()) = SecureChannel::accept(stream, server_keys, |key| {
		(*key == client_public).then_some(())
	})?;
	let request = channel.receive_flat_document(EnvelopeKind::Request)?;
	let response = service.process_request(&request, Some(principal));
	channel.send_document(&response, EnvelopeKind::Result)?;
	let mut stream = channel.into_inner();
	let mut unexpected = [0];
	if stream.read(&mut unexpected)? != 0 {
		return Err("TCP IPC client sent data after its complete request".into());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::net::{Shutdown, TcpListener, TcpStream};
	use std::time::{SystemTime, UNIX_EPOCH};

	use super::*;
	use tith_ipc::{Document, EnvelopeKind};

	#[test]
	fn serves_capabilities_to_an_authenticated_client() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let root = std::env::temp_dir().join(format!("tithd-tcp-{unique}"));
		let database = root.join("state.redb");
		let exports = root.join("exports");
		fs::create_dir_all(&exports).unwrap();
		let service = IpcService::create(&database, &exports).unwrap();
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server_keys = KxKeyPair::generate().unwrap();
		let server_public = server_keys.public;
		let client_keys = KxKeyPair::generate().unwrap();
		let client_public = client_keys.public;
		let server = std::thread::spawn(move || {
			let (stream, _) = listener.accept().unwrap();
			transaction(
				stream,
				&service,
				&Principal::single("client", "tosser"),
				&server_keys,
				client_public,
			)
			.unwrap();
		});

		let stream = TcpStream::connect(address).unwrap();
		let mut channel = SecureChannel::connect(stream, &client_keys, &server_public).unwrap();
		let request = b"TITH-IPC 1\nCapabilities\nEnd\n";
		channel
			.send_document(request, EnvelopeKind::Request)
			.unwrap();
		let result = channel.receive_flat_document(EnvelopeKind::Result).unwrap();
		let document = Document::parse(&result, EnvelopeKind::Result).unwrap();
		assert_eq!(document.lines[0].fields[0].text, "Capabilities");
		assert_eq!(document.lines[0].fields[1].text, "Completed");
		channel.into_inner().shutdown(Shutdown::Both).unwrap();
		server.join().unwrap();
		fs::remove_file(database).unwrap();
		fs::remove_dir_all(root).unwrap();
	}
}
