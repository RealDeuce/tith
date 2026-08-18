#![forbid(unsafe_code)]

#[cfg(unix)]
mod tcp;
#[cfg(unix)]
mod unix;

use std::error::Error;
use std::fs;
#[cfg(unix)]
use std::net::SocketAddr;
use std::path::Path;

#[cfg(unix)]
use base64::Engine as _;
#[cfg(unix)]
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_config::ConfigurationSet;
#[cfg(unix)]
use tith_crypto::{KX_PUBLIC_KEY_BYTES, KxKeyPair, KxPublicKey};

fn main() {
	if let Err(error) = run() {
		eprintln!("tithd: {error}");
		std::process::exit(1);
	}
}

fn run() -> Result<(), Box<dyn Error>> {
	let mut arguments = std::env::args().skip(1);
	match arguments.next().as_deref() {
		#[cfg(unix)]
		Some("generate-ipc-key") => {
			let secret = arguments
				.next()
				.ok_or("usage: tithd generate-ipc-key SECRET-FILE")?;
			if arguments.next().is_some() {
				return Err("usage: tithd generate-ipc-key SECRET-FILE".into());
			}
			let keys = KxKeyPair::generate()?;
			tcp::write_secret(Path::new(&secret), &keys.secret)?;
			println!("Public-Key {}", STANDARD_NO_PAD.encode(keys.public.as_bytes()));
			Ok(())
		}
		Some("check-config") => {
			let directory = arguments.next().ok_or("usage: tithd check-config DIRECTORY")?;
			if arguments.next().is_some() { return Err("usage: tithd check-config DIRECTORY".into()); }
			load_config(Path::new(&directory))?;
			println!("configuration is valid");
			Ok(())
		}
		#[cfg(unix)]
		Some("serve-unix") => {
			let socket = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let database = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let exports = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let application = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			if arguments.next().is_some() { return Err("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION".into()); }
			unix::serve(Path::new(&socket), Path::new(&database), Path::new(&exports), application)
		}
		#[cfg(unix)]
		Some("serve-tcp") => {
			let usage = "usage: tithd serve-tcp ADDRESS DATABASE EXPORT-DIRECTORY APPLICATION SERVER-PUBLIC-KEY SERVER-SECRET-FILE CLIENT-PUBLIC-KEY";
			let address: SocketAddr = arguments.next().ok_or(usage)?.parse()?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			let server_public = decode_public(&arguments.next().ok_or(usage)?)?;
			let server_secret = tcp::read_secret(Path::new(&arguments.next().ok_or(usage)?))?;
			let client_public = decode_public(&arguments.next().ok_or(usage)?)?;
			if arguments.next().is_some() {
				return Err(usage.into());
			}
			tcp::serve(
				address,
				Path::new(&database),
				Path::new(&exports),
				application,
				KxKeyPair {
					public: server_public,
					secret: server_secret,
				},
				client_public,
			)
		}
		_ => Err("usage: tithd check-config DIRECTORY | generate-ipc-key SECRET-FILE | serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION | serve-tcp ADDRESS DATABASE EXPORT-DIRECTORY APPLICATION SERVER-PUBLIC-KEY SERVER-SECRET-FILE CLIENT-PUBLIC-KEY".into()),
	}
}

#[cfg(unix)]
fn decode_public(value: &str) -> Result<KxPublicKey, Box<dyn Error>> {
	if value.len() != 43 || value.contains('=') {
		return Err("invalid IPC public key".into());
	}
	let bytes: [u8; KX_PUBLIC_KEY_BYTES] = STANDARD_NO_PAD
		.decode(value)?
		.try_into()
		.map_err(|_| "invalid IPC public key length")?;
	Ok(KxPublicKey::from_bytes(bytes))
}

fn load_config(directory: &Path) -> Result<ConfigurationSet, Box<dyn Error>> {
	let read = |name: &str| fs::read_to_string(directory.join(name));
	Ok(ConfigurationSet::parse(
		&read("peers")?,
		&read("routes")?,
		&read("areas")?,
		&read("schedules")?,
	)?)
}
