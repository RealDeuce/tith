#![deny(unsafe_code)]

mod accept;
mod client_exchange;
mod deliver;
mod filesystem;
mod framing;
mod ipc;
mod mail;
mod owner_only;
mod public_key_response;
mod schedule;
mod server_exchange;
mod submission;
mod tcp;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

use std::error::Error;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_config::ConfigurationSet;
use tith_config::IdentityRef;
use tith_crypto::SigningKeyPair;
use tith_crypto::{KX_PUBLIC_KEY_BYTES, KxKeyPair, KxPublicKey};
use tith_crypto::{SECRET_KEY_BYTES, SecretKey};
use tith_nodelist::Nodelist;
use tith_wire::address::Address;
use tith_wire::bundle::Identity;

fn main() {
	if let Err(error) = run() {
		eprintln!("tithd: {error}");
		std::process::exit(1);
	}
}

fn run() -> Result<(), Box<dyn Error>> {
	let mut arguments = std::env::args().skip(1);
	match arguments.next().as_deref() {
		Some("generate-node-key") => {
			let secret = arguments
				.next()
				.ok_or("usage: tithd generate-node-key SECRET-FILE")?;
			if arguments.next().is_some() {
				return Err("usage: tithd generate-node-key SECRET-FILE".into());
			}
			let keys = SigningKeyPair::generate()?;
			mail::write_secret(Path::new(&secret), &keys.secret)?;
			println!("Public-Key {}", STANDARD_NO_PAD.encode(keys.public.as_bytes()));
			Ok(())
		}
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
		Some("serve-files") => {
			let usage = "usage: tithd serve-files ENDPOINT-ROOT DATABASE EXPORT-DIRECTORY APPLICATION";
			let root = arguments.next().ok_or(usage)?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			if arguments.next().is_some() { return Err(usage.into()); }
			filesystem::serve(Path::new(&root), Path::new(&database), Path::new(&exports), application, None)
		}
		#[cfg(windows)]
		Some("serve-named-pipe") => {
			let usage = "usage: tithd serve-named-pipe PIPE-NAME DATABASE EXPORT-DIRECTORY APPLICATION";
			let pipe = arguments.next().ok_or(usage)?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			if arguments.next().is_some() { return Err(usage.into()); }
			windows::serve(&pipe, Path::new(&database), Path::new(&exports), &application, None)
		}
		#[cfg(windows)]
		Some("serve-named-pipe-mailer") => {
			let usage = "usage: tithd serve-named-pipe-mailer PIPE-NAME DATABASE EXPORT-DIRECTORY APPLICATION CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE";
			let pipe = arguments.next().ok_or(usage)?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			let config_directory = arguments.next().ok_or(usage)?;
			let nodelist_domain = arguments.next().ok_or(usage)?;
			let nodelist_file = arguments.next().ok_or(usage)?;
			let local_name = arguments.next().ok_or(usage)?;
			let secret_file = arguments.next().ok_or(usage)?;
			if arguments.next().is_some() { return Err(usage.into()); }
			let configuration = Arc::new(load_config(Path::new(&config_directory))?);
			let nodelist = Arc::new(Nodelist::parse(&nodelist_domain, &fs::read_to_string(nodelist_file)?)?);
			let secret = mail::read_secret(Path::new(&secret_file))?;
			let (local_ref, local) = resolve_local(&local_name, &configuration, &nodelist, secret.public_key())?;
			let submission = Arc::new(submission::SubmissionEngine::new(
				Arc::clone(&configuration), Arc::clone(&nodelist),
				[submission::LocalSigner { reference: local_ref, identity: local, secret: Arc::new(secret) }],
			));
			windows::serve(&pipe, Path::new(&database), Path::new(&exports), &application, Some(submission))
		}
		Some("serve-files-mailer") => {
			let usage = "usage: tithd serve-files-mailer ENDPOINT-ROOT DATABASE EXPORT-DIRECTORY APPLICATION CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE";
			let root = arguments.next().ok_or(usage)?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			let config_directory = arguments.next().ok_or(usage)?;
			let nodelist_domain = arguments.next().ok_or(usage)?;
			let nodelist_file = arguments.next().ok_or(usage)?;
			let local_name = arguments.next().ok_or(usage)?;
			let secret_file = arguments.next().ok_or(usage)?;
			if arguments.next().is_some() { return Err(usage.into()); }
			let configuration = Arc::new(load_config(Path::new(&config_directory))?);
			let nodelist = Arc::new(Nodelist::parse(&nodelist_domain, &fs::read_to_string(nodelist_file)?)?);
			let secret = mail::read_secret(Path::new(&secret_file))?;
			let (local_ref, local) = resolve_local(&local_name, &configuration, &nodelist, secret.public_key())?;
			let submission = Arc::new(submission::SubmissionEngine::new(
				Arc::clone(&configuration), Arc::clone(&nodelist),
				[submission::LocalSigner { reference: local_ref, identity: local, secret: Arc::new(secret) }],
			));
			filesystem::serve(Path::new(&root), Path::new(&database), Path::new(&exports), application, Some(submission))
		}
		#[cfg(unix)]
		Some("serve-unix") => {
			let socket = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let database = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let exports = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let application = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			if arguments.next().is_some() { return Err("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION".into()); }
			unix::serve(Path::new(&socket), Path::new(&database), Path::new(&exports), application, None)
		}
		#[cfg(unix)]
		Some("serve-unix-mailer") => {
			let usage = "usage: tithd serve-unix-mailer SOCKET DATABASE EXPORT-DIRECTORY APPLICATION CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE";
			let socket = arguments.next().ok_or(usage)?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			let config_directory = arguments.next().ok_or(usage)?;
			let nodelist_domain = arguments.next().ok_or(usage)?;
			let nodelist_file = arguments.next().ok_or(usage)?;
			let local_name = arguments.next().ok_or(usage)?;
			let secret_file = arguments.next().ok_or(usage)?;
			if arguments.next().is_some() {
				return Err(usage.into());
			}
			let configuration = Arc::new(load_config(Path::new(&config_directory))?);
			let nodelist = Arc::new(Nodelist::parse(
				&nodelist_domain,
				&fs::read_to_string(nodelist_file)?,
			)?);
			let secret = Arc::new(mail::read_secret(Path::new(&secret_file))?);
			let (local_ref, local) = resolve_local(&local_name, &configuration, &nodelist, secret.public_key())?;
			let submission = Arc::new(submission::SubmissionEngine::new(
				Arc::clone(&configuration),
				Arc::clone(&nodelist),
				[submission::LocalSigner {
					reference: local_ref,
					identity: local,
					secret,
				}],
			));
			unix::serve(
				Path::new(&socket),
				Path::new(&database),
				Path::new(&exports),
				application,
				Some(submission),
			)
		}
		Some("serve-mail") => {
			let usage = "usage: tithd serve-mail ADDRESS DATABASE APPLICATION CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE [--retired-node-secret FILE]... [--listen-only] [--local-offset SECONDS] [--timeout SECONDS]";
			let address: SocketAddr = arguments.next().ok_or(usage)?.parse()?;
			let database = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			let config_directory = arguments.next().ok_or(usage)?;
			let nodelist_domain = arguments.next().ok_or(usage)?;
			let nodelist_file = arguments.next().ok_or(usage)?;
			let local_name = arguments.next().ok_or(usage)?;
			let secret_file = arguments.next().ok_or(usage)?;
			let mut outbound = mail::OutboundOptions {
				enabled: true,
				local_offset: None,
				timeout: Duration::from_mins(1),
			};
			let mut retired_secret_files = Vec::new();
			while let Some(option) = arguments.next() {
				match option.as_str() {
					"--retired-node-secret" => {
						retired_secret_files.push(arguments.next().ok_or(usage)?);
					}
					"--listen-only" => outbound.enabled = false,
					"--local-offset" => {
						outbound.local_offset = Some(arguments.next().ok_or(usage)?.parse()?);
					}
					"--timeout" => {
						outbound.timeout =
							Duration::from_secs(arguments.next().ok_or(usage)?.parse()?);
					}
					_ => return Err(usage.into()),
				}
			}
			let configuration = load_config(Path::new(&config_directory))?;
			let nodelist = Nodelist::parse(
				&nodelist_domain,
				&fs::read_to_string(nodelist_file)?,
			)?;
			let secret = mail::read_secret(Path::new(&secret_file))?;
			let (local_ref, local) = resolve_local(
				&local_name,
				&configuration,
				&nodelist,
				secret.public_key(),
			)?;
			let retired_secrets = retired_secret_files
				.iter()
				.map(|path| mail::read_secret(Path::new(path)))
				.collect::<Result<Vec<_>, _>>()?;
			mail::serve(
				address,
				Path::new(&database),
				application,
				configuration,
				nodelist,
				mail::LocalNode {
					reference: local_ref,
					identity: local,
					secret,
					retired_secrets,
				},
				&outbound,
			)
		}
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
				None,
			)
		}
		Some("serve-tcp-mailer") => {
			let usage = "usage: tithd serve-tcp-mailer ADDRESS DATABASE EXPORT-DIRECTORY APPLICATION SERVER-PUBLIC-KEY SERVER-SECRET-FILE CLIENT-PUBLIC-KEY CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE";
			let address: SocketAddr = arguments.next().ok_or(usage)?.parse()?;
			let database = arguments.next().ok_or(usage)?;
			let exports = arguments.next().ok_or(usage)?;
			let application = arguments.next().ok_or(usage)?;
			let server_public = decode_public(&arguments.next().ok_or(usage)?)?;
			let server_secret = tcp::read_secret(Path::new(&arguments.next().ok_or(usage)?))?;
			let client_public = decode_public(&arguments.next().ok_or(usage)?)?;
			let config_directory = arguments.next().ok_or(usage)?;
			let nodelist_domain = arguments.next().ok_or(usage)?;
			let nodelist_file = arguments.next().ok_or(usage)?;
			let local_name = arguments.next().ok_or(usage)?;
			let node_secret = arguments.next().ok_or(usage)?;
			if arguments.next().is_some() { return Err(usage.into()); }
			let configuration = Arc::new(load_config(Path::new(&config_directory))?);
			let nodelist = Arc::new(Nodelist::parse(&nodelist_domain, &fs::read_to_string(nodelist_file)?)?);
			let node_secret: [u8; SECRET_KEY_BYTES] = fs::read(node_secret)?
				.try_into()
				.map_err(|_| "node secret key file has the wrong length")?;
			let node_secret = SecretKey::from_bytes(node_secret);
			let (local_ref, local) = resolve_local(&local_name, &configuration, &nodelist, node_secret.public_key())?;
			let submission = Arc::new(submission::SubmissionEngine::new(
				Arc::clone(&configuration),
				Arc::clone(&nodelist),
				[submission::LocalSigner { reference: local_ref, identity: local, secret: Arc::new(node_secret) }],
			));
			tcp::serve(
				address,
				Path::new(&database),
				Path::new(&exports),
				application,
				KxKeyPair { public: server_public, secret: server_secret },
				client_public,
				Some(submission),
			)
		}
		_ => Err("usage: tithd check-config DIRECTORY | generate-node-key SECRET-FILE | generate-ipc-key SECRET-FILE | serve-mail ADDRESS DATABASE APPLICATION CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE [--listen-only] [--local-offset SECONDS] [--timeout SECONDS] | serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION | serve-unix-mailer SOCKET DATABASE EXPORT-DIRECTORY APPLICATION CONFIG-DIRECTORY NODELIST-DOMAIN NODELIST-FILE LOCAL-IDENTITY NODE-SECRET-FILE | serve-tcp ADDRESS DATABASE EXPORT-DIRECTORY APPLICATION SERVER-PUBLIC-KEY SERVER-SECRET-FILE CLIENT-PUBLIC-KEY".into()),
	}
}

fn resolve_local(
	value: &str,
	configuration: &ConfigurationSet,
	nodelist: &Nodelist,
	current_key: tith_crypto::PublicKey,
) -> Result<(IdentityRef, Identity), Box<dyn Error>> {
	if let Some(name) = value.strip_prefix('@') {
		let peer = configuration.peers.get(name).ok_or("unknown local Peer")?;
		if !peer.address.is_anonymous() {
			return Err("a local Peer reference must identify an anonymous address".into());
		}
		let public_key = peer
			.public_key
			.ok_or("anonymous local Peer has no public key")?;
		if public_key != current_key {
			return Err("local Peer public key does not match the current secret key".into());
		}
		return Ok((
			IdentityRef::Peer(name.to_owned()),
			Identity {
				address: peer.address.clone(),
				public_key,
			},
		));
	}
	let address: Address = value.parse()?;
	if address.is_anonymous() {
		return Err("an anonymous local identity must use a Peer reference".into());
	}
	nodelist
		.get(&address)
		.ok_or("local non-anonymous identity has no nodelist entry")?;
	Ok((
		IdentityRef::Address(address.clone()),
		Identity {
			address,
			public_key: current_key,
		},
	))
}

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

/// Seconds since the Unix epoch.
#[must_use]
pub fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

#[cfg(test)]
mod trust_tests {
	use super::*;

	#[test]
	fn a_rotated_local_identity_uses_its_current_key_while_the_nodelist_is_stale() {
		let published = SigningKeyPair::from_seed(&[1; 32]).unwrap();
		let current = SigningKeyPair::from_seed(&[2; 32]).unwrap();
		let nodelist = Nodelist::parse(
			"fidonet",
			&format!(
				"Zone\t1\tNode\tLocation\tSysop\t\tCM\t\tIIH:node.example:24555:{}\t\t\n",
				STANDARD_NO_PAD.encode(published.public.as_bytes())
			),
		)
		.unwrap();
		let configuration = ConfigurationSet::parse("", "Routes fidonet#1\nEnd\n", "", "").unwrap();
		let (reference, identity) =
			resolve_local("fidonet#1", &configuration, &nodelist, current.public).unwrap();
		assert_eq!(reference.to_string(), "fidonet#1");
		assert_eq!(identity.public_key, current.public);
	}
}
