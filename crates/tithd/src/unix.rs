use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use nix::unistd::{Uid, geteuid};
use tith_ipc::{ConsumeRequest, Document, EnvelopeKind, Field, Line, Presentation, capabilities};
use tith_store::{ClaimResult, InboundState, InboundStore, Resolution, StoreError};

pub fn serve(
	socket: &Path,
	database: &Path,
	exports: &Path,
	application: String,
) -> Result<(), Box<dyn Error>> {
	if socket.exists() {
		return Err("refusing to replace an existing socket path".into());
	}
	fs::create_dir_all(exports)?;
	fs::set_permissions(exports, fs::Permissions::from_mode(0o700))?;
	let listener = UnixListener::bind(socket)?;
	fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
	let store = Arc::new(InboundStore::create(database)?);
	let exports = Arc::new(exports.to_path_buf());
	let application = Arc::new(application);
	for connection in listener.incoming() {
		match connection {
			Ok(stream) => {
				let store = Arc::clone(&store);
				let exports = Arc::clone(&exports);
				let application = Arc::clone(&application);
				std::thread::spawn(move || {
					if let Err(error) = transaction(&stream, &store, &exports, &application) {
						eprintln!("tithd: IPC transaction failed: {error}");
					}
				});
			}
			Err(error) => eprintln!("tithd: accept failed: {error}"),
		}
	}
	Ok(())
}

fn transaction(
	mut stream: &UnixStream,
	store: &InboundStore,
	exports: &Path,
	application: &str,
) -> Result<(), Box<dyn Error>> {
	let authorized = peer_uid(stream)? == geteuid();
	let request = read_request(&mut stream)?;
	let response = process_request(&request, authorized, store, exports, application);
	stream.write_all(&response)?;
	stream.flush()?;
	Ok(())
}

pub(crate) fn process_request(
	request: &[u8],
	authorized: bool,
	store: &InboundStore,
	exports: &Path,
	application: &str,
) -> Vec<u8> {
	match ConsumeRequest::parse(request) {
		Ok(request) if authorized => dispatch(request, store, exports, application),
		Ok(_) => error_result("NotAuthorized", "caller is not authorized"),
		Err(error) => error_result("Invalid", &error.to_string()),
	}
}

#[cfg(any(
	target_os = "freebsd",
	target_os = "dragonfly",
	target_os = "macos",
	target_os = "ios",
	target_os = "netbsd",
	target_os = "openbsd"
))]
fn peer_uid(stream: &UnixStream) -> Result<Uid, Box<dyn Error>> {
	Ok(nix::unistd::getpeereid(stream)?.0)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> Result<Uid, Box<dyn Error>> {
	use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
	Ok(Uid::from_raw(getsockopt(stream, PeerCredentials)?.uid()))
}

#[cfg(not(any(
	target_os = "freebsd",
	target_os = "dragonfly",
	target_os = "macos",
	target_os = "ios",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "linux",
	target_os = "android"
)))]
fn peer_uid(_: &UnixStream) -> Result<Uid, Box<dyn Error>> {
	Err("this Unix platform has no implemented peer-credential binding".into())
}

fn read_request(stream: &mut &UnixStream) -> Result<Vec<u8>, Box<dyn Error>> {
	let mut request = Vec::new();
	let mut byte = [0_u8; 1];
	loop {
		let count = stream.read(&mut byte)?;
		if count == 0 {
			return Err("connection ended before final End".into());
		}
		request.push(byte[0]);
		if request.ends_with(b"\nEnd\n") {
			return Ok(request);
		}
	}
}

fn dispatch(
	request: ConsumeRequest,
	store: &InboundStore,
	exports: &Path,
	allowed_application: &str,
) -> Vec<u8> {
	let operation = request_name(&request);
	match dispatch_inner(request, store, exports, allowed_application) {
		Ok(value) => value,
		Err(StoreError::NotFound) => operation_result(operation, &["NotFound"]),
		Err(StoreError::Stale(state)) => operation_result(operation, &["Stale", state_name(state)]),
		Err(error) => error_result("TemporaryFailure", &error.to_string()),
	}
}

fn request_name(request: &ConsumeRequest) -> &'static str {
	match request {
		ConsumeRequest::Capabilities => "Capabilities",
		ConsumeRequest::Claim { .. } => "Claim-Inbound",
		ConsumeRequest::Renew { .. } => "Renew-Inbound",
		ConsumeRequest::Acknowledge { .. } => "Acknowledge-Inbound",
		ConsumeRequest::Release { .. } => "Release-Inbound",
		ConsumeRequest::Defer { .. } => "Defer-Inbound",
		ConsumeRequest::Reject { .. } => "Reject-Inbound",
		ConsumeRequest::Query { .. } => "Query-Inbound",
	}
}

fn dispatch_inner(
	request: ConsumeRequest,
	store: &InboundStore,
	exports: &Path,
	allowed_application: &str,
) -> Result<Vec<u8>, StoreError> {
	let now = now();
	match request {
		ConsumeRequest::Capabilities => Ok(capabilities(
			[
				"Acknowledge-Inbound",
				"Claim-Inbound",
				"Defer-Inbound",
				"Query-Inbound",
				"Reject-Inbound",
				"Release-Inbound",
				"Renew-Inbound",
			]
			.map(str::to_owned),
			[],
		)),
		ConsumeRequest::Claim {
			application,
			wait,
			claim_key,
			presentation,
		} => {
			if application != allowed_application {
				return Ok(operation_result("Claim-Inbound", &["NotAuthorized"]));
			}
			if presentation == Presentation::Handle {
				return Ok(operation_result("Claim-Inbound", &["NotSupported"]));
			}
			match store.claim(&application, &claim_key, now, 300)? {
				ClaimResult::Empty if wait => {
					Ok(operation_result("Claim-Inbound", &["TemporaryFailure"]))
				}
				ClaimResult::Empty => Ok(operation_result("Claim-Inbound", &["Empty"])),
				ClaimResult::Resolved { inbound_id, state } => Ok(operation_result_owned(
					"Claim-Inbound",
					vec![
						"Resolved".to_owned(),
						inbound_id,
						state_name(state).to_owned(),
					],
				)),
				ClaimResult::Completed(claim) => {
					let payload = store.payload(&claim.inbound_id)?;
					let path =
						export_payload(exports, &claim.inbound_id, &claim.claim_token, &payload)
							.map_err(|_| StoreError::CorruptRecord)?;
					Ok(claim_result(&claim, &path))
				}
			}
		}
		ConsumeRequest::Renew {
			inbound_id,
			claim_token,
		} => {
			let expires = store.renew(&inbound_id, &claim_token, now, 300)?;
			Ok(operation_result_owned(
				"Renew-Inbound",
				vec!["Completed".to_owned(), expires.to_string()],
			))
		}
		ConsumeRequest::Acknowledge {
			inbound_id,
			claim_token,
		} => control(
			store,
			"Acknowledge-Inbound",
			&inbound_id,
			&claim_token,
			now,
			Resolution::Acknowledge,
		),
		ConsumeRequest::Release {
			inbound_id,
			claim_token,
		} => control(
			store,
			"Release-Inbound",
			&inbound_id,
			&claim_token,
			now,
			Resolution::Release,
		),
		ConsumeRequest::Defer {
			inbound_id,
			claim_token,
			retry_after,
			description,
		} => control(
			store,
			"Defer-Inbound",
			&inbound_id,
			&claim_token,
			now,
			Resolution::Defer {
				retry_after,
				description: &description,
			},
		),
		ConsumeRequest::Reject {
			inbound_id,
			claim_token,
			description,
		} => control(
			store,
			"Reject-Inbound",
			&inbound_id,
			&claim_token,
			now,
			Resolution::Reject {
				description: &description,
			},
		),
		ConsumeRequest::Query { inbound_id } => {
			let record = store.query(&inbound_id)?;
			if record.application != allowed_application {
				return Ok(operation_result("Query-Inbound", &["NotFound"]));
			}
			Ok(query_result(&record))
		}
	}
}

fn control(
	store: &InboundStore,
	operation: &str,
	id: &str,
	token: &str,
	now: u64,
	resolution: Resolution<'_>,
) -> Result<Vec<u8>, StoreError> {
	let state = store.resolve(id, token, now, resolution)?;
	Ok(operation_result(
		operation,
		&["Completed", state_name(state)],
	))
}
fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |value| value.as_secs())
}
fn export_payload(
	directory: &Path,
	id: &str,
	token: &str,
	payload: &[u8],
) -> std::io::Result<PathBuf> {
	let path = directory.join(format!("{id}-{token}.tlv"));
	let mut file = OpenOptions::new()
		.create(true)
		.truncate(true)
		.write(true)
		.mode(0o600)
		.open(&path)?;
	file.write_all(payload)?;
	file.sync_all()?;
	Ok(path)
}

fn unquoted(value: impl Into<String>) -> Field {
	Field {
		text: value.into(),
		quoted: false,
	}
}
fn quoted(value: impl Into<String>) -> Field {
	Field {
		text: value.into(),
		quoted: true,
	}
}
fn result(lines: Vec<Line>) -> Vec<u8> {
	Document {
		kind: EnvelopeKind::Result,
		lines,
	}
	.encode()
}
fn operation_result(operation: &str, values: &[&str]) -> Vec<u8> {
	operation_result_owned(
		operation,
		values.iter().map(|value| (*value).to_owned()).collect(),
	)
}
fn operation_result_owned(operation: &str, values: Vec<String>) -> Vec<u8> {
	let mut fields = vec![unquoted(operation)];
	fields.extend(values.into_iter().map(unquoted));
	result(vec![Line { fields }])
}
fn error_result(kind: &str, description: &str) -> Vec<u8> {
	result(vec![Line {
		fields: vec![unquoted("Error"), unquoted(kind), quoted(description)],
	}])
}
fn state_name(value: InboundState) -> &'static str {
	match value {
		InboundState::Available => "Available",
		InboundState::Claimed => "Claimed",
		InboundState::Deferred => "Deferred",
		InboundState::Consumed => "Consumed",
		InboundState::Rejected => "Rejected",
		InboundState::Failed => "Failed",
	}
}
fn kind_name(value: tith_store::ItemKind) -> &'static str {
	match value {
		tith_store::ItemKind::Message => "Message",
		tith_store::ItemKind::File => "File",
		tith_store::ItemKind::FileRequest => "FileRequest",
	}
}
fn auth_name(value: tith_store::ItemAuthentication) -> &'static str {
	match value {
		tith_store::ItemAuthentication::Valid => "Valid",
		tith_store::ItemAuthentication::Invalid => "Invalid",
		tith_store::ItemAuthentication::Transport => "Transport",
	}
}

fn claim_result(claim: &tith_store::Claim, path: &Path) -> Vec<u8> {
	let record = &claim.record;
	result(vec![
		Line {
			fields: vec![unquoted("Claim-Inbound"), unquoted("Completed")],
		},
		Line {
			fields: vec![
				unquoted("Item"),
				unquoted(&record.inbound_id),
				unquoted("Claimed"),
			],
		},
		Line {
			fields: vec![unquoted("Claim-Token"), unquoted(&claim.claim_token)],
		},
		Line {
			fields: vec![
				unquoted("Claim-Expires"),
				unquoted(claim.expires.to_string()),
			],
		},
		Line {
			fields: vec![unquoted("Kind"), unquoted(kind_name(record.kind))],
		},
		Line {
			fields: vec![unquoted("Local-Identity"), quoted(&record.local_identity)],
		},
		Line {
			fields: vec![unquoted("Peer"), quoted(&record.peer)],
		},
		Line {
			fields: vec![
				unquoted("Peer-Key"),
				quoted(STANDARD_NO_PAD.encode(record.peer_key.as_bytes())),
			],
		},
		Line {
			fields: vec![
				unquoted("Item-Authentication"),
				unquoted(auth_name(record.authentication)),
			],
		},
		Line {
			fields: vec![unquoted("Received"), unquoted(record.received.to_string())],
		},
		Line {
			fields: vec![
				unquoted("Payload-Size"),
				unquoted(record.payload_size.to_string()),
			],
		},
		Line {
			fields: vec![
				unquoted("Payload-Hash"),
				quoted(STANDARD_NO_PAD.encode(record.payload_hash.as_bytes())),
			],
		},
		Line {
			fields: vec![unquoted("Payload-Path"), quoted(path.to_string_lossy())],
		},
	])
}

fn query_result(record: &tith_store::InboundRecord) -> Vec<u8> {
	let mut lines = vec![
		Line {
			fields: vec![unquoted("Query-Inbound"), unquoted("Completed")],
		},
		Line {
			fields: vec![
				unquoted("Item"),
				unquoted(&record.inbound_id),
				unquoted(state_name(record.state)),
			],
		},
		Line {
			fields: vec![unquoted("Application"), quoted(&record.application)],
		},
		Line {
			fields: vec![unquoted("Kind"), unquoted(kind_name(record.kind))],
		},
		Line {
			fields: vec![unquoted("Local-Identity"), quoted(&record.local_identity)],
		},
		Line {
			fields: vec![unquoted("Peer"), quoted(&record.peer)],
		},
		Line {
			fields: vec![
				unquoted("Peer-Key"),
				quoted(STANDARD_NO_PAD.encode(record.peer_key.as_bytes())),
			],
		},
		Line {
			fields: vec![
				unquoted("Item-Authentication"),
				unquoted(auth_name(record.authentication)),
			],
		},
		Line {
			fields: vec![unquoted("Received"), unquoted(record.received.to_string())],
		},
		Line {
			fields: vec![unquoted("Changed"), unquoted(record.changed.to_string())],
		},
		Line {
			fields: vec![unquoted("Attempts"), unquoted(record.attempts.to_string())],
		},
	];
	if let Some(expires) = record.claim_expires {
		lines.push(Line {
			fields: vec![unquoted("Claim-Expires"), unquoted(expires.to_string())],
		});
	}
	lines.extend([
		Line {
			fields: vec![
				unquoted("Payload-Size"),
				unquoted(record.payload_size.to_string()),
			],
		},
		Line {
			fields: vec![
				unquoted("Payload-Hash"),
				quoted(STANDARD_NO_PAD.encode(record.payload_hash.as_bytes())),
			],
		},
	]);
	if let Some(value) = &record.last_result {
		lines.push(Line {
			fields: vec![unquoted("Last-Result"), quoted(value)],
		});
	}
	result(lines)
}
