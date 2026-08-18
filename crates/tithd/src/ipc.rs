use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_ipc::{ConsumeRequest, Document, EnvelopeKind, Field, Line, Presentation, capabilities};
use tith_store::{ClaimResult, InboundState, InboundStore, Resolution, StoreError};

const CLAIM_DURATION: u64 = 300;
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Principal {
	pub name: String,
	applications: BTreeSet<String>,
}

impl Principal {
	#[must_use]
	pub fn single(name: impl Into<String>, application: impl Into<String>) -> Self {
		Self {
			name: name.into(),
			applications: BTreeSet::from([application.into()]),
		}
	}

	fn authorizes(&self, application: &str) -> bool {
		self.applications.contains(application)
	}

	fn sole_application(&self) -> Option<&str> {
		if self.applications.len() == 1 {
			self.applications.first().map(String::as_str)
		} else {
			None
		}
	}
}

pub struct IpcService {
	store: Arc<InboundStore>,
	exports: PathBuf,
}

impl IpcService {
	pub fn create(database: &Path, exports: &Path) -> Result<Self, Box<dyn Error>> {
		if exports.to_str().is_none() {
			return Err("the payload export directory is not representable as UTF-8".into());
		}
		fs::create_dir_all(exports)?;
		#[cfg(unix)]
		fs::set_permissions(exports, fs::Permissions::from_mode(0o700))?;
		Ok(Self {
			store: Arc::new(InboundStore::create(database)?),
			exports: exports.to_path_buf(),
		})
	}

	#[cfg(test)]
	pub(crate) fn from_store(store: Arc<InboundStore>, exports: PathBuf) -> Self {
		Self { store, exports }
	}

	#[must_use]
	pub fn process_request(&self, request: &[u8], principal: Option<&Principal>) -> Vec<u8> {
		let parsed = match ConsumeRequest::parse(request) {
			Ok(value) => value,
			Err(error) => return error_result("Invalid", &error.to_string()),
		};
		let Some(principal) = principal else {
			return error_result("NotAuthorized", "caller is not authorized");
		};
		self.dispatch(parsed, principal)
	}

	fn dispatch(&self, request: ConsumeRequest, principal: &Principal) -> Vec<u8> {
		let operation = request_name(&request);
		match self.dispatch_inner(request, principal) {
			Ok(value) => value,
			Err(StoreError::NotFound) => operation_result(operation, &["NotFound"]),
			Err(StoreError::Stale(state)) => {
				operation_result(operation, &["Stale", state_name(state)])
			}
			Err(error) => error_result("TemporaryFailure", &error.to_string()),
		}
	}

	fn dispatch_inner(
		&self,
		request: ConsumeRequest,
		principal: &Principal,
	) -> Result<Vec<u8>, StoreError> {
		if principal.name.is_empty() {
			return Err(StoreError::NotFound);
		}
		self.store.refresh_expirations(now())?;
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
			} => self.claim(principal, &application, wait, &claim_key, presentation),
			ConsumeRequest::Renew {
				inbound_id,
				claim_token,
			} => {
				let application = authorized_application(principal)?;
				let expires = self.store.renew(
					application,
					&inbound_id,
					&claim_token,
					now(),
					CLAIM_DURATION,
				)?;
				Ok(operation_result_owned(
					"Renew-Inbound",
					vec!["Completed".to_owned(), expires.to_string()],
				))
			}
			ConsumeRequest::Acknowledge {
				inbound_id,
				claim_token,
			} => self.control(
				principal,
				"Acknowledge-Inbound",
				&inbound_id,
				&claim_token,
				Resolution::Acknowledge,
			),
			ConsumeRequest::Release {
				inbound_id,
				claim_token,
			} => self.control(
				principal,
				"Release-Inbound",
				&inbound_id,
				&claim_token,
				Resolution::Release,
			),
			ConsumeRequest::Defer {
				inbound_id,
				claim_token,
				retry_after,
				description,
			} => self.control(
				principal,
				"Defer-Inbound",
				&inbound_id,
				&claim_token,
				Resolution::Defer {
					retry_after,
					description: &description,
				},
			),
			ConsumeRequest::Reject {
				inbound_id,
				claim_token,
				description,
			} => self.control(
				principal,
				"Reject-Inbound",
				&inbound_id,
				&claim_token,
				Resolution::Reject {
					description: &description,
				},
			),
			ConsumeRequest::Query { inbound_id } => {
				let application = authorized_application(principal)?;
				let record = self.store.query_for(application, &inbound_id)?;
				Ok(query_result(&record))
			}
		}
	}

	fn claim(
		&self,
		principal: &Principal,
		application: &str,
		wait: bool,
		claim_key: &str,
		presentation: Presentation,
	) -> Result<Vec<u8>, StoreError> {
		if !principal.authorizes(application) {
			return Ok(operation_result("Claim-Inbound", &["NotAuthorized"]));
		}
		if presentation == Presentation::Handle {
			return Ok(operation_result("Claim-Inbound", &["NotSupported"]));
		}
		let started = Instant::now();
		loop {
			match self
				.store
				.claim(application, claim_key, now(), CLAIM_DURATION)?
			{
				ClaimResult::Empty if wait && started.elapsed() < WAIT_TIMEOUT => {
					thread::sleep(WAIT_POLL_INTERVAL);
				}
				ClaimResult::Empty if wait => {
					return Ok(operation_result("Claim-Inbound", &["TemporaryFailure"]));
				}
				ClaimResult::Empty => {
					return Ok(operation_result("Claim-Inbound", &["Empty"]));
				}
				ClaimResult::Resolved { inbound_id, state } => {
					return Ok(operation_result_owned(
						"Claim-Inbound",
						vec![
							"Resolved".to_owned(),
							inbound_id,
							state_name(state).to_owned(),
						],
					));
				}
				ClaimResult::Completed(claim) => {
					self.remove_other_exports(&claim.inbound_id, &claim.claim_token);
					let payload = self.store.claimed_payload(
						application,
						&claim.inbound_id,
						&claim.claim_token,
						now(),
					)?;
					let path = self
						.export_payload(&claim.inbound_id, &claim.claim_token, &payload)
						.map_err(|_| StoreError::CorruptRecord)?;
					return Ok(claim_result(&claim, &path));
				}
			}
		}
	}

	fn control(
		&self,
		principal: &Principal,
		operation: &str,
		id: &str,
		token: &str,
		resolution: Resolution<'_>,
	) -> Result<Vec<u8>, StoreError> {
		let application = authorized_application(principal)?;
		let state = self
			.store
			.resolve(application, id, token, now(), resolution)?;
		self.remove_export(id, token);
		Ok(operation_result(
			operation,
			&["Completed", state_name(state)],
		))
	}

	fn export_payload(&self, id: &str, token: &str, payload: &[u8]) -> std::io::Result<PathBuf> {
		let path = self.exports.join(format!("{id}-{token}.tlv"));
		if path.exists() {
			return Ok(path);
		}
		let temporary = self.exports.join(format!(".{id}-{token}.tmp"));
		let mut options = OpenOptions::new();
		options.create_new(true).write(true);
		#[cfg(unix)]
		options.mode(0o600);
		let mut file = options.open(&temporary)?;
		file.write_all(payload)?;
		file.sync_all()?;
		#[cfg(unix)]
		fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400))?;
		fs::rename(&temporary, &path)?;
		if let Ok(directory) = fs::File::open(&self.exports) {
			directory.sync_all()?;
		}
		Ok(path)
	}

	fn remove_export(&self, id: &str, token: &str) {
		let _ = fs::remove_file(self.exports.join(format!("{id}-{token}.tlv")));
	}

	fn remove_other_exports(&self, id: &str, token: &str) {
		let keep = format!("{id}-{token}.tlv");
		let prefix = format!("{id}-C");
		let Ok(entries) = fs::read_dir(&self.exports) else {
			return;
		};
		for entry in entries.flatten() {
			let name = entry.file_name();
			let name = name.to_string_lossy();
			if name.starts_with(&prefix) && name != keep {
				let _ = fs::remove_file(entry.path());
			}
		}
	}
}

fn authorized_application(principal: &Principal) -> Result<&str, StoreError> {
	principal.sole_application().ok_or(StoreError::NotFound)
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

fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |value| value.as_secs())
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
	let path = path
		.to_str()
		.expect("export roots are checked for UTF-8 at service construction");
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
			fields: vec![unquoted("Payload-Path"), quoted(path)],
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

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::PublicKey;
	use tith_store::{ItemAuthentication, NewInbound};
	use tith_wire::tlv::OwnedTlv;
	use tith_wire::types;

	#[test]
	fn control_requires_the_principals_application_and_removes_the_export() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let root = std::env::temp_dir().join(format!("tith-ipc-service-{unique}"));
		fs::create_dir_all(&root).unwrap();
		let database = root.join("state.redb");
		let exports = root.join("exports");
		fs::create_dir_all(&exports).unwrap();
		let store = Arc::new(InboundStore::create(&database).unwrap());
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let item = store
			.insert(NewInbound {
				application: "tosser",
				local_identity: "fidonet#1",
				peer: "fidonet#2",
				peer_key: PublicKey::from_bytes([3; 32]),
				received: now(),
				authentication: ItemAuthentication::Valid,
				payload: &payload,
			})
			.unwrap();
		let service = IpcService::from_store(Arc::clone(&store), exports);
		let wrong = Principal::single("uid:1", "other");
		let query = format!("TITH-IPC 1\nQuery-Inbound {}\nEnd\n", item.inbound_id);
		assert!(
			String::from_utf8(service.process_request(query.as_bytes(), Some(&wrong)))
				.unwrap()
				.contains("Query-Inbound NotFound")
		);
		let right = Principal::single("uid:2", "tosser");
		let claim = service.process_request(
			b"TITH-IPC 1\nClaim-Inbound \"tosser\" Now\nClaim-Key \"worker\"\nPresentation Path\nEnd\n",
			Some(&right),
		);
		let document = Document::parse(&claim, EnvelopeKind::Result).unwrap();
		let token = document.lines[2].fields[1].text.clone();
		let path = PathBuf::from(&document.lines.last().unwrap().fields[1].text);
		assert!(path.exists());
		let acknowledge = format!(
			"TITH-IPC 1\nAcknowledge-Inbound {} {}\nEnd\n",
			item.inbound_id, token
		);
		let response = service.process_request(acknowledge.as_bytes(), Some(&right));
		assert!(
			String::from_utf8(response)
				.unwrap()
				.contains("Acknowledge-Inbound Completed Consumed")
		);
		assert!(!path.exists());
		drop(service);
		drop(store);
		fs::remove_dir_all(root).unwrap();
	}
}
