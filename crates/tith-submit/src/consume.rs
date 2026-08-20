//! The TSP-0012 tosser consumption client.
//!
//! One item is claimed at a time. The claim grants temporary read access, not
//! payload ownership: section 7 requires the consumer to stop depending on the
//! export before resolving the claim, and forbids acknowledging until every
//! effect it accepts responsibility for is durable.

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::{TlvHash, hash_inbound_item};
use tith_ipc::{Document, EnvelopeKind, quote};

use crate::{Binding, ClientError, validate};

/// The item kinds a claim can present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
	Message,
	File,
	FileRequest,
}

/// The five end-to-end states plus the transport-only one a `FileRequest` has.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
	Unsigned,
	SignedOriginInvalid,
	SignedOriginValid,
	OriginInvalid,
	OriginValid,
	Transport,
}

impl Authentication {
	fn parse(value: &str) -> Option<Self> {
		Some(match value {
			"Unsigned" => Self::Unsigned,
			"SignedOrigin-Invalid" => Self::SignedOriginInvalid,
			"SignedOrigin-Valid" => Self::SignedOriginValid,
			"Origin-Invalid" => Self::OriginInvalid,
			"Origin-Valid" => Self::OriginValid,
			"Transport" => Self::Transport,
			_ => return None,
		})
	}
}

/// A current claim on one inbound item.
#[derive(Clone, Debug)]
pub struct Claim {
	pub inbound_id: String,
	pub claim_token: String,
	pub claim_expires: u64,
	pub kind: Kind,
	pub local_identity: String,
	pub peer: String,
	pub peer_key: String,
	pub authentication: Authentication,
	pub received: u64,
	pub payload_size: u64,
	pub payload_hash: TlvHash,
	pub forward_job: Option<String>,
	pub payload_path: PathBuf,
}

/// What a claim request produced.
#[derive(Clone, Debug)]
pub enum Claimed {
	Completed(Box<Claim>),
	/// The key already owns a resolved claim. Section 4: it "MUST NOT select
	/// another item", so the consumer must use a new key.
	Resolved {
		inbound_id: String,
		state: String,
	},
	Empty,
	Failed(String),
}

/// The outcome of a claim control operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Controlled {
	Completed(String),
	/// The token is not current. The item was not altered.
	Stale(String),
	NotFound,
	TemporaryFailure,
}

fn line_fields<'a>(document: &'a Document, keyword: &str) -> Option<Vec<&'a str>> {
	document
		.lines
		.iter()
		.find(|line| {
			line.fields
				.first()
				.is_some_and(|field| !field.quoted && field.text == keyword)
		})
		.map(|line| {
			line.fields
				.iter()
				.skip(1)
				.map(|field| field.text.as_str())
				.collect()
		})
}

fn required<'a>(document: &'a Document, keyword: &str) -> Result<&'a str, ClientError> {
	line_fields(document, keyword)
		.and_then(|fields| fields.first().copied())
		.ok_or_else(|| ClientError::new(format!("claim result has no {keyword}")))
}

fn number(value: &str) -> Result<u64, ClientError> {
	value
		.parse()
		.map_err(|_| ClientError::new(format!("{value:?} is not an unsigned integer")))
}

/// Claims one inbound item.
///
/// `wait` selects the section 3 Wait mode, which never returns Empty.
pub fn claim(
	binding: &impl Binding,
	application: &str,
	claim_key: &str,
	wait: bool,
) -> Result<Claimed, ClientError> {
	let request = format!(
		"TITH-IPC 1\nClaim-Inbound {} {}\nClaim-Key {}\nPresentation Path\nEnd\n",
		quote(application),
		if wait { "Wait" } else { "Now" },
		quote(claim_key)
	);
	let result = binding.transact(request.as_bytes())?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let outcome = line_fields(&document, "Claim-Inbound")
		.ok_or_else(|| ClientError::new("result is not a Claim-Inbound result"))?;
	match outcome.first().copied() {
		Some("Empty") => return Ok(Claimed::Empty),
		Some("Resolved") => {
			return Ok(Claimed::Resolved {
				inbound_id: outcome.get(1).copied().unwrap_or_default().to_owned(),
				state: outcome.get(2).copied().unwrap_or_default().to_owned(),
			});
		}
		Some("Completed") => {}
		Some(other) => return Ok(Claimed::Failed(other.to_owned())),
		None => return Err(ClientError::new("Claim-Inbound result has no outcome")),
	}

	let item = line_fields(&document, "Item")
		.ok_or_else(|| ClientError::new("claim result has no Item"))?;
	let hash = STANDARD_NO_PAD
		.decode(required(&document, "Payload-Hash")?)
		.ok()
		.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
		.ok_or_else(|| ClientError::new("Payload-Hash is not 32 base 64 encoded bytes"))?;
	let kind = match required(&document, "Kind")? {
		"Message" => Kind::Message,
		"File" => Kind::File,
		"FileRequest" => Kind::FileRequest,
		other => return Err(ClientError::new(format!("unknown item Kind {other:?}"))),
	};
	let authentication = Authentication::parse(required(&document, "Item-Authentication")?)
		.ok_or_else(|| ClientError::new("unknown Item-Authentication"))?;
	Ok(Claimed::Completed(Box::new(Claim {
		inbound_id: item
			.first()
			.copied()
			.ok_or_else(|| ClientError::new("Item has no InboundID"))?
			.to_owned(),
		claim_token: required(&document, "Claim-Token")?.to_owned(),
		claim_expires: number(required(&document, "Claim-Expires")?)?,
		kind,
		local_identity: required(&document, "Local-Identity")?.to_owned(),
		peer: required(&document, "Peer")?.to_owned(),
		peer_key: required(&document, "Peer-Key")?.to_owned(),
		authentication,
		received: number(required(&document, "Received")?)?,
		payload_size: number(required(&document, "Payload-Size")?)?,
		payload_hash: TlvHash::from_bytes(hash),
		forward_job: line_fields(&document, "Forward-Job")
			.and_then(|fields| fields.first().copied())
			.map(str::to_owned),
		payload_path: PathBuf::from(required(&document, "Payload-Path")?),
	})))
}

impl Claim {
	/// Reads and verifies the payload.
	///
	/// TSP-0012 section 2: the consumer reads exactly `Payload-Size` bytes,
	/// confirms end of file, and verifies `Payload-Hash` before acting on decoded
	/// contents. A mismatch or an extra byte is a local service failure and MUST
	/// NOT be acknowledged as Consumed.
	pub fn read_payload(&self) -> Result<Vec<u8>, ClientError> {
		let bytes = fs::read(&self.payload_path)?;
		let expected = usize::try_from(self.payload_size)
			.map_err(|_| ClientError::new("Payload-Size does not fit this host"))?;
		if bytes.len() != expected {
			return Err(ClientError::new(format!(
				"payload is {} bytes but Payload-Size is {expected}",
				bytes.len()
			)));
		}
		let hash = hash_inbound_item(&bytes).map_err(ClientError::new)?;
		if hash != self.payload_hash {
			return Err(ClientError::new("payload does not match Payload-Hash"));
		}
		Ok(bytes)
	}

	/// Whether the claim is still current at `now`.
	///
	/// Section 4: the client verifies `Claim-Expires` has not passed before
	/// reading or acting on the payload.
	#[must_use]
	pub const fn is_current(&self, now: u64) -> bool {
		now < self.claim_expires
	}
}

fn control(
	binding: &impl Binding,
	operation: &str,
	request: &str,
) -> Result<Controlled, ClientError> {
	let result = binding.transact(request.as_bytes())?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let fields = line_fields(&document, operation)
		.ok_or_else(|| ClientError::new(format!("result is not a {operation} result")))?;
	Ok(match fields.first().copied() {
		Some("Completed") => {
			Controlled::Completed(fields.get(1).copied().unwrap_or_default().to_owned())
		}
		Some("Stale") => Controlled::Stale(fields.get(1).copied().unwrap_or_default().to_owned()),
		Some("NotFound") => Controlled::NotFound,
		Some("TemporaryFailure") => Controlled::TemporaryFailure,
		other => {
			return Err(ClientError::new(format!(
				"unknown {operation} outcome {other:?}"
			)));
		}
	})
}

/// Extends the claim, replacing `Claim-Expires` with a new service value.
pub fn renew(
	binding: &impl Binding,
	inbound_id: &str,
	claim_token: &str,
) -> Result<Controlled, ClientError> {
	control(
		binding,
		"Renew-Inbound",
		&format!("TITH-IPC 1\nRenew-Inbound {inbound_id} {claim_token}\nEnd\n"),
	)
}

/// Reports the item durably consumed.
pub fn acknowledge(
	binding: &impl Binding,
	inbound_id: &str,
	claim_token: &str,
) -> Result<Controlled, ClientError> {
	control(
		binding,
		"Acknowledge-Inbound",
		&format!("TITH-IPC 1\nAcknowledge-Inbound {inbound_id} {claim_token}\nEnd\n"),
	)
}

/// Returns the item to the queue without a durable outcome.
pub fn release(
	binding: &impl Binding,
	inbound_id: &str,
	claim_token: &str,
) -> Result<Controlled, ClientError> {
	control(
		binding,
		"Release-Inbound",
		&format!("TITH-IPC 1\nRelease-Inbound {inbound_id} {claim_token}\nEnd\n"),
	)
}

/// Defers the item until `retry_after`, recording a diagnostic.
pub fn defer(
	binding: &impl Binding,
	inbound_id: &str,
	claim_token: &str,
	retry_after: u64,
	description: &str,
) -> Result<Controlled, ClientError> {
	control(
		binding,
		"Defer-Inbound",
		&format!(
			"TITH-IPC 1\nDefer-Inbound {inbound_id} {claim_token}\nRetry-After {retry_after}\nDescription {}\nEnd\n",
			quote(description)
		),
	)
}

/// Terminally refuses the item.
///
/// TSP-0013 section 4 permits this "only when trusted policy authorizes the
/// local terminal outcome".
pub fn reject(
	binding: &impl Binding,
	inbound_id: &str,
	claim_token: &str,
	description: &str,
) -> Result<Controlled, ClientError> {
	control(
		binding,
		"Reject-Inbound",
		&format!(
			"TITH-IPC 1\nReject-Inbound {inbound_id} {claim_token}\nDescription {}\nEnd\n",
			quote(description)
		),
	)
}

/// Retained state for one item, which does not change it.
pub fn query(binding: &impl Binding, inbound_id: &str) -> Result<Option<String>, ClientError> {
	let request = format!("TITH-IPC 1\nQuery-Inbound {inbound_id}\nEnd\n");
	let result = binding.transact(request.as_bytes())?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let fields = line_fields(&document, "Query-Inbound")
		.ok_or_else(|| ClientError::new("result is not a Query-Inbound result"))?;
	if fields.first().copied() != Some("Completed") {
		return Ok(None);
	}
	Ok(
		line_fields(&document, "Item")
			.and_then(|item| item.get(1).map(|state| (*state).to_owned())),
	)
}

/// The outcome of a `Submit-Items` batch carrying one `Job Forward`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Forwarded {
	/// The Job exists. `New` committed it now; `Existing` means its idempotency
	/// identity was already committed, which TSP-0006 section 8 says confirms
	/// the same thing.
	Committed { job_id: String, state: String },
	/// The batch did not commit. The description is the service's.
	NotCommitted { reason: String, description: String },
}

/// Commits the native distribution copies for a claimed inbound item.
///
/// TSP-0013 section 4 requires an adapter to satisfy an `EchoMail` or file
/// distribution obligation by committing the equivalent native copies with
/// TSP-0006 Job Forward while the claim remains current, which is why the
/// caller must not have acknowledged yet.
///
/// A Forward Job preserves the exact signed children and Signature of its
/// inbound item, so the item's authentication state survives the fan-out
/// unchanged. TSP-0006 section 6 accordingly refuses one for an Unsigned,
/// `Origin-Invalid`, or `SignedOrigin-Invalid` item: those are final-delivery
/// work and have no native onward copy.
pub fn forward(
	binding: &impl Binding,
	application: &str,
	idempotency_key: &str,
	inbound_id: &str,
	claim_token: &str,
) -> Result<Forwarded, ClientError> {
	let request = format!(
		"TITH-IPC 1\nSubmit-Items\nJob Forward\nApplication {}\nIdempotency-Key {}\nInbound {inbound_id} {claim_token}\nEnd\nEnd\n",
		quote(application),
		quote(idempotency_key)
	);
	submitted(binding, request.as_bytes())
}

/// One file offered in answer to a `FileRequest`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerFile {
	/// The local path the request processor named.
	pub path: PathBuf,
	/// The TSP-0006 `Wire-Filename`, which a peer-addressed File must state
	/// explicitly and which is never inferred from the path by the service.
	pub wire_filename: String,
	/// `Keep`, `Delete`, or `Truncate`.
	pub disposition: &'static str,
}

/// Submits the files answering one `FileRequest` back to the peer that asked.
///
/// TSP-0006 section 2: each is one `Job Peer-File`, addressed by `Destination`
/// rather than an Area, and the whole set is one all-or-nothing Batch. The
/// caller's `idempotency_key` is derived from the `InboundID`, so a redelivered
/// request resolves to the original Jobs instead of sending everything twice.
///
/// `Next-Hop` is omitted, so each copy is Active when the peer has a usable
/// endpoint at commitment and Passive otherwise — a peer that cannot be called
/// collects its answer by polling.
///
/// # Errors
///
/// Returns [`ClientError`] when the binding fails or the result is not a
/// conforming `Submit-Items` result. An empty `files` list submits nothing and
/// reports `Committed` with no Jobs, because TTS-0005 section 6 permits an
/// accepted `FileRequest` to return no files at all.
pub fn submit_peer_files(
	binding: &impl Binding,
	application: &str,
	idempotency_key: &str,
	origin: &str,
	destination: &str,
	files: &[PeerFile],
) -> Result<Forwarded, ClientError> {
	if files.is_empty() {
		return Ok(Forwarded::Committed {
			job_id: String::new(),
			state: "Delivered".to_owned(),
		});
	}
	let jobs: Vec<String> = files
		.iter()
		.enumerate()
		.map(|(index, file)| {
			format!(
				"Job Peer-File\nApplication {}\nIdempotency-Key {}\nOrigin {}\n\
				 Destination {}\nFile\nSource-Path {}\nIngestion Copy\n\
				 Source-Disposition {}\nWire-Filename {}\nEnd\nEnd\n",
				quote(application),
				quote(&format!("{idempotency_key}-{}", index + 1)),
				quote(origin),
				quote(destination),
				quote(&file.path.to_string_lossy()),
				file.disposition,
				quote(&file.wire_filename)
			)
		})
		.collect();
	submitted(
		binding,
		format!("TITH-IPC 1\nSubmit-Items\n{}End\n", jobs.concat()).as_bytes(),
	)
}

/// Reads a `Submit-Items` result into the outcome it reports.
fn submitted(binding: &impl Binding, request: &[u8]) -> Result<Forwarded, ClientError> {
	let result = binding.transact(request)?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let outcome = line_fields(&document, "Submit-Items")
		.ok_or_else(|| ClientError::new("result is not a Submit-Items result"))?;
	match outcome.first().copied() {
		Some("Committed") => {
			let job = line_fields(&document, "Job")
				.ok_or_else(|| ClientError::new("committed result has no Job line"))?;
			Ok(Forwarded::Committed {
				job_id: job
					.get(2)
					.copied()
					.ok_or_else(|| ClientError::new("Job line has no JobID"))?
					.to_owned(),
				state: job.get(3).copied().unwrap_or_default().to_owned(),
			})
		}
		Some("Not-Committed") => {
			let failure = line_fields(&document, "Failure").unwrap_or_default();
			Ok(Forwarded::NotCommitted {
				reason: failure.get(1).copied().unwrap_or("Invalid").to_owned(),
				description: failure.get(2).copied().unwrap_or_default().to_owned(),
			})
		}
		other => Err(ClientError::new(format!(
			"unknown Submit-Items outcome {other:?}"
		))),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::cell::RefCell;

	struct Canned {
		result: Vec<u8>,
		seen: RefCell<Vec<u8>>,
	}

	impl Binding for Canned {
		fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
			*self.seen.borrow_mut() = request.to_vec();
			Ok(self.result.clone())
		}
	}

	fn canned(result: &str) -> Canned {
		Canned {
			result: result.as_bytes().to_vec(),
			seen: RefCell::new(Vec::new()),
		}
	}

	#[test]
	fn a_completed_claim_reads_every_documented_field() {
		let hash = STANDARD_NO_PAD.encode([7_u8; 32]);
		let key = STANDARD_NO_PAD.encode([8_u8; 32]);
		let binding = canned(&format!(
			"TITH-IPC-Result 1\nClaim-Inbound Completed\nItem I123 Claimed\nClaim-Token T456\n\
			 Claim-Expires 1755518400\nKind Message\nLocal-Identity \"fidonet#1:104/36\"\n\
			 Peer \"fidonet#1:104/1\"\nPeer-Key \"{key}\"\nItem-Authentication Origin-Valid\n\
			 Received 1755518000\nPayload-Size 42\nPayload-Hash \"{hash}\"\n\
			 Payload-Path \"/var/db/tith/exports/I123.tlv\"\nEnd\n"
		));
		let Claimed::Completed(claim) = claim(&binding, "tosser", "worker-1", false).unwrap()
		else {
			panic!("expected a completed claim");
		};
		assert_eq!(claim.inbound_id, "I123");
		assert_eq!(claim.claim_token, "T456");
		assert_eq!(claim.kind, Kind::Message);
		assert_eq!(claim.authentication, Authentication::OriginValid);
		assert_eq!(claim.payload_size, 42);
		assert_eq!(claim.payload_hash.as_bytes(), &[7_u8; 32]);
		assert_eq!(
			claim.payload_path,
			PathBuf::from("/var/db/tith/exports/I123.tlv")
		);
		assert!(claim.forward_job.is_none());
		assert!(claim.is_current(1_755_518_399));
		assert!(!claim.is_current(1_755_518_400));

		// The request is the exact section 3 grammar.
		assert_eq!(
			String::from_utf8(binding.seen.into_inner()).unwrap(),
			"TITH-IPC 1\nClaim-Inbound \"tosser\" Now\nClaim-Key \"worker-1\"\nPresentation Path\nEnd\n"
		);
	}

	#[test]
	fn the_other_claim_outcomes_are_distinguished() {
		assert!(matches!(
			claim(
				&canned("TITH-IPC-Result 1\nClaim-Inbound Empty\nEnd\n"),
				"tosser",
				"k",
				false
			)
			.unwrap(),
			Claimed::Empty
		));
		assert!(matches!(
			claim(
				&canned("TITH-IPC-Result 1\nClaim-Inbound Resolved I1 Consumed\nEnd\n"),
				"tosser",
				"k",
				false
			)
			.unwrap(),
			Claimed::Resolved { .. }
		));
		assert!(matches!(
			claim(
				&canned("TITH-IPC-Result 1\nClaim-Inbound NotAuthorized\nEnd\n"),
				"tosser",
				"k",
				false
			)
			.unwrap(),
			Claimed::Failed(_)
		));
	}

	#[test]
	fn wait_mode_and_the_control_operations_use_their_grammars() {
		let binding = canned("TITH-IPC-Result 1\nClaim-Inbound Empty\nEnd\n");
		let _ = claim(&binding, "tosser", "k", true);
		assert!(
			String::from_utf8(binding.seen.into_inner())
				.unwrap()
				.contains("Claim-Inbound \"tosser\" Wait")
		);

		let binding = canned("TITH-IPC-Result 1\nAcknowledge-Inbound Completed Consumed\nEnd\n");
		assert_eq!(
			acknowledge(&binding, "I1", "T1").unwrap(),
			Controlled::Completed("Consumed".to_owned())
		);
		assert_eq!(
			String::from_utf8(binding.seen.into_inner()).unwrap(),
			"TITH-IPC 1\nAcknowledge-Inbound I1 T1\nEnd\n"
		);

		let binding = canned("TITH-IPC-Result 1\nDefer-Inbound Completed Deferred\nEnd\n");
		defer(&binding, "I1", "T1", 1_755_600_000, "blocked on #17").unwrap();
		assert_eq!(
			String::from_utf8(binding.seen.into_inner()).unwrap(),
			"TITH-IPC 1\nDefer-Inbound I1 T1\nRetry-After 1755600000\nDescription \"blocked on #17\"\nEnd\n"
		);

		let binding = canned("TITH-IPC-Result 1\nRelease-Inbound Stale Available\nEnd\n");
		assert_eq!(
			release(&binding, "I1", "T1").unwrap(),
			Controlled::Stale("Available".to_owned())
		);
	}

	#[test]
	fn a_payload_is_refused_unless_its_size_and_hash_both_match() {
		let directory = std::env::temp_dir().join(format!("tith-consume-{}", std::process::id()));
		let _ = fs::remove_dir_all(&directory);
		fs::create_dir_all(&directory).unwrap();
		let path = directory.join("payload.tlv");
		fs::write(&path, b"exact bytes").unwrap();

		let mut claim = Claim {
			inbound_id: "I1".to_owned(),
			claim_token: "T1".to_owned(),
			claim_expires: u64::MAX,
			kind: Kind::Message,
			local_identity: String::new(),
			peer: String::new(),
			peer_key: String::new(),
			authentication: Authentication::OriginValid,
			received: 0,
			payload_size: 11,
			payload_hash: hash_inbound_item(b"exact bytes").unwrap(),
			forward_job: None,
			payload_path: path,
		};
		assert_eq!(claim.read_payload().unwrap(), b"exact bytes");

		claim.payload_size = 10;
		assert!(claim.read_payload().is_err(), "a size mismatch must refuse");

		claim.payload_size = 11;
		claim.payload_hash = hash_inbound_item(b"other bytes").unwrap();
		assert!(claim.read_payload().is_err(), "a hash mismatch must refuse");

		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn a_forward_job_uses_the_documented_grammar_and_reads_its_job_line() {
		let binding =
			canned("TITH-IPC-Result 1\nSubmit-Items Committed\nJob 1 New J0123 Queued\nEnd\n");
		assert_eq!(
			forward(&binding, "tosser", "fwd:I1", "I1", "T1").unwrap(),
			Forwarded::Committed {
				job_id: "J0123".to_owned(),
				state: "Queued".to_owned()
			}
		);
		assert_eq!(
			String::from_utf8(binding.seen.into_inner()).unwrap(),
			"TITH-IPC 1\nSubmit-Items\nJob Forward\nApplication \"tosser\"\nIdempotency-Key \"fwd:I1\"\nInbound I1 T1\nEnd\nEnd\n"
		);
	}

	#[test]
	fn an_existing_forward_is_as_good_as_a_new_one() {
		// TSP-0006 section 8: "Either result confirms that delivery no longer
		// depends on the Source fields in this request."
		let binding =
			canned("TITH-IPC-Result 1\nSubmit-Items Committed\nJob 1 Existing J9 Sent\nEnd\n");
		assert!(matches!(
			forward(&binding, "tosser", "k", "I1", "T1").unwrap(),
			Forwarded::Committed { .. }
		));
	}

	#[test]
	fn a_refused_forward_reports_why() {
		// A Job Forward for an Invalid item is itself Invalid, which is how the
		// service says the item is final-delivery work with no onward copy.
		let binding = canned(
			"TITH-IPC-Result 1\nSubmit-Items Not-Committed\nFailure 1 Invalid \"Forward requires EchoMail or standalone File\"\nEnd\n",
		);
		let Forwarded::NotCommitted {
			reason,
			description,
		} = forward(&binding, "tosser", "k", "I1", "T1").unwrap()
		else {
			panic!("expected Not-Committed");
		};
		assert_eq!(reason, "Invalid");
		assert!(description.contains("EchoMail"));
	}
}
