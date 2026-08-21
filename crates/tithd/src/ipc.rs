use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_ipc::{
	ConsumeRequest, Document, EnvelopeKind, Field, JobRequest, Line, LookupSubmission,
	Presentation, SubmissionRequest, capabilities,
};
use tith_store::{
	BatchCommit, ClaimResult, CommitOutcome, ControlOutcome, DeliveryMode, FailureDisposition,
	FailureNotification, InboundState, InboundStore, JobBuildFailure, JobKind, JobState, JobTarget,
	OutboundEvent, OutboundJob, OutboundStore, Resolution, StoreError, SubmissionLookup,
};

use crate::submission::SubmissionEngine;

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

	pub(crate) fn authorizes(&self, application: &str) -> bool {
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
	outbound: OutboundStore,
	exports: PathBuf,
	submission: Option<Arc<SubmissionEngine>>,
}

impl IpcService {
	pub fn create(database: &Path, exports: &Path) -> Result<Self, Box<dyn Error>> {
		if exports.to_str().is_none() {
			return Err("the payload export directory is not representable as UTF-8".into());
		}
		crate::owner_only::create_directory(exports)?;
		let store = Arc::new(InboundStore::create(database)?);
		let outbound = store.outbound()?;
		Ok(Self {
			store,
			outbound,
			exports: exports.to_path_buf(),
			submission: None,
		})
	}

	#[cfg(test)]
	pub(crate) fn from_store(store: Arc<InboundStore>, exports: PathBuf) -> Self {
		let outbound = store.outbound().expect("test outbound store");
		Self {
			store,
			outbound,
			exports,
			submission: None,
		}
	}

	#[must_use]
	pub fn with_submission(mut self, submission: Arc<SubmissionEngine>) -> Self {
		self.submission = Some(submission);
		self
	}

	#[must_use]
	pub fn process_request(&self, request: &[u8], principal: Option<&Principal>) -> Vec<u8> {
		let document = match Document::parse(request, EnvelopeKind::Request) {
			Ok(value) => value,
			Err(error) => return error_result("Invalid", &error.to_string()),
		};
		let Some(principal) = principal else {
			return error_result("NotAuthorized", "caller is not authorized");
		};
		let Some(operation) = document
			.lines
			.first()
			.and_then(|line| line.fields.first())
			.filter(|field| !field.quoted)
			.map(|field| field.text.as_str())
		else {
			return error_result("Invalid", "missing operation");
		};
		match operation {
			"Capabilities" if document.lines.len() == 1 => self.capabilities(),
			"Claim-Inbound"
			| "Renew-Inbound"
			| "Acknowledge-Inbound"
			| "Release-Inbound"
			| "Defer-Inbound"
			| "Reject-Inbound"
			| "Query-Inbound" => match ConsumeRequest::parse(request) {
				Ok(parsed) => self.dispatch(parsed, principal),
				Err(error) => error_result("Invalid", &error.to_string()),
			},
			"Submit" | "Submit-Items" => self.submit(request, principal),
			"Lookup-Submission" => self.lookup_submission(request, principal),
			"Query" | "Query-Job" | "Cancel" | "Retry" | "Reroute" | "Events" | "Acknowledge" => {
				self.job_request(request, principal)
			}
			_ => error_result("Invalid", "unknown or malformed operation"),
		}
	}

	fn capabilities(&self) -> Vec<u8> {
		let mut operations = vec![
			"Acknowledge-Inbound",
			"Claim-Inbound",
			"Defer-Inbound",
			"Query-Inbound",
			"Reject-Inbound",
			"Release-Inbound",
			"Renew-Inbound",
		];
		if self.submission.is_some() {
			operations.extend([
				"Acknowledge",
				"Cancel",
				"Events",
				"Lookup-Submission",
				"Query",
				"Query-Job",
				"Reroute",
				"Retry",
				"Submit",
				"Submit-Items",
			]);
		}
		capabilities(operations.into_iter().map(str::to_owned), [])
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
			ConsumeRequest::Capabilities => Ok(self.capabilities()),
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

	fn submit(&self, request: &[u8], principal: &Principal) -> Vec<u8> {
		let parsed = match SubmissionRequest::parse(request) {
			Ok(value) => value,
			Err(error) => return error_result("Invalid", &error.to_string()),
		};
		let operation = match parsed.operation {
			tith_ipc::SubmitOperation::Submit => "Submit",
			tith_ipc::SubmitOperation::SubmitItems => "Submit-Items",
		};
		if let Some((position, _)) = parsed
			.jobs
			.iter()
			.enumerate()
			.find(|(_, job)| !principal.authorizes(&job.application))
		{
			return submit_failure(
				operation,
				position + 1,
				"Invalid",
				"Application is not authorized for this caller",
			);
		}
		let Some(engine) = &self.submission else {
			return submit_failure(
				operation,
				1,
				"Invalid",
				"submission is not configured for this service",
			);
		};
		match engine.submit(&parsed, &self.outbound) {
			Ok(BatchCommit::Committed(outcomes)) => submit_committed(operation, &outcomes),
			Ok(BatchCommit::Conflict(positions)) => {
				let lines = positions
					.into_iter()
					.map(|position| Line {
						fields: vec![
							unquoted("Failure"),
							unquoted(position.to_string()),
							unquoted("Conflict"),
							quoted("Idempotency-Key maps to another JobDigest"),
						],
					})
					.collect();
				submit_not_committed(operation, lines)
			}
			Err(StoreError::JobBuild {
				position,
				kind,
				description,
			}) => submit_failure(
				operation,
				position,
				match kind {
					JobBuildFailure::Invalid => "Invalid",
					JobBuildFailure::Permanent => "PermanentFailure",
					JobBuildFailure::Temporary => "TemporaryFailure",
				},
				&description,
			),
			Err(error) => submit_failure(operation, 1, "TemporaryFailure", &error.to_string()),
		}
	}

	fn lookup_submission(&self, request: &[u8], principal: &Principal) -> Vec<u8> {
		let parsed = match LookupSubmission::parse(request) {
			Ok(value) => value,
			Err(error) => return error_result("Invalid", &error.to_string()),
		};
		if !principal.authorizes(&parsed.application) {
			return operation_result("Lookup-Submission", &["NotAuthorized"]);
		}
		match self.outbound.lookup(&parsed.application, &parsed.keys) {
			Ok(values) => {
				let mut lines = vec![Line {
					fields: vec![unquoted("Lookup-Submission"), unquoted("Completed")],
				}];
				for (index, value) in values.into_iter().enumerate() {
					let mut fields =
						vec![unquoted("Submission"), unquoted((index + 1).to_string())];
					match value {
						SubmissionLookup::Existing { job_id, state } => fields.extend([
							unquoted("Existing"),
							unquoted(job_id),
							unquoted(job_state_name(state)),
						]),
						SubmissionLookup::NotFound => fields.push(unquoted("NotFound")),
					}
					lines.push(Line { fields });
				}
				result(lines)
			}
			Err(_) => operation_result("Lookup-Submission", &["TemporaryFailure"]),
		}
	}

	fn job_request(&self, request: &[u8], principal: &Principal) -> Vec<u8> {
		let parsed = match JobRequest::parse(request) {
			Ok(value) => value,
			Err(error) => return error_result("Invalid", &error.to_string()),
		};
		match self.job_request_inner(parsed, principal) {
			Ok(value) => value,
			Err(StoreError::NotFound) => {
				let operation = Document::parse(request, EnvelopeKind::Request)
					.ok()
					.and_then(|document| {
						document
							.lines
							.first()
							.and_then(|line| line.fields.first())
							.map(|field| field.text.clone())
					})
					.unwrap_or_else(|| "Query-Job".to_owned());
				operation_result(&operation, &["NotFound"])
			}
			Err(StoreError::JobBuild {
				kind: JobBuildFailure::Invalid | JobBuildFailure::Permanent,
				description,
				..
			}) => error_result("PermanentFailure", &description),
			Err(error) => error_result("TemporaryFailure", &error.to_string()),
		}
	}

	fn job_request_inner(
		&self,
		request: JobRequest,
		principal: &Principal,
	) -> Result<Vec<u8>, StoreError> {
		match request {
			JobRequest::Query {
				job_id,
				item_aware,
				paths,
			} => {
				let application = authorized_application(principal)?;
				let job = self.outbound.query_for(application, &job_id)?;
				if !item_aware && job.kind != JobKind::NetMail {
					return Err(StoreError::NotFound);
				}
				Ok(outbound_query_result(&job, item_aware, paths))
			}
			JobRequest::Cancel { job_id } => {
				let application = authorized_application(principal)?;
				Ok(control_result(
					"Cancel",
					self.outbound.cancel(application, &job_id, now())?,
				))
			}
			JobRequest::Retry { job_id } => {
				let application = authorized_application(principal)?;
				Ok(control_result(
					"Retry",
					self.outbound.retry(application, &job_id, now())?,
				))
			}
			JobRequest::Reroute {
				job_id,
				next_hop,
				failure_policy,
			} => {
				let application = authorized_application(principal)?;
				let job = self.outbound.query_for(application, &job_id)?;
				if job.state == JobState::Active {
					return Ok(control_result("Reroute", ControlOutcome::Busy(job.state)));
				}
				if job.kind != JobKind::NetMail
					|| matches!(job.state, JobState::Delivered | JobState::Cancelled)
				{
					return Ok(control_result(
						"Reroute",
						ControlOutcome::NotPermitted(job.state),
					));
				}
				let engine = self.submission.as_ref().ok_or(StoreError::CorruptRecord)?;
				let item = self.outbound.item(&job_id)?;
				let delivery = engine.reroute_delivery(&job, &item, &next_hop, failure_policy)?;
				Ok(control_result(
					"Reroute",
					self.outbound
						.reroute(application, &job_id, now(), delivery)?,
				))
			}
			JobRequest::Events { application, wait } => {
				if !principal.authorizes(&application) {
					return Ok(operation_result("Events", &["NotAuthorized"]));
				}
				let started = Instant::now();
				loop {
					let events = self.outbound.events(&application)?;
					if !events.is_empty() || !wait {
						return Ok(events_result(&events));
					}
					if started.elapsed() >= WAIT_TIMEOUT {
						return Ok(operation_result("Events", &["TemporaryFailure"]));
					}
					thread::sleep(WAIT_POLL_INTERVAL);
				}
			}
			JobRequest::Acknowledge {
				application,
				event_id,
			} => {
				if !principal.authorizes(&application) {
					return Ok(operation_result("Acknowledge", &["NotFound"]));
				}
				self.outbound.acknowledge_event(&application, &event_id)?;
				Ok(operation_result("Acknowledge", &["Completed"]))
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
		let mut file = crate::owner_only::create_file(&temporary)?;
		file.write_all(payload)?;
		file.sync_all()?;
		drop(file);
		// Sealed before it is published, so the name a consumer can see never
		// refers to a writable object.
		crate::owner_only::seal(&temporary)?;
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
fn submit_committed(operation: &str, outcomes: &[CommitOutcome]) -> Vec<u8> {
	let mut lines = vec![Line {
		fields: vec![unquoted(operation), unquoted("Committed")],
	}];
	for (index, outcome) in outcomes.iter().enumerate() {
		let (kind, job_id, state) = match outcome {
			CommitOutcome::New { job_id, state } => ("New", job_id, *state),
			CommitOutcome::Existing { job_id, state } => ("Existing", job_id, *state),
		};
		lines.push(Line {
			fields: vec![
				unquoted("Job"),
				unquoted((index + 1).to_string()),
				unquoted(kind),
				unquoted(job_id),
				unquoted(job_state_name(state)),
			],
		});
	}
	result(lines)
}
fn submit_not_committed(operation: &str, failures: Vec<Line>) -> Vec<u8> {
	let mut lines = vec![Line {
		fields: vec![unquoted(operation), unquoted("Not-Committed")],
	}];
	lines.extend(failures);
	result(lines)
}
fn submit_failure(operation: &str, position: usize, kind: &str, description: &str) -> Vec<u8> {
	submit_not_committed(
		operation,
		vec![Line {
			fields: vec![
				unquoted("Failure"),
				unquoted(position.to_string()),
				unquoted(kind),
				quoted(description),
			],
		}],
	)
}
fn error_result(kind: &str, description: &str) -> Vec<u8> {
	result(vec![Line {
		fields: vec![unquoted("Error"), unquoted(kind), quoted(description)],
	}])
}
fn control_result(operation: &str, outcome: ControlOutcome) -> Vec<u8> {
	let (status, state) = match outcome {
		ControlOutcome::Completed(state) => ("Completed", state),
		ControlOutcome::Busy(state) => ("Busy", state),
		ControlOutcome::NotPermitted(state) => ("NotPermitted", state),
	};
	operation_result(operation, &[status, job_state_name(state)])
}

fn events_result(events: &[OutboundEvent]) -> Vec<u8> {
	let mut lines = vec![Line {
		fields: vec![unquoted("Events"), unquoted("Completed")],
	}];
	for event in events {
		lines.extend([
			Line {
				fields: vec![unquoted("Event")],
			},
			Line {
				fields: vec![unquoted("Event-ID"), quoted(&event.event_id)],
			},
			Line {
				fields: vec![unquoted("Job"), unquoted(&event.job_id)],
			},
			Line {
				fields: vec![
					unquoted("Previous"),
					unquoted(event.previous.map_or("None", job_state_name)),
				],
			},
			Line {
				fields: vec![unquoted("Current"), unquoted(job_state_name(event.current))],
			},
			Line {
				fields: vec![unquoted("Changed"), unquoted(event.changed.to_string())],
			},
			Line {
				fields: vec![unquoted("Last-Result"), quoted(&event.last_result)],
			},
			Line {
				fields: vec![unquoted("End")],
			},
		]);
	}
	result(lines)
}

fn outbound_query_result(job: &OutboundJob, item_aware: bool, paths: bool) -> Vec<u8> {
	let operation = if item_aware { "Query-Job" } else { "Query" };
	let mut lines = vec![
		Line {
			fields: vec![unquoted(operation), unquoted("Completed")],
		},
		Line {
			fields: vec![
				unquoted("Job"),
				unquoted(&job.job_id),
				unquoted(job_state_name(job.state)),
			],
		},
		Line {
			fields: vec![unquoted("Application"), quoted(&job.application)],
		},
	];
	if item_aware {
		lines.push(Line {
			fields: vec![
				unquoted("Kind"),
				unquoted(match job.kind {
					JobKind::NetMail => "NetMail",
					JobKind::EchoMail => "EchoMail",
					JobKind::File => "File",
					JobKind::PeerFile => "Peer-File",
					JobKind::FileRequest => "FileRequest",
				}),
			],
		});
		lines.push(Line {
			fields: vec![unquoted("Local-Identity"), quoted(&job.local_identity)],
		});
		match &job.target {
			JobTarget::Destination(value) => lines.push(Line {
				fields: vec![unquoted("Destination"), quoted(value)],
			}),
			JobTarget::Area(value) => lines.push(Line {
				fields: vec![unquoted("Area"), quoted(value)],
			}),
		}
		lines.extend([
			Line {
				fields: vec![unquoted("Created"), unquoted(job.created.to_string())],
			},
			Line {
				fields: vec![unquoted("Changed"), unquoted(job.changed.to_string())],
			},
			Line {
				fields: vec![unquoted("Attempts"), unquoted(job.attempts().to_string())],
			},
			Line {
				fields: vec![unquoted("Last-Result"), quoted(&job.last_result)],
			},
		]);
		for copy in &job.deliveries {
			lines.push(Line {
				fields: vec![
					unquoted("Delivery"),
					unquoted(copy.index.to_string()),
					unquoted(job_state_name(copy.state)),
				],
			});
			append_delivery(&mut lines, copy);
			lines.extend([
				Line {
					fields: vec![unquoted("Attempts"), unquoted(copy.attempts.to_string())],
				},
				Line {
					fields: vec![unquoted("Last-Result"), quoted(&copy.last_result)],
				},
				Line {
					fields: vec![unquoted("End")],
				},
			]);
		}
		for source in &job.sources {
			lines.push(Line {
				fields: vec![
					unquoted("Source"),
					unquoted(source.index.to_string()),
					unquoted(match source.kind {
						tith_store::SourceKind::Attachment => "Attachment",
						tith_store::SourceKind::File => "File",
					}),
					quoted(&source.wire_filename),
					unquoted(cleanup_name(source.cleanup)),
				],
			});
		}
	} else {
		let copy = &job.deliveries[0];
		lines.extend([
			Line {
				fields: vec![unquoted("Origin"), quoted(&copy.local_identity)],
			},
			Line {
				fields: vec![
					unquoted("Destination"),
					quoted(match &job.target {
						JobTarget::Destination(value) => value,
						JobTarget::Area(_) => unreachable!(),
					}),
				],
			},
		]);
		append_delivery(&mut lines, copy);
		lines.extend([
			Line {
				fields: vec![unquoted("Created"), unquoted(job.created.to_string())],
			},
			Line {
				fields: vec![unquoted("Changed"), unquoted(job.changed.to_string())],
			},
			Line {
				fields: vec![unquoted("Attempts"), unquoted(job.attempts().to_string())],
			},
			Line {
				fields: vec![unquoted("Last-Result"), quoted(&job.last_result)],
			},
		]);
		for source in &job.sources {
			lines.push(Line {
				fields: vec![
					unquoted("Attachment"),
					unquoted(source.index.to_string()),
					quoted(&source.wire_filename),
					unquoted(cleanup_name(source.cleanup)),
				],
			});
		}
	}
	if paths {
		for source in &job.sources {
			if let Some(path) = &source.path {
				lines.push(Line {
					fields: vec![
						unquoted("Source-Path"),
						unquoted(source.index.to_string()),
						quoted(path),
					],
				});
			}
		}
	}
	result(lines)
}

fn append_delivery(lines: &mut Vec<Line>, copy: &tith_store::DeliveryRecord) {
	lines.extend([
		Line {
			fields: vec![
				unquoted("Next-Hop"),
				unquoted(match copy.mode {
					DeliveryMode::Active => "Active",
					DeliveryMode::Passive => "Passive",
				}),
				quoted(&copy.next_hop),
			],
		},
		Line {
			fields: vec![unquoted("Class"), quoted(&copy.class)],
		},
	]);
	for (kind, policy) in ["Relay-Denied", "Rejected"].into_iter().zip(copy.policies) {
		lines.push(Line {
			fields: vec![
				unquoted("Failure-Policy"),
				unquoted(kind),
				unquoted(match policy.disposition {
					FailureDisposition::DeadLetter => "Dead-Letter",
					FailureDisposition::Discard => "Discard",
				}),
				unquoted("Notify"),
				unquoted(match policy.notification {
					FailureNotification::None => "None",
					FailureNotification::Sender => "Sender",
					FailureNotification::OriginSysop => "Origin-Sysop",
					FailureNotification::Both => "Both",
				}),
			],
		});
	}
}

fn cleanup_name(value: tith_store::CleanupState) -> &'static str {
	match value {
		tith_store::CleanupState::NotRequested => "NotRequested",
		tith_store::CleanupState::Pending => "Pending",
		tith_store::CleanupState::Complete => "Complete",
		tith_store::CleanupState::NotFound => "NotFound",
		tith_store::CleanupState::Replaced => "Replaced",
		tith_store::CleanupState::Failed => "Failed",
	}
}
fn job_state_name(value: JobState) -> &'static str {
	match value {
		JobState::Queued => "Queued",
		JobState::Active => "Active",
		JobState::Deferred => "Deferred",
		JobState::Delivered => "Delivered",
		JobState::Rejected => "Rejected",
		JobState::Failed => "Failed",
		JobState::Cancelled => "Cancelled",
	}
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
		tith_store::ItemAuthentication::Unsigned => "Unsigned",
		tith_store::ItemAuthentication::SignedOriginInvalid => "SignedOrigin-Invalid",
		tith_store::ItemAuthentication::SignedOriginValid => "SignedOrigin-Valid",
		tith_store::ItemAuthentication::OriginInvalid => "Origin-Invalid",
		tith_store::ItemAuthentication::OriginValid => "Origin-Valid",
		tith_store::ItemAuthentication::Transport => "Transport",
	}
}

fn claim_result(claim: &tith_store::Claim, path: &Path) -> Vec<u8> {
	let record = &claim.record;
	let path = path
		.to_str()
		.expect("export roots are checked for UTF-8 at service construction");
	let mut lines = vec![
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
	];
	if let Some(job_id) = &record.forward_job {
		lines.push(Line {
			fields: vec![unquoted("Forward-Job"), unquoted(job_id)],
		});
	}
	lines.push(Line {
		fields: vec![unquoted("Payload-Path"), quoted(path)],
	});
	result(lines)
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
	if let Some(job_id) = &record.forward_job {
		lines.push(Line {
			fields: vec![unquoted("Forward-Job"), unquoted(job_id)],
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
				authentication: ItemAuthentication::OriginValid,
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
