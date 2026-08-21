use std::collections::BTreeSet;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tith_crypto::PublicKey;
use tith_crypto::TlvHash;
use tith_wire::{tlv::parse_sequence, types};

use super::{
	InboundRecord, InboundState, PAYLOADS, RECORDS, StoreError, decode_record, encode_record,
	put_bytes, put_string, put_u64, random_identifier, take_byte, take_bytes, take_bytes_fixed,
	take_string, take_u64,
};

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("outbound-jobs");
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("outbound-items");
const SUBMISSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("outbound-submissions");
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("outbound-events");

/// The TSP-0005 section 2 Kind a Job records.
///
/// `encode_job` writes the discriminant, so new variants are appended and the
/// existing three keep 0, 1, and 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobKind {
	NetMail,
	EchoMail,
	File,
	/// A standalone File with no Area, addressed by the Bundle which carries it.
	PeerFile,
	FileRequest,
}

impl JobKind {
	/// Whether this Kind commits one copy straight to its Destination.
	///
	/// TSP-0005 section 3: neither a Peer-File nor a `FileRequest` carries a
	/// Destination value a receiver could route on, so its Destination is also
	/// its next hop.
	#[must_use]
	pub const fn is_direct(self) -> bool {
		matches!(self, Self::PeerFile | Self::FileRequest)
	}

	/// Whether this Kind is addressed by a Destination rather than an Area.
	#[must_use]
	pub const fn has_destination(self) -> bool {
		matches!(self, Self::NetMail | Self::PeerFile | Self::FileRequest)
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobTarget {
	Destination(String),
	Area(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobState {
	Queued,
	Active,
	Deferred,
	Delivered,
	Rejected,
	Failed,
	Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryMode {
	Active,
	Passive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureDisposition {
	DeadLetter,
	Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureNotification {
	None,
	Sender,
	OriginSysop,
	Both,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailurePolicy {
	pub disposition: FailureDisposition,
	pub notification: FailureNotification,
}

/// The permanent remote response kinds for which a committed copy stores
/// policy. The discriminants are the policy-array indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PermanentFailureKind {
	RelayDenied,
	Rejected,
}

impl Default for FailurePolicy {
	fn default() -> Self {
		Self {
			disposition: FailureDisposition::DeadLetter,
			notification: FailureNotification::None,
		}
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDelivery {
	pub local_identity: String,
	pub next_hop: String,
	/// The next hop's `PublicKey` when its address is the anonymous one.
	///
	/// TSP-0002 section 9 requires a copy record "its exact next-hop address and
	/// anonymous `PublicKey`, if any". Two anonymous peers share the address
	/// `p2p#-1`, so without this the address alone cannot tell them apart and a
	/// Poll from one would collect the other's mail.
	pub next_hop_key: Option<PublicKey>,
	pub mode: DeliveryMode,
	pub class: String,
	pub retry_at: Option<u64>,
	pub policies: [FailurePolicy; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
	pub index: u64,
	pub local_identity: String,
	pub next_hop: String,
	/// See [`NewDelivery::next_hop_key`].
	pub next_hop_key: Option<PublicKey>,
	pub mode: DeliveryMode,
	pub class: String,
	pub retry_at: Option<u64>,
	pub policies: [FailurePolicy; 2],
	pub state: JobState,
	pub attempts: u64,
	pub last_result: String,
	pub last_failure: Option<PermanentFailureKind>,
	pub worker_token: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
	Attachment,
	File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDisposition {
	Keep,
	Delete,
	Truncate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupState {
	NotRequested,
	Pending,
	Complete,
	NotFound,
	Replaced,
	Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRecord {
	pub index: u64,
	pub kind: SourceKind,
	pub wire_filename: String,
	pub path: Option<String>,
	pub disposition: SourceDisposition,
	pub cleanup: CleanupState,
	pub file_identity: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionIdentity {
	pub application: String,
	pub idempotency_key: String,
	pub digest: TlvHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewOutboundJob {
	pub identity: SubmissionIdentity,
	pub kind: JobKind,
	pub target: JobTarget,
	pub local_identity: String,
	pub item: Vec<u8>,
	pub deliveries: Vec<NewDelivery>,
	pub sources: Vec<SourceRecord>,
	pub created: u64,
	pub forward_inbound: Option<String>,
	pub forward_claim_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundJob {
	pub job_id: String,
	pub application: String,
	pub idempotency_key: String,
	pub digest: TlvHash,
	pub kind: JobKind,
	pub target: JobTarget,
	pub local_identity: String,
	pub state: JobState,
	pub created: u64,
	pub changed: u64,
	pub deliveries: Vec<DeliveryRecord>,
	pub sources: Vec<SourceRecord>,
	pub forward_inbound: Option<String>,
	pub last_result: String,
}

impl OutboundJob {
	#[must_use]
	pub fn attempts(&self) -> u64 {
		self.deliveries.iter().map(|copy| copy.attempts).sum()
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionClass {
	New { job_id: String },
	Existing { job_id: String, state: JobState },
	Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
	New { job_id: String, state: JobState },
	Existing { job_id: String, state: JobState },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchCommit {
	Committed(Vec<CommitOutcome>),
	Conflict(Vec<usize>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionLookup {
	Existing { job_id: String, state: JobState },
	NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryClaim {
	pub job_id: String,
	pub delivery_index: u64,
	pub worker_token: String,
	pub item: Vec<u8>,
	pub delivery: DeliveryRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
	Delivered(String),
	Deferred {
		retry_at: u64,
		result: String,
	},
	Rejected {
		kind: PermanentFailureKind,
		result: String,
	},
	Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundEvent {
	pub event_id: String,
	pub job_id: String,
	pub previous: Option<JobState>,
	pub current: JobState,
	pub changed: u64,
	pub last_result: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlOutcome {
	Completed(JobState),
	Busy(JobState),
	NotPermitted(JobState),
}

#[derive(Clone)]
pub struct OutboundStore {
	database: Arc<Database>,
}

pub struct BatchContext<'a> {
	write: &'a redb::WriteTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardInbound {
	pub record: InboundRecord,
	pub payload: Vec<u8>,
}

impl BatchContext<'_> {
	pub fn claimed_inbound(
		&self,
		application: &str,
		inbound_id: &str,
		claim_token: &str,
		now: u64,
	) -> Result<ForwardInbound, StoreError> {
		let records = self.write.open_table(RECORDS)?;
		let value = records.get(inbound_id)?.ok_or(StoreError::NotFound)?;
		let record = decode_record(value.value())?;
		if record.application != application
			|| record.state != InboundState::Claimed
			|| record.claim_token.as_deref() != Some(claim_token)
			|| record.claim_expires.is_none_or(|expires| expires <= now)
		{
			return Err(StoreError::Stale(record.state));
		}
		if record.forward_job.is_some() {
			return Err(StoreError::CorruptRecord);
		}
		let payloads = self.write.open_table(PAYLOADS)?;
		let payload = payloads
			.get(inbound_id)?
			.ok_or(StoreError::CorruptRecord)?
			.value()
			.to_vec();
		Ok(ForwardInbound { record, payload })
	}
}

impl OutboundStore {
	pub(crate) fn new(database: Arc<Database>) -> Result<Self, StoreError> {
		let write = database.begin_write()?;
		{
			write.open_table(JOBS)?;
			write.open_table(ITEMS)?;
			write.open_table(SUBMISSIONS)?;
			write.open_table(EVENTS)?;
		}
		write.commit()?;
		Ok(Self { database })
	}

	#[must_use]
	pub fn key_pins(&self) -> crate::KeyPinStore {
		crate::KeyPinStore {
			database: Arc::clone(&self.database),
		}
	}

	pub fn commit_batch<F>(
		&self,
		identities: &[SubmissionIdentity],
		build: F,
	) -> Result<BatchCommit, StoreError>
	where
		F: FnOnce(&[SubmissionClass], &BatchContext<'_>) -> Result<Vec<NewOutboundJob>, StoreError>,
	{
		if identities.is_empty() {
			return Err(StoreError::CorruptRecord);
		}
		let mut unique = BTreeSet::new();
		for identity in identities {
			if identity.application.is_empty()
				|| identity.idempotency_key.is_empty()
				|| !unique.insert(submission_key(
					&identity.application,
					&identity.idempotency_key,
				)) {
				return Err(StoreError::CorruptRecord);
			}
		}
		let write = self.database.begin_write()?;
		let mut classes = Vec::with_capacity(identities.len());
		let mut conflicts = Vec::new();
		{
			let submissions = write.open_table(SUBMISSIONS)?;
			let records = write.open_table(JOBS)?;
			for (position, identity) in identities.iter().enumerate() {
				let key = submission_key(&identity.application, &identity.idempotency_key);
				if let Some(value) = submissions.get(key.as_slice())? {
					let (job_id, digest) = decode_submission(value.value())?;
					if digest == identity.digest {
						let value = records
							.get(job_id.as_str())?
							.ok_or(StoreError::CorruptRecord)?;
						let job = decode_job(value.value())?;
						classes.push(SubmissionClass::Existing {
							job_id,
							state: job.state,
						});
					} else {
						conflicts.push(position + 1);
						classes.push(SubmissionClass::Conflict);
					}
				} else {
					classes.push(SubmissionClass::New {
						job_id: String::new(),
					});
				}
			}
		}
		if !conflicts.is_empty() {
			return Ok(BatchCommit::Conflict(conflicts));
		}
		let mut assigned = BTreeSet::new();
		for class in &mut classes {
			if let SubmissionClass::New { job_id } = class {
				loop {
					let candidate = unique_job_id(&write)?;
					if assigned.insert(candidate.clone()) {
						*job_id = candidate;
						break;
					}
				}
			}
		}

		let context = BatchContext { write: &write };
		let new_jobs = build(&classes, &context)?;
		let expected_new = classes
			.iter()
			.filter(|class| matches!(class, SubmissionClass::New { .. }))
			.count();
		if new_jobs.len() != expected_new {
			return Err(StoreError::CorruptRecord);
		}
		let mut new_jobs = new_jobs.into_iter();
		let mut outcomes = Vec::with_capacity(classes.len());
		for (identity, class) in identities.iter().zip(&classes) {
			match class {
				SubmissionClass::Existing { job_id, state } => {
					outcomes.push(CommitOutcome::Existing {
						job_id: job_id.clone(),
						state: *state,
					});
				}
				SubmissionClass::New { job_id } => {
					let value = new_jobs.next().ok_or(StoreError::CorruptRecord)?;
					if value.identity != *identity {
						return Err(StoreError::CorruptRecord);
					}
					validate_new_job(&value)?;
					if let Some(inbound_id) = &value.forward_inbound {
						let token = value
							.forward_claim_token
							.as_deref()
							.ok_or(StoreError::CorruptRecord)?;
						let mut record = context
							.claimed_inbound(
								&identity.application,
								inbound_id,
								token,
								value.created,
							)?
							.record;
						record.forward_job = Some(job_id.clone());
						write
							.open_table(RECORDS)?
							.insert(inbound_id.as_str(), encode_record(&record).as_slice())?;
					}
					let item = value.item.clone();
					let job = make_job(job_id.clone(), value);
					{
						let mut jobs = write.open_table(JOBS)?;
						jobs.insert(job_id.as_str(), encode_job(&job).as_slice())?;
						let mut items = write.open_table(ITEMS)?;
						items.insert(job_id.as_str(), item.as_slice())?;
						let mut submissions = write.open_table(SUBMISSIONS)?;
						let key = submission_key(&identity.application, &identity.idempotency_key);
						submissions.insert(
							key.as_slice(),
							encode_submission(job_id, &identity.digest).as_slice(),
						)?;
					}
					append_event(&write, &job, None)?;
					outcomes.push(CommitOutcome::New {
						job_id: job_id.clone(),
						state: job.state,
					});
				}
				SubmissionClass::Conflict => return Err(StoreError::CorruptRecord),
			}
		}
		write.commit()?;
		Ok(BatchCommit::Committed(outcomes))
	}

	pub fn lookup(
		&self,
		application: &str,
		keys: &[String],
	) -> Result<Vec<SubmissionLookup>, StoreError> {
		let read = self.database.begin_read()?;
		let submissions = read.open_table(SUBMISSIONS)?;
		let jobs = read.open_table(JOBS)?;
		let mut output = Vec::with_capacity(keys.len());
		for key in keys {
			let map_key = submission_key(application, key);
			if let Some(value) = submissions.get(map_key.as_slice())? {
				let (job_id, _) = decode_submission(value.value())?;
				let value = jobs
					.get(job_id.as_str())?
					.ok_or(StoreError::CorruptRecord)?;
				output.push(SubmissionLookup::Existing {
					job_id,
					state: decode_job(value.value())?.state,
				});
			} else {
				output.push(SubmissionLookup::NotFound);
			}
		}
		Ok(output)
	}

	pub fn query(&self, job_id: &str) -> Result<OutboundJob, StoreError> {
		let read = self.database.begin_read()?;
		let jobs = read.open_table(JOBS)?;
		let value = jobs.get(job_id)?.ok_or(StoreError::NotFound)?;
		decode_job(value.value())
	}

	pub fn query_for(&self, application: &str, job_id: &str) -> Result<OutboundJob, StoreError> {
		let job = self.query(job_id)?;
		if job.application != application {
			return Err(StoreError::NotFound);
		}
		Ok(job)
	}

	pub fn events(&self, application: &str) -> Result<Vec<OutboundEvent>, StoreError> {
		let read = self.database.begin_read()?;
		let table = read.open_table(EVENTS)?;
		let mut output = Vec::new();
		for entry in table.iter()? {
			let (_, value) = entry?;
			let (owner, acknowledged, event) = decode_event(value.value())?;
			if owner == application && !acknowledged {
				output.push(event);
			}
		}
		output.sort_by(|left, right| {
			(left.changed, &left.event_id).cmp(&(right.changed, &right.event_id))
		});
		Ok(output)
	}

	pub fn acknowledge_event(&self, application: &str, event_id: &str) -> Result<(), StoreError> {
		let write = self.database.begin_write()?;
		let encoded = {
			let table = write.open_table(EVENTS)?;
			let value = table.get(event_id)?.ok_or(StoreError::NotFound)?;
			let (owner, _, event) = decode_event(value.value())?;
			if owner != application {
				return Err(StoreError::NotFound);
			}
			encode_event(&owner, true, &event)
		};
		write
			.open_table(EVENTS)?
			.insert(event_id, encoded.as_slice())?;
		write.commit()?;
		Ok(())
	}

	pub fn cancel(
		&self,
		application: &str,
		job_id: &str,
		now: u64,
	) -> Result<ControlOutcome, StoreError> {
		self.control(application, job_id, now, "Cancelled", |job| {
			if job
				.deliveries
				.iter()
				.any(|copy| copy.state == JobState::Active)
			{
				return ControlOutcome::Busy(job.state);
			}
			if job.state == JobState::Cancelled {
				return ControlOutcome::Completed(job.state);
			}
			let mut changed = false;
			for copy in &mut job.deliveries {
				if matches!(
					copy.state,
					JobState::Queued | JobState::Deferred | JobState::Rejected | JobState::Failed
				) {
					copy.state = JobState::Cancelled;
					copy.retry_at = None;
					copy.last_failure = None;
					"Cancelled".clone_into(&mut copy.last_result);
					changed = true;
				}
			}
			if changed {
				ControlOutcome::Completed(JobState::Cancelled)
			} else {
				ControlOutcome::NotPermitted(job.state)
			}
		})
	}

	pub fn retry(
		&self,
		application: &str,
		job_id: &str,
		now: u64,
	) -> Result<ControlOutcome, StoreError> {
		self.control(application, job_id, now, "Retry requested", |job| {
			let mut changed = false;
			for copy in &mut job.deliveries {
				if matches!(copy.state, JobState::Deferred | JobState::Failed) {
					copy.state = JobState::Queued;
					copy.retry_at = None;
					copy.last_failure = None;
					"Retry requested".clone_into(&mut copy.last_result);
					changed = true;
				}
			}
			if changed {
				ControlOutcome::Completed(JobState::Queued)
			} else {
				ControlOutcome::NotPermitted(job.state)
			}
		})
	}

	pub fn reroute(
		&self,
		application: &str,
		job_id: &str,
		now: u64,
		delivery: NewDelivery,
	) -> Result<ControlOutcome, StoreError> {
		self.control(application, job_id, now, "Rerouted", |job| {
			if job.kind != JobKind::NetMail
				|| job.deliveries.len() != 1
				|| matches!(job.state, JobState::Delivered | JobState::Cancelled)
			{
				return ControlOutcome::NotPermitted(job.state);
			}
			if job.state == JobState::Active {
				return ControlOutcome::Busy(job.state);
			}
			let copy = &mut job.deliveries[0];
			copy.local_identity = delivery.local_identity;
			copy.next_hop = delivery.next_hop;
			copy.mode = delivery.mode;
			copy.class = delivery.class;
			copy.retry_at = None;
			copy.policies = delivery.policies;
			copy.state = JobState::Queued;
			copy.last_failure = None;
			"Rerouted".clone_into(&mut copy.last_result);
			ControlOutcome::Completed(JobState::Queued)
		})
	}

	fn control(
		&self,
		application: &str,
		job_id: &str,
		now: u64,
		result: &str,
		update: impl FnOnce(&mut OutboundJob) -> ControlOutcome,
	) -> Result<ControlOutcome, StoreError> {
		let write = self.database.begin_write()?;
		let mut job = {
			let jobs = write.open_table(JOBS)?;
			let value = jobs.get(job_id)?.ok_or(StoreError::NotFound)?;
			decode_job(value.value())?
		};
		if job.application != application {
			return Err(StoreError::NotFound);
		}
		let previous = job.state;
		let outcome = update(&mut job);
		if matches!(outcome, ControlOutcome::Completed(_))
			&& (job.state != previous || job.last_result != result)
		{
			job.state = aggregate_state(&job.deliveries);
			job.changed = now;
			result.clone_into(&mut job.last_result);
			write
				.open_table(JOBS)?
				.insert(job_id, encode_job(&job).as_slice())?;
			append_event(&write, &job, Some(previous))?;
		}
		write.commit()?;
		Ok(match outcome {
			ControlOutcome::Completed(_) => ControlOutcome::Completed(job.state),
			other => other,
		})
	}

	pub fn item(&self, job_id: &str) -> Result<Vec<u8>, StoreError> {
		let read = self.database.begin_read()?;
		let items = read.open_table(ITEMS)?;
		let value = items.get(job_id)?.ok_or(StoreError::NotFound)?;
		Ok(value.value().to_vec())
	}

	/// Claims the next Active copy a schedule selects.
	///
	/// TSP-0002 section 8 selects on the schedule's Origin, its classes, and its
	/// Next-Hop selectors. Those live in `tith-config`, which this crate does
	/// not depend on, so the caller supplies the predicate and this adds the
	/// rules the spool owns: only an Active copy, only one which is Queued or
	/// Deferred, and only when its retry Timestamp has passed. A Passive copy is
	/// collected by Poll and is never sent by a schedule.
	pub fn claim_scheduled(
		&self,
		now: u64,
		selects: impl Fn(&DeliveryRecord) -> bool,
	) -> Result<Option<DeliveryClaim>, StoreError> {
		self.claim_matching(now, |copy| {
			copy.mode == DeliveryMode::Active && selects(copy)
		})
	}

	/// Claims the complete poll snapshot for one authenticated identity.
	///
	/// TTS-0005 section 3: the Destination "MUST atomically claim every matching
	/// held value which is not already claimed for an active exchange" and "MUST
	/// NOT select only part of the otherwise available matching set", so this
	/// takes all of them in one transaction or none.
	///
	/// A held value matches only when it is held for the identity the Bundle
	/// Origin represents, which for an anonymous Origin includes its `PublicKey`.
	/// TSP-0002 section 8 adds that an inbound Poll "is not constrained by
	/// schedules, delivery class, passive status, or a retry Timestamp", so
	/// neither the mode nor `retry_at` is consulted here.
	pub fn claim_poll_snapshot(
		&self,
		next_hop: &str,
		next_hop_key: Option<&PublicKey>,
		kinds: &[JobKind],
		now: u64,
	) -> Result<Vec<DeliveryClaim>, StoreError> {
		let write = self.database.begin_write()?;
		let mut selected: Vec<(OutboundJob, usize)> = Vec::new();
		{
			let jobs = write.open_table(JOBS)?;
			for entry in jobs.iter()? {
				let (_, value) = entry?;
				let job = decode_job(value.value())?;
				if !kinds.contains(&job.kind) {
					continue;
				}
				for (index, copy) in job.deliveries.iter().enumerate() {
					if copy.next_hop == next_hop
						&& copy.next_hop_key.as_ref() == next_hop_key
						&& matches!(copy.state, JobState::Queued | JobState::Deferred)
					{
						selected.push((job.clone(), index));
					}
				}
			}
		}
		if selected.is_empty() {
			return Ok(Vec::new());
		}
		// Order is stable so a snapshot is reproducible for diagnosis.
		selected.sort_by(|(left, left_index), (right, right_index)| {
			(
				left.created,
				&left.job_id,
				left.deliveries[*left_index].index,
			)
				.cmp(&(
					right.created,
					&right.job_id,
					right.deliveries[*right_index].index,
				))
		});
		let mut claims = Vec::with_capacity(selected.len());
		for (mut job, index) in selected {
			let previous = job.state;
			let token = random_identifier('W')?;
			let copy = &mut job.deliveries[index];
			copy.state = JobState::Active;
			copy.attempts = copy
				.attempts
				.checked_add(1)
				.ok_or(StoreError::CorruptRecord)?;
			copy.retry_at = None;
			copy.worker_token = Some(token.clone());
			job.changed = now;
			job.state = aggregate_state(&job.deliveries);
			let item = {
				let items = write.open_table(ITEMS)?;
				items
					.get(job.job_id.as_str())?
					.ok_or(StoreError::CorruptRecord)?
					.value()
					.to_vec()
			};
			{
				let mut jobs = write.open_table(JOBS)?;
				jobs.insert(job.job_id.as_str(), encode_job(&job).as_slice())?;
			}
			append_event(&write, &job, Some(previous))?;
			let delivery = job.deliveries[index].clone();
			claims.push(DeliveryClaim {
				job_id: job.job_id,
				delivery_index: delivery.index,
				worker_token: token,
				item,
				delivery,
			});
		}
		write.commit()?;
		Ok(claims)
	}

	fn claim_matching(
		&self,
		now: u64,
		matches_selector: impl Fn(&DeliveryRecord) -> bool,
	) -> Result<Option<DeliveryClaim>, StoreError> {
		let write = self.database.begin_write()?;
		let mut selected: Option<(OutboundJob, usize)> = None;
		{
			let jobs = write.open_table(JOBS)?;
			for entry in jobs.iter()? {
				let (_, value) = entry?;
				let job = decode_job(value.value())?;
				for (index, copy) in job.deliveries.iter().enumerate() {
					let eligible = matches_selector(copy)
						&& matches!(copy.state, JobState::Queued | JobState::Deferred)
						&& copy.retry_at.is_none_or(|retry| retry <= now);
					if eligible
						&& selected.as_ref().is_none_or(|(old, old_index)| {
							(job.created, &job.job_id, copy.index)
								< (old.created, &old.job_id, old.deliveries[*old_index].index)
						}) {
						selected = Some((job.clone(), index));
					}
				}
			}
		}
		let Some((mut job, index)) = selected else {
			return Ok(None);
		};
		let previous = job.state;
		let token = random_identifier('W')?;
		let copy = &mut job.deliveries[index];
		copy.state = JobState::Active;
		copy.attempts = copy
			.attempts
			.checked_add(1)
			.ok_or(StoreError::CorruptRecord)?;
		copy.retry_at = None;
		copy.worker_token = Some(token.clone());
		job.changed = now;
		job.state = aggregate_state(&job.deliveries);
		let item = {
			let items = write.open_table(ITEMS)?;
			items
				.get(job.job_id.as_str())?
				.ok_or(StoreError::CorruptRecord)?
				.value()
				.to_vec()
		};
		{
			let mut jobs = write.open_table(JOBS)?;
			jobs.insert(job.job_id.as_str(), encode_job(&job).as_slice())?;
		}
		append_event(&write, &job, Some(previous))?;
		let delivery = job.deliveries[index].clone();
		write.commit()?;
		Ok(Some(DeliveryClaim {
			job_id: job.job_id,
			delivery_index: delivery.index,
			worker_token: token,
			item,
			delivery,
		}))
	}

	pub fn finish_delivery(
		&self,
		job_id: &str,
		index: u64,
		token: &str,
		now: u64,
		outcome: DeliveryOutcome,
	) -> Result<JobState, StoreError> {
		let write = self.database.begin_write()?;
		let mut job = {
			let jobs = write.open_table(JOBS)?;
			let value = jobs.get(job_id)?.ok_or(StoreError::NotFound)?;
			decode_job(value.value())?
		};
		let previous = job.state;
		let copy = job
			.deliveries
			.iter_mut()
			.find(|copy| copy.index == index)
			.ok_or(StoreError::NotFound)?;
		if copy.state != JobState::Active || copy.worker_token.as_deref() != Some(token) {
			return Err(StoreError::JobStale(job.state));
		}
		let (state, retry_at, result) = match outcome {
			DeliveryOutcome::Delivered(result) => (JobState::Delivered, None, result),
			DeliveryOutcome::Deferred { retry_at, result } => {
				(JobState::Deferred, Some(retry_at), result)
			}
			DeliveryOutcome::Rejected { kind, result } => {
				copy.last_failure = Some(kind);
				(JobState::Rejected, None, result)
			}
			DeliveryOutcome::Failed(result) => (JobState::Failed, None, result),
		};
		if !matches!(state, JobState::Rejected) {
			copy.last_failure = None;
		}
		copy.state = state;
		copy.retry_at = retry_at;
		copy.last_result.clone_from(&result);
		copy.worker_token = None;
		job.changed = now;
		job.last_result = result;
		job.state = aggregate_state(&job.deliveries);
		let state = job.state;
		{
			let mut jobs = write.open_table(JOBS)?;
			jobs.insert(job_id, encode_job(&job).as_slice())?;
		}
		append_event(&write, &job, Some(previous))?;
		write.commit()?;
		Ok(state)
	}

	pub fn recover_active(&self, now: u64, retry_at: u64, result: &str) -> Result<u64, StoreError> {
		let write = self.database.begin_write()?;
		let mut changed = Vec::new();
		{
			let jobs = write.open_table(JOBS)?;
			for entry in jobs.iter()? {
				let (_, value) = entry?;
				let mut job = decode_job(value.value())?;
				let mut recovered = false;
				for copy in &mut job.deliveries {
					if copy.state == JobState::Active {
						copy.state = JobState::Deferred;
						copy.retry_at = Some(retry_at);
						result.clone_into(&mut copy.last_result);
						copy.worker_token = None;
						recovered = true;
					}
				}
				if recovered {
					let previous = job.state;
					job.state = aggregate_state(&job.deliveries);
					job.changed = now;
					result.clone_into(&mut job.last_result);
					changed.push((job, previous));
				}
			}
		}
		let count = changed.len() as u64;
		{
			let mut jobs = write.open_table(JOBS)?;
			for (job, _) in &changed {
				jobs.insert(job.job_id.as_str(), encode_job(job).as_slice())?;
			}
		}
		for (job, previous) in &changed {
			append_event(&write, job, Some(*previous))?;
		}
		write.commit()?;
		Ok(count)
	}
}

fn validate_new_job(value: &NewOutboundJob) -> Result<(), StoreError> {
	let parsed = parse_sequence(&value.item).map_err(|_| StoreError::InvalidPayload)?;
	if parsed.len() != 1
		|| !matches!(
			(value.kind, parsed[0].type_code),
			(JobKind::NetMail | JobKind::EchoMail, types::MESSAGE)
				| (JobKind::File | JobKind::PeerFile, types::FILE)
				| (JobKind::FileRequest, types::FILE_REQUEST)
		) {
		return Err(StoreError::InvalidPayload);
	}
	if value.kind.has_destination() != matches!(value.target, JobTarget::Destination(_))
		|| (!value.kind.has_destination() && !matches!(value.target, JobTarget::Area(_)))
		|| (value.deliveries.is_empty() && value.forward_inbound.is_none())
		// A directly committed Kind has exactly one copy: its Destination.
		|| (value.kind.is_direct() && value.deliveries.len() != 1)
		|| (value.forward_inbound.is_some() != value.forward_claim_token.is_some())
		|| value.local_identity.is_empty()
	{
		return Err(StoreError::CorruptRecord);
	}
	for (index, source) in value.sources.iter().enumerate() {
		if source.index != index as u64 + 1 {
			return Err(StoreError::CorruptRecord);
		}
	}
	Ok(())
}

fn make_job(job_id: String, value: NewOutboundJob) -> OutboundJob {
	let deliveries: Vec<_> = value
		.deliveries
		.into_iter()
		.enumerate()
		.map(|(index, copy)| DeliveryRecord {
			index: index as u64 + 1,
			local_identity: copy.local_identity,
			next_hop: copy.next_hop,
			next_hop_key: copy.next_hop_key,
			mode: copy.mode,
			class: copy.class,
			retry_at: copy.retry_at,
			policies: copy.policies,
			state: if copy.retry_at.is_some() {
				JobState::Deferred
			} else {
				JobState::Queued
			},
			attempts: 0,
			last_result: String::new(),
			last_failure: None,
			worker_token: None,
		})
		.collect();
	let state = if deliveries.is_empty() {
		JobState::Delivered
	} else {
		aggregate_state(&deliveries)
	};
	OutboundJob {
		job_id,
		application: value.identity.application,
		idempotency_key: value.identity.idempotency_key,
		digest: value.identity.digest,
		kind: value.kind,
		target: value.target,
		local_identity: value.local_identity,
		state,
		created: value.created,
		changed: value.created,
		deliveries,
		sources: value.sources,
		forward_inbound: value.forward_inbound,
		last_result: String::new(),
	}
}

fn aggregate_state(copies: &[DeliveryRecord]) -> JobState {
	if copies.iter().any(|copy| copy.state == JobState::Active) {
		JobState::Active
	} else if copies.iter().any(|copy| copy.state == JobState::Queued) {
		JobState::Queued
	} else if copies.iter().any(|copy| copy.state == JobState::Deferred) {
		JobState::Deferred
	} else if copies.iter().any(|copy| copy.state == JobState::Failed) {
		JobState::Failed
	} else if copies.iter().any(|copy| copy.state == JobState::Rejected) {
		JobState::Rejected
	} else if copies.iter().any(|copy| copy.state == JobState::Cancelled) {
		JobState::Cancelled
	} else {
		JobState::Delivered
	}
}

fn unique_job_id(write: &redb::WriteTransaction) -> Result<String, StoreError> {
	let jobs = write.open_table(JOBS)?;
	loop {
		let candidate = random_identifier('J')?;
		if jobs.get(candidate.as_str())?.is_none() {
			return Ok(candidate);
		}
	}
}

fn submission_key(application: &str, key: &str) -> Vec<u8> {
	let mut output = Vec::new();
	put_bytes(&mut output, application.as_bytes());
	output.extend_from_slice(key.as_bytes());
	output
}

fn encode_submission(job_id: &str, digest: &TlvHash) -> Vec<u8> {
	let mut output = Vec::new();
	put_string(&mut output, job_id);
	output.extend_from_slice(digest.as_bytes());
	output
}

fn decode_submission(mut input: &[u8]) -> Result<(String, TlvHash), StoreError> {
	let id = take_string(&mut input)?;
	let digest = TlvHash::from_bytes(take_bytes_fixed::<32>(&mut input)?);
	if !input.is_empty() {
		return Err(StoreError::CorruptRecord);
	}
	Ok((id, digest))
}

fn append_event(
	write: &redb::WriteTransaction,
	job: &OutboundJob,
	previous: Option<JobState>,
) -> Result<(), StoreError> {
	let table = write.open_table(EVENTS)?;
	let prefix = format!("{}:", job.job_id);
	let mut sequence = 0_u64;
	for entry in table.iter()? {
		let (key, _) = entry?;
		if let Some(number) = key
			.value()
			.strip_prefix(&prefix)
			.and_then(|value| value.parse::<u64>().ok())
		{
			sequence = sequence.max(number);
		}
	}
	drop(table);
	let sequence = sequence.checked_add(1).ok_or(StoreError::CorruptRecord)?;
	let event = OutboundEvent {
		event_id: format!("{}:{sequence}", job.job_id),
		job_id: job.job_id.clone(),
		previous,
		current: job.state,
		changed: job.changed,
		last_result: job.last_result.clone(),
	};
	write.open_table(EVENTS)?.insert(
		event.event_id.as_str(),
		encode_event(&job.application, false, &event).as_slice(),
	)?;
	Ok(())
}

fn encode_event(application: &str, acknowledged: bool, event: &OutboundEvent) -> Vec<u8> {
	let mut output = Vec::new();
	put_string(&mut output, application);
	output.push(u8::from(acknowledged));
	put_string(&mut output, &event.event_id);
	put_string(&mut output, &event.job_id);
	match event.previous {
		Some(state) => {
			output.push(1);
			output.push(state as u8);
		}
		None => output.push(0),
	}
	output.push(event.current as u8);
	put_u64(&mut output, event.changed);
	put_string(&mut output, &event.last_result);
	output
}

fn decode_event(mut input: &[u8]) -> Result<(String, bool, OutboundEvent), StoreError> {
	let application = take_string(&mut input)?;
	let acknowledged = match take_byte(&mut input)? {
		0 => false,
		1 => true,
		_ => return Err(StoreError::CorruptRecord),
	};
	let event_id = take_string(&mut input)?;
	let job_id = take_string(&mut input)?;
	let previous = match take_byte(&mut input)? {
		0 => None,
		1 => Some(decode_job_state(take_byte(&mut input)?)?),
		_ => return Err(StoreError::CorruptRecord),
	};
	let current = decode_job_state(take_byte(&mut input)?)?;
	let changed = take_u64(&mut input)?;
	let last_result = take_string(&mut input)?;
	if !input.is_empty() {
		return Err(StoreError::CorruptRecord);
	}
	Ok((
		application,
		acknowledged,
		OutboundEvent {
			event_id,
			job_id,
			previous,
			current,
			changed,
			last_result,
		},
	))
}

fn encode_job(value: &OutboundJob) -> Vec<u8> {
	let mut output = vec![4];
	for text in [&value.job_id, &value.application, &value.idempotency_key] {
		put_string(&mut output, text);
	}
	output.extend_from_slice(value.digest.as_bytes());
	output.push(value.kind as u8);
	match &value.target {
		JobTarget::Destination(text) => {
			output.push(0);
			put_string(&mut output, text);
		}
		JobTarget::Area(text) => {
			output.push(1);
			put_string(&mut output, text);
		}
	}
	output.push(value.state as u8);
	put_u64(&mut output, value.created);
	put_u64(&mut output, value.changed);
	put_string(&mut output, &value.last_result);
	match &value.forward_inbound {
		Some(text) => {
			output.push(1);
			put_string(&mut output, text);
		}
		None => output.push(0),
	}
	put_u64(&mut output, value.deliveries.len() as u64);
	for copy in &value.deliveries {
		put_u64(&mut output, copy.index);
		put_string(&mut output, &copy.local_identity);
		put_string(&mut output, &copy.next_hop);
		match &copy.next_hop_key {
			Some(key) => {
				output.push(1);
				output.extend_from_slice(key.as_bytes());
			}
			None => output.push(0),
		}
		output.push(copy.mode as u8);
		put_string(&mut output, &copy.class);
		put_optional_u64(&mut output, copy.retry_at);
		for policy in copy.policies {
			output.push(policy.disposition as u8);
			output.push(policy.notification as u8);
		}
		output.push(copy.state as u8);
		put_u64(&mut output, copy.attempts);
		put_string(&mut output, &copy.last_result);
		match copy.last_failure {
			Some(kind) => {
				output.push(1);
				output.push(kind as u8);
			}
			None => output.push(0),
		}
		put_optional_string(&mut output, copy.worker_token.as_deref());
	}
	put_u64(&mut output, value.sources.len() as u64);
	for source in &value.sources {
		put_u64(&mut output, source.index);
		output.push(source.kind as u8);
		put_string(&mut output, &source.wire_filename);
		put_optional_string(&mut output, source.path.as_deref());
		output.push(source.disposition as u8);
		output.push(source.cleanup as u8);
		put_bytes(&mut output, &source.file_identity);
	}
	put_string(&mut output, &value.local_identity);
	output
}

fn decode_job(mut input: &[u8]) -> Result<OutboundJob, StoreError> {
	let version = take_byte(&mut input)?;
	if version != 4 {
		return Err(StoreError::UnsupportedRecordVersion {
			record: "outbound job",
			version,
		});
	}
	let job_id = take_string(&mut input)?;
	let application = take_string(&mut input)?;
	let idempotency_key = take_string(&mut input)?;
	let digest = TlvHash::from_bytes(take_bytes_fixed::<32>(&mut input)?);
	let kind = decode_job_kind(take_byte(&mut input)?)?;
	let target_kind = take_byte(&mut input)?;
	let target_text = take_string(&mut input)?;
	let target = match target_kind {
		0 => JobTarget::Destination(target_text),
		1 => JobTarget::Area(target_text),
		_ => return Err(StoreError::CorruptRecord),
	};
	let state = decode_job_state(take_byte(&mut input)?)?;
	let created = take_u64(&mut input)?;
	let changed = take_u64(&mut input)?;
	let last_result = take_string(&mut input)?;
	let forward_inbound = take_optional_string(&mut input)?;
	let delivery_count = take_count(&mut input)?;
	let mut deliveries = Vec::with_capacity(delivery_count);
	for _ in 0..delivery_count {
		let index = take_u64(&mut input)?;
		let local_identity = take_string(&mut input)?;
		let next_hop = take_string(&mut input)?;
		let next_hop_key = match take_byte(&mut input)? {
			0 => None,
			1 => Some(PublicKey::from_bytes(take_bytes_fixed::<32>(&mut input)?)),
			_ => return Err(StoreError::CorruptRecord),
		};
		let mode = match take_byte(&mut input)? {
			0 => DeliveryMode::Active,
			1 => DeliveryMode::Passive,
			_ => return Err(StoreError::CorruptRecord),
		};
		let class = take_string(&mut input)?;
		let retry_at = take_optional_u64(&mut input)?;
		let mut policies = [FailurePolicy::default(); 2];
		for policy in &mut policies {
			policy.disposition = match take_byte(&mut input)? {
				0 => FailureDisposition::DeadLetter,
				1 => FailureDisposition::Discard,
				_ => return Err(StoreError::CorruptRecord),
			};
			policy.notification = match take_byte(&mut input)? {
				0 => FailureNotification::None,
				1 => FailureNotification::Sender,
				2 => FailureNotification::OriginSysop,
				3 => FailureNotification::Both,
				_ => return Err(StoreError::CorruptRecord),
			};
		}
		let state = decode_job_state(take_byte(&mut input)?)?;
		let attempts = take_u64(&mut input)?;
		let last_result = take_string(&mut input)?;
		let last_failure = match take_byte(&mut input)? {
			0 => None,
			1 => Some(match take_byte(&mut input)? {
				0 => PermanentFailureKind::RelayDenied,
				1 => PermanentFailureKind::Rejected,
				_ => return Err(StoreError::CorruptRecord),
			}),
			_ => return Err(StoreError::CorruptRecord),
		};
		deliveries.push(DeliveryRecord {
			index,
			local_identity,
			next_hop,
			next_hop_key,
			mode,
			class,
			retry_at,
			policies,
			state,
			attempts,
			last_result,
			last_failure,
			worker_token: take_optional_string(&mut input)?,
		});
	}
	let source_count = take_count(&mut input)?;
	let mut sources = Vec::with_capacity(source_count);
	for _ in 0..source_count {
		sources.push(SourceRecord {
			index: take_u64(&mut input)?,
			kind: match take_byte(&mut input)? {
				0 => SourceKind::Attachment,
				1 => SourceKind::File,
				_ => return Err(StoreError::CorruptRecord),
			},
			wire_filename: take_string(&mut input)?,
			path: take_optional_string(&mut input)?,
			disposition: match take_byte(&mut input)? {
				0 => SourceDisposition::Keep,
				1 => SourceDisposition::Delete,
				2 => SourceDisposition::Truncate,
				_ => return Err(StoreError::CorruptRecord),
			},
			cleanup: match take_byte(&mut input)? {
				0 => CleanupState::NotRequested,
				1 => CleanupState::Pending,
				2 => CleanupState::Complete,
				3 => CleanupState::NotFound,
				4 => CleanupState::Replaced,
				5 => CleanupState::Failed,
				_ => return Err(StoreError::CorruptRecord),
			},
			file_identity: take_bytes(&mut input)?.to_vec(),
		});
	}
	let local_identity = if input.is_empty() {
		deliveries
			.first()
			.map_or_else(String::new, |copy| copy.local_identity.clone())
	} else {
		take_string(&mut input)?
	};
	if !input.is_empty() {
		return Err(StoreError::CorruptRecord);
	}
	Ok(OutboundJob {
		job_id,
		application,
		idempotency_key,
		digest,
		kind,
		target,
		local_identity,
		state,
		created,
		changed,
		deliveries,
		sources,
		forward_inbound,
		last_result,
	})
}

fn put_optional_string(output: &mut Vec<u8>, value: Option<&str>) {
	match value {
		Some(text) => {
			output.push(1);
			put_string(output, text);
		}
		None => output.push(0),
	}
}

fn take_optional_string(input: &mut &[u8]) -> Result<Option<String>, StoreError> {
	match take_byte(input)? {
		0 => Ok(None),
		1 => Ok(Some(take_string(input)?)),
		_ => Err(StoreError::CorruptRecord),
	}
}

fn put_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
	match value {
		Some(number) => {
			output.push(1);
			put_u64(output, number);
		}
		None => output.push(0),
	}
}

fn take_optional_u64(input: &mut &[u8]) -> Result<Option<u64>, StoreError> {
	match take_byte(input)? {
		0 => Ok(None),
		1 => Ok(Some(take_u64(input)?)),
		_ => Err(StoreError::CorruptRecord),
	}
}

fn take_count(input: &mut &[u8]) -> Result<usize, StoreError> {
	usize::try_from(take_u64(input)?).map_err(|_| StoreError::CorruptRecord)
}

fn decode_job_kind(value: u8) -> Result<JobKind, StoreError> {
	match value {
		0 => Ok(JobKind::NetMail),
		1 => Ok(JobKind::EchoMail),
		2 => Ok(JobKind::File),
		3 => Ok(JobKind::PeerFile),
		4 => Ok(JobKind::FileRequest),
		_ => Err(StoreError::CorruptRecord),
	}
}

fn decode_job_state(value: u8) -> Result<JobState, StoreError> {
	match value {
		0 => Ok(JobState::Queued),
		1 => Ok(JobState::Active),
		2 => Ok(JobState::Deferred),
		3 => Ok(JobState::Delivered),
		4 => Ok(JobState::Rejected),
		5 => Ok(JobState::Failed),
		6 => Ok(JobState::Cancelled),
		_ => Err(StoreError::CorruptRecord),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::hash_inbound_item;
	use tith_wire::tlv::OwnedTlv;

	fn identity(key: &str, payload: &[u8]) -> SubmissionIdentity {
		SubmissionIdentity {
			application: "mailer".to_owned(),
			idempotency_key: key.to_owned(),
			digest: hash_inbound_item(payload).unwrap(),
		}
	}

	fn new_job(identity: SubmissionIdentity, payload: Vec<u8>) -> NewOutboundJob {
		NewOutboundJob {
			identity,
			kind: JobKind::NetMail,
			target: JobTarget::Destination("fidonet#1/2".to_owned()),
			local_identity: "fidonet#1/1".to_owned(),
			item: payload,
			deliveries: vec![NewDelivery {
				local_identity: "fidonet#1/1".to_owned(),
				next_hop: "fidonet#1/2".to_owned(),
				next_hop_key: None,
				mode: DeliveryMode::Active,
				class: "normal".to_owned(),
				retry_at: None,
				policies: [FailurePolicy::default(); 2],
			}],
			sources: Vec::new(),
			created: 10,
			forward_inbound: None,
			forward_claim_token: None,
		}
	}

	#[test]
	fn outbound_records_use_only_the_current_private_format() {
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let job = make_job(
			"J-current".to_owned(),
			new_job(identity("format", &payload), payload),
		);
		let current = encode_job(&job);
		assert_eq!(current[0], 4);

		let mut obsolete = current;
		obsolete[0] = 3;
		assert!(matches!(
			decode_job(&obsolete),
			Err(StoreError::UnsupportedRecordVersion {
				record: "outbound job",
				version: 3
			})
		));
	}

	#[test]
	fn batch_commit_is_atomic_idempotent_and_claimable() {
		let path = std::env::temp_dir().join(format!(
			"tith-outbound-{}.redb",
			random_identifier('T').unwrap()
		));
		let inbound = super::super::InboundStore::create(&path).unwrap();
		let store = inbound.outbound().unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let id = identity("one", &payload);
		let result = store
			.commit_batch(std::slice::from_ref(&id), |_, _| {
				Ok(vec![new_job(id.clone(), payload.clone())])
			})
			.unwrap();
		let BatchCommit::Committed(outcomes) = result else {
			panic!("commit expected");
		};
		let CommitOutcome::New { job_id, .. } = &outcomes[0] else {
			panic!("new job expected");
		};
		let repeated = store
			.commit_batch(std::slice::from_ref(&id), |classes, _| {
				assert!(matches!(classes[0], SubmissionClass::Existing { .. }));
				Ok(Vec::new())
			})
			.unwrap();
		assert!(matches!(
			repeated,
			BatchCommit::Committed(ref values)
				if matches!(values[0], CommitOutcome::Existing { .. })
		));
		let claim = store
			.claim_scheduled(11, |copy| copy.next_hop == "fidonet#1/2")
			.unwrap()
			.unwrap();
		assert_eq!(claim.job_id, *job_id);
		assert_eq!(claim.item, payload);
		assert_eq!(
			store
				.finish_delivery(
					job_id,
					1,
					&claim.worker_token,
					12,
					DeliveryOutcome::Delivered("Accepted".to_owned())
				)
				.unwrap(),
			JobState::Delivered
		);
		drop(store);
		drop(inbound);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn changed_digest_conflicts_without_running_builder() {
		let path = std::env::temp_dir().join(format!(
			"tith-outbound-{}.redb",
			random_identifier('T').unwrap()
		));
		let inbound = super::super::InboundStore::create(&path).unwrap();
		let store = inbound.outbound().unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let id = identity("one", &payload);
		store
			.commit_batch(std::slice::from_ref(&id), |_, _| {
				Ok(vec![new_job(id.clone(), payload.clone())])
			})
			.unwrap();
		let other_payload = OwnedTlv::new(types::MESSAGE, vec![1]).unwrap().encode();
		let other = identity("one", &other_payload);
		let result = store
			.commit_batch(std::slice::from_ref(&other), |_, _| {
				panic!("conflict must be classified before source construction")
			})
			.unwrap();
		assert_eq!(result, BatchCommit::Conflict(vec![1]));
		drop(store);
		drop(inbound);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn controls_and_events_are_durable_and_application_scoped() {
		let path = std::env::temp_dir().join(format!(
			"tith-outbound-events-{}.redb",
			random_identifier('T').unwrap()
		));
		let inbound = super::super::InboundStore::create(&path).unwrap();
		let store = inbound.outbound().unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let id = identity("events", &payload);
		let BatchCommit::Committed(created) = store
			.commit_batch(std::slice::from_ref(&id), |_, _| {
				Ok(vec![new_job(id.clone(), payload)])
			})
			.unwrap()
		else {
			panic!("commit expected")
		};
		let CommitOutcome::New { job_id, .. } = &created[0] else {
			panic!("new expected")
		};
		let events = store.events("mailer").unwrap();
		assert_eq!(events.len(), 1);
		assert_eq!(events[0].previous, None);
		store
			.acknowledge_event("mailer", &events[0].event_id)
			.unwrap();
		assert!(store.events("mailer").unwrap().is_empty());
		assert!(matches!(
			store.cancel("other", job_id, 20),
			Err(StoreError::NotFound)
		));
		let claim = store
			.claim_scheduled(20, |copy| copy.class == "normal")
			.unwrap()
			.unwrap();
		assert_eq!(
			store.cancel("mailer", job_id, 21).unwrap(),
			ControlOutcome::Busy(JobState::Active)
		);
		store
			.finish_delivery(
				job_id,
				1,
				&claim.worker_token,
				22,
				DeliveryOutcome::Deferred {
					retry_at: 40,
					result: "later".to_owned(),
				},
			)
			.unwrap();
		assert_eq!(
			store.retry("mailer", job_id, 23).unwrap(),
			ControlOutcome::Completed(JobState::Queued)
		);
		assert_eq!(store.events("mailer").unwrap().len(), 3);
		let claim = store
			.claim_scheduled(24, |copy| copy.class == "normal")
			.unwrap()
			.unwrap();
		store
			.finish_delivery(
				job_id,
				1,
				&claim.worker_token,
				25,
				DeliveryOutcome::Rejected {
					kind: PermanentFailureKind::Rejected,
					result: "terminal".to_owned(),
				},
			)
			.unwrap();
		assert_eq!(
			store.retry("mailer", job_id, 26).unwrap(),
			ControlOutcome::NotPermitted(JobState::Rejected)
		);
		drop(store);
		drop(inbound);
		std::fs::remove_file(path).unwrap();
	}

	fn held_job(
		key: &str,
		next_hop: &str,
		next_hop_key: Option<PublicKey>,
		kind: JobKind,
		created: u64,
	) -> NewOutboundJob {
		// The item type and the target both have to agree with the kind.
		let payload = OwnedTlv::new(
			match kind {
				JobKind::File | JobKind::PeerFile => types::FILE,
				JobKind::FileRequest => types::FILE_REQUEST,
				JobKind::NetMail | JobKind::EchoMail => types::MESSAGE,
			},
			key.as_bytes().to_vec(),
		)
		.unwrap()
		.encode();
		let target = if kind.has_destination() {
			JobTarget::Destination(next_hop.to_owned())
		} else {
			JobTarget::Area("SYNCHRONET".to_owned())
		};
		NewOutboundJob {
			identity: identity(key, &payload),
			kind,
			target,
			local_identity: "fidonet#1/1".to_owned(),
			item: payload,
			deliveries: vec![NewDelivery {
				local_identity: "fidonet#1/1".to_owned(),
				next_hop: next_hop.to_owned(),
				next_hop_key,
				// Passive, and with a future retry Timestamp: an inbound Poll is
				// constrained by neither.
				mode: DeliveryMode::Passive,
				class: "normal".to_owned(),
				retry_at: Some(u64::MAX),
				policies: [FailurePolicy::default(); 2],
			}],
			sources: Vec::new(),
			created,
			forward_inbound: None,
			forward_claim_token: None,
		}
	}

	fn temporary_store() -> (std::path::PathBuf, super::super::InboundStore) {
		let path = std::env::temp_dir().join(format!(
			"tith-poll-{}.redb",
			random_identifier('T').unwrap()
		));
		let inbound = super::super::InboundStore::create(&path).unwrap();
		(path, inbound)
	}

	fn commit(store: &OutboundStore, job: &NewOutboundJob) -> String {
		let id = job.identity.clone();
		let BatchCommit::Committed(outcomes) = store
			.commit_batch(std::slice::from_ref(&id), |_, _| Ok(vec![job.clone()]))
			.unwrap()
		else {
			panic!("commit expected");
		};
		let (CommitOutcome::New { job_id, .. } | CommitOutcome::Existing { job_id, .. }) =
			&outcomes[0];
		job_id.clone()
	}

	#[test]
	fn a_poll_snapshot_takes_every_matching_copy_and_ignores_mode_and_retry() {
		let (path, inbound) = temporary_store();
		let store = inbound.outbound().unwrap();
		let first = commit(
			&store,
			&held_job("a", "fidonet#1/2", None, JobKind::NetMail, 10),
		);
		let second = commit(
			&store,
			&held_job("b", "fidonet#1/2", None, JobKind::NetMail, 20),
		);
		// A copy for a different peer must not be returned.
		commit(
			&store,
			&held_job("c", "fidonet#1/3", None, JobKind::NetMail, 30),
		);

		let snapshot = store
			.claim_poll_snapshot("fidonet#1/2", None, &[JobKind::NetMail], 100)
			.unwrap();
		let claimed: Vec<&str> = snapshot.iter().map(|claim| claim.job_id.as_str()).collect();
		assert_eq!(claimed, [first.as_str(), second.as_str()]);

		// Everything matching is now claimed, so a second Poll returns nothing.
		assert!(
			store
				.claim_poll_snapshot("fidonet#1/2", None, &[JobKind::NetMail], 100)
				.unwrap()
				.is_empty()
		);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_snapshot_is_scoped_to_the_authenticated_identity_not_just_the_address() {
		// Two anonymous peers share the address p2p#-1, so the PublicKey is the
		// only thing telling them apart. Without it one would collect the
		// other's mail.
		let (path, inbound) = temporary_store();
		let store = inbound.outbound().unwrap();
		let mine = PublicKey::from_bytes([1; 32]);
		let theirs = PublicKey::from_bytes([2; 32]);
		let held = commit(
			&store,
			&held_job("a", "p2p#-1", Some(mine), JobKind::NetMail, 10),
		);
		commit(
			&store,
			&held_job("b", "p2p#-1", Some(theirs), JobKind::NetMail, 20),
		);

		let snapshot = store
			.claim_poll_snapshot("p2p#-1", Some(&mine), &[JobKind::NetMail], 100)
			.unwrap();
		assert_eq!(snapshot.len(), 1);
		assert_eq!(snapshot[0].job_id, held);

		// An address-only match returns neither.
		assert!(
			store
				.claim_poll_snapshot("p2p#-1", None, &[JobKind::NetMail], 100)
				.unwrap()
				.is_empty()
		);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_snapshot_selects_only_the_requested_kinds() {
		let (path, inbound) = temporary_store();
		let store = inbound.outbound().unwrap();
		commit(
			&store,
			&held_job("a", "fidonet#1/2", None, JobKind::NetMail, 10),
		);
		let file = commit(
			&store,
			&held_job("b", "fidonet#1/2", None, JobKind::File, 20),
		);
		let snapshot = store
			.claim_poll_snapshot("fidonet#1/2", None, &[JobKind::File], 100)
			.unwrap();
		assert_eq!(snapshot.len(), 1);
		assert_eq!(snapshot[0].job_id, file);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn the_directly_committed_kinds_round_trip_and_answer_their_own_polls() {
		let (path, inbound) = temporary_store();
		let store = inbound.outbound().unwrap();
		let peer_file = commit(
			&store,
			&held_job("a", "fidonet#1/2", None, JobKind::PeerFile, 10),
		);
		let request = commit(
			&store,
			&held_job("b", "fidonet#1/2", None, JobKind::FileRequest, 20),
		);

		// The Kind survives encode and decode, and a Peer-File is addressed by a
		// Destination rather than an Area.
		let job = store.query_for("mailer", &peer_file).unwrap();
		assert_eq!(job.kind, JobKind::PeerFile);
		assert_eq!(job.target, JobTarget::Destination("fidonet#1/2".to_owned()));
		assert_eq!(
			store.query_for("mailer", &request).unwrap().kind,
			JobKind::FileRequest
		);

		// PollFiles collects both File flavours; PollFileRequests collects only
		// the requests.
		let files = store
			.claim_poll_snapshot(
				"fidonet#1/2",
				None,
				&[JobKind::File, JobKind::PeerFile],
				100,
			)
			.unwrap();
		assert_eq!(files.len(), 1);
		assert_eq!(files[0].job_id, peer_file);
		let requests = store
			.claim_poll_snapshot("fidonet#1/2", None, &[JobKind::FileRequest], 100)
			.unwrap();
		assert_eq!(requests.len(), 1);
		assert_eq!(requests[0].job_id, request);

		// Neither may be rerouted: its Destination is its only next hop.
		assert!(matches!(
			store
				.reroute(
					"mailer",
					&peer_file,
					110,
					held_job("a", "fidonet#1/3", None, JobKind::PeerFile, 10).deliveries[0].clone(),
				)
				.unwrap(),
			ControlOutcome::NotPermitted(_)
		));
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_directly_committed_job_needs_one_copy_and_a_destination() {
		let (path, inbound) = temporary_store();
		let store = inbound.outbound().unwrap();
		let mut job = held_job("a", "fidonet#1/2", None, JobKind::PeerFile, 10);
		job.target = JobTarget::Area("FILES".to_owned());
		assert!(matches!(
			store.commit_batch(std::slice::from_ref(&job.identity.clone()), |_, _| Ok(
				vec![job.clone()]
			)),
			Err(StoreError::CorruptRecord)
		));

		// A FileRequest owns a FileRequest, never a File.
		let mut wrong_item = held_job("b", "fidonet#1/2", None, JobKind::FileRequest, 10);
		wrong_item.item = OwnedTlv::new(types::FILE, Vec::new()).unwrap().encode();
		assert!(matches!(
			store.commit_batch(
				std::slice::from_ref(&wrong_item.identity.clone()),
				|_, _| Ok(vec![wrong_item.clone()])
			),
			Err(StoreError::InvalidPayload)
		));
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_schedule_claims_only_active_copies_its_predicate_selects() {
		let (path, inbound) = temporary_store();
		let store = inbound.outbound().unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		// Held Passive, under its own next hop so this cannot match the Active
		// copy committed below.
		commit(
			&store,
			&held_job("a", "fidonet#1/9", None, JobKind::NetMail, 10),
		);
		let id = identity("b", &payload);
		let active = commit(&store, &new_job(id, payload.clone()));

		assert!(
			store
				.claim_scheduled(100, |copy| copy.next_hop == "fidonet#1/9")
				.unwrap()
				.is_none(),
			"a Passive copy must not be claimed by a schedule"
		);
		let claim = store
			.claim_scheduled(100, |copy| copy.class == "normal")
			.unwrap()
			.expect("the Active copy is claimable");
		assert_eq!(claim.job_id, active);
		// The predicate is what selects, so a non-matching one claims nothing.
		assert!(
			store
				.claim_scheduled(100, |copy| copy.class == "bulk")
				.unwrap()
				.is_none()
		);
		std::fs::remove_file(path).unwrap();
	}
}
