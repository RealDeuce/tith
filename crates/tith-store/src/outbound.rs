use std::collections::BTreeSet;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tith_crypto::TlvHash;
use tith_wire::{tlv::parse_sequence, types};

use super::{
	StoreError, put_bytes, put_string, put_u64, random_identifier, take_byte, take_bytes,
	take_bytes_fixed, take_string, take_u64,
};

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("outbound-jobs");
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("outbound-items");
const SUBMISSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("outbound-submissions");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobKind {
	NetMail,
	EchoMail,
	File,
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
	pub mode: DeliveryMode,
	pub class: String,
	pub retry_at: Option<u64>,
	pub policies: [FailurePolicy; 5],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
	pub index: u64,
	pub local_identity: String,
	pub next_hop: String,
	pub mode: DeliveryMode,
	pub class: String,
	pub retry_at: Option<u64>,
	pub policies: [FailurePolicy; 5],
	pub state: JobState,
	pub attempts: u64,
	pub last_result: String,
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
	pub item: Vec<u8>,
	pub deliveries: Vec<NewDelivery>,
	pub sources: Vec<SourceRecord>,
	pub created: u64,
	pub forward_inbound: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundJob {
	pub job_id: String,
	pub application: String,
	pub idempotency_key: String,
	pub digest: TlvHash,
	pub kind: JobKind,
	pub target: JobTarget,
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
	New,
	Existing { job_id: String, state: JobState },
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
	Deferred { retry_at: u64, result: String },
	Rejected(String),
	Failed(String),
}

pub struct OutboundStore {
	database: Arc<Database>,
}

impl OutboundStore {
	pub(crate) fn new(database: Arc<Database>) -> Result<Self, StoreError> {
		let write = database.begin_write()?;
		{
			write.open_table(JOBS)?;
			write.open_table(ITEMS)?;
			write.open_table(SUBMISSIONS)?;
		}
		write.commit()?;
		Ok(Self { database })
	}

	pub fn commit_batch<F>(
		&self,
		identities: &[SubmissionIdentity],
		build: F,
	) -> Result<BatchCommit, StoreError>
	where
		F: FnOnce(&[SubmissionClass]) -> Result<Vec<NewOutboundJob>, StoreError>,
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
						classes.push(SubmissionClass::New);
					}
				} else {
					classes.push(SubmissionClass::New);
				}
			}
		}
		if !conflicts.is_empty() {
			return Ok(BatchCommit::Conflict(conflicts));
		}

		let new_jobs = build(&classes)?;
		let expected_new = classes
			.iter()
			.filter(|class| matches!(class, SubmissionClass::New))
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
				SubmissionClass::New => {
					let value = new_jobs.next().ok_or(StoreError::CorruptRecord)?;
					if value.identity != *identity {
						return Err(StoreError::CorruptRecord);
					}
					validate_new_job(&value)?;
					let item = value.item.clone();
					let job_id = unique_job_id(&write)?;
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
							encode_submission(&job_id, &identity.digest).as_slice(),
						)?;
					}
					outcomes.push(CommitOutcome::New {
						job_id,
						state: job.state,
					});
				}
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

	pub fn item(&self, job_id: &str) -> Result<Vec<u8>, StoreError> {
		let read = self.database.begin_read()?;
		let items = read.open_table(ITEMS)?;
		let value = items.get(job_id)?.ok_or(StoreError::NotFound)?;
		Ok(value.value().to_vec())
	}

	pub fn claim_scheduled(
		&self,
		class: &str,
		now: u64,
	) -> Result<Option<DeliveryClaim>, StoreError> {
		self.claim_matching(now, |copy| {
			copy.mode == DeliveryMode::Active && copy.class == class
		})
	}

	pub fn claim_for_poll(
		&self,
		next_hop: &str,
		now: u64,
	) -> Result<Option<DeliveryClaim>, StoreError> {
		self.claim_matching(now, |copy| copy.next_hop == next_hop)
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
			DeliveryOutcome::Rejected(result) => (JobState::Rejected, None, result),
			DeliveryOutcome::Failed(result) => (JobState::Failed, None, result),
		};
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
					job.state = aggregate_state(&job.deliveries);
					job.changed = now;
					result.clone_into(&mut job.last_result);
					changed.push(job);
				}
			}
		}
		let count = changed.len() as u64;
		{
			let mut jobs = write.open_table(JOBS)?;
			for job in changed {
				jobs.insert(job.job_id.as_str(), encode_job(&job).as_slice())?;
			}
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
			(JobKind::NetMail | JobKind::EchoMail, types::MESSAGE) | (JobKind::File, types::FILE)
		) {
		return Err(StoreError::InvalidPayload);
	}
	if matches!(value.kind, JobKind::NetMail) != matches!(value.target, JobTarget::Destination(_))
		|| (!matches!(value.kind, JobKind::NetMail) && !matches!(value.target, JobTarget::Area(_)))
		|| (value.deliveries.is_empty() && value.forward_inbound.is_none())
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

fn encode_job(value: &OutboundJob) -> Vec<u8> {
	let mut output = vec![1];
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
	output
}

fn decode_job(mut input: &[u8]) -> Result<OutboundJob, StoreError> {
	if take_byte(&mut input)? != 1 {
		return Err(StoreError::CorruptRecord);
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
		let mode = match take_byte(&mut input)? {
			0 => DeliveryMode::Active,
			1 => DeliveryMode::Passive,
			_ => return Err(StoreError::CorruptRecord),
		};
		let class = take_string(&mut input)?;
		let retry_at = take_optional_u64(&mut input)?;
		let mut policies = [FailurePolicy::default(); 5];
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
		deliveries.push(DeliveryRecord {
			index,
			local_identity,
			next_hop,
			mode,
			class,
			retry_at,
			policies,
			state: decode_job_state(take_byte(&mut input)?)?,
			attempts: take_u64(&mut input)?,
			last_result: take_string(&mut input)?,
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
			item: payload,
			deliveries: vec![NewDelivery {
				local_identity: "fidonet#1/1".to_owned(),
				next_hop: "fidonet#1/2".to_owned(),
				mode: DeliveryMode::Active,
				class: "normal".to_owned(),
				retry_at: None,
				policies: [FailurePolicy::default(); 5],
			}],
			sources: Vec::new(),
			created: 10,
			forward_inbound: None,
		}
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
			.commit_batch(std::slice::from_ref(&id), |_| {
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
			.commit_batch(std::slice::from_ref(&id), |classes| {
				assert!(matches!(classes[0], SubmissionClass::Existing { .. }));
				Ok(Vec::new())
			})
			.unwrap();
		assert!(matches!(
			repeated,
			BatchCommit::Committed(ref values)
				if matches!(values[0], CommitOutcome::Existing { .. })
		));
		let claim = store.claim_for_poll("fidonet#1/2", 11).unwrap().unwrap();
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
			.commit_batch(std::slice::from_ref(&id), |_| {
				Ok(vec![new_job(id.clone(), payload.clone())])
			})
			.unwrap();
		let other_payload = OwnedTlv::new(types::MESSAGE, vec![1]).unwrap().encode();
		let other = identity("one", &other_payload);
		let result = store
			.commit_batch(std::slice::from_ref(&other), |_| {
				panic!("conflict must be classified before source construction")
			})
			.unwrap();
		assert_eq!(result, BatchCommit::Conflict(vec![1]));
		drop(store);
		drop(inbound);
		std::fs::remove_file(path).unwrap();
	}
}
