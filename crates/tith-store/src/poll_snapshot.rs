//! Atomic TTS-0005 Poll snapshot claims.

use redb::ReadableTable;
use tith_crypto::PublicKey;

use crate::outbound::{
	DeliveryClaim, ITEMS, JOBS, JobKind, JobState, OutboundJob, OutboundStore, aggregate_state,
	append_event, decode_job, encode_job,
};
use crate::{StoreError, random_identifier};

impl OutboundStore {
	/// Claims the complete poll snapshot for one authenticated identity.
	///
	/// TTS-0005 section 3 requires all matching, unclaimed held values to be
	/// claimed in one transaction. Anonymous identities additionally match on
	/// their exact `PublicKey`. Schedules, class, mode, and retry time do not
	/// constrain an inbound Poll.
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
}
