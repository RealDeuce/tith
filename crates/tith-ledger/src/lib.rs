//! The TSP-0013 section 2 private durable adapter ledger.
//!
//! Legacy file publication and deletion do not share a transaction with the
//! native queue, so the ledger is what bridges the two. It "MUST NOT depend on
//! a legacy pathname, directory scan order, file timestamp, Subject, or
//! disappearance alone as proof of a native IPC result".
//!
//! The recorded state and ordering must let recovery distinguish not started,
//! staged, published, acknowledged, and completed work, which is exactly the
//! [`State`] progression below. Every transition is durable before the external
//! action it authorises.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};

/// Inbound conversion records, keyed by `InboundID`.
const INBOUND: TableDefinition<&str, &[u8]> = TableDefinition::new("inbound");

/// A monotonic counter for the stable generated names section 5 requires.
const COUNTER: TableDefinition<&str, u64> = TableDefinition::new("counter");

#[derive(Debug)]
pub enum LedgerError {
	Database(String),
	/// A stored record could not be decoded.
	CorruptRecord,
}

impl fmt::Display for LedgerError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Database(message) => write!(f, "ledger database error: {message}"),
			Self::CorruptRecord => f.write_str("ledger record is corrupt"),
		}
	}
}

impl std::error::Error for LedgerError {}

macro_rules! database_error {
	($type:ty) => {
		impl From<$type> for LedgerError {
			fn from(value: $type) -> Self {
				Self::Database(value.to_string())
			}
		}
	};
}

database_error!(redb::Error);
database_error!(redb::DatabaseError);
database_error!(redb::TransactionError);
database_error!(redb::TableError);
database_error!(redb::StorageError);
database_error!(redb::CommitError);

/// How far one inbound item has progressed.
///
/// The order matters: recovery decides what to do from this alone, so a state
/// is only advanced once the action it describes is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
	/// The intended conversion and generated names are recorded, but nothing
	/// has been written to the legacy filesystem under a final name.
	Staged,
	/// Every object is durably published. TSP-0013 section 6: "An entry with
	/// published objects is never published again."
	Published,
	/// The native claim is resolved, so the mailer no longer owns the item.
	Acknowledged,
	/// The item needed no legacy object: Orphan, or a terminal refusal.
	Retired,
}

impl State {
	const fn code(self) -> u8 {
		match self {
			Self::Staged => 1,
			Self::Published => 2,
			Self::Acknowledged => 3,
			Self::Retired => 4,
		}
	}

	const fn from_code(code: u8) -> Option<Self> {
		Some(match code {
			1 => Self::Staged,
			2 => Self::Published,
			3 => Self::Acknowledged,
			4 => Self::Retired,
			_ => return None,
		})
	}
}

/// One legacy object the adapter intends to publish, or has published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
	/// The final name, generated from local identity and recorded before
	/// publication so recovery never overwrites an unrelated file.
	pub name: String,
	/// The digest of the intended contents, so recovery can tell the adapter's
	/// own object from an unrelated file which took the name.
	pub digest: u64,
}

/// The complete inbound conversion record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
	pub inbound_id: String,
	/// The native `PayloadHash`, which together with `InboundID` identifies the
	/// exact item a redelivery would repeat.
	pub payload_hash: [u8; 32],
	pub state: State,
	/// The complete intended legacy object set, in publication order.
	///
	/// Section 5 publishes every companion before the object referring to it,
	/// so this order is the publication order and the last entry is the packet.
	pub objects: Vec<Object>,
	/// The conversion policy and any diagnostic, for replay and for diagnosis.
	pub note: String,
	/// The claim token while one is current, for acknowledgement recovery.
	pub claim_token: String,
	/// The `EchoMail` or file distribution obligation, which TSP-0013 section 4
	/// requires the ledger record.
	///
	/// Empty when the item has none. Otherwise the legacy area tag, and the
	/// `JobID` of the native `Job Forward` once one is committed, so recovery can
	/// tell an obligation which is still owed from one already discharged.
	pub distribution: String,
	pub forward_job: String,
	/// Legacy pathnames the adapter still owes a removal for.
	///
	/// TSP-0013 section 3: where a legacy disposition has no exact TSP-0006
	/// mapping, "the adapter uses Copy with Keep and records its own later legacy
	/// cleanup". This is that record. It is durable before the submission which
	/// makes the removal owed, and cleared once every path is gone, so a crash in
	/// between leaves the obligation recoverable rather than forgotten.
	pub cleanup: Vec<String>,
}

pub struct Ledger {
	database: Database,
}

impl Ledger {
	/// Opens or creates the ledger.
	pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
		let database = Database::create(path)?;
		let transaction = database.begin_write()?;
		{
			transaction.open_table(INBOUND)?;
			transaction.open_table(COUNTER)?;
		}
		transaction.commit()?;
		Ok(Self { database })
	}

	/// Records the intended conversion before anything is published.
	///
	/// TSP-0013 section 4: "For a new `InboundID`, the adapter durably records the
	/// intended conversion and generated legacy names before publication."
	pub fn stage(&self, record: &Record) -> Result<(), LedgerError> {
		let transaction = self.database.begin_write()?;
		{
			let mut table = transaction.open_table(INBOUND)?;
			table.insert(record.inbound_id.as_str(), encode(record).as_slice())?;
		}
		transaction.commit()?;
		Ok(())
	}

	/// Advances an existing record to a later state.
	pub fn advance(&self, inbound_id: &str, state: State) -> Result<(), LedgerError> {
		let transaction = self.database.begin_write()?;
		{
			let mut table = transaction.open_table(INBOUND)?;
			let mut record = match table.get(inbound_id)? {
				Some(value) => decode(value.value())?,
				None => return Err(LedgerError::CorruptRecord),
			};
			record.state = state;
			table.insert(inbound_id, encode(&record).as_slice())?;
		}
		transaction.commit()?;
		Ok(())
	}

	/// Records the `JobID` of a committed native `Job Forward`.
	///
	/// Durable before the item is acknowledged, so recovery can tell a
	/// discharged distribution obligation from an outstanding one.
	pub fn record_forward(&self, inbound_id: &str, job_id: &str) -> Result<(), LedgerError> {
		self.amend(inbound_id, |record| {
			job_id.clone_into(&mut record.forward_job);
		})
	}

	/// Records the legacy pathnames the adapter still owes a removal for.
	///
	/// Called with the paths before the submission which makes them owed, and
	/// with an empty slice once every one is gone. Recovery performs whatever is
	/// left, so an interrupted run does not silently drop a removal a legacy
	/// disposition asked for.
	pub fn record_cleanup(&self, inbound_id: &str, paths: &[String]) -> Result<(), LedgerError> {
		self.amend(inbound_id, |record| {
			record.cleanup = paths.to_vec();
		})
	}

	fn amend(&self, inbound_id: &str, change: impl FnOnce(&mut Record)) -> Result<(), LedgerError> {
		let transaction = self.database.begin_write()?;
		{
			let mut table = transaction.open_table(INBOUND)?;
			let mut record = match table.get(inbound_id)? {
				Some(value) => decode(value.value())?,
				None => return Err(LedgerError::CorruptRecord),
			};
			change(&mut record);
			table.insert(inbound_id, encode(&record).as_slice())?;
		}
		transaction.commit()?;
		Ok(())
	}

	/// The record for an item, if the ledger has one.
	pub fn get(&self, inbound_id: &str) -> Result<Option<Record>, LedgerError> {
		let transaction = self.database.begin_read()?;
		let table = transaction.open_table(INBOUND)?;
		match table.get(inbound_id)? {
			Some(value) => Ok(Some(decode(value.value())?)),
			None => Ok(None),
		}
	}

	/// Every record which has not reached a terminal state.
	///
	/// TSP-0013 section 6: recovery runs before scanning for new work or
	/// claiming another item.
	pub fn unfinished(&self) -> Result<Vec<Record>, LedgerError> {
		let transaction = self.database.begin_read()?;
		let table = transaction.open_table(INBOUND)?;
		let mut records = Vec::new();
		for entry in table.iter()? {
			let (_, value) = entry?;
			let record = decode(value.value())?;
			if matches!(record.state, State::Staged | State::Published) {
				records.push(record);
			}
		}
		Ok(records)
	}

	/// Every record which still owes a legacy removal, whatever its state.
	///
	/// Unlike [`Ledger::unfinished`] this ignores State: the obligation outlives
	/// the conversion it came from, and a record which reached a terminal state
	/// with paths still listed is exactly the case recovery must not miss.
	pub fn pending_cleanup(&self) -> Result<Vec<Record>, LedgerError> {
		let transaction = self.database.begin_read()?;
		let table = transaction.open_table(INBOUND)?;
		let mut records = Vec::new();
		for entry in table.iter()? {
			let (_, value) = entry?;
			let record = decode(value.value())?;
			if !record.cleanup.is_empty() {
				records.push(record);
			}
		}
		Ok(records)
	}

	/// The next value of a monotonic counter.
	///
	/// Generated names are "stable ledger data derived from locally generated
	/// identity, not an arbitrary remote pathname".
	pub fn next_identity(&self, name: &str) -> Result<u64, LedgerError> {
		let transaction = self.database.begin_write()?;
		let value;
		{
			let mut table = transaction.open_table(COUNTER)?;
			value = table.get(name)?.map_or(1, |entry| entry.value() + 1);
			table.insert(name, value)?;
		}
		transaction.commit()?;
		Ok(value)
	}
}

fn push_string(output: &mut Vec<u8>, value: &str) {
	let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
	output.extend_from_slice(&length.to_le_bytes());
	output.extend_from_slice(&value.as_bytes()[..length as usize]);
}

fn take_string(input: &mut &[u8]) -> Option<String> {
	let length = usize::try_from(u32::from_le_bytes(take_fixed::<4>(input)?)).ok()?;
	if input.len() < length {
		return None;
	}
	let (value, rest) = input.split_at(length);
	*input = rest;
	String::from_utf8(value.to_vec()).ok()
}

fn take_fixed<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
	if input.len() < N {
		return None;
	}
	let (value, rest) = input.split_at(N);
	*input = rest;
	value.try_into().ok()
}

fn encode(record: &Record) -> Vec<u8> {
	let mut output = Vec::new();
	output.push(record.state.code());
	output.extend_from_slice(&record.payload_hash);
	push_string(&mut output, &record.inbound_id);
	push_string(&mut output, &record.note);
	push_string(&mut output, &record.claim_token);
	push_string(&mut output, &record.distribution);
	push_string(&mut output, &record.forward_job);
	let count = u32::try_from(record.objects.len()).unwrap_or(u32::MAX);
	output.extend_from_slice(&count.to_le_bytes());
	for object in record.objects.iter().take(count as usize) {
		push_string(&mut output, &object.name);
		output.extend_from_slice(&object.digest.to_le_bytes());
	}
	let count = u32::try_from(record.cleanup.len()).unwrap_or(u32::MAX);
	output.extend_from_slice(&count.to_le_bytes());
	for path in record.cleanup.iter().take(count as usize) {
		push_string(&mut output, path);
	}
	output
}

fn decode(mut input: &[u8]) -> Result<Record, LedgerError> {
	let mut read = || -> Option<Record> {
		let state = State::from_code(take_fixed::<1>(&mut input)?[0])?;
		let payload_hash = take_fixed::<32>(&mut input)?;
		let inbound_id = take_string(&mut input)?;
		let note = take_string(&mut input)?;
		let claim_token = take_string(&mut input)?;
		let distribution = take_string(&mut input)?;
		let forward_job = take_string(&mut input)?;
		let count = u32::from_le_bytes(take_fixed::<4>(&mut input)?);
		let mut objects = Vec::new();
		for _ in 0..count {
			objects.push(Object {
				name: take_string(&mut input)?,
				digest: u64::from_le_bytes(take_fixed::<8>(&mut input)?),
			});
		}
		// A record written before cleanup obligations were tracked simply ends
		// here, and reads back with none.
		let mut cleanup = Vec::new();
		if !input.is_empty() {
			let count = u32::from_le_bytes(take_fixed::<4>(&mut input)?);
			for _ in 0..count {
				cleanup.push(take_string(&mut input)?);
			}
		}
		input.is_empty().then_some(Record {
			inbound_id,
			payload_hash,
			state,
			objects,
			note,
			claim_token,
			distribution,
			forward_job,
			cleanup,
		})
	};
	read().ok_or(LedgerError::CorruptRecord)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn temporary(name: &str) -> std::path::PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-ledger-{name}-{}-{:?}.redb",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = std::fs::remove_file(&path);
		path
	}

	fn record(inbound_id: &str, state: State) -> Record {
		Record {
			inbound_id: inbound_id.to_owned(),
			payload_hash: [7; 32],
			state,
			objects: vec![
				Object {
					name: "work.zip".to_owned(),
					digest: 0x1234,
				},
				Object {
					name: "00000001.pkt".to_owned(),
					digest: 0x5678,
				},
			],
			note: "canonical".to_owned(),
			claim_token: "T1".to_owned(),
			distribution: "SYNCHRONET".to_owned(),
			forward_job: String::new(),
			cleanup: Vec::new(),
		}
	}

	#[test]
	fn a_record_round_trips_through_the_database() {
		let path = temporary("roundtrip");
		let ledger = Ledger::open(&path).unwrap();
		let value = record("I1", State::Staged);
		ledger.stage(&value).unwrap();
		assert_eq!(ledger.get("I1").unwrap().unwrap(), value);
		assert_eq!(ledger.get("absent").unwrap(), None);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn recovery_sees_staged_and_published_work_but_not_finished_work() {
		let path = temporary("recovery");
		let ledger = Ledger::open(&path).unwrap();
		ledger.stage(&record("staged", State::Staged)).unwrap();
		ledger
			.stage(&record("published", State::Published))
			.unwrap();
		ledger
			.stage(&record("acknowledged", State::Acknowledged))
			.unwrap();
		ledger.stage(&record("retired", State::Retired)).unwrap();

		let mut unfinished: Vec<String> = ledger
			.unfinished()
			.unwrap()
			.into_iter()
			.map(|record| record.inbound_id)
			.collect();
		unfinished.sort();
		assert_eq!(unfinished, ["published", "staged"]);

		ledger.advance("staged", State::Published).unwrap();
		assert_eq!(
			ledger.get("staged").unwrap().unwrap().state,
			State::Published
		);
		ledger.advance("published", State::Acknowledged).unwrap();
		assert_eq!(ledger.unfinished().unwrap().len(), 1);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_reopened_ledger_keeps_its_records_and_counter() {
		let path = temporary("reopen");
		{
			let ledger = Ledger::open(&path).unwrap();
			ledger.stage(&record("I1", State::Published)).unwrap();
			assert_eq!(ledger.next_identity("object").unwrap(), 1);
			assert_eq!(ledger.next_identity("object").unwrap(), 2);
		}
		let ledger = Ledger::open(&path).unwrap();
		assert_eq!(ledger.get("I1").unwrap().unwrap().state, State::Published);
		// The counter never repeats a value across restarts, so a generated name
		// cannot collide with one an earlier run already published.
		assert_eq!(ledger.next_identity("object").unwrap(), 3);
		assert_eq!(ledger.next_identity("other").unwrap(), 1);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_cleanup_obligation_survives_until_it_is_cleared() {
		// TSP-0013 section 3: a legacy disposition with no exact TSP-0006 mapping
		// leaves the adapter owing its own removal, and section 2 requires the
		// ledger record it rather than a pathname's disappearance.
		let path = temporary("cleanup");
		let ledger = Ledger::open(&path).unwrap();
		ledger.stage(&record("I1", State::Published)).unwrap();
		assert!(ledger.pending_cleanup().unwrap().is_empty());

		let owed = ["/tmp/a.zip".to_owned(), "/tmp/b.zip".to_owned()];
		ledger.record_cleanup("I1", &owed).unwrap();
		let pending = ledger.pending_cleanup().unwrap();
		assert_eq!(pending.len(), 1);
		assert_eq!(pending[0].cleanup, owed);

		// A terminal state does not discharge it: the obligation outlives the
		// conversion, so recovery must still find it.
		ledger.advance("I1", State::Acknowledged).unwrap();
		assert!(ledger.unfinished().unwrap().is_empty());
		assert_eq!(ledger.pending_cleanup().unwrap().len(), 1);

		ledger.record_cleanup("I1", &[]).unwrap();
		assert!(ledger.pending_cleanup().unwrap().is_empty());
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_record_written_before_cleanup_was_tracked_still_decodes() {
		// The field is appended, so an existing ledger reads back with no
		// obligation rather than as a corrupt record.
		let value = record("I1", State::Published);
		let encoded = encode(&value);
		let legacy = &encoded[..encoded.len() - 4];
		assert_eq!(decode(legacy).unwrap(), value);
	}

	#[test]
	fn a_truncated_or_overlong_record_is_corrupt() {
		let encoded = encode(&record("I1", State::Staged));
		assert!(decode(&encoded).is_ok());
		assert!(decode(&encoded[..encoded.len() - 1]).is_err());
		let mut extra = encoded;
		extra.push(0);
		assert!(decode(&extra).is_err());
		assert!(decode(&[]).is_err());
	}
}
