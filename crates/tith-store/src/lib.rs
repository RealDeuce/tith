//! Durable TSP-0011 inbound items backed by the pure-Rust `redb` engine.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tith_crypto::{CryptoError, PublicKey, TlvHash, hash_inbound_item, random_bytes};
use tith_wire::item::SignedItemIdentity;
use tith_wire::{tlv::parse_sequence, types};

const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("inbound-records");
const PAYLOADS: TableDefinition<&str, &[u8]> = TableDefinition::new("inbound-payloads");
const DUPLICATES: TableDefinition<&[u8], &str> = TableDefinition::new("inbound-duplicates");
const CLAIM_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbound-claim-keys");
const RESOLVED_TOKENS: TableDefinition<&str, &[u8]> =
	TableDefinition::new("inbound-resolved-tokens");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
	Message,
	File,
	FileRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemAuthentication {
	Valid,
	Invalid,
	Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundState {
	Available,
	Claimed,
	Deferred,
	Consumed,
	Rejected,
	Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewInbound<'a> {
	pub application: &'a str,
	pub local_identity: &'a str,
	pub peer: &'a str,
	pub peer_key: PublicKey,
	pub received: u64,
	pub authentication: ItemAuthentication,
	pub payload: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
	pub inbound_id: String,
	pub claim_token: String,
	pub expires: u64,
	pub record: InboundRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimResult {
	Completed(Box<Claim>),
	Empty,
	Resolved {
		inbound_id: String,
		state: InboundState,
	},
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundRecord {
	pub inbound_id: String,
	pub application: String,
	pub local_identity: String,
	pub peer: String,
	pub peer_key: PublicKey,
	pub received: u64,
	pub changed: u64,
	pub kind: ItemKind,
	pub authentication: ItemAuthentication,
	pub payload_size: u64,
	pub payload_hash: TlvHash,
	pub state: InboundState,
	pub attempts: u64,
	pub eligible_at: u64,
	pub claim_key: Option<String>,
	pub claim_token: Option<String>,
	pub claim_expires: Option<u64>,
	pub last_result: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptResult {
	Stored(Box<InboundRecord>),
	Duplicate { inbound_id: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution<'a> {
	Acknowledge,
	Release,
	Defer {
		retry_after: u64,
		description: &'a str,
	},
	Reject {
		description: &'a str,
	},
}

#[derive(Debug)]
pub enum StoreError {
	Database(redb::DatabaseError),
	Transaction(redb::TransactionError),
	Table(redb::TableError),
	Storage(redb::StorageError),
	Commit(redb::CommitError),
	Crypto(CryptoError),
	InvalidPayload,
	CorruptRecord,
	NotFound,
	Stale(InboundState),
}

impl fmt::Display for StoreError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{self:?}")
	}
}

impl std::error::Error for StoreError {}

macro_rules! from_error {
	($variant:ident, $source:ty) => {
		impl From<$source> for StoreError {
			fn from(value: $source) -> Self {
				Self::$variant(value)
			}
		}
	};
}
from_error!(Database, redb::DatabaseError);
from_error!(Transaction, redb::TransactionError);
from_error!(Table, redb::TableError);
from_error!(Storage, redb::StorageError);
from_error!(Commit, redb::CommitError);
from_error!(Crypto, CryptoError);

pub struct InboundStore {
	database: Database,
}

impl InboundStore {
	pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
		let database = Database::create(path)?;
		let write = database.begin_write()?;
		{
			write.open_table(RECORDS)?;
			write.open_table(PAYLOADS)?;
			write.open_table(DUPLICATES)?;
			write.open_table(CLAIM_KEYS)?;
			write.open_table(RESOLVED_TOKENS)?;
		}
		write.commit()?;
		Ok(Self { database })
	}

	pub fn insert(&self, value: NewInbound<'_>) -> Result<InboundRecord, StoreError> {
		match self.accept(value, None)? {
			AcceptResult::Stored(record) => Ok(*record),
			AcceptResult::Duplicate { .. } => unreachable!("no duplicate identity was supplied"),
		}
	}

	pub fn accept(
		&self,
		value: NewInbound<'_>,
		duplicate_identity: Option<&SignedItemIdentity>,
	) -> Result<AcceptResult, StoreError> {
		let parsed = parse_sequence(value.payload).map_err(|_| StoreError::InvalidPayload)?;
		if parsed.len() != 1 {
			return Err(StoreError::InvalidPayload);
		}
		let kind = match parsed[0].type_code {
			types::MESSAGE => ItemKind::Message,
			types::FILE => ItemKind::File,
			types::FILE_REQUEST => ItemKind::FileRequest,
			_ => return Err(StoreError::InvalidPayload),
		};
		if matches!(kind, ItemKind::FileRequest)
			!= matches!(value.authentication, ItemAuthentication::Transport)
		{
			return Err(StoreError::InvalidPayload);
		}
		if let Some(identity) = duplicate_identity
			&& (identity.type_code != parsed[0].type_code
				|| matches!(kind, ItemKind::FileRequest)
				|| value.authentication != ItemAuthentication::Valid)
		{
			return Err(StoreError::InvalidPayload);
		}
		let hash = hash_inbound_item(value.payload)?;
		let write = self.database.begin_write()?;
		let duplicate_key = duplicate_identity.map(encode_duplicate_identity);
		if let Some(key) = duplicate_key.as_ref() {
			let duplicates = write.open_table(DUPLICATES)?;
			if let Some(existing) = duplicates.get(key.as_slice())? {
				return Ok(AcceptResult::Duplicate {
					inbound_id: existing.value().to_owned(),
				});
			}
		}
		let id = {
			let records = write.open_table(RECORDS)?;
			loop {
				let candidate = random_identifier('I')?;
				if records.get(candidate.as_str())?.is_none() {
					break candidate;
				}
			}
		};
		let record = InboundRecord {
			inbound_id: id.clone(),
			application: value.application.to_owned(),
			local_identity: value.local_identity.to_owned(),
			peer: value.peer.to_owned(),
			peer_key: value.peer_key,
			received: value.received,
			changed: value.received,
			kind,
			authentication: value.authentication,
			payload_size: value.payload.len() as u64,
			payload_hash: hash,
			state: InboundState::Available,
			attempts: 0,
			eligible_at: value.received,
			claim_key: None,
			claim_token: None,
			claim_expires: None,
			last_result: None,
		};
		{
			let mut records = write.open_table(RECORDS)?;
			records.insert(id.as_str(), encode_record(&record).as_slice())?;
			let mut payloads = write.open_table(PAYLOADS)?;
			payloads.insert(id.as_str(), value.payload)?;
			if let Some(key) = duplicate_key.as_ref() {
				let mut duplicates = write.open_table(DUPLICATES)?;
				duplicates.insert(key.as_slice(), id.as_str())?;
			}
		}
		write.commit()?;
		Ok(AcceptResult::Stored(Box::new(record)))
	}

	pub fn refresh_expirations(&self, now: u64) -> Result<(), StoreError> {
		let write = self.database.begin_write()?;
		let mut expired_mappings = Vec::new();
		{
			let mut records = write.open_table(RECORDS)?;
			let mut expired = Vec::new();
			for entry in records.iter()? {
				let (_, value) = entry?;
				let record = decode_record(value.value())?;
				if record.state == InboundState::Claimed
					&& record.claim_expires.is_some_and(|expires| expires <= now)
				{
					expired.push(record);
				}
			}
			for mut record in expired {
				let expired_at = record.claim_expires.ok_or(StoreError::CorruptRecord)?;
				record.state = InboundState::Available;
				record.changed = expired_at;
				record.eligible_at = expired_at;
				record.claim_expires = None;
				record.last_result = Some("Available".to_owned());
				let claim_key = record.claim_key.as_ref().ok_or(StoreError::CorruptRecord)?;
				let claim_token = record
					.claim_token
					.as_ref()
					.ok_or(StoreError::CorruptRecord)?;
				expired_mappings.push((
					claim_mapping_key(&record.application, claim_key),
					claim_token.clone(),
					record.inbound_id.clone(),
				));
				records.insert(
					record.inbound_id.as_str(),
					encode_record(&record).as_slice(),
				)?;
			}
		}
		{
			let mut mappings = write.open_table(CLAIM_KEYS)?;
			for (key, token, id) in &expired_mappings {
				mappings.insert(
					key.as_slice(),
					encode_mapping(id, token, Some(InboundState::Available)).as_slice(),
				)?;
			}
		}
		{
			let mut tokens = write.open_table(RESOLVED_TOKENS)?;
			for (_, token, id) in &expired_mappings {
				tokens.insert(
					token.as_str(),
					encode_token_resolution(id, InboundState::Available, false).as_slice(),
				)?;
			}
		}
		write.commit()?;
		Ok(())
	}

	pub fn claim(
		&self,
		application: &str,
		claim_key: &str,
		now: u64,
		duration: u64,
	) -> Result<ClaimResult, StoreError> {
		if claim_key.is_empty() {
			return Err(StoreError::CorruptRecord);
		}
		self.refresh_expirations(now)?;
		let write = self.database.begin_write()?;
		let mapping_key = claim_mapping_key(application, claim_key);
		if let Some(mapped) = write.open_table(CLAIM_KEYS)?.get(mapping_key.as_slice())? {
			let mapped = decode_mapping(mapped.value())?;
			let records = write.open_table(RECORDS)?;
			let data = records
				.get(mapped.0.as_str())?
				.ok_or(StoreError::CorruptRecord)?;
			let record = decode_record(data.value())?;
			if mapped.2.is_some()
				|| record.state != InboundState::Claimed
				|| record.claim_token.as_deref() != Some(mapped.1.as_str())
				|| record.claim_expires.is_none_or(|expires| expires <= now)
			{
				return Ok(ClaimResult::Resolved {
					inbound_id: mapped.0,
					state: mapped.2.unwrap_or(record.state),
				});
			}
			return Ok(ClaimResult::Completed(Box::new(claim_from(record)?)));
		}
		let selected = {
			let records = write.open_table(RECORDS)?;
			let mut selected: Option<InboundRecord> = None;
			for entry in records.iter()? {
				let (_, value) = entry?;
				let record = decode_record(value.value())?;
				if record.application == application
					&& matches!(
						record.state,
						InboundState::Available | InboundState::Deferred
					) && record.eligible_at <= now
					&& selected.as_ref().is_none_or(|old| {
						(record.eligible_at, record.received, &record.inbound_id)
							< (old.eligible_at, old.received, &old.inbound_id)
					}) {
					selected = Some(record);
				}
			}
			selected
		};
		let Some(mut record) = selected else {
			return Ok(ClaimResult::Empty);
		};
		let token = random_identifier('C')?;
		let expires = now.checked_add(duration).ok_or(StoreError::CorruptRecord)?;
		record.state = InboundState::Claimed;
		record.changed = now;
		record.attempts = record
			.attempts
			.checked_add(1)
			.ok_or(StoreError::CorruptRecord)?;
		record.claim_key = Some(claim_key.to_owned());
		record.claim_token = Some(token.clone());
		record.claim_expires = Some(expires);
		{
			let mut records = write.open_table(RECORDS)?;
			records.insert(
				record.inbound_id.as_str(),
				encode_record(&record).as_slice(),
			)?;
			let mut mappings = write.open_table(CLAIM_KEYS)?;
			mappings.insert(
				mapping_key.as_slice(),
				encode_mapping(&record.inbound_id, &token, None).as_slice(),
			)?;
		}
		write.commit()?;
		Ok(ClaimResult::Completed(Box::new(claim_from(record)?)))
	}

	pub fn resolve(
		&self,
		application: &str,
		inbound_id: &str,
		token: &str,
		now: u64,
		resolution: Resolution<'_>,
	) -> Result<InboundState, StoreError> {
		let write = self.database.begin_write()?;
		if let Some(value) = write.open_table(RESOLVED_TOKENS)?.get(token)? {
			let (resolved_id, state, completed) = decode_token_resolution(value.value())?;
			let authorized = {
				let records = write.open_table(RECORDS)?;
				let value = records
					.get(resolved_id.as_str())?
					.ok_or(StoreError::NotFound)?;
				decode_record(value.value())?.application == application
			};
			return if !authorized {
				Err(StoreError::NotFound)
			} else if resolved_id == inbound_id && completed {
				Ok(state)
			} else {
				Err(StoreError::Stale(state))
			};
		}
		let mut record = {
			let records = write.open_table(RECORDS)?;
			let value = records.get(inbound_id)?.ok_or(StoreError::NotFound)?;
			decode_record(value.value())?
		};
		if record.application != application {
			return Err(StoreError::NotFound);
		}
		if record.state != InboundState::Claimed {
			return if record.claim_token.as_deref() == Some(token) {
				Ok(record.state)
			} else {
				Err(StoreError::Stale(record.state))
			};
		}
		if record.claim_token.as_deref() != Some(token)
			|| record.claim_expires.is_none_or(|expires| expires <= now)
		{
			return Err(StoreError::Stale(record.state));
		}
		let (state, eligible_at, result) = match resolution {
			Resolution::Acknowledge => (
				InboundState::Consumed,
				record.eligible_at,
				"Consumed".to_owned(),
			),
			Resolution::Release => (InboundState::Available, now, "Available".to_owned()),
			Resolution::Defer {
				retry_after,
				description,
			} => (InboundState::Deferred, retry_after, description.to_owned()),
			Resolution::Reject { description } => (
				InboundState::Rejected,
				record.eligible_at,
				description.to_owned(),
			),
		};
		let application = record.application.clone();
		let claim_key = record.claim_key.clone().ok_or(StoreError::CorruptRecord)?;
		record.state = state;
		record.changed = now;
		record.eligible_at = eligible_at;
		record.claim_expires = None;
		record.last_result = Some(result);
		{
			let mut records = write.open_table(RECORDS)?;
			records.insert(inbound_id, encode_record(&record).as_slice())?;
			let mut mappings = write.open_table(CLAIM_KEYS)?;
			mappings.insert(
				claim_mapping_key(&application, &claim_key).as_slice(),
				encode_mapping(inbound_id, token, Some(state)).as_slice(),
			)?;
			let mut tokens = write.open_table(RESOLVED_TOKENS)?;
			tokens.insert(
				token,
				encode_token_resolution(inbound_id, state, true).as_slice(),
			)?;
		}
		write.commit()?;
		Ok(state)
	}

	pub fn renew(
		&self,
		application: &str,
		inbound_id: &str,
		token: &str,
		now: u64,
		duration: u64,
	) -> Result<u64, StoreError> {
		let write = self.database.begin_write()?;
		let mut record = {
			let records = write.open_table(RECORDS)?;
			let value = records.get(inbound_id)?.ok_or(StoreError::NotFound)?;
			decode_record(value.value())?
		};
		if record.application != application {
			return Err(StoreError::NotFound);
		}
		if record.state != InboundState::Claimed
			|| record.claim_token.as_deref() != Some(token)
			|| record.claim_expires.is_none_or(|expires| expires <= now)
		{
			return Err(StoreError::Stale(record.state));
		}
		let expires = now.checked_add(duration).ok_or(StoreError::CorruptRecord)?;
		record.claim_expires = Some(expires);
		{
			let mut records = write.open_table(RECORDS)?;
			records.insert(inbound_id, encode_record(&record).as_slice())?;
		}
		write.commit()?;
		Ok(expires)
	}

	pub fn claimed_payload(
		&self,
		application: &str,
		inbound_id: &str,
		token: &str,
		now: u64,
	) -> Result<Vec<u8>, StoreError> {
		let read = self.database.begin_read()?;
		let records = read.open_table(RECORDS)?;
		let value = records.get(inbound_id)?.ok_or(StoreError::NotFound)?;
		let record = decode_record(value.value())?;
		if record.application != application {
			return Err(StoreError::NotFound);
		}
		if record.state != InboundState::Claimed
			|| record.claim_token.as_deref() != Some(token)
			|| record.claim_expires.is_none_or(|expires| expires <= now)
		{
			return Err(StoreError::Stale(record.state));
		}
		let payloads = read.open_table(PAYLOADS)?;
		let value = payloads.get(inbound_id)?.ok_or(StoreError::NotFound)?;
		Ok(value.value().to_vec())
	}

	pub fn query_for(
		&self,
		application: &str,
		inbound_id: &str,
	) -> Result<InboundRecord, StoreError> {
		let record = self.query(inbound_id)?;
		if record.application == application {
			Ok(record)
		} else {
			Err(StoreError::NotFound)
		}
	}

	pub fn query(&self, inbound_id: &str) -> Result<InboundRecord, StoreError> {
		let read = self.database.begin_read()?;
		let table = read.open_table(RECORDS)?;
		let value = table.get(inbound_id)?.ok_or(StoreError::NotFound)?;
		decode_record(value.value())
	}
}

fn random_identifier(prefix: char) -> Result<String, StoreError> {
	let mut bytes = [0_u8; 16];
	random_bytes(&mut bytes)?;
	let mut output = String::with_capacity(33);
	output.push(prefix);
	for byte in bytes {
		use fmt::Write as _;
		write!(output, "{byte:02x}").expect("String writes cannot fail");
	}
	Ok(output)
}

fn encode_duplicate_identity(value: &SignedItemIdentity) -> Vec<u8> {
	let mut output = Vec::new();
	put_u64(&mut output, value.type_code);
	put_string(&mut output, &value.origin.address.to_string());
	output.extend_from_slice(value.origin.public_key.as_bytes());
	output.extend_from_slice(value.signature.as_bytes());
	output
}

fn claim_from(record: InboundRecord) -> Result<Claim, StoreError> {
	Ok(Claim {
		inbound_id: record.inbound_id.clone(),
		claim_token: record
			.claim_token
			.clone()
			.ok_or(StoreError::CorruptRecord)?,
		expires: record.claim_expires.ok_or(StoreError::CorruptRecord)?,
		record,
	})
}

fn claim_mapping_key(application: &str, key: &str) -> Vec<u8> {
	let mut out = Vec::with_capacity(application.len() + key.len() + 8);
	put_bytes(&mut out, application.as_bytes());
	out.extend_from_slice(key.as_bytes());
	out
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
	out.extend_from_slice(&value.to_be_bytes());
}
fn take_u64(input: &mut &[u8]) -> Result<u64, StoreError> {
	let bytes = input.get(..8).ok_or(StoreError::CorruptRecord)?;
	*input = &input[8..];
	Ok(u64::from_be_bytes(
		bytes.try_into().expect("length checked"),
	))
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
	put_u64(out, value.len() as u64);
	out.extend_from_slice(value);
}
fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], StoreError> {
	let length = usize::try_from(take_u64(input)?).map_err(|_| StoreError::CorruptRecord)?;
	let value = input.get(..length).ok_or(StoreError::CorruptRecord)?;
	*input = &input[length..];
	Ok(value)
}
fn put_string(out: &mut Vec<u8>, value: &str) {
	put_bytes(out, value.as_bytes());
}
fn take_string(input: &mut &[u8]) -> Result<String, StoreError> {
	String::from_utf8(take_bytes(input)?.to_vec()).map_err(|_| StoreError::CorruptRecord)
}

fn encode_record(value: &InboundRecord) -> Vec<u8> {
	let mut out = Vec::new();
	for text in [
		&value.inbound_id,
		&value.application,
		&value.local_identity,
		&value.peer,
	] {
		put_string(&mut out, text);
	}
	out.extend_from_slice(value.peer_key.as_bytes());
	for number in [
		value.received,
		value.changed,
		value.payload_size,
		value.attempts,
		value.eligible_at,
	] {
		put_u64(&mut out, number);
	}
	out.push(value.kind as u8);
	out.push(value.authentication as u8);
	out.push(value.state as u8);
	out.extend_from_slice(value.payload_hash.as_bytes());
	for text in [&value.claim_key, &value.claim_token, &value.last_result] {
		match text {
			Some(value) => {
				out.push(1);
				put_string(&mut out, value);
			}
			None => out.push(0),
		}
	}
	match value.claim_expires {
		Some(value) => {
			out.push(1);
			put_u64(&mut out, value);
		}
		None => out.push(0),
	}
	out
}
fn decode_record(mut input: &[u8]) -> Result<InboundRecord, StoreError> {
	let inbound_id = take_string(&mut input)?;
	let application = take_string(&mut input)?;
	let local_identity = take_string(&mut input)?;
	let peer = take_string(&mut input)?;
	let peer_key = PublicKey::from_bytes(take_bytes_fixed::<32>(&mut input)?);
	let received = take_u64(&mut input)?;
	let changed = take_u64(&mut input)?;
	let payload_size = take_u64(&mut input)?;
	let attempts = take_u64(&mut input)?;
	let eligible_at = take_u64(&mut input)?;
	let kind = match take_byte(&mut input)? {
		0 => ItemKind::Message,
		1 => ItemKind::File,
		2 => ItemKind::FileRequest,
		_ => return Err(StoreError::CorruptRecord),
	};
	let authentication = match take_byte(&mut input)? {
		0 => ItemAuthentication::Valid,
		1 => ItemAuthentication::Invalid,
		2 => ItemAuthentication::Transport,
		_ => return Err(StoreError::CorruptRecord),
	};
	let state = decode_state(take_byte(&mut input)?)?;
	let payload_hash = TlvHash::from_bytes(take_bytes_fixed::<32>(&mut input)?);
	let claim_key = take_optional_string(&mut input)?;
	let claim_token = take_optional_string(&mut input)?;
	let last_result = take_optional_string(&mut input)?;
	let claim_expires = match take_byte(&mut input)? {
		0 => None,
		1 => Some(take_u64(&mut input)?),
		_ => return Err(StoreError::CorruptRecord),
	};
	if !input.is_empty() {
		return Err(StoreError::CorruptRecord);
	}
	Ok(InboundRecord {
		inbound_id,
		application,
		local_identity,
		peer,
		peer_key,
		received,
		changed,
		kind,
		authentication,
		payload_size,
		payload_hash,
		state,
		attempts,
		eligible_at,
		claim_key,
		claim_token,
		claim_expires,
		last_result,
	})
}
fn take_byte(input: &mut &[u8]) -> Result<u8, StoreError> {
	let value = *input.first().ok_or(StoreError::CorruptRecord)?;
	*input = &input[1..];
	Ok(value)
}
fn take_bytes_fixed<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], StoreError> {
	let value = input.get(..N).ok_or(StoreError::CorruptRecord)?;
	*input = &input[N..];
	Ok(value.try_into().expect("length checked"))
}
fn take_optional_string(input: &mut &[u8]) -> Result<Option<String>, StoreError> {
	match take_byte(input)? {
		0 => Ok(None),
		1 => Ok(Some(take_string(input)?)),
		_ => Err(StoreError::CorruptRecord),
	}
}
fn decode_state(value: u8) -> Result<InboundState, StoreError> {
	match value {
		0 => Ok(InboundState::Available),
		1 => Ok(InboundState::Claimed),
		2 => Ok(InboundState::Deferred),
		3 => Ok(InboundState::Consumed),
		4 => Ok(InboundState::Rejected),
		5 => Ok(InboundState::Failed),
		_ => Err(StoreError::CorruptRecord),
	}
}
fn encode_mapping(id: &str, token: &str, state: Option<InboundState>) -> Vec<u8> {
	let mut out = Vec::new();
	put_string(&mut out, id);
	put_string(&mut out, token);
	match state {
		Some(value) => {
			out.push(1);
			out.push(value as u8);
		}
		None => out.push(0),
	}
	out
}
fn decode_mapping(mut input: &[u8]) -> Result<(String, String, Option<InboundState>), StoreError> {
	let id = take_string(&mut input)?;
	let token = take_string(&mut input)?;
	let state = match take_byte(&mut input)? {
		0 => None,
		1 => Some(decode_state(take_byte(&mut input)?)?),
		_ => return Err(StoreError::CorruptRecord),
	};
	if !input.is_empty() {
		return Err(StoreError::CorruptRecord);
	}
	Ok((id, token, state))
}

fn encode_token_resolution(id: &str, state: InboundState, completed: bool) -> Vec<u8> {
	let mut output = Vec::new();
	put_string(&mut output, id);
	output.push(state as u8);
	output.push(u8::from(completed));
	output
}

fn decode_token_resolution(mut input: &[u8]) -> Result<(String, InboundState, bool), StoreError> {
	let id = take_string(&mut input)?;
	let state = decode_state(take_byte(&mut input)?)?;
	let completed = match take_byte(&mut input)? {
		0 => false,
		1 => true,
		_ => return Err(StoreError::CorruptRecord),
	};
	if !input.is_empty() {
		return Err(StoreError::CorruptRecord);
	}
	Ok((id, state, completed))
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::Signature;
	use tith_wire::bundle::Identity;
	use tith_wire::tlv::OwnedTlv;

	#[test]
	fn claims_are_atomic_and_idempotent() {
		let path = std::env::temp_dir().join(format!(
			"tith-store-{}.redb",
			random_identifier('T').unwrap()
		));
		let store = InboundStore::create(&path).unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let inserted = store
			.insert(NewInbound {
				application: "tosser",
				local_identity: "fidonet#1",
				peer: "fidonet#2",
				peer_key: PublicKey::from_bytes([7; 32]),
				received: 10,
				authentication: ItemAuthentication::Valid,
				payload: &payload,
			})
			.unwrap();
		let first = store.claim("tosser", "worker-1", 11, 60).unwrap();
		let ClaimResult::Completed(first) = first else {
			panic!("claim expected")
		};
		let ClaimResult::Completed(repeated) = store.claim("tosser", "worker-1", 12, 60).unwrap()
		else {
			panic!("repeat expected")
		};
		assert_eq!(first.claim_token, repeated.claim_token);
		assert_eq!(
			store
				.resolve(
					"tosser",
					&inserted.inbound_id,
					&first.claim_token,
					13,
					Resolution::Acknowledge
				)
				.unwrap(),
			InboundState::Consumed
		);
		assert!(matches!(
			store.claim("tosser", "worker-1", 14, 60).unwrap(),
			ClaimResult::Resolved {
				state: InboundState::Consumed,
				..
			}
		));
		drop(store);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn expired_and_resolved_tokens_remain_idempotent() {
		let path = std::env::temp_dir().join(format!(
			"tith-store-{}.redb",
			random_identifier('T').unwrap()
		));
		let store = InboundStore::create(&path).unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let item = store
			.insert(NewInbound {
				application: "tosser",
				local_identity: "fidonet#1",
				peer: "fidonet#2",
				peer_key: PublicKey::from_bytes([8; 32]),
				received: 1,
				authentication: ItemAuthentication::Valid,
				payload: &payload,
			})
			.unwrap();
		let ClaimResult::Completed(first) = store.claim("tosser", "first", 2, 2).unwrap() else {
			panic!("claim expected")
		};
		let ClaimResult::Completed(second) = store.claim("tosser", "second", 4, 10).unwrap() else {
			panic!("expired item should be claimable")
		};
		assert_ne!(first.claim_token, second.claim_token);
		assert!(matches!(
			store.claim("tosser", "first", 5, 10).unwrap(),
			ClaimResult::Resolved {
				state: InboundState::Available,
				..
			}
		));
		assert_eq!(
			store
				.resolve(
					"tosser",
					&item.inbound_id,
					&second.claim_token,
					5,
					Resolution::Release
				)
				.unwrap(),
			InboundState::Available
		);
		let ClaimResult::Completed(third) = store.claim("tosser", "third", 6, 10).unwrap() else {
			panic!("released item should be claimable")
		};
		assert_eq!(
			store
				.resolve(
					"tosser",
					&item.inbound_id,
					&second.claim_token,
					7,
					Resolution::Release
				)
				.unwrap(),
			InboundState::Available
		);
		assert_eq!(
			store.query(&item.inbound_id).unwrap().claim_token,
			Some(third.claim_token)
		);
		drop(store);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn signed_item_acceptance_is_durable_and_idempotent() {
		let path = std::env::temp_dir().join(format!(
			"tith-store-{}.redb",
			random_identifier('T').unwrap()
		));
		let payload = OwnedTlv::new(types::MESSAGE, b"exact item".to_vec())
			.unwrap()
			.encode();
		let identity = SignedItemIdentity {
			type_code: types::MESSAGE,
			origin: Identity {
				address: "fidonet#1/2".parse().unwrap(),
				public_key: PublicKey::from_bytes([9; 32]),
			},
			signature: Signature::from_bytes([10; 64]),
		};
		let inbound = || NewInbound {
			application: "tosser",
			local_identity: "fidonet#1/1",
			peer: "fidonet#1/2",
			peer_key: PublicKey::from_bytes([9; 32]),
			received: 10,
			authentication: ItemAuthentication::Valid,
			payload: &payload,
		};
		let stored_id = {
			let store = InboundStore::create(&path).unwrap();
			let AcceptResult::Stored(record) = store.accept(inbound(), Some(&identity)).unwrap()
			else {
				panic!("first acceptance must store the item")
			};
			record.inbound_id.clone()
		};
		let store = InboundStore::create(&path).unwrap();
		assert_eq!(
			store.accept(inbound(), Some(&identity)).unwrap(),
			AcceptResult::Duplicate {
				inbound_id: stored_id.clone()
			}
		);
		assert_eq!(
			store.query(&stored_id).unwrap().payload_hash,
			hash_inbound_item(&payload).unwrap()
		);
		drop(store);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn renewal_preserves_changed_and_claim_access_is_application_scoped() {
		let path = std::env::temp_dir().join(format!(
			"tith-store-{}.redb",
			random_identifier('T').unwrap()
		));
		let store = InboundStore::create(&path).unwrap();
		let payload = OwnedTlv::new(types::MESSAGE, Vec::new()).unwrap().encode();
		let item = store
			.insert(NewInbound {
				application: "tosser",
				local_identity: "fidonet#1",
				peer: "fidonet#2",
				peer_key: PublicKey::from_bytes([4; 32]),
				received: 10,
				authentication: ItemAuthentication::Valid,
				payload: &payload,
			})
			.unwrap();
		let ClaimResult::Completed(claim) = store.claim("tosser", "worker", 11, 60).unwrap() else {
			panic!("claim expected");
		};
		assert_eq!(
			store
				.renew("tosser", &item.inbound_id, &claim.claim_token, 12, 60)
				.unwrap(),
			72
		);
		assert_eq!(store.query(&item.inbound_id).unwrap().changed, 11);
		assert!(matches!(
			store.claimed_payload("other", &item.inbound_id, &claim.claim_token, 12),
			Err(StoreError::NotFound)
		));
		drop(store);
		std::fs::remove_file(path).unwrap();
	}
}
