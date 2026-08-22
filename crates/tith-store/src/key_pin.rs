//! TSP-0015 durable non-anonymous key pins and effective-key resolution.

use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use tith_crypto::PublicKey;
use tith_wire::Address;

use crate::StoreError;

const KEY_PINS: TableDefinition<&str, &[u8]> = TableDefinition::new("listed-key-pins");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPinEvidence {
	AuthorizedInitialObservation,
	AuthenticatedContinuityProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPin {
	pub current: PublicKey,
	pub anchor: Option<PublicKey>,
	pub predecessor: Option<PublicKey>,
	pub observed: u64,
	pub evidence: KeyPinEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialObservation {
	Established(KeyPin),
	Unchanged(PublicKey),
}

impl InitialObservation {
	#[must_use]
	pub fn effective_key(self) -> PublicKey {
		match self {
			Self::Established(pin) => pin.current,
			Self::Unchanged(key) => key,
		}
	}
}

#[derive(Clone)]
pub struct KeyPinStore {
	database: Arc<Database>,
}

pub(crate) fn open_table(write: &WriteTransaction) -> Result<(), StoreError> {
	write.open_table(KEY_PINS)?;
	Ok(())
}

impl KeyPinStore {
	pub(crate) fn new(database: Arc<Database>) -> Self {
		Self { database }
	}

	pub fn get(&self, address: &Address) -> Result<Option<KeyPin>, StoreError> {
		let address = canonical_non_anonymous(address)?;
		let read = self.database.begin_read()?;
		let table = read.open_table(KEY_PINS)?;
		table
			.get(address.as_str())?
			.map(|value| decode_key_pin(value.value()))
			.transpose()
	}

	pub fn resolve(
		&self,
		address: &Address,
		authoritative_anchor: Option<PublicKey>,
	) -> Result<Option<PublicKey>, StoreError> {
		Ok(resolve(self.get(address)?, authoritative_anchor))
	}

	pub fn observe_initial(
		&self,
		address: &Address,
		key: PublicKey,
		authoritative_anchor: Option<PublicKey>,
		observed: u64,
	) -> Result<InitialObservation, StoreError> {
		let address = canonical_non_anonymous(address)?;
		let write = self.database.begin_write()?;
		let pin;
		{
			let mut table = write.open_table(KEY_PINS)?;
			let existing = table
				.get(address.as_str())?
				.map(|value| decode_key_pin(value.value()))
				.transpose()?;
			if let Some(effective) = resolve(existing, authoritative_anchor) {
				return Ok(InitialObservation::Unchanged(effective));
			}
			pin = KeyPin {
				current: key,
				anchor: None,
				predecessor: None,
				observed,
				evidence: KeyPinEvidence::AuthorizedInitialObservation,
			};
			let encoded = encode_key_pin(pin);
			table.insert(address.as_str(), encoded.as_slice())?;
		}
		write.commit()?;
		Ok(InitialObservation::Established(pin))
	}

	pub fn advance(
		&self,
		address: &Address,
		predecessor: PublicKey,
		current: PublicKey,
		authoritative_anchor: Option<PublicKey>,
		observed: u64,
	) -> Result<KeyPin, StoreError> {
		let address = canonical_non_anonymous(address)?;
		let write = self.database.begin_write()?;
		let pin;
		{
			let mut table = write.open_table(KEY_PINS)?;
			let existing = table
				.get(address.as_str())?
				.map(|value| decode_key_pin(value.value()))
				.transpose()?;
			if resolve(existing, authoritative_anchor) != Some(predecessor) {
				return Err(StoreError::InvalidPayload);
			}
			pin = KeyPin {
				current,
				anchor: authoritative_anchor.or_else(|| existing.and_then(|value| value.anchor)),
				predecessor: Some(predecessor),
				observed,
				evidence: KeyPinEvidence::AuthenticatedContinuityProof,
			};
			let encoded = encode_key_pin(pin);
			table.insert(address.as_str(), encoded.as_slice())?;
		}
		write.commit()?;
		Ok(pin)
	}
}

fn canonical_non_anonymous(address: &Address) -> Result<String, StoreError> {
	if address.is_anonymous() {
		return Err(StoreError::InvalidPayload);
	}
	Ok(address.to_string())
}

fn resolve(pin: Option<KeyPin>, anchor: Option<PublicKey>) -> Option<PublicKey> {
	match (pin, anchor) {
		(Some(pin), Some(anchor)) if pin.anchor == Some(anchor) => Some(pin.current),
		(_, Some(anchor)) => Some(anchor),
		(Some(pin), None) => Some(pin.current),
		(None, None) => None,
	}
}

fn encode_key_pin(pin: KeyPin) -> Vec<u8> {
	let mut output = Vec::with_capacity(108);
	output.push(1);
	output.push(match pin.evidence {
		KeyPinEvidence::AuthorizedInitialObservation => 0,
		KeyPinEvidence::AuthenticatedContinuityProof => 1,
	});
	output.extend_from_slice(pin.current.as_bytes());
	for key in [pin.anchor, pin.predecessor] {
		output.push(u8::from(key.is_some()));
		output.extend_from_slice(key.unwrap_or(PublicKey::from_bytes([0; 32])).as_bytes());
	}
	output.extend_from_slice(&pin.observed.to_be_bytes());
	output
}

fn decode_key_pin(value: &[u8]) -> Result<KeyPin, StoreError> {
	if value.len() != 108 || value[0] != 1 || value[34] > 1 || value[67] > 1 {
		return Err(StoreError::CorruptRecord);
	}
	let evidence = match value[1] {
		0 | 2 => KeyPinEvidence::AuthorizedInitialObservation,
		1 => KeyPinEvidence::AuthenticatedContinuityProof,
		_ => return Err(StoreError::CorruptRecord),
	};
	let current = PublicKey::from_bytes(value[2..34].try_into().unwrap());
	let anchor = (value[34] == 1).then(|| PublicKey::from_bytes(value[35..67].try_into().unwrap()));
	let predecessor =
		(value[67] == 1).then(|| PublicKey::from_bytes(value[68..100].try_into().unwrap()));
	let observed = u64::from_be_bytes(value[100..108].try_into().unwrap());
	Ok(KeyPin {
		current,
		anchor,
		predecessor,
		observed,
		evidence,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::random_bytes;

	fn address() -> Address {
		"fidonet#1/2".parse().unwrap()
	}

	fn key(value: u8) -> PublicKey {
		PublicKey::from_bytes([value; 32])
	}

	fn store() -> (KeyPinStore, std::path::PathBuf) {
		let mut suffix = [0; 16];
		random_bytes(&mut suffix).unwrap();
		let path = std::env::temp_dir().join(format!("tith-key-pin-{suffix:?}.redb"));
		let database = Arc::new(Database::create(&path).unwrap());
		let write = database.begin_write().unwrap();
		open_table(&write).unwrap();
		write.commit().unwrap();
		(KeyPinStore::new(database), path)
	}

	#[test]
	fn initial_observation_requires_an_unanchored_unpinned_non_anonymous_identity() {
		let (pins, path) = store();
		let address = address();
		assert_eq!(pins.resolve(&address, None).unwrap(), None);
		let established = pins.observe_initial(&address, key(1), None, 7).unwrap();
		assert!(matches!(established, InitialObservation::Established(_)));
		assert_eq!(established.effective_key(), key(1));
		let unchanged = pins.observe_initial(&address, key(2), None, 8).unwrap();
		assert_eq!(unchanged, InitialObservation::Unchanged(key(1)));
		assert_eq!(unchanged.effective_key(), key(1));
		let other: Address = "fidonet#1/3".parse().unwrap();
		assert_eq!(
			pins.observe_initial(&other, key(2), Some(key(3)), 9)
				.unwrap(),
			InitialObservation::Unchanged(key(3))
		);
		assert_eq!(pins.get(&other).unwrap(), None);
		let anonymous: Address = "fidonet#-1".parse().unwrap();
		assert!(pins.observe_initial(&anonymous, key(4), None, 10).is_err());
		drop(pins);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn authoritative_publication_restarts_continuity_from_its_current_key() {
		let (pins, path) = store();
		let address = address();
		pins.advance(&address, key(1), key(2), Some(key(1)), 10)
			.unwrap();
		pins.advance(&address, key(2), key(3), Some(key(1)), 11)
			.unwrap();
		assert_eq!(pins.resolve(&address, Some(key(1))).unwrap(), Some(key(3)));
		assert_eq!(pins.resolve(&address, Some(key(2))).unwrap(), Some(key(2)));
		assert!(
			pins.advance(&address, key(1), key(4), Some(key(2)), 12)
				.is_err()
		);
		assert_eq!(pins.resolve(&address, Some(key(2))).unwrap(), Some(key(2)));
		let pin = pins
			.advance(&address, key(2), key(3), Some(key(2)), 13)
			.unwrap();
		assert_eq!(pin.anchor, Some(key(2)));
		assert_eq!(pin.predecessor, Some(key(2)));
		assert_eq!(pin.evidence, KeyPinEvidence::AuthenticatedContinuityProof);
		assert_eq!(pins.resolve(&address, Some(key(2))).unwrap(), Some(key(3)));
		assert_eq!(pins.resolve(&address, Some(key(4))).unwrap(), Some(key(4)));
		drop(pins);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn an_initial_pin_and_unanchored_continuity_survive_reopening_the_service_store() {
		let (pins, path) = store();
		let address = address();
		pins.observe_initial(&address, key(1), None, 7).unwrap();
		let pin = pins.advance(&address, key(1), key(2), None, 8).unwrap();
		assert_eq!(pin.anchor, None);
		assert_eq!(pin.predecessor, Some(key(1)));
		drop(pins);

		let reopened = KeyPinStore::new(Arc::new(Database::create(&path).unwrap()));
		assert_eq!(reopened.get(&address).unwrap(), Some(pin));
		assert_eq!(reopened.resolve(&address, None).unwrap(), Some(key(2)));
		assert!(reopened.advance(&address, key(1), key(3), None, 9).is_err());
		assert_eq!(reopened.get(&address).unwrap(), Some(pin));
		drop(reopened);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn records_round_trip_and_legacy_directed_provenance_remains_initial_evidence() {
		let pin = KeyPin {
			current: key(1),
			anchor: Some(key(2)),
			predecessor: Some(key(3)),
			observed: u64::MAX,
			evidence: KeyPinEvidence::AuthenticatedContinuityProof,
		};
		assert_eq!(decode_key_pin(&encode_key_pin(pin)).unwrap(), pin);
		let mut legacy = encode_key_pin(pin);
		legacy[1] = 2;
		assert_eq!(
			decode_key_pin(&legacy).unwrap().evidence,
			KeyPinEvidence::AuthorizedInitialObservation
		);
		for index in [0, 1, 34, 67] {
			let mut corrupt = encode_key_pin(pin);
			corrupt[index] = u8::MAX;
			assert!(decode_key_pin(&corrupt).is_err());
		}
		assert!(decode_key_pin(&encode_key_pin(pin)[..107]).is_err());
	}
}
