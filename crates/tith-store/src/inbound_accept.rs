//! TTS-0005 inbound item acceptance and duplicate handling.

use redb::ReadableTable;
use tith_crypto::hash_inbound_item;
use tith_wire::item::{ItemAuthentication, SignedItemIdentity, SignedItemKind};
use tith_wire::{tlv::parse_sequence, types};

use crate::duplicate_identity::encode_duplicate_identity;
use crate::inbound_identifier;
use crate::{
	AcceptResult, DUPLICATES, InboundRecord, InboundState, InboundStore, ItemKind, NewInbound,
	PAYLOADS, RECORDS, StoreError, encode_record,
};

impl InboundStore {
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
			&& (Some(identity.kind)
				!= match kind {
					ItemKind::Message => Some(SignedItemKind::Message),
					ItemKind::File => Some(SignedItemKind::File),
					ItemKind::FileRequest => None,
				} || matches!(kind, ItemKind::FileRequest)
				|| !matches!(
					value.authentication,
					ItemAuthentication::OriginValid | ItemAuthentication::SignedOriginValid
				)) {
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
		let id = inbound_identifier::allocate(&write)?;
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
			forward_job: None,
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
}
