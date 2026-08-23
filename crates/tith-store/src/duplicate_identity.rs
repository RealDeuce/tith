//! Durable TTS-0005 signed-item duplicate identities.

use tith_wire::item::{SignedItemIdentity, SignedItemKind};
use tith_wire::types;

use super::{DUPLICATES, InboundStore, StoreError, put_string, put_u64};

pub(crate) fn encode_duplicate_identity(value: &SignedItemIdentity) -> Vec<u8> {
	let mut output = Vec::new();
	put_u64(
		&mut output,
		match value.kind {
			SignedItemKind::Message => types::MESSAGE,
			SignedItemKind::File => types::FILE,
		},
	);
	put_string(&mut output, &value.signer.address.to_string());
	output.extend_from_slice(value.signer.public_key.as_bytes());
	output.extend_from_slice(value.signature.as_bytes());
	output
}

impl InboundStore {
	/// Removes the durable duplicate association for one authenticated item.
	///
	/// This is an explicit administrative operation. It does not remove or
	/// mutate the stored inbound record which the association previously named.
	pub fn remove_duplicate_identity(
		&self,
		identity: &SignedItemIdentity,
	) -> Result<bool, StoreError> {
		let key = encode_duplicate_identity(identity);
		let write = self.database.begin_write()?;
		let removed = {
			let mut duplicates = write.open_table(DUPLICATES)?;
			duplicates.remove(key.as_slice())?.is_some()
		};
		write.commit()?;
		Ok(removed)
	}
}
