//! Allocation of private inbound-record identifiers.

use redb::ReadableTable;

use crate::{RECORDS, StoreError, random_identifier};

pub(crate) fn allocate(write: &redb::WriteTransaction) -> Result<String, StoreError> {
	let records = write.open_table(RECORDS)?;
	loop {
		let candidate = random_identifier('I')?;
		if records.get(candidate.as_str())?.is_none() {
			return Ok(candidate);
		}
	}
}
