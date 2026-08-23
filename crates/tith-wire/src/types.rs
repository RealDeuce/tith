//! Type assignments from TTS-0003, TTS-0005, and TSP-0016.

pub use crate::item_types::{
	ADDITIONAL_KLUDGE_LINE, AREA, AREA_DESCRIPTION, AREA_NAME, CONTENTS, FILENAME, FROM_USER_NAME,
	LEGACY_ATTRIBUTES, LONG_DESCRIPTION_LINE, MAGIC_WORD, MESSAGE_ID, MESSAGE_TEXT, ORIGIN_LINE,
	ORIGINAL_CHARACTER_SET, REPLACES, REPLY_TO, REQUEST_IDENTIFIER, SEEN_BY, SHORT_DESCRIPTION,
	SUBJECT, TEAR_LINE, TIMESTAMP_OFFSET, TO_USER_NAME, VIA,
};

pub const ORIGIN: u64 = 1;
pub const SIGNATURE: u64 = 2;
pub const SIGNED_DATA: u64 = 3;
pub const SIGNED_TLV: u64 = 4;
pub const TIMESTAMP: u64 = 5;
pub const DESTINATION: u64 = 6;
pub const ADDRESS: u64 = 7;
pub const PUBLIC_KEY: u64 = 8;
pub const SIGNED_ORIGIN: u64 = 9;

pub const MESSAGE: u64 = 64;
pub const FILE: u64 = 65;
pub const FILE_REQUEST: u64 = 66;
pub const REJECTED: u64 = 67;
pub const ACCEPTED: u64 = 68;
pub const POLL_MESSAGES: u64 = 69;
pub const POLL_FILES: u64 = 70;
pub const POLL_FILE_REQUESTS: u64 = 71;
pub const PUBLIC_KEY_REQUEST: u64 = 72;

pub const TLV_HASH: u64 = 99;

#[must_use]
pub const fn is_defined(type_code: u64) -> bool {
	matches!(type_code, 0..=9 | 64..=72 | 96..=99 | 101..=121)
}

#[must_use]
pub const fn is_request(type_code: u64) -> bool {
	matches!(
		type_code,
		MESSAGE
			| FILE | FILE_REQUEST
			| POLL_MESSAGES
			| POLL_FILES
			| POLL_FILE_REQUESTS
			| PUBLIC_KEY_REQUEST
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn common_assignments_are_exact_and_the_rest_of_the_range_is_reserved() {
		assert_eq!(
			[
				ORIGIN,
				SIGNATURE,
				SIGNED_DATA,
				SIGNED_TLV,
				TIMESTAMP,
				DESTINATION,
				ADDRESS,
				PUBLIC_KEY,
				SIGNED_ORIGIN,
			],
			[1, 2, 3, 4, 5, 6, 7, 8, 9]
		);
		assert!(is_defined(0));
		for reserved in 10..=31 {
			assert!(!is_defined(reserved));
		}
	}
}
