//! TTS-0005 Bundle type assignments.

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
	matches!(type_code, 64..=72 | TLV_HASH)
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
	fn assignments_and_request_membership_are_exact() {
		assert_eq!(
			[
				MESSAGE,
				FILE,
				FILE_REQUEST,
				REJECTED,
				ACCEPTED,
				POLL_MESSAGES,
				POLL_FILES,
				POLL_FILE_REQUESTS,
				PUBLIC_KEY_REQUEST,
				TLV_HASH,
			],
			[64, 65, 66, 67, 68, 69, 70, 71, 72, 99]
		);
		for code in 64..=72 {
			assert!(is_defined(code));
		}
		assert!(is_defined(99));
		assert!(!is_defined(63));
		assert!(!is_defined(73));
		assert!(!is_defined(98));
		assert!(!is_request(REJECTED));
		assert!(!is_request(ACCEPTED));
		assert!(!is_request(TLV_HASH));
		for code in [
			MESSAGE,
			FILE,
			FILE_REQUEST,
			POLL_MESSAGES,
			POLL_FILES,
			POLL_FILE_REQUESTS,
			PUBLIC_KEY_REQUEST,
		] {
			assert!(is_request(code));
		}
	}
}
