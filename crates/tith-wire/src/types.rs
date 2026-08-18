//! Type assignments from TTS-0003 and TTS-0005.

pub const ORIGIN: u64 = 1;
pub const SIGNATURE: u64 = 2;
pub const SIGNED_DATA: u64 = 3;
pub const SIGNED_TLV: u64 = 4;
pub const TIMESTAMP: u64 = 5;
pub const DESTINATION: u64 = 6;
pub const ADDRESS: u64 = 7;
pub const PUBLIC_KEY: u64 = 8;

pub const MESSAGE: u64 = 64;
pub const FILE: u64 = 65;
pub const FILE_REQUEST: u64 = 66;
pub const REJECTED: u64 = 67;
pub const ACCEPTED: u64 = 68;
pub const POLL_MESSAGES: u64 = 69;
pub const POLL_FILES: u64 = 70;
pub const POLL_FILE_REQUESTS: u64 = 71;

pub const FILENAME: u64 = 96;
pub const CONTENTS: u64 = 97;
pub const REQUEST_IDENTIFIER: u64 = 98;
pub const TLV_HASH: u64 = 99;
pub const LEGACY_ATTRIBUTES: u64 = 101;
pub const TIMESTAMP_OFFSET: u64 = 102;
pub const TO_USER_NAME: u64 = 103;
pub const FROM_USER_NAME: u64 = 104;
pub const SUBJECT: u64 = 105;
pub const MESSAGE_TEXT: u64 = 106;
pub const AREA: u64 = 107;
pub const AREA_NAME: u64 = 108;
pub const AREA_DESCRIPTION: u64 = 109;
pub const TEAR_LINE: u64 = 110;
pub const ORIGIN_LINE: u64 = 111;
pub const SEEN_BY: u64 = 112;
pub const VIA: u64 = 113;
pub const MESSAGE_ID: u64 = 114;
pub const REPLY_TO: u64 = 115;
pub const ORIGINAL_CHARACTER_SET: u64 = 116;
pub const ADDITIONAL_KLUDGE_LINE: u64 = 117;
pub const SHORT_DESCRIPTION: u64 = 118;
pub const LONG_DESCRIPTION_LINE: u64 = 119;
pub const MAGIC_WORD: u64 = 120;
pub const REPLACES: u64 = 121;

#[must_use]
pub(crate) const fn is_defined(type_code: u64) -> bool {
	matches!(type_code, 0..=8 | 64..=71 | 96..=99 | 101..=121)
}

#[must_use]
pub const fn is_request(type_code: u64) -> bool {
	matches!(
		type_code,
		MESSAGE | FILE | FILE_REQUEST | POLL_MESSAGES | POLL_FILES | POLL_FILE_REQUESTS
	)
}
