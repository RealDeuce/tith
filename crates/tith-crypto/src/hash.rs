//! TITH protocol hashes and their fixed libhydrogen contexts.

use std::mem::MaybeUninit;

use libhydrogen_sys as hydro;

use crate::signature::{initialize, operation_result};
use crate::{CryptoError, HASH_BYTES};

const HASH_TLV_CONTEXT: [u8; 8] = *b"HashTLV\0";
const INBOUND_ITEM_CONTEXT: [u8; 8] = *b"InItem1\0";
const SUBMISSION_JOB_CONTEXT: [u8; 8] = *b"SubJob1\0";
const SUBMISSION_FILE_CONTEXT: [u8; 8] = *b"SubFile\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TlvHash([u8; HASH_BYTES]);

impl TlvHash {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; HASH_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; HASH_BYTES] {
		&self.0
	}
}

pub struct TlvHasher {
	state: hydro::hydro_hash_state,
}

impl TlvHasher {
	pub fn new() -> Result<Self, CryptoError> {
		Self::with_context(HASH_TLV_CONTEXT)
	}

	fn with_context(context: [u8; 8]) -> Result<Self, CryptoError> {
		initialize()?;
		let mut state = MaybeUninit::<hydro::hydro_hash_state>::uninit();
		// SAFETY: output storage and the fixed context are valid; a null key
		// selects unkeyed hashing.
		let result = unsafe {
			hydro::hydro_hash_init(
				state.as_mut_ptr(),
				context.as_ptr().cast(),
				std::ptr::null(),
			)
		};
		operation_result(result, CryptoError::Operation)?;
		// SAFETY: a successful call initialized state.
		Ok(Self {
			state: unsafe { state.assume_init() },
		})
	}

	pub fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
		// SAFETY: both pointers remain valid for the duration of the call.
		let result = unsafe {
			hydro::hydro_hash_update(&mut self.state, bytes.as_ptr().cast(), bytes.len())
		};
		operation_result(result, CryptoError::Operation)
	}

	pub fn finish(mut self) -> Result<TlvHash, CryptoError> {
		let mut hash = [0; HASH_BYTES];
		// SAFETY: output has exactly the requested length.
		let result =
			unsafe { hydro::hydro_hash_final(&mut self.state, hash.as_mut_ptr(), hash.len()) };
		operation_result(result, CryptoError::Operation)?;
		Ok(TlvHash(hash))
	}
}

fn hash_with_context(bytes: &[u8], context: [u8; 8]) -> Result<TlvHash, CryptoError> {
	let mut hasher = TlvHasher::with_context(context)?;
	hasher.update(bytes)?;
	hasher.finish()
}

pub fn hash_tlv(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	hash_with_context(bytes, HASH_TLV_CONTEXT)
}

pub fn hash_inbound_item(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	hash_with_context(bytes, INBOUND_ITEM_CONTEXT)
}

pub fn hash_submission_job(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	hash_with_context(bytes, SUBMISSION_JOB_CONTEXT)
}

pub fn hash_submission_file(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	hash_with_context(bytes, SUBMISSION_FILE_CONTEXT)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tlv_hash_is_stream_independent() {
		let expected = hash_tlv(b"one two three").unwrap();
		let mut hasher = TlvHasher::new().unwrap();
		hasher.update(b"one ").unwrap();
		hasher.update(b"two ").unwrap();
		hasher.update(b"three").unwrap();
		assert_eq!(hasher.finish().unwrap(), expected);
	}

	#[test]
	fn protocol_hash_contexts_are_distinct() {
		let bytes = b"same bytes";
		let hashes = [
			hash_tlv(bytes).unwrap(),
			hash_inbound_item(bytes).unwrap(),
			hash_submission_job(bytes).unwrap(),
			hash_submission_file(bytes).unwrap(),
		];
		for left in 0..hashes.len() {
			for right in left + 1..hashes.len() {
				assert_ne!(hashes[left], hashes[right]);
			}
		}
	}
}
