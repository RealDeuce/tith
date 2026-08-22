//! TTS-0002 canonical unsigned integers.

use std::fmt;

pub use crate::signed_integer::{decode_i64, encode_i64};

pub const MAX_U64_BYTES: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerError {
	Empty,
	NonCanonical,
	Overflow,
	Unterminated,
	TrailingBytes,
}

impl fmt::Display for IntegerError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Empty => "empty integer",
			Self::NonCanonical => "non-canonical integer",
			Self::Overflow => "integer is outside the supported range",
			Self::Unterminated => "unterminated integer",
			Self::TrailingBytes => "bytes follow the encoded integer",
		})
	}
}

impl std::error::Error for IntegerError {}

#[must_use]
pub fn encode_u64(mut value: u64) -> Vec<u8> {
	let mut reverse = [0_u8; MAX_U64_BYTES];
	let mut used = 0;
	loop {
		reverse[used] = u8::try_from(value & 0x7f).expect("seven bits fit in u8");
		used += 1;
		value >>= 7;
		if value == 0 {
			break;
		}
	}

	let mut encoded = Vec::with_capacity(used);
	for index in (0..used).rev() {
		let continuation = if index == 0 { 0 } else { 0x80 };
		encoded.push(reverse[index] | continuation);
	}
	encoded
}

pub fn decode_u64_prefix(bytes: &[u8]) -> Result<(u64, usize), IntegerError> {
	let Some(&first) = bytes.first() else {
		return Err(IntegerError::Empty);
	};
	if first == 0x80 {
		return Err(IntegerError::NonCanonical);
	}

	let mut value = 0_u64;
	for (index, byte) in bytes.iter().copied().enumerate() {
		value = value.checked_mul(128).ok_or(IntegerError::Overflow)?;
		value += u64::from(byte & 0x7f);
		if byte & 0x80 == 0 {
			return Ok((value, index + 1));
		}
	}
	Err(IntegerError::Unterminated)
}

pub fn decode_u64(bytes: &[u8]) -> Result<u64, IntegerError> {
	let (value, used) = decode_u64_prefix(bytes)?;
	if used == bytes.len() {
		Ok(value)
	} else {
		Err(IntegerError::TrailingBytes)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unsigned_examples_and_supported_boundaries() {
		assert_eq!(encode_u64(0), [0]);
		assert_eq!(encode_u64(127), [0x7f]);
		assert_eq!(encode_u64(128), [0x81, 0]);
		assert_eq!(encode_u64(378), [130, 122]);
		assert_eq!(encode_u64(16_383), [0xff, 0x7f]);
		assert_eq!(encode_u64(16_384), [0x81, 0x80, 0]);
		assert_eq!(
			encode_u64(u64::from(u32::MAX)),
			[0x8f, 0xff, 0xff, 0xff, 0x7f]
		);
		assert_eq!(
			encode_u64(i64::MAX.cast_unsigned()),
			[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
		);
		assert_eq!(
			encode_u64(u64::MAX),
			[0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
		);
		for value in [u64::from(u32::MAX), i64::MAX.cast_unsigned(), u64::MAX] {
			assert_eq!(decode_u64(&encode_u64(value)), Ok(value));
		}
	}

	#[test]
	fn every_seven_bit_width_transition_is_canonical() {
		for groups in 1..=9 {
			let bit = groups * 7;
			let lower_max = (1_u64 << bit) - 1;
			let upper_min = 1_u64 << bit;
			assert_eq!(encode_u64(lower_max).len(), groups);
			assert_eq!(encode_u64(upper_min).len(), groups + 1);
			assert_eq!(decode_u64(&encode_u64(lower_max)), Ok(lower_max));
			assert_eq!(decode_u64(&encode_u64(upper_min)), Ok(upper_min));
		}

		for value in 0..=u64::from(u16::MAX) {
			let encoded = encode_u64(value);
			assert_ne!(encoded.first(), Some(&0x80));
			assert_eq!(decode_u64(&encoded), Ok(value));
		}
	}

	#[test]
	fn prefix_and_complete_decoding_have_explicit_boundaries() {
		assert_eq!(decode_u64_prefix(&[]), Err(IntegerError::Empty));
		assert_eq!(decode_u64(&[]), Err(IntegerError::Empty));
		assert_eq!(decode_u64_prefix(&[0x82, 0x7a, 0]), Ok((378, 2)));
		assert_eq!(decode_u64(&[0x82, 0x7a]), Ok(378));
		assert_eq!(
			decode_u64(&[0x82, 0x7a, 0]),
			Err(IntegerError::TrailingBytes)
		);
	}

	#[test]
	fn rejects_noncanonical_unterminated_and_overflow() {
		assert_eq!(decode_u64(&[0x80]), Err(IntegerError::NonCanonical));
		assert_eq!(decode_u64(&[0x80, 0]), Err(IntegerError::NonCanonical));
		assert_eq!(decode_u64(&[0x81]), Err(IntegerError::Unterminated));
		assert_eq!(
			decode_u64(&[0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]),
			Err(IntegerError::Unterminated)
		);
		assert_eq!(
			decode_u64(&[0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0]),
			Err(IntegerError::Overflow)
		);
	}

	#[test]
	fn every_error_has_a_distinct_description() {
		for (error, message) in [
			(IntegerError::Empty, "empty integer"),
			(IntegerError::NonCanonical, "non-canonical integer"),
			(
				IntegerError::Overflow,
				"integer is outside the supported range",
			),
			(IntegerError::Unterminated, "unterminated integer"),
			(
				IntegerError::TrailingBytes,
				"bytes follow the encoded integer",
			),
		] {
			assert_eq!(error.to_string(), message);
		}
	}
}
