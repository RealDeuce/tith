//! TTS-0007 canonical signed integers.

use crate::integer::{IntegerError, decode_u64, encode_u64};

#[must_use]
pub fn encode_i64(value: i64) -> Vec<u8> {
	let mapped = if value >= 0 {
		value.cast_unsigned() * 2
	} else {
		(value.unsigned_abs() - 1) * 2 + 1
	};
	encode_u64(mapped)
}

pub fn decode_i64(bytes: &[u8]) -> Result<i64, IntegerError> {
	let mapped = decode_u64(bytes)?;
	// Dividing any u64 by two produces a value no greater than i64::MAX.
	let half = (mapped / 2).cast_signed();
	if mapped & 1 == 0 {
		Ok(half)
	} else {
		Ok(-half - 1)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signed_examples_and_supported_boundaries() {
		for (value, encoded) in [(0, 0), (-1, 1), (1, 2), (-2, 3), (2, 4)] {
			assert_eq!(encode_i64(value), [encoded]);
			assert_eq!(decode_i64(&[encoded]), Ok(value));
		}
		let signed_63_min = -(1_i64 << 62);
		let signed_63_max = (1_i64 << 62) - 1;
		for value in [
			i64::MIN,
			i64::MIN + 1,
			i64::from(i32::MIN),
			signed_63_min,
			-1,
			0,
			1,
			i64::from(i32::MAX),
			signed_63_max,
			i64::MAX,
		] {
			assert_eq!(decode_i64(&encode_i64(value)), Ok(value));
		}
		assert_eq!(encode_i64(i64::MIN), encode_u64(u64::MAX));
		assert_eq!(encode_i64(i64::MAX), encode_u64(u64::MAX - 1));
		assert_ne!(encode_i64(0), encode_i64(-1));
	}

	#[test]
	fn every_mapped_width_transition_is_canonical() {
		for value in i16::MIN..=i16::MAX {
			let value = i64::from(value);
			assert_eq!(decode_i64(&encode_i64(value)), Ok(value));
		}

		for groups in 1..=9 {
			let bit = groups * 7;
			for mapped in [(1_u64 << bit) - 1, 1_u64 << bit] {
				let value = if mapped & 1 == 0 {
					(mapped / 2).cast_signed()
				} else {
					-(mapped / 2).cast_signed() - 1
				};
				let encoded = encode_u64(mapped);
				assert_eq!(encode_i64(value), encoded);
				assert_eq!(decode_i64(&encoded), Ok(value));
			}
		}
	}

	#[test]
	fn rejects_every_invalid_unsigned_encoding() {
		assert_eq!(decode_i64(&[]), Err(IntegerError::Empty));
		assert_eq!(decode_i64(&[0x80]), Err(IntegerError::NonCanonical));
		assert_eq!(decode_i64(&[0x81]), Err(IntegerError::Unterminated));
		assert_eq!(decode_i64(&[0, 0]), Err(IntegerError::TrailingBytes));
		assert_eq!(
			decode_i64(&[0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0]),
			Err(IntegerError::Overflow)
		);
	}
}
