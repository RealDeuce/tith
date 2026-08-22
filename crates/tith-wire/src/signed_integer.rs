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
	if mapped & 1 == 0 {
		i64::try_from(mapped / 2).map_err(|_| IntegerError::Overflow)
	} else {
		let magnitude = mapped / 2 + 1;
		if magnitude == 1_u64 << 63 {
			Ok(i64::MIN)
		} else {
			Ok(-i64::try_from(magnitude).map_err(|_| IntegerError::Overflow)?)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signed_examples_and_boundaries() {
		for (value, encoded) in [(0, 0), (-1, 1), (1, 2), (-2, 3), (2, 4)] {
			assert_eq!(encode_i64(value), [encoded]);
			assert_eq!(decode_i64(&[encoded]), Ok(value));
		}
		for value in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX] {
			assert_eq!(decode_i64(&encode_i64(value)), Ok(value));
		}
	}
}
