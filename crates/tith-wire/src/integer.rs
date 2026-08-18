//! TTS-0002 and TTS-0007 canonical integers.

use std::fmt;

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
		value = value
			.checked_add(u64::from(byte & 0x7f))
			.ok_or(IntegerError::Overflow)?;
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
	fn unsigned_examples_and_boundaries() {
		assert_eq!(encode_u64(0), [0]);
		assert_eq!(encode_u64(127), [0x7f]);
		assert_eq!(encode_u64(128), [0x81, 0]);
		assert_eq!(encode_u64(378), [130, 122]);
		assert_eq!(decode_u64(&encode_u64(u64::MAX)), Ok(u64::MAX));
	}

	#[test]
	fn rejects_noncanonical_and_overflow() {
		assert_eq!(decode_u64(&[0x80, 0]), Err(IntegerError::NonCanonical));
		assert_eq!(decode_u64(&[0x81]), Err(IntegerError::Unterminated));
		assert_eq!(
			decode_u64(&[
				0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0
			]),
			Err(IntegerError::Overflow)
		);
	}

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
