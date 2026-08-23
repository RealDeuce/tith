//! Streaming and owned TLV codecs.

use std::fmt;
use std::io::{self, Read, Write};

use crate::integer::{IntegerError, decode_u64_prefix, encode_u64};

#[derive(Debug)]
pub enum FramingError {
	Io(io::Error),
	Integer(IntegerError),
	InvalidType,
	TruncatedValue { expected: u64, received: u64 },
	UnconsumedValue(u64),
	LengthOverflow,
}

impl fmt::Display for FramingError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(error) => write!(f, "I/O error: {error}"),
			Self::Integer(error) => write!(f, "invalid TLV integer: {error}"),
			Self::InvalidType => f.write_str("TLV type zero is invalid"),
			Self::TruncatedValue { expected, received } => {
				write!(
					f,
					"truncated TLV value: expected {expected} bytes, received {received}"
				)
			}
			Self::UnconsumedValue(remaining) => {
				write!(f, "{remaining} bytes remain in the current TLV value")
			}
			Self::LengthOverflow => f.write_str("TLV length does not fit this platform"),
		}
	}
}

impl std::error::Error for FramingError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			Self::Integer(error) => Some(error),
			_ => None,
		}
	}
}

impl From<io::Error> for FramingError {
	fn from(value: io::Error) -> Self {
		Self::Io(value)
	}
}

impl From<IntegerError> for FramingError {
	fn from(value: IntegerError) -> Self {
		Self::Integer(value)
	}
}

fn checked_capacity(length: u64, maximum: usize) -> Result<usize, FramingError> {
	if length > maximum as u64 {
		Err(FramingError::LengthOverflow)
	} else {
		Ok(usize::try_from(length).expect("length was checked against the platform maximum"))
	}
}

fn platform_capacity(length: u64) -> Result<usize, FramingError> {
	checked_capacity(length, usize::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlvHeader {
	pub type_code: u64,
	pub length: u64,
}

impl TlvHeader {
	pub fn new(type_code: u64, length: u64) -> Result<Self, FramingError> {
		if type_code == 0 {
			Err(FramingError::InvalidType)
		} else {
			Ok(Self { type_code, length })
		}
	}

	#[must_use]
	pub fn encoded_len(&self) -> usize {
		encode_u64(self.type_code).len() + encode_u64(self.length).len()
	}

	pub fn write_to(&self, writer: &mut impl Write) -> Result<(), FramingError> {
		writer.write_all(&encode_u64(self.type_code))?;
		writer.write_all(&encode_u64(self.length))?;
		Ok(())
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedTlv {
	pub type_code: u64,
	pub value: Vec<u8>,
}

impl OwnedTlv {
	pub fn new(type_code: u64, value: Vec<u8>) -> Result<Self, FramingError> {
		TlvHeader::new(type_code, value.len() as u64)?;
		Ok(Self { type_code, value })
	}

	#[must_use]
	pub fn encoded_len(&self) -> usize {
		encode_u64(self.type_code).len()
			+ encode_u64(self.value.len() as u64).len()
			+ self.value.len()
	}

	pub fn write_to(&self, writer: &mut impl Write) -> Result<(), FramingError> {
		TlvHeader::new(self.type_code, self.value.len() as u64)?.write_to(writer)?;
		writer.write_all(&self.value)?;
		Ok(())
	}

	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.encoded_len());
		self.write_to(&mut bytes).expect("Vec writes cannot fail");
		bytes
	}

	pub fn children(&self) -> Result<Vec<Self>, FramingError> {
		parse_sequence(&self.value)
	}
}

pub fn parse_sequence(mut bytes: &[u8]) -> Result<Vec<OwnedTlv>, FramingError> {
	let mut values = Vec::new();
	while !bytes.is_empty() {
		let (type_code, type_len) = decode_u64_prefix(bytes)?;
		if type_code == 0 {
			return Err(FramingError::InvalidType);
		}
		bytes = &bytes[type_len..];
		let (length, length_len) = decode_u64_prefix(bytes)?;
		bytes = &bytes[length_len..];
		let length = platform_capacity(length)?;
		if bytes.len() < length {
			return Err(FramingError::TruncatedValue {
				expected: length as u64,
				received: bytes.len() as u64,
			});
		}
		values.push(OwnedTlv {
			type_code,
			value: bytes[..length].to_vec(),
		});
		bytes = &bytes[length..];
	}
	Ok(values)
}

pub struct TlvReader<R> {
	inner: R,
	remaining: u64,
	invalid_type: bool,
}

impl<R: Read> TlvReader<R> {
	#[must_use]
	pub const fn new(inner: R) -> Self {
		Self {
			inner,
			remaining: 0,
			invalid_type: false,
		}
	}

	fn read_integer(&mut self, allow_eof: bool) -> Result<Option<u64>, FramingError> {
		let mut bytes = [0_u8; 10];
		let mut used = 0;
		while used < bytes.len() {
			match self.inner.read(&mut bytes[used..=used]) {
				Ok(0) if used == 0 && allow_eof => return Ok(None),
				Ok(0) => return Err(IntegerError::Unterminated.into()),
				Ok(_) => {}
				Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
				Err(error) => return Err(error.into()),
			}
			if bytes[used] & 0x80 == 0 {
				return decode_u64_prefix(&bytes[..=used])
					.map(|(value, _)| Some(value))
					.map_err(Into::into);
			}
			used += 1;
		}
		Err(IntegerError::Overflow.into())
	}

	pub fn read_next(&mut self) -> Result<Option<TlvValue<'_, R>>, FramingError> {
		if self.invalid_type {
			return Err(FramingError::InvalidType);
		}
		if self.remaining != 0 {
			return Err(FramingError::UnconsumedValue(self.remaining));
		}
		let Some(type_code) = self.read_integer(true)? else {
			return Ok(None);
		};
		if type_code == 0 {
			self.invalid_type = true;
			return Err(FramingError::InvalidType);
		}
		let length = self
			.read_integer(false)?
			.expect("EOF is an error when allow_eof is false");
		self.remaining = length;
		Ok(Some(TlvValue {
			header: TlvHeader { type_code, length },
			reader: self,
		}))
	}

	#[must_use]
	pub fn into_inner(self) -> R {
		self.inner
	}
}

pub struct TlvValue<'a, R> {
	header: TlvHeader,
	reader: &'a mut TlvReader<R>,
}

impl<R: Read> TlvValue<'_, R> {
	#[must_use]
	pub const fn header(&self) -> TlvHeader {
		self.header
	}

	#[must_use]
	pub const fn remaining(&self) -> u64 {
		self.reader.remaining
	}

	pub fn skip(mut self) -> Result<(), FramingError> {
		io::copy(&mut self, &mut io::sink())?;
		Ok(())
	}

	pub fn read_owned(mut self) -> Result<OwnedTlv, FramingError> {
		let capacity = platform_capacity(self.header.length)?;
		let mut value = Vec::with_capacity(capacity);
		self.read_to_end(&mut value)?;
		Ok(OwnedTlv {
			type_code: self.header.type_code,
			value,
		})
	}
}

impl<R: Read> Read for TlvValue<'_, R> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		if self.reader.remaining == 0 || buffer.is_empty() {
			return Ok(0);
		}
		let allowed = usize::try_from(self.reader.remaining.min(buffer.len() as u64))
			.expect("allowed length is bounded by buffer length");
		loop {
			match self.reader.inner.read(&mut buffer[..allowed]) {
				Ok(0) => {
					return Err(io::Error::new(
						io::ErrorKind::UnexpectedEof,
						format!("{} TLV value bytes remain", self.reader.remaining),
					));
				}
				Ok(read) => {
					self.reader.remaining -= read as u64;
					return Ok(read);
				}
				Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
				Err(error) => return Err(error),
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct Controlled<'a> {
		input: &'a [u8],
		calls: usize,
		interrupt_at: Option<usize>,
		fail_at: Option<usize>,
	}

	impl Read for Controlled<'_> {
		fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
			self.calls += 1;
			if self.interrupt_at == Some(self.calls) {
				return Err(io::ErrorKind::Interrupted.into());
			}
			if self.fail_at == Some(self.calls) {
				return Err(io::Error::other("injected read failure"));
			}
			if self.input.is_empty() || output.is_empty() {
				return Ok(0);
			}
			output[0] = self.input[0];
			self.input = &self.input[1..];
			Ok(1)
		}
	}

	fn controlled(input: &[u8]) -> Controlled<'_> {
		Controlled {
			input,
			calls: 0,
			interrupt_at: None,
			fail_at: None,
		}
	}

	#[test]
	fn owned_round_trip() {
		let value = OwnedTlv::new(64, b"hello".to_vec()).unwrap();
		assert_eq!(parse_sequence(&value.encode()).unwrap(), [value]);
	}

	#[test]
	fn streaming_requires_consumption() {
		let bytes = [1, 2, 10, 11, 2, 1, 12];
		let mut reader = TlvReader::new(bytes.as_slice());
		{
			let first = reader.read_next().unwrap().unwrap();
			assert_eq!(
				first.header(),
				TlvHeader {
					type_code: 1,
					length: 2
				}
			);
		}
		assert!(matches!(
			reader.read_next(),
			Err(FramingError::UnconsumedValue(2))
		));
	}

	#[test]
	fn streaming_handles_one_byte_reads() {
		struct OneByte<'a>(&'a [u8]);
		impl Read for OneByte<'_> {
			fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
				if self.0.is_empty() || output.is_empty() {
					return Ok(0);
				}
				output[0] = self.0[0];
				self.0 = &self.0[1..];
				Ok(1)
			}
		}

		let encoded = OwnedTlv::new(378, b"payload".to_vec()).unwrap().encode();
		let mut reader = TlvReader::new(OneByte(&encoded));
		let value = reader.read_next().unwrap().unwrap().read_owned().unwrap();
		assert_eq!(value.type_code, 378);
		assert_eq!(value.value, b"payload");
		assert!(reader.read_next().unwrap().is_none());
	}

	#[test]
	fn type_and_length_use_the_canonical_unsigned_codec() {
		let header = TlvHeader::new(378, 16_384).unwrap();
		let mut encoded = Vec::new();
		header.write_to(&mut encoded).unwrap();
		assert_eq!(encoded, [0x82, 0x7a, 0x81, 0x80, 0]);

		encoded.resize(encoded.len() + 16_384, 0);
		let mut reader = TlvReader::new(encoded.as_slice());
		let value = reader.read_next().unwrap().unwrap();
		assert_eq!(value.header(), header);
		value.skip().unwrap();
		assert!(reader.read_next().unwrap().is_none());
	}

	#[test]
	fn noncanonical_type_and_length_encodings_are_rejected() {
		for bytes in [&[0x80, 0, 0][..], &[1, 0x80, 0][..]] {
			assert!(matches!(
				parse_sequence(bytes),
				Err(FramingError::Integer(IntegerError::NonCanonical))
			));
			assert!(matches!(
				TlvReader::new(bytes).read_next(),
				Err(FramingError::Integer(IntegerError::NonCanonical))
			));
		}
	}

	#[test]
	fn type_zero_is_never_produced_and_terminates_its_sequence() {
		assert!(matches!(
			TlvHeader::new(0, 0),
			Err(FramingError::InvalidType)
		));
		assert!(matches!(
			OwnedTlv::new(0, Vec::new()),
			Err(FramingError::InvalidType)
		));

		let first = OwnedTlv::new(1, Vec::new()).unwrap().encode();
		let later = OwnedTlv::new(2, Vec::new()).unwrap().encode();
		let bytes = [first.as_slice(), &[0, 0], later.as_slice()].concat();
		assert!(matches!(
			parse_sequence(&bytes),
			Err(FramingError::InvalidType)
		));

		let mut reader = TlvReader::new(bytes.as_slice());
		reader.read_next().unwrap().unwrap().skip().unwrap();
		assert!(matches!(reader.read_next(), Err(FramingError::InvalidType)));
		assert!(matches!(reader.read_next(), Err(FramingError::InvalidType)));
		assert_eq!(reader.into_inner(), &[0, 2, 0][..]);
	}

	#[test]
	fn framing_errors_preserve_their_sources_and_diagnostics() {
		let errors = [
			FramingError::Io(io::Error::other("read")),
			FramingError::Integer(IntegerError::Overflow),
			FramingError::InvalidType,
			FramingError::TruncatedValue {
				expected: 2,
				received: 1,
			},
			FramingError::UnconsumedValue(2),
			FramingError::LengthOverflow,
		];
		for (index, error) in errors.into_iter().enumerate() {
			assert!(!error.to_string().is_empty());
			assert_eq!(std::error::Error::source(&error).is_some(), index < 2);
		}
		assert!(matches!(
			FramingError::from(io::Error::other("read")),
			FramingError::Io(_)
		));
		assert!(matches!(
			FramingError::from(IntegerError::Overflow),
			FramingError::Integer(IntegerError::Overflow)
		));
	}

	#[test]
	fn owned_and_streaming_accessors_cover_complete_values() {
		let child = OwnedTlv::new(2, b"child".to_vec()).unwrap();
		let parent = OwnedTlv::new(1, child.encode()).unwrap();
		assert_eq!(parent.children().unwrap(), [child]);

		let header = TlvHeader::new(378, 16_384).unwrap();
		assert_eq!(header.encoded_len(), 5);

		let bytes = [1, 1, 42];
		let mut reader = TlvReader::new(bytes.as_slice());
		let mut value = reader.read_next().unwrap().unwrap();
		assert_eq!(value.remaining(), 1);
		assert_eq!(value.read(&mut []).unwrap(), 0);
		assert_eq!(value.remaining(), 1);
		assert_eq!(value.read_owned().unwrap().value, [42]);
	}

	#[test]
	fn streaming_integer_and_value_io_failures_are_explicit() {
		for bytes in [&[0x80][..], &[1][..], &[0x80; 10][..]] {
			assert!(TlvReader::new(bytes).read_next().is_err());
		}

		let mut interrupted = controlled(&[1, 0]);
		interrupted.interrupt_at = Some(1);
		let mut reader = TlvReader::new(interrupted);
		reader.read_next().unwrap().unwrap().skip().unwrap();

		let mut failed = controlled(&[1, 0]);
		failed.fail_at = Some(1);
		assert!(matches!(
			TlvReader::new(failed).read_next(),
			Err(FramingError::Io(_))
		));

		let mut interrupted = controlled(&[1, 1, 42]);
		interrupted.interrupt_at = Some(3);
		let mut reader = TlvReader::new(interrupted);
		assert_eq!(
			reader
				.read_next()
				.unwrap()
				.unwrap()
				.read_owned()
				.unwrap()
				.value,
			[42]
		);

		let mut failed = controlled(&[1, 1, 42]);
		failed.fail_at = Some(3);
		let mut reader = TlvReader::new(failed);
		assert!(reader.read_next().unwrap().unwrap().read_owned().is_err());

		let mut reader = TlvReader::new(&[1, 2, 42][..]);
		let error = reader
			.read_next()
			.unwrap()
			.unwrap()
			.read_owned()
			.unwrap_err();
		assert!(matches!(
			error,
			FramingError::Io(ref error) if error.kind() == io::ErrorKind::UnexpectedEof
		));
	}

	#[test]
	fn allocation_lengths_are_checked_against_the_platform_limit() {
		assert_eq!(checked_capacity(3, 3).unwrap(), 3);
		assert!(matches!(
			checked_capacity(4, 3),
			Err(FramingError::LengthOverflow)
		));
		assert_eq!(platform_capacity(4).unwrap(), 4);
	}
}
