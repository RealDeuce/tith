//! TSP-0009 authenticated and encrypted IPC records over a byte stream.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};

use tith_crypto::{
	CryptoError, KX_PACKET_BYTES, KX_PUBLIC_KEY_BYTES, KkInitiator, KxKeyPair, KxPublicKey,
	SECRETBOX_HEADER_BYTES, SessionKeys, decrypt_ipc_line, encrypt_ipc_line, kk_respond,
};
use tith_ipc::{Document, DocumentFramer, EnvelopeKind, IpcError};
use tith_wire::integer::{IntegerError, MAX_U64_BYTES, decode_u64, encode_u64};

const GREETING: &[u8; 8] = b"TITHIPC1";

#[derive(Debug)]
pub enum TcpIpcError {
	Io(io::Error),
	Crypto(CryptoError),
	Integer(IntegerError),
	Document(IpcError),
	InvalidGreeting,
	UnknownClient,
	InvalidLine,
	LengthOverflow,
	SequenceExhausted,
}

impl fmt::Display for TcpIpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(error) => write!(f, "TCP IPC I/O error: {error}"),
			Self::Crypto(error) => write!(f, "TCP IPC cryptographic error: {error}"),
			Self::Integer(error) => write!(f, "TCP IPC record length error: {error}"),
			Self::Document(error) => write!(f, "TCP IPC document error: {error}"),
			Self::InvalidGreeting => f.write_str("invalid TCP IPC greeting"),
			Self::UnknownClient => f.write_str("unknown TCP IPC client key"),
			Self::InvalidLine => f.write_str("decrypted record is not one IPC line"),
			Self::LengthOverflow => f.write_str("TCP IPC record length is not representable"),
			Self::SequenceExhausted => f.write_str("TCP IPC record sequence is exhausted"),
		}
	}
}

impl std::error::Error for TcpIpcError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			Self::Crypto(error) => Some(error),
			Self::Integer(error) => Some(error),
			Self::Document(error) => Some(error),
			_ => None,
		}
	}
}

macro_rules! from_error {
	($variant:ident, $source:ty) => {
		impl From<$source> for TcpIpcError {
			fn from(value: $source) -> Self {
				Self::$variant(value)
			}
		}
	};
}

from_error!(Io, io::Error);
from_error!(Crypto, CryptoError);
from_error!(Integer, IntegerError);
from_error!(Document, IpcError);

pub struct SecureChannel<S> {
	stream: S,
	keys: SessionKeys,
	receive_id: Option<u64>,
	transmit_id: Option<u64>,
}

impl<S: Read + Write> SecureChannel<S> {
	pub fn connect(
		mut stream: S,
		local: &KxKeyPair,
		server: &KxPublicKey,
	) -> Result<Self, TcpIpcError> {
		let (state, packet_one) = KkInitiator::start(local, server)?;
		stream.write_all(GREETING)?;
		stream.write_all(local.public.as_bytes())?;
		stream.write_all(&packet_one)?;
		stream.flush()?;
		let mut packet_two = [0; KX_PACKET_BYTES];
		stream.read_exact(&mut packet_two)?;
		let keys = state.finish(&packet_two, local)?;
		Ok(Self::new(stream, keys))
	}

	pub fn accept<P>(
		mut stream: S,
		local: &KxKeyPair,
		authorize: impl FnOnce(&KxPublicKey) -> Option<P>,
	) -> Result<(Self, P), TcpIpcError> {
		let mut greeting = [0; GREETING.len()];
		stream.read_exact(&mut greeting)?;
		if greeting != *GREETING {
			return Err(TcpIpcError::InvalidGreeting);
		}
		let mut public_key = [0; KX_PUBLIC_KEY_BYTES];
		stream.read_exact(&mut public_key)?;
		let public_key = KxPublicKey::from_bytes(public_key);
		let principal = authorize(&public_key).ok_or(TcpIpcError::UnknownClient)?;
		let mut packet_one = [0; KX_PACKET_BYTES];
		stream.read_exact(&mut packet_one)?;
		let (keys, packet_two) = kk_respond(&packet_one, local, &public_key)?;
		stream.write_all(&packet_two)?;
		stream.flush()?;
		Ok((Self::new(stream, keys), principal))
	}

	fn new(stream: S, keys: SessionKeys) -> Self {
		Self {
			stream,
			keys,
			receive_id: Some(0),
			transmit_id: Some(0),
		}
	}

	pub fn send_line(&mut self, line: &[u8]) -> Result<(), TcpIpcError> {
		if !valid_line(line) {
			return Err(TcpIpcError::InvalidLine);
		}
		let message_id = self.transmit_id.ok_or(TcpIpcError::SequenceExhausted)?;
		let cipher = encrypt_ipc_line(line, message_id, &self.keys.transmit)?;
		let length = u64::try_from(cipher.len()).map_err(|_| TcpIpcError::LengthOverflow)?;
		self.stream.write_all(&encode_u64(length))?;
		self.stream.write_all(&cipher)?;
		self.transmit_id = message_id.checked_add(1);
		Ok(())
	}

	pub fn receive_line(&mut self) -> Result<Vec<u8>, TcpIpcError> {
		let message_id = self.receive_id.ok_or(TcpIpcError::SequenceExhausted)?;
		let length = read_length(&mut self.stream)?;
		if length <= SECRETBOX_HEADER_BYTES as u64 {
			return Err(TcpIpcError::InvalidLine);
		}
		let length = usize::try_from(length).map_err(|_| TcpIpcError::LengthOverflow)?;
		let mut cipher = vec![0; length];
		self.stream.read_exact(&mut cipher)?;
		let line = decrypt_ipc_line(&cipher, message_id, &self.keys.receive)?;
		if !valid_line(&line) {
			return Err(TcpIpcError::InvalidLine);
		}
		self.receive_id = message_id.checked_add(1);
		Ok(line)
	}

	pub fn send_document(&mut self, encoded: &[u8], kind: EnvelopeKind) -> Result<(), TcpIpcError> {
		let document = Document::parse(encoded, kind)?;
		if document.encode() != encoded {
			return Err(TcpIpcError::InvalidLine);
		}
		for line in encoded.split_inclusive(|byte| *byte == b'\n') {
			self.send_line(line)?;
		}
		self.stream.flush()?;
		Ok(())
	}

	pub fn receive_document(&mut self, kind: EnvelopeKind) -> Result<Vec<u8>, TcpIpcError> {
		let mut encoded = Vec::new();
		let mut framer = DocumentFramer::new(kind);
		loop {
			let line = self.receive_line()?;
			let complete = framer.push(&line)?;
			encoded.extend_from_slice(&line);
			if complete {
				Document::parse(&encoded, kind)?;
				return Ok(encoded);
			}
		}
	}

	pub fn flush(&mut self) -> Result<(), TcpIpcError> {
		self.stream.flush().map_err(Into::into)
	}

	#[must_use]
	pub fn into_inner(self) -> S {
		self.stream
	}
}

fn valid_line(line: &[u8]) -> bool {
	line.len() > 1 && line.last() == Some(&b'\n') && !line[..line.len() - 1].contains(&b'\n')
}

fn read_length(stream: &mut impl Read) -> Result<u64, TcpIpcError> {
	let mut encoded = [0; MAX_U64_BYTES];
	for index in 0..MAX_U64_BYTES {
		stream.read_exact(&mut encoded[index..=index])?;
		if encoded[index] & 0x80 == 0 {
			return decode_u64(&encoded[..=index]).map_err(Into::into);
		}
	}
	Err(IntegerError::Overflow.into())
}

#[cfg(test)]
mod tests {
	use std::net::{Shutdown, TcpListener, TcpStream};
	use std::thread;

	use tith_ipc::{Document, EnvelopeKind, Field, Line};

	use super::*;

	fn request() -> Vec<u8> {
		Document {
			kind: EnvelopeKind::Request,
			lines: vec![Line {
				fields: vec![Field {
					text: "Capabilities".to_owned(),
					quoted: false,
				}],
			}],
		}
		.encode()
	}

	fn result() -> Vec<u8> {
		Document {
			kind: EnvelopeKind::Result,
			lines: vec![Line {
				fields: vec![
					Field {
						text: "Capabilities".to_owned(),
						quoted: false,
					},
					Field {
						text: "Completed".to_owned(),
						quoted: false,
					},
				],
			}],
		}
		.encode()
	}

	#[test]
	fn authenticates_and_carries_encrypted_documents() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server_keys = KxKeyPair::generate().unwrap();
		let server_public = server_keys.public;
		let client_keys = KxKeyPair::generate().unwrap();
		let client_public = client_keys.public;
		let server = thread::spawn(move || {
			let (stream, _) = listener.accept().unwrap();
			let (mut channel, principal) = SecureChannel::accept(stream, &server_keys, |key| {
				(*key == client_public).then_some("tosser")
			})
			.unwrap();
			assert_eq!(principal, "tosser");
			assert_eq!(
				channel.receive_document(EnvelopeKind::Request).unwrap(),
				request()
			);
			channel
				.send_document(&result(), EnvelopeKind::Result)
				.unwrap();
		});

		let stream = TcpStream::connect(address).unwrap();
		let mut channel = SecureChannel::connect(stream, &client_keys, &server_public).unwrap();
		channel
			.send_document(&request(), EnvelopeKind::Request)
			.unwrap();
		assert_eq!(
			channel.receive_document(EnvelopeKind::Result).unwrap(),
			result()
		);
		channel.into_inner().shutdown(Shutdown::Both).unwrap();
		server.join().unwrap();
	}

	#[test]
	fn rejects_unknown_clients_without_a_response_packet() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server_keys = KxKeyPair::generate().unwrap();
		let server_public = server_keys.public;
		let client_keys = KxKeyPair::generate().unwrap();
		let server = thread::spawn(move || {
			let (stream, _) = listener.accept().unwrap();
			assert!(matches!(
				SecureChannel::accept(stream, &server_keys, |_| None::<()>),
				Err(TcpIpcError::UnknownClient)
			));
		});
		let stream = TcpStream::connect(address).unwrap();
		assert!(matches!(
			SecureChannel::connect(stream, &client_keys, &server_public),
			Err(TcpIpcError::Io(_))
		));
		server.join().unwrap();
	}

	#[test]
	fn rejects_a_noncanonical_record_length() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server_keys = KxKeyPair::generate().unwrap();
		let server_public = server_keys.public;
		let client_keys = KxKeyPair::generate().unwrap();
		let client_public = client_keys.public;
		let server = thread::spawn(move || {
			let (stream, _) = listener.accept().unwrap();
			let (mut channel, ()) = SecureChannel::accept(stream, &server_keys, |key| {
				(*key == client_public).then_some(())
			})
			.unwrap();
			assert!(matches!(
				channel.receive_line(),
				Err(TcpIpcError::Integer(IntegerError::NonCanonical))
			));
		});
		let stream = TcpStream::connect(address).unwrap();
		let channel = SecureChannel::connect(stream, &client_keys, &server_public).unwrap();
		let mut stream = channel.into_inner();
		stream.write_all(&[0x80, 0]).unwrap();
		stream.shutdown(Shutdown::Both).unwrap();
		server.join().unwrap();
	}
}
