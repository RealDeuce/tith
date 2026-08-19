//! Binding clients for the carrier-independent TITH IPC protocol.

#![deny(unsafe_code)]

pub mod cli;
pub mod consume;
mod filesystem;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

use std::error::Error;
use std::fmt;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;

use tith_crypto::{KxKeyPair, KxPublicKey};
use tith_ipc::{Document, EnvelopeKind};
use tith_ipc_tcp::SecureChannel;

pub use filesystem::FilesystemBinding;
#[cfg(unix)]
pub use unix::UnixBinding;
#[cfg(windows)]
pub use windows::{NamedPipeBinding, current_user_sid};

#[derive(Debug)]
pub struct ClientError(String);

impl ClientError {
	pub fn new(error: impl fmt::Display) -> Self {
		Self(error.to_string())
	}

	fn invalid(message: &'static str) -> Self {
		Self(message.to_owned())
	}
}

impl fmt::Display for ClientError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl Error for ClientError {}

impl From<std::io::Error> for ClientError {
	fn from(value: std::io::Error) -> Self {
		Self::new(value)
	}
}

pub trait Binding {
	fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError>;
}

pub struct TcpBinding {
	address: SocketAddr,
	client: KxKeyPair,
	server: KxPublicKey,
}

impl TcpBinding {
	#[must_use]
	pub const fn new(address: SocketAddr, client: KxKeyPair, server: KxPublicKey) -> Self {
		Self {
			address,
			client,
			server,
		}
	}
}

impl Binding for TcpBinding {
	fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		validate(request, EnvelopeKind::Request)?;
		if !self.address.ip().is_loopback() {
			return Err(ClientError::invalid(
				"refusing to connect TCP IPC to a nonloopback address",
			));
		}
		let stream = TcpStream::connect(self.address)?;
		if !stream.peer_addr()?.ip().is_loopback() {
			return Err(ClientError::invalid("TCP IPC peer is not loopback"));
		}
		let mut channel =
			SecureChannel::connect(stream, &self.client, &self.server).map_err(ClientError::new)?;
		channel
			.send_document(request, EnvelopeKind::Request)
			.map_err(ClientError::new)?;
		let result = channel
			.receive_document(EnvelopeKind::Result)
			.map_err(ClientError::new)?;
		channel
			.into_inner()
			.shutdown(Shutdown::Both)
			.map_err(ClientError::new)?;
		validate(&result, EnvelopeKind::Result)?;
		Ok(result)
	}
}

pub enum ConfiguredBinding {
	Filesystem(FilesystemBinding),
	Tcp(TcpBinding),
	#[cfg(unix)]
	Unix(UnixBinding),
	#[cfg(windows)]
	NamedPipe(NamedPipeBinding),
}

impl Binding for ConfiguredBinding {
	fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		match self {
			Self::Filesystem(binding) => binding.transact(request),
			Self::Tcp(binding) => binding.transact(request),
			#[cfg(unix)]
			Self::Unix(binding) => binding.transact(request),
			#[cfg(windows)]
			Self::NamedPipe(binding) => binding.transact(request),
		}
	}
}

pub fn validate(input: &[u8], kind: EnvelopeKind) -> Result<Document, ClientError> {
	let document = Document::parse(input, kind).map_err(ClientError::new)?;
	if document.encode() != input {
		return Err(ClientError::invalid("IPC document is not canonical"));
	}
	Ok(document)
}

/// Runs the common minimum conformance check against any IPC binding.
pub fn check_capabilities(binding: &impl Binding) -> Result<Vec<u8>, ClientError> {
	let result = binding.transact(b"TITH-IPC 1\nCapabilities\nEnd\n")?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let completed = document.lines.first().is_some_and(|line| {
		line.fields.len() == 2
			&& !line.fields[0].quoted
			&& line.fields[0].text == "Capabilities"
			&& !line.fields[1].quoted
			&& line.fields[1].text == "Completed"
	});
	let advertised = document.lines.iter().skip(1).any(|line| {
		line.fields.len() == 2
			&& !line.fields[0].quoted
			&& line.fields[0].text == "Operation"
			&& line.fields[1].quoted
			&& line.fields[1].text == "Capabilities"
	});
	if !completed || !advertised {
		return Err(ClientError::invalid(
			"binding did not return conforming Capabilities",
		));
	}
	Ok(result)
}

#[must_use]
pub fn filesystem(root: impl Into<PathBuf>) -> ConfiguredBinding {
	ConfiguredBinding::Filesystem(FilesystemBinding::new(root.into()))
}
