use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use tith_ipc::EnvelopeKind;

use crate::{Binding, ClientError, validate};

pub struct UnixBinding {
	socket: PathBuf,
}

impl UnixBinding {
	#[must_use]
	pub const fn new(socket: PathBuf) -> Self {
		Self { socket }
	}
}

impl Binding for UnixBinding {
	fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		validate(request, EnvelopeKind::Request)?;
		let mut stream = UnixStream::connect(&self.socket)?;
		stream.write_all(request)?;
		stream.flush()?;
		let mut result = Vec::new();
		stream.read_to_end(&mut result)?;
		validate(&result, EnvelopeKind::Result)?;
		Ok(result)
	}
}
