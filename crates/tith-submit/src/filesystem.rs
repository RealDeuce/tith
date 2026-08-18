use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use tith_crypto::random_bytes;
use tith_ipc::EnvelopeKind;

use crate::{Binding, ClientError, validate};

const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub struct FilesystemBinding {
	root: PathBuf,
}

impl FilesystemBinding {
	#[must_use]
	pub const fn new(root: PathBuf) -> Self {
		Self { root }
	}
}

impl Binding for FilesystemBinding {
	fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		validate(request, EnvelopeKind::Request)?;
		let requests = self.root.join("requests");
		let claimed = self.root.join("claimed");
		let results = self.root.join("results");
		let acknowledgements = self.root.join("acknowledgements");
		for directory in [&requests, &claimed, &results, &acknowledgements] {
			if !directory.is_dir() {
				return Err(ClientError::invalid(
					"filesystem IPC endpoint is not initialized",
				));
			}
		}
		let token = unused_token(&requests, &claimed, &results, &acknowledgements)?;
		publish(&self.root, &requests, &format!("{token}.req"), request)?;
		let result_path = results.join(format!("{token}.rsp"));
		while !result_path.exists() {
			thread::sleep(POLL_INTERVAL);
		}
		let result = read_stable(&result_path)?;
		validate(&result, EnvelopeKind::Result)?;
		publish(&self.root, &acknowledgements, &format!("{token}.ack"), &[])?;
		Ok(result)
	}
}

fn unused_token(
	requests: &Path,
	claimed: &Path,
	results: &Path,
	acknowledgements: &Path,
) -> Result<String, ClientError> {
	loop {
		let mut random = [0; 16];
		random_bytes(&mut random).map_err(ClientError::new)?;
		let token = random
			.iter()
			.fold(String::with_capacity(32), |mut token, byte| {
				write!(token, "{byte:02x}").expect("String writes cannot fail");
				token
			});
		if !requests.join(format!("{token}.req")).exists()
			&& !claimed.join(format!("{token}.req")).exists()
			&& !results.join(format!("{token}.rsp")).exists()
			&& !acknowledgements.join(format!("{token}.ack")).exists()
		{
			return Ok(token);
		}
	}
}

fn publish(root: &Path, target: &Path, name: &str, contents: &[u8]) -> Result<(), ClientError> {
	let temporary = root.join(format!(".{name}.tmp"));
	let mut file = OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(&temporary)?;
	file.write_all(contents)?;
	file.sync_all()?;
	drop(file);
	if let Err(error) = fs::hard_link(&temporary, target.join(name)) {
		let _ = fs::remove_file(&temporary);
		return Err(error.into());
	}
	fs::remove_file(temporary)?;
	sync_directory(root)?;
	sync_directory(target)?;
	Ok(())
}

fn read_stable(path: &Path) -> Result<Vec<u8>, ClientError> {
	let before = fs::symlink_metadata(path)?;
	if !before.file_type().is_file() {
		return Err(ClientError::invalid(
			"filesystem IPC result is not a regular file",
		));
	}
	let mut file = OpenOptions::new().read(true).open(path)?;
	let mut contents = Vec::new();
	file.read_to_end(&mut contents)?;
	let after = file.metadata()?;
	if before.len() != contents.len() as u64
		|| before.len() != after.len()
		|| before.modified().ok() != after.modified().ok()
	{
		return Err(ClientError::invalid(
			"filesystem IPC result changed during read",
		));
	}
	Ok(contents)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ClientError> {
	fs::File::open(path)?.sync_all()?;
	Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_: &Path) -> Result<(), ClientError> {
	Ok(())
}
