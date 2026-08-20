use std::error::Error;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::ipc::{IpcService, Principal};
use crate::submission::SubmissionEngine;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

struct Endpoint {
	requests: PathBuf,
	claimed: PathBuf,
	results: PathBuf,
	acknowledgements: PathBuf,
	private: PathBuf,
}

impl Endpoint {
	fn create(root: &Path) -> Result<Self, Box<dyn Error>> {
		crate::owner_only::create_directory(root)?;
		let endpoint = Self {
			requests: root.join("requests"),
			claimed: root.join("claimed"),
			results: root.join("results"),
			acknowledgements: root.join("acknowledgements"),
			private: root.join(".service"),
		};
		for directory in [
			&endpoint.requests,
			&endpoint.claimed,
			&endpoint.results,
			&endpoint.acknowledgements,
			&endpoint.private,
		] {
			crate::owner_only::create_directory(directory)?;
		}
		Ok(endpoint)
	}
}

pub fn serve(
	root: &Path,
	database: &Path,
	exports: &Path,
	application: String,
	submission: Option<Arc<SubmissionEngine>>,
) -> Result<(), Box<dyn Error>> {
	let endpoint = Endpoint::create(root)?;
	let mut service = IpcService::create(database, exports)?;
	if let Some(submission) = submission {
		service = service.with_submission(submission);
	}
	let principal = Principal::single(format!("filesystem:{}", root.display()), application);
	loop {
		process_once(&endpoint, &service, &principal)?;
		thread::sleep(POLL_INTERVAL);
	}
}

fn process_once(
	endpoint: &Endpoint,
	service: &IpcService,
	principal: &Principal,
) -> Result<(), Box<dyn Error>> {
	cleanup_acknowledged(endpoint)?;
	for path in transaction_files(&endpoint.requests, "req")? {
		let token = token_from(&path, "req").expect("transaction_files validates names");
		let claimed = endpoint.claimed.join(format!("{token}.req"));
		match fs::hard_link(&path, &claimed) {
			Ok(()) => {
				fs::remove_file(&path)?;
				sync_directory(&endpoint.requests)?;
				sync_directory(&endpoint.claimed)?;
			}
			Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
			Err(error) => return Err(error.into()),
		}
	}
	for path in transaction_files(&endpoint.claimed, "req")? {
		let token = token_from(&path, "req").expect("transaction_files validates names");
		let result_path = endpoint.results.join(format!("{token}.rsp"));
		if result_path.exists() {
			continue;
		}
		let request = match read_stable(&path) {
			Ok(value) => value,
			Err(_) => b"TITH-IPC 1\nInvalid-Carrier\nEnd\n".to_vec(),
		};
		let response = service.process_request(&request, Some(principal));
		publish_result(endpoint, &token, &response)?;
	}
	Ok(())
}

fn cleanup_acknowledged(endpoint: &Endpoint) -> Result<(), Box<dyn Error>> {
	for path in transaction_files(&endpoint.acknowledgements, "ack")? {
		let token = token_from(&path, "ack").expect("transaction_files validates names");
		let metadata = fs::symlink_metadata(&path)?;
		if !metadata.file_type().is_file() || metadata.len() != 0 {
			continue;
		}
		for object in [
			endpoint.claimed.join(format!("{token}.req")),
			endpoint.results.join(format!("{token}.rsp")),
			path,
		] {
			match fs::remove_file(object) {
				Ok(()) => {}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(error.into()),
			}
		}
		sync_directory(&endpoint.claimed)?;
		sync_directory(&endpoint.results)?;
		sync_directory(&endpoint.acknowledgements)?;
	}
	Ok(())
}

fn transaction_files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, Box<dyn Error>> {
	let mut output = Vec::new();
	for entry in fs::read_dir(directory)? {
		let path = entry?.path();
		if token_from(&path, extension).is_some() {
			output.push(path);
		}
	}
	output.sort();
	Ok(output)
}

fn token_from(path: &Path, extension: &str) -> Option<String> {
	let name = path.file_name()?.to_str()?;
	let token = name.strip_suffix(&format!(".{extension}"))?;
	(token.len() == 32
		&& token
			.bytes()
			.all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
	.then(|| token.to_owned())
}

fn read_stable(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
	let before_link = fs::symlink_metadata(path)?;
	if !before_link.file_type().is_file() {
		return Err("request object is not a regular file".into());
	}
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(nix::libc::O_NOFOLLOW);
	let mut file = options.open(path)?;
	let before = file.metadata()?;
	let mut contents = Vec::new();
	file.read_to_end(&mut contents)?;
	let after = file.metadata()?;
	if before.len() != contents.len() as u64
		|| before.len() != after.len()
		|| before.modified().ok() != after.modified().ok()
	{
		return Err("request changed during read".into());
	}
	#[cfg(unix)]
	if before.dev() != after.dev() || before.ino() != after.ino() {
		return Err("request identity changed during read".into());
	}
	Ok(contents)
}

fn publish_result(endpoint: &Endpoint, token: &str, response: &[u8]) -> Result<(), Box<dyn Error>> {
	let temporary = endpoint.private.join(format!("{token}.rsp.tmp"));
	let published = endpoint.results.join(format!("{token}.rsp"));
	let mut options = OpenOptions::new();
	options.create_new(true).write(true);
	#[cfg(unix)]
	options.mode(0o600);
	let mut file = options.open(&temporary)?;
	file.write_all(response)?;
	file.sync_all()?;
	drop(file);
	match fs::hard_link(&temporary, &published) {
		Ok(()) => {}
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
		Err(error) => return Err(error.into()),
	}
	fs::remove_file(temporary)?;
	sync_directory(&endpoint.private)?;
	sync_directory(&endpoint.results)?;
	Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), Box<dyn Error>> {
	File::open(path)?.sync_all()?;
	Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_: &Path) -> Result<(), Box<dyn Error>> {
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::{SystemTime, UNIX_EPOCH};
	use tith_submit::{FilesystemBinding, check_capabilities};

	#[test]
	fn conforms_and_removes_an_acknowledged_result() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let root = std::env::temp_dir().join(format!("tith-files-{unique}"));
		let endpoint = Endpoint::create(&root).unwrap();
		let server_root = root.clone();
		let server = std::thread::spawn(move || {
			let service = IpcService::create(
				&server_root.join("state.redb"),
				&server_root.join("exports"),
			)
			.unwrap();
			let principal = Principal::single("files", "tosser");
			let mut published = false;
			loop {
				process_once(&endpoint, &service, &principal).unwrap();
				let result_count = transaction_files(&endpoint.results, "rsp").unwrap().len();
				if result_count != 0 {
					published = true;
				} else if published {
					break;
				}
				std::thread::sleep(Duration::from_millis(5));
			}
		});
		check_capabilities(&FilesystemBinding::new(root.clone())).unwrap();
		server.join().unwrap();
		assert!(fs::read_dir(root.join("results")).unwrap().next().is_none());
		fs::remove_dir_all(root).unwrap();
	}
}
