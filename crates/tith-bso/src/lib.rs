//! Binkley Style Outbound reading, per FTS-5005.003.
//!
//! This is a legacy conversion boundary and does not depend on the native
//! protocol layer. It resolves the outbound layout, classifies flow files,
//! reads reference files, and owns the `.bsy` and `.hld` control files.
//!
//! Consuming an outbound is not a read-only activity: the caller deletes
//! packets and rewrites reference files once their contents are committed,
//! which is exactly why section 5.1 makes `.bsy` REQUIRED.

#![forbid(unsafe_code)]

mod layout;

use std::fs::{self, File, TryLockError};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tith_message_legacy::{Attachment, Disposition};

pub use layout::{Flavour, FlowFile, FlowKind, NodeAddress, Outbound, classify_extension};

/// One line of a reference file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
	/// The filename with its directive removed.
	pub name: String,
	/// What the sender asked to happen after a successful transfer.
	pub disposition: Disposition,
	/// The exact original line, so an unconsumed entry can be written back
	/// byte for byte.
	pub line: String,
}

impl Reference {
	/// The path this entry names, resolved against the flow file's directory
	/// when it carries no path of its own.
	///
	/// FTS-5005 section 3.1 leaves a bare name implementation dependent and
	/// recommends full paths; resolving beside the flow file matches `BinkIT`.
	#[must_use]
	pub fn resolve(&self, beside: &Path) -> PathBuf {
		let path = Path::new(&self.name);
		if path.is_absolute() {
			path.to_path_buf()
		} else {
			beside.join(path)
		}
	}
}

/// Parses a reference file.
///
/// Directives are the FTS-5005 section 3.1 set, which is the same grammar the
/// Subject `FileList` uses, so the classification lives in one place.
/// A `~` or `!` line is already processed and is skipped, but its exact text is
/// preserved so rewriting the file does not disturb it.
#[must_use]
pub fn parse_reference(contents: &str) -> Vec<Reference> {
	contents
		.lines()
		.filter_map(|raw| {
			let line = raw.trim_end_matches('\r');
			if line.is_empty() {
				return None;
			}
			let (disposition, name) = match line.as_bytes()[0] {
				b'#' => (Disposition::Truncate, &line[1..]),
				b'^' | b'-' => (Disposition::Delete, &line[1..]),
				b'~' | b'!' => return None,
				b'@' => (Disposition::Keep, &line[1..]),
				_ => (Disposition::Keep, line),
			};
			(!name.is_empty()).then(|| Reference {
				name: name.to_owned(),
				disposition,
				line: line.to_owned(),
			})
		})
		.collect()
}

/// Converts a reference into the attachment shape the submission builder takes.
#[must_use]
pub fn as_attachment(reference: &Reference) -> Attachment {
	Attachment {
		name: reference.name.clone(),
		disposition: reference.disposition,
	}
}

/// One action from an FTS-0006.002 request list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
	pub filename: String,
	/// A plus time, which asks for the file only if it is newer than this.
	pub newer_than: Option<u64>,
	/// The exact original line, so an action with no TITH representation can be
	/// written back byte for byte.
	pub line: String,
	/// True when the line has no exact TITH representation and must be retained.
	///
	/// TSP-0003 section 8: a minus time asks for files at or older than a
	/// timestamp, and TTS-0005 has no request for that.
	pub unsupported: bool,
}

/// Parses a request list, per TSP-0003 section 8.
///
/// "Import accepts CR, LF, or CRLF line endings. Each nonempty line is split
/// into Filename, an optional `!password`, and an optional signed decimal update
/// time in that order." The password may be checked by legacy link policy but is
/// never carried into TITH, so it is dropped here rather than returned.
#[must_use]
pub fn parse_request(contents: &str) -> Vec<Request> {
	contents
		.split(['\r', '\n'])
		.filter_map(|raw| {
			let line = raw.trim();
			if line.is_empty() {
				return None;
			}
			let mut fields = line.split_whitespace();
			let filename = fields.next()?;
			let mut newer_than = None;
			let mut unsupported = false;
			let mut password_seen = false;
			let mut condition_seen = false;
			for field in fields {
				if let Some(password) = field.strip_prefix('!') {
					// A legacy transaction password. It is not transmitted, stored as
					// a TITH credential, or treated as native authority.
					if password.is_empty() || password_seen || condition_seen {
						unsupported = true;
					}
					password_seen = true;
					continue;
				}
				let (newer, value) = if let Some(value) = field.strip_prefix('+') {
					(true, value)
				} else if let Some(value) = field.strip_prefix('-') {
					(false, value)
				} else {
					unsupported = true;
					continue;
				};
				if condition_seen || value.is_empty() {
					unsupported = true;
				}
				condition_seen = true;
				match value.parse::<u64>() {
					Ok(value) if newer => newer_than = Some(value),
					Ok(_) => {
						// A minus time has no exact TITH representation.
						unsupported = true;
					}
					Err(_) => unsupported = true,
				}
			}
			// The filename restrictions are the ones section 8 states for canonical
			// output; a path component would also fail TTS-0005 type 96.
			if filename.contains(['/', '\\', '\0']) || filename.starts_with(['+', '-', '!']) {
				unsupported = true;
			}
			Some(Request {
				filename: filename.to_owned(),
				newer_than,
				line: line.to_owned(),
				unsupported,
			})
		})
		.collect()
}

/// Rewrites a request list without the submitted actions.
///
/// The same rule the reference files use: the file is deleted when nothing is
/// left, and an action which was not submitted is written back exactly as it
/// arrived.
pub fn rewrite_request(path: &Path, keep: &[String]) -> io::Result<()> {
	rewrite_reference(path, keep)
}

static BUSY_OWNER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A held `.bsy` lock. Dropping it removes the file if this guard still owns it.
#[derive(Debug)]
pub struct BusyLock {
	path: PathBuf,
	file: File,
	owner: Vec<u8>,
	remove_on_drop: bool,
}

impl BusyLock {
	/// Takes the lock, or reports that another program holds it.
	///
	/// Created with `create_new`, which is the `O_EXCL` that section 5.1's own
	/// note about `fopen` quietly overwriting is asking for. A lock older than
	/// `stale_after` is reclaimed in place: section 5.1 recommends ignoring and
	/// deleting a bsy older than twice the maximum session time. Keeping an
	/// exclusive OS lock on the file serializes our stale reclaimers without
	/// weakening the existence-based convention used by other BSO programs.
	pub fn take(path: PathBuf, stale_after: Duration) -> io::Result<Option<Self>> {
		let owner = Self::owner_record();
		for _ in 0..4 {
			match fs::OpenOptions::new()
				.create_new(true)
				.read(true)
				.write(true)
				.open(&path)
			{
				Ok(mut file) => {
					file.try_lock().map_err(|error| match error {
						TryLockError::WouldBlock => {
							io::Error::other("new BSO busy file was unexpectedly locked")
						}
						TryLockError::Error(error) => error,
					})?;
					if let Err(error) = Self::write_owner(&mut file, &owner) {
						let _ = fs::remove_file(&path);
						return Err(error);
					}
					return Ok(Some(Self {
						path,
						file,
						owner,
						remove_on_drop: true,
					}));
				}
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => return Err(error),
			}

			let mut file = match fs::OpenOptions::new().read(true).write(true).open(&path) {
				Ok(file) => file,
				Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
				Err(error) => return Err(error),
			};
			if !Self::is_stale(&file, stale_after)? {
				return Ok(None);
			}
			match file.try_lock() {
				Ok(()) => {}
				Err(TryLockError::WouldBlock) => return Ok(None),
				Err(TryLockError::Error(error)) => return Err(error),
			}
			// The owner may have refreshed the file before releasing its lock.
			if !Self::is_stale(&file, stale_after)? {
				return Ok(None);
			}
			Self::write_owner(&mut file, &owner)?;
			// The former owner could have removed this open file immediately before
			// we acquired its lock. Do not claim a replacement at the same path.
			if fs::read(&path).ok().as_deref() != Some(owner.as_slice()) {
				return Ok(None);
			}
			return Ok(Some(Self {
				path,
				file,
				owner,
				remove_on_drop: true,
			}));
		}
		Ok(None)
	}

	fn owner_record() -> Vec<u8> {
		let sequence = BUSY_OWNER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
		let nanos = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_or(0, |duration| duration.as_nanos());
		// FTS-5005 section 5.1 permits one line of PID information under 70 bytes.
		format!(
			"tith bso scan pid {} {nanos:x} {sequence:x}\n",
			std::process::id()
		)
		.into_bytes()
	}

	fn write_owner(file: &mut File, owner: &[u8]) -> io::Result<()> {
		file.set_len(0)?;
		file.write_all(owner)?;
		file.sync_all()
	}

	fn is_stale(file: &File, stale_after: Duration) -> io::Result<bool> {
		Ok(file
			.metadata()?
			.modified()?
			.elapsed()
			.is_ok_and(|age| age >= stale_after))
	}

	#[must_use]
	pub fn path(&self) -> &Path {
		&self.path
	}

	#[cfg(test)]
	fn abandon(mut self) {
		self.remove_on_drop = false;
	}
}

impl Drop for BusyLock {
	fn drop(&mut self) {
		// Section 5.1: after the job, successful or not, the file is deleted.
		if self.remove_on_drop
			&& fs::read(&self.path).ok().as_deref() == Some(self.owner.as_slice())
		{
			let _ = fs::remove_file(&self.path);
		}
		let _ = self.file.unlock();
	}
}

/// Whether a `.hld` file forbids contacting this node right now.
///
/// Section 5.3: the file holds one line with the expiration in UNIX time. A
/// future expiration means hold; a past one means the file must be deleted.
pub fn held(path: &Path) -> io::Result<bool> {
	let contents = match fs::read_to_string(path) {
		Ok(contents) => contents,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
		Err(error) => return Err(error),
	};
	let Some(expiry) = contents
		.split_whitespace()
		.next()
		.and_then(|value| value.parse::<i64>().ok())
	else {
		// An unreadable hold is not a licence to ignore it.
		return Ok(true);
	};
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |since| {
			i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
		});
	if expiry > now {
		return Ok(true);
	}
	fs::remove_file(path)?;
	Ok(false)
}

/// Rewrites a reference file without the consumed lines, deleting it when
/// nothing is left.
///
/// Section 3.1 requires the flow file be deleted after its listed files are
/// transferred. Lines that were not consumed are written back exactly as they
/// arrived.
pub fn rewrite_reference(path: &Path, keep: &[String]) -> io::Result<()> {
	if keep.is_empty() {
		return match fs::remove_file(path) {
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
			other => other,
		};
	}
	let mut body = String::new();
	for line in keep {
		body.push_str(line);
		body.push('\n');
	}
	fs::write(path, body)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn temp_dir(name: &str) -> PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-bso-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = fs::remove_dir_all(&path);
		fs::create_dir_all(&path).expect("temp directory");
		path
	}

	#[test]
	fn reads_every_reference_directive() {
		let references = parse_reference(
			"#bundle.su0\r\n^work.zip\r\n-other.zip\r\n~done.zip\r\n!also.zip\r\n@keep.zip\r\nplain.zip\r\n",
		);
		let names: Vec<_> = references.iter().map(|item| item.name.as_str()).collect();
		assert_eq!(
			names,
			[
				"bundle.su0",
				"work.zip",
				"other.zip",
				"keep.zip",
				"plain.zip"
			]
		);
		let dispositions: Vec<_> = references.iter().map(|item| item.disposition).collect();
		assert_eq!(
			dispositions,
			[
				Disposition::Truncate,
				Disposition::Delete,
				Disposition::Delete,
				Disposition::Keep,
				Disposition::Keep
			]
		);
		// The original text is preserved so an unconsumed line round-trips.
		assert_eq!(references[0].line, "#bundle.su0");
	}

	#[test]
	fn reads_every_request_action_form() {
		let requests = parse_request(
			"nodediff.zip\r\nfiles.zip +1755400000\rsecret.zip !password\nold.zip -1755400000\n\n",
		);
		let names: Vec<_> = requests.iter().map(|item| item.filename.as_str()).collect();
		assert_eq!(
			names,
			["nodediff.zip", "files.zip", "secret.zip", "old.zip"]
		);
		assert_eq!(requests[1].newer_than, Some(1_755_400_000));
		// A password is legacy link policy only and never reaches TITH.
		assert_eq!(requests[2].newer_than, None);
		assert!(!requests[2].unsupported);
		// TSP-0003 section 8: a minus time has no exact TITH representation.
		assert!(requests[3].unsupported);
		assert_eq!(requests[3].line, "old.zip -1755400000");
		// A Filename may not carry a path component.
		assert!(parse_request("sub/dir.zip\n")[0].unsupported);
	}

	#[test]
	fn malformed_or_out_of_order_request_conditions_stay_unsupported() {
		let valid = &parse_request("good.zip !password +123")[0];
		assert!(!valid.unsupported);
		assert_eq!(valid.newer_than, Some(123));

		for line in [
			"bad.zip +not-a-time",
			"bad.zip !",
			"bad.zip +123 !password",
			"bad.zip !one !two",
			"bad.zip +123 +456",
			"bad.zip unexpected",
		] {
			let request = &parse_request(line)[0];
			assert!(request.unsupported, "{line} became a native request");
		}
	}

	#[test]
	fn resolves_a_bare_name_beside_the_flow_file() {
		let reference = &parse_reference("work.zip\n")[0];
		assert_eq!(
			reference.resolve(Path::new("/bink/outbound")),
			PathBuf::from("/bink/outbound/work.zip")
		);
		let absolute = &parse_reference("/spool/work.zip\n")[0];
		assert_eq!(
			absolute.resolve(Path::new("/bink/outbound")),
			PathBuf::from("/spool/work.zip")
		);
	}

	#[test]
	fn exactly_one_holder_takes_the_lock_and_drop_releases_it() {
		let directory = temp_dir("bsy");
		let path = directory.join("00680024.bsy");
		let first = BusyLock::take(path.clone(), Duration::from_mins(10))
			.expect("take")
			.expect("first holder");
		assert!(path.exists());
		assert!(
			BusyLock::take(path.clone(), Duration::from_mins(10))
				.expect("take")
				.is_none(),
			"a second holder took a held lock"
		);
		drop(first);
		assert!(!path.exists(), "drop did not release the lock");
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn dropping_a_displaced_guard_does_not_remove_its_replacement() {
		let directory = temp_dir("bsy-replacement");
		let path = directory.join("00680024.bsy");
		let first = BusyLock::take(path.clone(), Duration::from_mins(10))
			.expect("take")
			.expect("first holder");
		fs::remove_file(&path).expect("simulate stale-lock displacement");
		let replacement = BusyLock::take(path.clone(), Duration::from_mins(10))
			.expect("take")
			.expect("replacement holder");

		drop(first);
		assert!(path.exists(), "the old guard removed the replacement lock");
		drop(replacement);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_stale_lock_is_reclaimed_but_a_fresh_one_is_not() {
		let directory = temp_dir("stale");
		let path = directory.join("00680024.bsy");
		let held = BusyLock::take(path.clone(), Duration::from_mins(10))
			.expect("take")
			.expect("holder");

		assert!(
			BusyLock::take(path.clone(), Duration::from_mins(10))
				.expect("take")
				.is_none()
		);
		assert!(
			BusyLock::take(path.clone(), Duration::ZERO)
				.expect("take")
				.is_none(),
			"a live scanner must not lose its lock merely because it ran long"
		);
		held.abandon(); // simulate a crash: close the handle but retain the file
		let reclaimed = BusyLock::take(path.clone(), Duration::ZERO)
			.expect("take")
			.expect("stale lock reclaimed");
		assert_eq!(reclaimed.path(), path);
		drop(reclaimed);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_future_hold_blocks_and_an_expired_one_is_deleted() {
		let directory = temp_dir("hld");
		let path = directory.join("00680024.hld");
		assert!(!held(&path).expect("absent hold"));

		let future = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_secs()
			+ 3600;
		fs::write(&path, format!("{future}\n")).expect("write");
		assert!(held(&path).expect("future hold"));
		assert!(path.exists());

		fs::write(&path, "1\n").expect("write");
		assert!(!held(&path).expect("expired hold"));
		assert!(!path.exists(), "an expired hold must be deleted");
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn rewriting_keeps_unconsumed_lines_and_deletes_an_empty_file() {
		let directory = temp_dir("rewrite");
		let path = directory.join("00680024.flo");
		fs::write(&path, "#bundle.su0\n^work.zip\n").expect("write");

		rewrite_reference(&path, &["#bundle.su0".to_owned()]).expect("rewrite");
		assert_eq!(fs::read_to_string(&path).expect("read"), "#bundle.su0\n");

		rewrite_reference(&path, &[]).expect("rewrite");
		assert!(!path.exists());
		fs::remove_dir_all(directory).expect("cleanup");
	}
}
