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

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
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

/// A held `.bsy` lock. Dropping it removes the file.
#[derive(Debug)]
pub struct BusyLock {
	path: PathBuf,
}

impl BusyLock {
	/// Takes the lock, or reports that another program holds it.
	///
	/// Created with `create_new`, which is the `O_EXCL` that section 5.1's own
	/// note about `fopen` quietly overwriting is asking for. A lock older than
	/// `stale_after` is removed first: section 5.1 recommends ignoring and
	/// deleting a bsy older than twice the maximum session time.
	pub fn take(path: PathBuf, stale_after: Duration) -> io::Result<Option<Self>> {
		if let Ok(metadata) = fs::metadata(&path)
			&& metadata
				.modified()
				.ok()
				.and_then(|modified| modified.elapsed().ok())
				.is_some_and(|age| age >= stale_after)
		{
			let _ = fs::remove_file(&path);
		}
		match fs::OpenOptions::new()
			.create_new(true)
			.write(true)
			.open(&path)
		{
			Ok(mut file) => {
				// Section 5.1 permits one line of PID information under 70 bytes.
				let line = format!("tith bso scan pid {}\n", std::process::id());
				file.write_all(line.as_bytes())?;
				file.sync_all()?;
				Ok(Some(Self { path }))
			}
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(None),
			Err(error) => Err(error),
		}
	}

	#[must_use]
	pub fn path(&self) -> &Path {
		&self.path
	}
}

impl Drop for BusyLock {
	fn drop(&mut self) {
		// Section 5.1: after the job, successful or not, the file is deleted.
		let _ = fs::remove_file(&self.path);
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
	fn a_stale_lock_is_reclaimed_but_a_fresh_one_is_not() {
		let directory = temp_dir("stale");
		let path = directory.join("00680024.bsy");
		let held = BusyLock::take(path.clone(), Duration::from_mins(10))
			.expect("take")
			.expect("holder");
		std::mem::forget(held); // simulate a crash: the file stays behind

		assert!(
			BusyLock::take(path.clone(), Duration::from_mins(10))
				.expect("take")
				.is_none()
		);
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
