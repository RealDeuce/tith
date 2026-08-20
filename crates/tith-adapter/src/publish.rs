//! TSP-0013 section 5 legacy publication.
//!
//! Every object is first constructed under a private temporary name on the
//! destination filesystem, its contents and metadata are made durable, and it
//! is then atomically published under an unused final name without replacing an
//! existing object. The containing directory update is then made durable.
//!
//! When a packet or control object refers to companion files, every companion
//! is durably published first and the referencing object is published last, so
//! "A legacy tosser MUST NOT be able to observe a packet whose required
//! companion is still temporary or incomplete."

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// One object to publish, in the order given.
#[derive(Clone, Debug)]
pub struct Publication {
	/// The generated final name, already recorded in the ledger.
	pub name: String,
	pub contents: Vec<u8>,
}

/// A digest which lets recovery recognise the adapter's own object.
///
/// FNV-1a: this is collision detection for a name the adapter itself generated,
/// not an authentication decision, so a short non-cryptographic digest is the
/// right tool.
#[must_use]
pub fn digest(bytes: &[u8]) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325_u64;
	for byte in bytes {
		hash ^= u64::from(*byte);
		hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
	}
	hash
}

/// Writes one object under a temporary name and makes its contents durable.
///
/// The temporary name is private to the adapter and is not the pattern the
/// tosser globs, so a partially written object is never a candidate for it.
fn stage(directory: &Path, name: &str, contents: &[u8]) -> io::Result<PathBuf> {
	let path = directory.join(format!(".tith-staging-{name}"));
	// create_new so two adapters cannot both believe they own this staging file.
	let mut file = match OpenOptions::new().create_new(true).write(true).open(&path) {
		Ok(file) => file,
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
			fs::remove_file(&path)?;
			OpenOptions::new()
				.create_new(true)
				.write(true)
				.open(&path)?
		}
		Err(error) => return Err(error),
	};
	file.write_all(contents)?;
	file.sync_all()?;
	Ok(path)
}

/// Makes a directory entry durable, so a crash cannot lose the publication.
///
/// A directory cannot be opened for writing; opening it read-only is enough for
/// fsync on the platforms which have one.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
	File::open(directory)?.sync_all()
}

/// Windows has no directory fsync, and cannot even open a directory as a file
/// without `FILE_FLAG_BACKUP_SEMANTICS`, so this is a documented no-op rather
/// than an error to catch. The object's own `sync_all` and the ordering NTFS
/// gives its metadata are what durability rests on there.
///
/// `tithd::filesystem` and `tith_submit::filesystem` say the same thing the
/// same way.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "one signature for both platforms")]
fn sync_directory(_: &Path) -> io::Result<()> {
	Ok(())
}

/// Publishes an object under an unused final name.
///
/// Returns false when the name is taken, which the caller resolves by selecting
/// and recording another name rather than replacing anything.
fn claim_name(staged: &Path, directory: &Path, name: &str) -> io::Result<bool> {
	let final_path = directory.join(name);
	// A rename would replace an existing object, which section 5 forbids, so the
	// name is claimed with an exclusive create and the staged bytes are moved
	// into it by a hard link where possible.
	match fs::hard_link(staged, &final_path) {
		Ok(()) => {
			fs::remove_file(staged)?;
			sync_directory(directory)?;
			Ok(true)
		}
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
		Err(_) => {
			// A filesystem without hard links still needs the no-replace rule, so
			// the name is reserved by an exclusive create and then written.
			match OpenOptions::new()
				.create_new(true)
				.write(true)
				.open(&final_path)
			{
				Ok(mut file) => {
					let contents = fs::read(staged)?;
					file.write_all(&contents)?;
					file.sync_all()?;
					fs::remove_file(staged)?;
					sync_directory(directory)?;
					Ok(true)
				}
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
				Err(error) => Err(error),
			}
		}
	}
}

/// Publishes a complete object set in order, companions before the object which
/// refers to them.
///
/// Returns the names actually used. A name already taken is reported so the
/// caller can record a fresh one before trying again; recovery never overwrites
/// an unrelated existing object.
pub fn publish(directory: &Path, objects: &[Publication]) -> io::Result<Result<(), String>> {
	let mut staged = Vec::new();
	for object in objects {
		staged.push(stage(directory, &object.name, &object.contents)?);
	}
	for (path, object) in staged.iter().zip(objects) {
		if !claim_name(path, directory, &object.name)? {
			// Leave every remaining staged object behind for the caller to retry
			// under new names. Nothing published so far is removed: an object the
			// tosser may already have consumed is not ours to withdraw.
			return Ok(Err(object.name.clone()));
		}
	}
	Ok(Ok(()))
}

/// Removes any staging files left by an interrupted publication.
///
/// Staged objects carry no final name, so nothing can have consumed them.
pub fn clear_staging(directory: &Path) -> io::Result<usize> {
	let mut removed = 0;
	for entry in fs::read_dir(directory)? {
		let entry = entry?;
		if entry
			.file_name()
			.to_string_lossy()
			.starts_with(".tith-staging-")
		{
			fs::remove_file(entry.path())?;
			removed += 1;
		}
	}
	Ok(removed)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn directory(name: &str) -> PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-publish-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = fs::remove_dir_all(&path);
		fs::create_dir_all(&path).unwrap();
		path
	}

	fn object(name: &str, contents: &str) -> Publication {
		Publication {
			name: name.to_owned(),
			contents: contents.as_bytes().to_vec(),
		}
	}

	#[test]
	fn every_object_appears_under_its_final_name() {
		let root = directory("publish");
		let objects = [
			object("work.zip", "payload"),
			object("00000001.pkt", "packet"),
		];
		assert!(publish(&root, &objects).unwrap().is_ok());
		assert_eq!(fs::read(root.join("work.zip")).unwrap(), b"payload");
		assert_eq!(fs::read(root.join("00000001.pkt")).unwrap(), b"packet");
		// No staging file is left behind.
		assert_eq!(clear_staging(&root).unwrap(), 0);
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn an_existing_object_is_never_replaced() {
		let root = directory("collision");
		fs::write(root.join("work.zip"), b"someone else's file").unwrap();
		let outcome = publish(&root, &[object("work.zip", "payload")]).unwrap();
		assert_eq!(outcome, Err("work.zip".to_owned()));
		// The existing bytes are untouched.
		assert_eq!(
			fs::read(root.join("work.zip")).unwrap(),
			b"someone else's file"
		);
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn a_companion_is_published_before_the_object_naming_it() {
		// The packet name collides, so the companion published first stays and the
		// packet does not appear at all. The tosser can therefore never see a
		// packet whose companion is missing, only the reverse.
		let root = directory("ordering");
		fs::write(root.join("00000001.pkt"), b"taken").unwrap();
		let outcome = publish(
			&root,
			&[
				object("work.zip", "payload"),
				object("00000001.pkt", "packet"),
			],
		)
		.unwrap();
		assert_eq!(outcome, Err("00000001.pkt".to_owned()));
		assert!(root.join("work.zip").exists());
		assert_eq!(fs::read(root.join("00000001.pkt")).unwrap(), b"taken");
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn staging_files_are_recoverable_and_not_visible_as_objects() {
		let root = directory("staging");
		let path = stage(&root, "00000001.pkt", b"partial").unwrap();
		assert!(path.exists());
		// The staged name is not the name a tosser globs for.
		assert!(!root.join("00000001.pkt").exists());
		assert!(
			path.file_name()
				.unwrap()
				.to_string_lossy()
				.starts_with(".tith-staging-")
		);
		assert_eq!(clear_staging(&root).unwrap(), 1);
		assert!(!path.exists());
		fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn the_digest_distinguishes_contents() {
		assert_eq!(digest(b"payload"), digest(b"payload"));
		assert_ne!(digest(b"payload"), digest(b"payloae"));
		assert_ne!(digest(b""), digest(b"\0"));
	}
}
