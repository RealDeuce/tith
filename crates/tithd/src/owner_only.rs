//! Files and directories only their owner may reach: the key files, the
//! endpoint directories, and the exported item payloads.
//!
//! POSIX spells this as a mode. Windows has no mode; its equivalent is a
//! protected DACL naming `LocalSystem` and the object owner and nobody else.
//! Protected matters: without it an object in a user profile inherits whatever
//! that profile grants.
//!
//! Each platform gets its own mechanism rather than one getting nothing, which
//! is why every function here is implemented twice instead of being skipped
//! under a `cfg`.
//!
//! Both mechanisms need a filesystem which has one. FAT and exFAT have neither,
//! and a network mount may have neither, so the state directory, the endpoint
//! roots, the exports, and the key files all have to live somewhere which does.
//! That is a real restriction and it is enforced rather than assumed: every
//! function here reads back what it applied, because a filesystem without
//! access control accepts the request and ignores it instead of refusing it.
//! The legacy inbound and outbound directories, which are the ones an operator
//! is likely to put on a share, are not restricted by anything here.

use std::fs::File;
use std::io;
use std::path::Path;

/// Creates `path` reachable only by its owner, failing when it already exists.
pub fn create_file(path: &Path) -> io::Result<File> {
	platform::create(path)
}

/// Creates `path` reachable only by its owner and writes `bytes` durably.
///
/// The create fails when the file already exists, so a key is never replaced by
/// accident.
pub fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
	write_verified(path, bytes, platform::check)
}

/// A filesystem with no access control of its own accepts the request and
/// ignores it rather than refusing it — FAT and exFAT do, and so do some
/// network mounts. Asking is therefore not the same as having asked
/// successfully, and only a read back says which happened.
///
/// The written key is removed when it did not take. Reporting the failure while
/// leaving an unprotected copy of a secret on disk would be the worst of both
/// answers.
fn write_verified(
	path: &Path,
	bytes: &[u8],
	verify: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<()> {
	use io::Write as _;
	let mut file = create_file(path)?;
	file.write_all(bytes)?;
	file.sync_all()?;
	drop(file);
	if let Err(error) = verify(path) {
		let _ = std::fs::remove_file(path);
		return Err(error);
	}
	Ok(())
}

/// Reads `path` once the host confirms nobody but its owner can reach it.
pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
	platform::check(path)?;
	std::fs::read(path)
}

/// Creates `path` and every missing parent, then restricts `path` to its owner.
///
/// The restriction is applied whether or not this call created the directory,
/// because an endpoint root handed over by an operator is exactly the case that
/// needs it.
pub fn create_directory(path: &Path) -> io::Result<()> {
	std::fs::create_dir_all(path)?;
	platform::restrict_directory(path)?;
	// Confirmed for the same reason `write_verified` confirms: a filesystem
	// without access control ignores the request instead of refusing it, and a
	// service which believes it restricted this directory would be wrong about
	// every item it later puts here.
	platform::check(path)
}

/// Leaves an existing file readable by its owner and writable by nobody.
///
/// Used for a published export, which its consumer reads and the service later
/// removes, and which neither should modify in place. Removing it stays
/// possible: POSIX gates that on the containing directory, and the Windows
/// spelling grants the owner DELETE rather than setting the read-only attribute,
/// which would make the service unable to clean up after itself.
pub fn seal(path: &Path) -> io::Result<()> {
	platform::seal_file(path)?;
	platform::check(path)
}

#[cfg(unix)]
mod platform {
	use std::fs::{File, OpenOptions, Permissions};
	use std::io;
	use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
	use std::path::Path;

	pub fn create(path: &Path) -> io::Result<File> {
		OpenOptions::new()
			.create_new(true)
			.write(true)
			.mode(0o600)
			.open(path)
	}

	pub fn check(path: &Path) -> io::Result<()> {
		// Every group and other bit clear, which is what mode 0600 leaves.
		if std::fs::metadata(path)?
			.permissions()
			.mode()
			.trailing_zeros()
			>= 6
		{
			return Ok(());
		}
		Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			format!(
				"{} is accessible by group or other users; it needs mode 0600",
				path.display()
			),
		))
	}

	pub fn restrict_directory(path: &Path) -> io::Result<()> {
		std::fs::set_permissions(path, Permissions::from_mode(0o700))
	}

	pub fn seal_file(path: &Path) -> io::Result<()> {
		std::fs::set_permissions(path, Permissions::from_mode(0o400))
	}
}

#[cfg(windows)]
mod platform {
	pub use crate::windows::{
		create_owner_only as create, owner_only_dacl as check, restrict_directory, seal_file,
	};
}

/// Whether an SDDL DACL is protected and reaches nobody but `LocalSystem` and
/// the object owner.
///
/// This lives here rather than beside the Win32 calls that produce its input so
/// that it is ordinary safe Rust with tests which run on every host. Only the
/// calls which fetch and apply the descriptor are Windows-only, and those are as
/// small as the API allows.
///
/// Rights are deliberately not compared. Windows may spell `FILE_ALL_ACCESS` as
/// "FA" or as its hexadecimal value, a sealed file grants its owner less than an
/// unsealed one, and none of that says who can reach the object. The trustees
/// do.
#[cfg(any(windows, test))]
pub(crate) fn permits_only_owner(sddl: &str) -> bool {
	// "SY" is LocalSystem and "OW" is OWNER RIGHTS, which Windows evaluates as
	// whoever currently owns the object. Either may appear as a raw SID.
	const ALLOWED: [&str; 4] = ["SY", "OW", "S-1-5-18", "S-1-3-4"];
	let Some(dacl) = sddl.strip_prefix("D:") else {
		return false;
	};
	let (flags, aces) = match dacl.find('(') {
		Some(position) => dacl.split_at(position),
		None => (dacl, ""),
	};
	// "P" is protected, which is what makes the containing directory's entries
	// not apply. "AI" may sit beside it: that is SE_DACL_AUTO_INHERITED, which
	// records that the auto-inheritance algorithm produced this DACL, and
	// SetNamedSecurityInfoW sets it where CreateFileW with an explicit
	// descriptor does not. It says nothing about who can reach the object. An
	// entry which really was inherited carries "ID" in its own flags, and the
	// per-entry check below rejects any flags at all.
	if !flags.contains('P') {
		return false;
	}
	let mut remaining = aces;
	let mut seen = 0;
	while let Some(rest) = remaining.strip_prefix('(') {
		let Some(end) = rest.find(')') else {
			return false;
		};
		let fields: Vec<&str> = rest[..end].split(';').collect();
		// type;flags;rights;object;inherited-object;trustee
		let [kind, ace_flags, _rights, _object, _inherited, trustee] = fields.as_slice() else {
			return false;
		};
		if *kind != "A" || !ace_flags.is_empty() || !ALLOWED.contains(trustee) {
			return false;
		}
		seen += 1;
		remaining = &rest[end + 1..];
	}
	remaining.is_empty() && seen > 0
}

#[cfg(test)]
mod tests {
	use super::{create_directory, permits_only_owner, read_file, seal, write_file};
	use std::io;

	fn directory(name: &str) -> std::path::PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-owner-only-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = std::fs::remove_dir_all(&path);
		std::fs::create_dir_all(&path).unwrap();
		path
	}

	/// The round trip through the host, which is the half `permits_only_owner`
	/// cannot check by itself: whether what `create` writes is what `check`
	/// accepts, in whatever spelling the host stores and reports it.
	#[test]
	fn a_key_reads_back_and_an_ordinary_file_does_not() {
		let root = directory("roundtrip");
		let key = root.join("node.secret");
		write_file(&key, b"secret bytes").unwrap();
		assert_eq!(read_file(&key).unwrap(), b"secret bytes");

		// The create is exclusive, so an existing key is never replaced.
		assert_eq!(
			write_file(&key, b"other").unwrap_err().kind(),
			io::ErrorKind::AlreadyExists
		);

		// A file made the ordinary way is reachable by more than its owner and is
		// refused. Without this the assertion above could pass by accepting
		// everything the host ever returns.
		let ordinary = root.join("ordinary");
		std::fs::write(&ordinary, b"secret bytes").unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt as _;
			std::fs::set_permissions(&ordinary, std::fs::Permissions::from_mode(0o644)).unwrap();
		}
		let error = read_file(&ordinary).unwrap_err();
		assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");

		std::fs::remove_dir_all(root).unwrap();
	}

	/// A host which ignores the request rather than refusing it leaves a secret
	/// on disk unprotected. No ordinary filesystem here does that, so the
	/// verifier is supplied directly; the behaviour it guards is the reason the
	/// check exists at all.
	#[test]
	fn a_key_the_host_did_not_protect_is_not_left_behind() {
		let root = directory("unprotected");
		let key = root.join("node.secret");
		let refused = |_: &std::path::Path| {
			Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"this filesystem has no access control",
			))
		};
		let error = super::write_verified(&key, b"secret bytes", refused).unwrap_err();
		assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
		assert!(!key.exists(), "an unprotected key was left on disk");

		// The name is free again, so a retry on a filesystem which does support
		// it is not blocked by the exclusive create.
		write_file(&key, b"secret bytes").unwrap();
		assert_eq!(read_file(&key).unwrap(), b"secret bytes");
		std::fs::remove_dir_all(root).unwrap();
	}

	/// A directory is restricted whether this created it or found it, and stays
	/// usable afterwards: the service still writes into it and reads back.
	#[test]
	fn a_directory_is_restricted_and_still_usable() {
		let root = directory("directory");
		let fresh = root.join("endpoint").join("requests");
		create_directory(&fresh).unwrap();
		assert!(fresh.is_dir());

		// An operator's existing directory is restricted rather than left alone.
		let existing = root.join("handed-over");
		std::fs::create_dir_all(&existing).unwrap();
		create_directory(&existing).unwrap();

		for path in [&fresh, &existing] {
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt as _;
				let mode = std::fs::metadata(path).unwrap().permissions().mode();
				assert_eq!(mode & 0o077, 0, "{} is {mode:o}", path.display());
			}
			let file = path.join("item.tlv");
			std::fs::write(&file, b"payload").unwrap();
			assert_eq!(std::fs::read(&file).unwrap(), b"payload");
		}
		std::fs::remove_dir_all(root).unwrap();
	}

	/// A sealed export stays readable and, crucially, stays removable: the
	/// service deletes it once its consumer acknowledges.
	#[test]
	fn a_sealed_file_is_readable_and_still_removable() {
		let root = directory("seal");
		let export = root.join("item.tlv");
		write_file(&export, b"payload").unwrap();
		seal(&export).unwrap();

		assert_eq!(std::fs::read(&export).unwrap(), b"payload");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt as _;
			assert_eq!(
				std::fs::metadata(&export).unwrap().permissions().mode() & 0o777,
				0o400
			);
		}
		std::fs::remove_file(&export).unwrap();
		std::fs::remove_dir_all(root).unwrap();
	}

	#[test]
	fn accepts_only_a_protected_owner_and_system_dacl() {
		// What `create` writes, in both spellings Windows may return.
		assert!(permits_only_owner("D:P(A;;FA;;;SY)(A;;FA;;;OW)"));
		assert!(permits_only_owner("D:P(A;;0x1f01ff;;;SY)(A;;FA;;;OW)"));
		assert!(permits_only_owner("D:P(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-3-4)"));
		assert!(permits_only_owner("D:P(A;;FA;;;OW)"));
		// What `seal` writes: the owner reads and deletes but cannot write.
		assert!(permits_only_owner("D:P(A;;FA;;;SY)(A;;FRSD;;;OW)"));
		// What SetNamedSecurityInfoW actually stores: protected, and flagged as
		// having come from the auto-inheritance algorithm. Windows reported this
		// spelling for a restricted directory and for a sealed file.
		assert!(permits_only_owner("D:PAI(A;;FA;;;SY)(A;;FA;;;OW)"));
		assert!(permits_only_owner("D:PAI(A;;FA;;;SY)(A;;FRSD;;;OW)"));

		// Any other trustee can reach the object, whoever it is.
		assert!(!permits_only_owner("D:P(A;;FA;;;SY)(A;;FA;;;WD)"));
		assert!(!permits_only_owner("D:P(A;;FA;;;BA)"));
		assert!(!permits_only_owner("D:P(A;;FR;;;S-1-5-21-1-2-3-1001)"));
		// An unprotected DACL inherits whatever the directory grants, with or
		// without the auto-inheritance flag beside it.
		assert!(!permits_only_owner("D:(A;;FA;;;OW)"));
		assert!(!permits_only_owner("D:AI(A;;FA;;;OW)"));
		// An entry which really was inherited says so in its own flags.
		assert!(!permits_only_owner("D:PAI(A;ID;FA;;;OW)"));
		assert!(!permits_only_owner("D:PAI(A;;FA;;;OW)(A;ID;FA;;;BA)"));
		// A deny entry is not an allow entry, and neither is a malformed one.
		assert!(!permits_only_owner("D:P(D;;FA;;;WD)(A;;FA;;;OW)"));
		assert!(!permits_only_owner("D:P(A;OICI;FA;;;OW)"));
		assert!(!permits_only_owner("D:P(A;;FA;;;OW"));
		assert!(!permits_only_owner("D:P(A;;FA;OW)"));
		assert!(!permits_only_owner("D:P(A;;FA;;;OW)junk"));
		// No entries at all is not owner-only; it is unreadable or inherited.
		assert!(!permits_only_owner("D:P"));
		assert!(!permits_only_owner(""));
		assert!(!permits_only_owner("O:BAG:BAD:P(A;;FA;;;OW)"));
	}
}
